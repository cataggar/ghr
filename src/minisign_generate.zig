//! Generate a local recovery keypair and provision GitHub Actions secrets.
//! Crypto is provided by minizign; serialization here only adds safe,
//! no-replacement file handling around the library's public key fields.
const std = @import("std");
const builtin = @import("builtin");
const minizign = @import("minizign");
const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;
const Writer = Io.Writer;
const Allocator = std.mem.Allocator;
const Environ = std.process.Environ.Map;

const private_path = "minisign.key";
const public_path = "minisign.pub";
const output_limit = 64 * 1024;

const Options = struct {
    repo: ?[]const u8 = null,
    encrypt: bool = false,
    replace: bool = false,
    reuse: bool = false,
    help: bool = false,
};

pub fn cmdGenerate(
    allocator: Allocator,
    io: Io,
    environ: *const Environ,
    args: *std.process.Args.Iterator,
    w: *Writer,
    err_w: *Writer,
) !void {
    const options = try parseOptions(args, err_w);
    if (options.help) {
        try printUsage(w);
        try w.flush();
        return;
    }
    try generate(allocator, io, environ, Dir.cwd(), options, .{}, w, err_w);
}

fn fail(w: *Writer, comptime format: []const u8, args: anytype) error{ GenerateFailed, WriteFailed } {
    w.print("error: " ++ format ++ "\n", args) catch return error.WriteFailed;
    w.flush() catch return error.WriteFailed;
    return error.GenerateFailed;
}

fn parseOptions(args: anytype, err_w: *Writer) !Options {
    var options: Options = .{};
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--repo")) {
            if (options.repo != null) return fail(err_w, "--repo may only be specified once", .{});
            const repo = args.next() orelse return fail(err_w, "--repo requires OWNER/REPO", .{});
            if (!validRepo(repo)) return fail(err_w, "--repo must be a valid OWNER/REPO", .{});
            options.repo = repo;
        } else if (std.mem.eql(u8, arg, "--encrypt")) {
            options.encrypt = true;
        } else if (std.mem.eql(u8, arg, "--replace-existing-secrets")) {
            options.replace = true;
        } else if (std.mem.eql(u8, arg, "--reuse-existing-local-pair")) {
            options.reuse = true;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            options.help = true;
        } else {
            return fail(err_w, "unknown option for 'ghr minisign generate'; run with --help", .{});
        }
    }
    return options;
}

pub fn printUsage(w: *Writer) !void {
    try w.writeAll(
        \\ghr minisign generate - generate recovery keys and provision Actions secrets
        \\
        \\USAGE:
        \\    ghr minisign generate [--repo OWNER/REPO] [--encrypt]
        \\        [--replace-existing-secrets] [--reuse-existing-local-pair]
        \\
        \\--repo OWNER/REPO          Override gh's current repository context
        \\--encrypt                  Encrypt with nonempty MINISIGN_PASSWORD;
        \\                           also upload that password as an Actions secret
        \\--replace-existing-secrets  Explicitly allow remote secret replacement
        \\--reuse-existing-local-pair Retry with minisign.key and minisign.pub;
        \\                           never generate or replace a private key
        \\-h, --help                  Show this help
        \\
        \\Default: unencrypted minisign.pub/minisign.key; only MINISIGN_SECRET_KEY
        \\is uploaded. MINISIGN_PASSWORD is not required, read, or modified.
        \\Existing local files/symlinks and either existing remote secret are
        \\refused without the corresponding explicit option. --replace-existing-
        \\secrets does not replace local files or alter a password in default mode.
        \\
        \\Private files use owner-only permissions (0600 on POSIX, a protected
        \\owner-only DACL on Windows). Keep minisign.key as a secure recovery
        \\backup; never commit, log, cache, or upload it as a build artifact.
        \\Upload is not a transaction: failures may have changed remote secrets.
        \\Retry with --reuse-existing-local-pair --replace-existing-secrets and
        \\the original --repo/--encrypt options. Reuse reconstructs minisign.pub
        \\if absent, but refuses a different public key or unsafe private file.
        \\
    );
}

fn validRepo(repo: []const u8) bool {
    const slash = std.mem.indexOfScalar(u8, repo, '/') orelse return false;
    const owner = repo[0..slash];
    const name = repo[slash + 1 ..];
    if (owner.len == 0 or owner.len > 39 or name.len == 0 or name.len > 100) return false;
    if (owner[0] == '-' or owner[owner.len - 1] == '-' or name[0] == '-') return false;
    if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return false;
    for (owner) |c| if (!std.ascii.isAlphanumeric(c) and c != '-') return false;
    for (name) |c| if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_' and c != '.') return false;
    return true;
}

fn validHost(host: []const u8) bool {
    if (host.len == 0 or host.len > 253) return false;
    var labels = std.mem.splitScalar(u8, host, '.');
    while (labels.next()) |label| {
        if (label.len == 0 or label.len > 63 or label[0] == '-' or label[label.len - 1] == '-') return false;
        for (label) |c| if (!std.ascii.isAlphanumeric(c) and c != '-') return false;
    }
    return true;
}

const Result = struct {
    stdout: []u8,
    term: std.process.Child.Term,

    fn deinit(self: Result, allocator: Allocator) void {
        std.crypto.secureZero(u8, self.stdout);
        allocator.free(self.stdout);
    }
};

const Runner = struct {
    context: ?*anyopaque = null,
    call: *const fn (?*anyopaque, Allocator, Io, *const Environ, []const []const u8, []const u8) anyerror!Result = runGh,
};

fn checked(
    allocator: Allocator,
    io: Io,
    environ: *const Environ,
    runner: Runner,
    argv: []const []const u8,
    input: []const u8,
    operation: []const u8,
    err_w: *Writer,
) !Result {
    const result = runner.call(runner.context, allocator, io, environ, argv, input) catch |err| {
        return fail(err_w, "{s}: {s}; install gh, authenticate with 'gh auth login', and check repository access", .{ operation, @errorName(err) });
    };
    if (!result.term.success()) {
        defer result.deinit(allocator);
        // Never print child output: gh or a failing wrapper could echo stdin.
        return fail(err_w, "{s}: gh terminated with {f}; check authentication, Actions secrets permissions, and network access", .{ operation, result.term });
    }
    return result;
}

fn childEnviron(allocator: Allocator, source: *const Environ) !Environ {
    var dest: Environ = .init(allocator);
    errdefer dest.deinit();
    var it = source.iterator();
    while (it.next()) |entry| {
        const name = entry.key_ptr.*;
        if (std.ascii.eqlIgnoreCase(name, "MINISIGN_SECRET_KEY") or
            std.ascii.eqlIgnoreCase(name, "MINISIGN_PASSWORD") or
            std.ascii.eqlIgnoreCase(name, "GH_DEBUG") or
            std.ascii.eqlIgnoreCase(name, "DEBUG")) continue;
        try dest.put(name, entry.value_ptr.*);
    }
    try dest.put("GH_PROMPT_DISABLED", "1");
    try dest.put("GH_PAGER", "cat");
    try dest.put("NO_COLOR", "1");
    return dest;
}

const Target = struct {
    repo: []u8,
    host: []u8,
    qualified: []u8,

    fn deinit(self: Target, allocator: Allocator) void {
        allocator.free(self.repo);
        allocator.free(self.host);
        allocator.free(self.qualified);
    }
};

fn resolveTarget(allocator: Allocator, io: Io, environ: *const Environ, options: Options, runner: Runner, err_w: *Writer) !Target {
    if (options.repo) |repo| if (!validRepo(repo)) return fail(err_w, "--repo must be a valid OWNER/REPO", .{});
    const result = try checked(allocator, io, environ, runner, if (options.repo) |repo|
        &.{ "gh", "repo", "view", repo, "--json", "nameWithOwner,url,viewerPermission" }
    else
        &.{ "gh", "repo", "view", "--json", "nameWithOwner,url,viewerPermission" }, "", "cannot resolve repository", err_w);
    defer result.deinit(allocator);
    const RepoInfo = struct { nameWithOwner: []const u8, url: []const u8, viewerPermission: []const u8 };
    const parsed = std.json.parseFromSlice(RepoInfo, allocator, result.stdout, .{}) catch
        return fail(err_w, "gh repo view returned invalid repository JSON", .{});
    defer parsed.deinit();
    const info = parsed.value;
    if (!validRepo(info.nameWithOwner)) return fail(err_w, "gh returned an invalid repository name", .{});
    if (options.repo) |repo| {
        if (!std.ascii.eqlIgnoreCase(repo, info.nameWithOwner))
            return fail(err_w, "gh resolved a different repository than --repo; refusing to provision", .{});
    }
    const prefix = "https://";
    if (!std.mem.startsWith(u8, info.url, prefix)) return fail(err_w, "gh returned an invalid repository URL", .{});
    const host_end = std.mem.indexOfScalarPos(u8, info.url, prefix.len, '/') orelse
        return fail(err_w, "gh returned an invalid repository URL", .{});
    const host = info.url[prefix.len..host_end];
    if (!validHost(host) or !std.ascii.eqlIgnoreCase(info.url[host_end + 1 ..], info.nameWithOwner))
        return fail(err_w, "gh returned an inconsistent repository URL/name", .{});
    if (!std.mem.eql(u8, info.viewerPermission, "ADMIN") and
        !std.mem.eql(u8, info.viewerPermission, "MAINTAIN") and
        !std.mem.eql(u8, info.viewerPermission, "WRITE"))
        return fail(err_w, "repository access is insufficient to manage Actions secrets; request write/admin access", .{});
    const repo_copy = try allocator.dupe(u8, info.nameWithOwner);
    errdefer allocator.free(repo_copy);
    const host_copy = try allocator.dupe(u8, host);
    errdefer allocator.free(host_copy);
    return .{ .repo = repo_copy, .host = host_copy, .qualified = try allocator.print("{s}/{s}", .{ host, info.nameWithOwner }) };
}

fn preflight(allocator: Allocator, io: Io, environ: *const Environ, target: Target, options: Options, runner: Runner, err_w: *Writer) !void {
    const auth = try checked(allocator, io, environ, runner, &.{ "gh", "auth", "status", "--active", "--hostname", target.host }, "", "GitHub authentication failed", err_w);
    auth.deinit(allocator);
    const endpoint = try allocator.print("repos/{s}/actions/secrets/public-key", .{target.repo});
    defer allocator.free(endpoint);
    const access = try checked(allocator, io, environ, runner, &.{ "gh", "api", "--hostname", target.host, "--method", "GET", endpoint }, "", "cannot access repository Actions secrets API", err_w);
    defer access.deinit(allocator);
    const ApiKey = struct { key_id: []const u8, key: []const u8 };
    const api_key = std.json.parseFromSlice(ApiKey, allocator, access.stdout, .{}) catch
        return fail(err_w, "Actions secrets API returned invalid public-key JSON", .{});
    defer api_key.deinit();
    if (api_key.value.key_id.len == 0 or api_key.value.key_id.len > 32 or api_key.value.key.len != 44)
        return fail(err_w, "Actions secrets API returned an invalid public key", .{});
    for (api_key.value.key_id) |c| if (!std.ascii.isDigit(c))
        return fail(err_w, "Actions secrets API returned an invalid key ID", .{});
    var key: [32]u8 = undefined;
    const decoded_length = std.base64.standard.Decoder.calcSizeForSlice(api_key.value.key) catch
        return fail(err_w, "Actions secrets API returned an invalid public key", .{});
    if (decoded_length != key.len)
        return fail(err_w, "Actions secrets API returned an invalid public key", .{});
    std.base64.standard.Decoder.decode(&key, api_key.value.key) catch
        return fail(err_w, "Actions secrets API returned an invalid public key", .{});

    const list = try checked(allocator, io, environ, runner, &.{ "gh", "secret", "list", "--repo", target.qualified, "--app", "actions", "--json", "name" }, "", "cannot list existing Actions secrets", err_w);
    defer list.deinit(allocator);
    const names = std.json.parseFromSlice([]const struct { name: []const u8 }, allocator, list.stdout, .{}) catch
        return fail(err_w, "gh secret list returned invalid secrets JSON", .{});
    defer names.deinit();
    var existing = false;
    for (names.value) |secret| {
        if (secret.name.len == 0 or secret.name.len > 256)
            return fail(err_w, "gh secret list returned an invalid secret name", .{});
        for (secret.name) |c| if (!std.ascii.isAlphanumeric(c) and c != '_')
            return fail(err_w, "gh secret list returned an invalid secret name", .{});
        existing = existing or std.ascii.eqlIgnoreCase(secret.name, "MINISIGN_SECRET_KEY") or
            std.ascii.eqlIgnoreCase(secret.name, "MINISIGN_PASSWORD");
    }
    if (existing and !options.replace)
        return fail(err_w, "MINISIGN_SECRET_KEY or MINISIGN_PASSWORD already exists; refusing replacement (only --replace-existing-secrets explicitly permits it)", .{});
}

fn generate(allocator: Allocator, io: Io, environ: *const Environ, dir: Dir, options: Options, runner: Runner, w: *Writer, err_w: *Writer) !void {
    const password = if (options.encrypt) blk: {
        const value = environ.get("MINISIGN_PASSWORD") orelse
            return fail(err_w, "--encrypt requires nonempty MINISIGN_PASSWORD in the environment", .{});
        if (value.len == 0 or value.len > 4096)
            return fail(err_w, "--encrypt requires MINISIGN_PASSWORD of 1 to 4096 bytes", .{});
        break :blk try allocator.dupe(u8, value);
    } else null;
    defer if (password) |bytes| {
        std.crypto.secureZero(u8, bytes);
        allocator.free(bytes);
    };
    var gh_environ = try childEnviron(allocator, environ);
    defer gh_environ.deinit();
    const target = try resolveTarget(allocator, io, &gh_environ, options, runner, err_w);
    defer target.deinit(allocator);
    try preflight(allocator, io, &gh_environ, target, options, runner, err_w);

    const pair = (if (options.reuse)
        reusePair(allocator, io, dir, options, password orelse "")
    else
        createPair(allocator, io, dir, password)) catch |err| {
        return localFailure(err_w, err);
    };
    defer pair.deinit(allocator);
    var public_bytes: [128]u8 = undefined;
    const public_text = try encodePublic(pair.public, &public_bytes);
    const encoded_public = std.mem.trim(u8, public_text[(std.mem.indexOfScalar(u8, public_text, '\n') orelse unreachable) + 1 ..], "\n");
    // Announce recovery paths before any non-transactional remote update.
    try w.print("repository: {s}\npublic key: {s}\nlocal recovery files: minisign.pub and minisign.key (keep private; never commit)\n", .{ target.qualified, encoded_public });
    try w.flush();

    const key_result = checked(allocator, io, &gh_environ, runner, &.{ "gh", "secret", "set", "MINISIGN_SECRET_KEY", "--repo", target.qualified, "--app", "actions" }, pair.secret, "uploading MINISIGN_SECRET_KEY failed", err_w) catch |err| {
        try recoveryMessage(err_w, options);
        return err;
    };
    key_result.deinit(allocator);
    if (password) |bytes| {
        const pw_result = checked(allocator, io, &gh_environ, runner, &.{ "gh", "secret", "set", "MINISIGN_PASSWORD", "--repo", target.qualified, "--app", "actions" }, bytes, "uploading MINISIGN_PASSWORD failed after MINISIGN_SECRET_KEY was updated", err_w) catch |err| {
            try recoveryMessage(err_w, options);
            return err;
        };
        pw_result.deinit(allocator);
    }
    try w.print("provisioned {s} for {s}\n", .{ if (options.encrypt) "MINISIGN_SECRET_KEY and MINISIGN_PASSWORD" else "MINISIGN_SECRET_KEY", target.qualified });
    try w.flush();
}

fn localFailure(err_w: *Writer, err: anyerror) error{ GenerateFailed, WriteFailed } {
    return switch (err) {
        error.PathAlreadyExists => fail(err_w, "minisign.key or minisign.pub already exists; use a secure empty directory or --reuse-existing-local-pair. Local files are never replaced", .{}),
        error.UnsafePrivateKeyPermissions, error.PrivateKeyAclAccessDenied => fail(err_w, "minisign.key requires owner-only protection: chmod 600 on POSIX, or a protected owner-only DACL on Windows. No secrets were uploaded", .{}),
        error.EncryptionOptionDoesNotMatchLocalKey => fail(err_w, "local key encryption does not match --encrypt; retry with the original encryption option and, for an encrypted key, its MINISIGN_PASSWORD", .{}),
        error.WrongPassword => fail(err_w, "MINISIGN_PASSWORD cannot decrypt minisign.key; reuse the original password, never generate a replacement key to retry", .{}),
        error.LocalKeyPairMismatch => fail(err_w, "minisign.pub does not match minisign.key; restore the matching public file before retrying. No secrets were uploaded", .{}),
        error.InvalidLocalSigningKey => fail(err_w, "minisign.key failed an in-process signing/verification check; restore an intact recovery key. No secrets were uploaded", .{}),
        error.UnsafeKeyFile => fail(err_w, "local key files must be regular, non-symlink, single-link files of at most 4096 bytes; restore safe recovery files before retrying", .{}),
        else => fail(err_w, "cannot prepare minisign.key/minisign.pub: {s}; check directory/file permissions and local key format. Keep any saved private key; --reuse-existing-local-pair can reconstruct a missing public file", .{@errorName(err)}),
    };
}

fn recoveryMessage(err_w: *Writer, options: Options) !void {
    try err_w.print("Remote update may be partial; this is NOT success. Local recovery keys were retained.\nRetry with --reuse-existing-local-pair --replace-existing-secrets{s} and the same --repo (or gh context); never generate a replacement pair to retry.\n", .{if (options.encrypt) " --encrypt (same MINISIGN_PASSWORD)" else ""});
    try err_w.flush();
}

const Pair = struct {
    secret: []u8,
    public: minizign.PublicKey,

    fn deinit(self: Pair, allocator: Allocator) void {
        std.crypto.secureZero(u8, self.secret);
        allocator.free(self.secret);
    }
};

fn requireAbsent(io: Io, dir: Dir, path: []const u8) !void {
    _ = dir.statFile(io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    return error.PathAlreadyExists;
}

fn encodePublic(key: minizign.PublicKey, buffer: []u8) ![]const u8 {
    var binary: [42]u8 = undefined;
    @memcpy(binary[0..2], &key.signature_algorithm);
    @memcpy(binary[2..10], &key.key_id);
    @memcpy(binary[10..42], &key.key);
    var encoded: [56]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&encoded, &binary);
    return std.fmt.bufPrint(buffer, "untrusted comment: minisign public key\n{s}\n", .{encoded});
}

fn encodeSecret(allocator: Allocator, key: *const minizign.SecretKey) ![]u8 {
    var binary: [158]u8 = undefined;
    defer std.crypto.secureZero(u8, &binary);
    @memcpy(binary[0..2], &key.signature_algorithm);
    @memcpy(binary[2..4], &key.kdf_algorithm);
    @memcpy(binary[4..6], &key.checksum_algorithm);
    @memcpy(binary[6..38], &key.kdf_salt);
    std.mem.writeInt(u64, binary[38..46], key.kdf_opslimit, .little);
    std.mem.writeInt(u64, binary[46..54], key.kdf_memlimit, .little);
    @memcpy(binary[54..62], &key.key_id);
    @memcpy(binary[62..126], &key.secret_key);
    @memcpy(binary[126..158], &key.checksum);
    var encoded: [212]u8 = undefined;
    defer std.crypto.secureZero(u8, &encoded);
    _ = std.base64.standard.Encoder.encode(&encoded, &binary);
    return allocator.print("untrusted comment: minisign {s}secret key\n{s}\n", .{
        if (std.mem.eql(u8, &key.kdf_algorithm, "\x00\x00")) "unencrypted " else "encrypted ",
        encoded,
    });
}

fn createPair(allocator: Allocator, io: Io, dir: Dir, password: ?[]const u8) !Pair {
    try requireAbsent(io, dir, private_path);
    try requireAbsent(io, dir, public_path);
    var private = if (builtin.os.tag == .windows)
        try WindowsAcl.create(io, dir)
    else
        try dir.createFileAtomic(io, private_path, .{
            .permissions = if (@hasDecl(File.Permissions, "fromMode")) .fromMode(0o600) else .default_file,
        });
    defer private.deinit(io);
    try protectPrivate(io, &private);
    var public = try dir.createFileAtomic(io, public_path, .{});
    defer public.deinit(io);
    var key = try minizign.SecretKey.generate(allocator, io);
    defer key.deinit();
    const pk = key.getPublicKey();
    if (password) |bytes| try key.encrypt(allocator, io, bytes);
    const secret = try encodeSecret(allocator, &key);
    errdefer {
        std.crypto.secureZero(u8, secret);
        allocator.free(secret);
    }
    var public_bytes: [128]u8 = undefined;
    try private.file.writeStreamingAll(io, secret);
    try public.file.writeStreamingAll(io, try encodePublic(pk, &public_bytes));
    try private.file.sync(io);
    try public.file.sync(io);
    try private.link(io);
    try public.link(io);
    return .{ .secret = secret, .public = pk };
}

fn readLocal(allocator: Allocator, io: Io, dir: Dir, path: []const u8, private: bool) ![]u8 {
    const before = try dir.statFile(io, path, .{ .follow_symlinks = false });
    if (before.kind != .file or before.nlink != 1 or before.size > 4096) return error.UnsafeKeyFile;
    const file = try dir.openFile(io, path, .{ .follow_symlinks = false, .allow_directory = false });
    defer file.close(io);
    const stat = try file.stat(io);
    if (stat.kind != .file or stat.nlink != 1 or stat.size > 4096 or stat.inode != before.inode) return error.UnsafeKeyFile;
    if (private) try verifyPrivate(io, file);
    var reader = file.reader(io, &.{});
    return reader.interface.allocRemaining(allocator, .limited(4096));
}

fn reusePair(allocator: Allocator, io: Io, dir: Dir, options: Options, password: []const u8) !Pair {
    const secret = try readLocal(allocator, io, dir, private_path, true);
    errdefer {
        std.crypto.secureZero(u8, secret);
        allocator.free(secret);
    }
    var key = try minizign.SecretKey.decode(allocator, secret);
    defer key.deinit();
    const encrypted = std.mem.eql(u8, &key.kdf_algorithm, "Sc");
    if (!encrypted and !std.mem.eql(u8, &key.kdf_algorithm, "\x00\x00")) return error.UnsupportedKdfAlgorithm;
    if (encrypted != options.encrypt) return error.EncryptionOptionDoesNotMatchLocalKey;
    if (encrypted) {
        // Bound attacker-controlled scrypt parameters before invoking the library.
        if (key.kdf_opslimit == 0 or key.kdf_opslimit > 524288 or key.kdf_memlimit == 0 or key.kdf_memlimit > 16777216)
            return error.UnsafeKdfLimits;
        try key.decrypt(allocator, password);
    }
    const pk = key.getPublicKey();
    const public_text = readLocal(allocator, io, dir, public_path, false) catch |err| switch (err) {
        error.FileNotFound => {
            var public = try dir.createFileAtomic(io, public_path, .{});
            defer public.deinit(io);
            var buffer: [128]u8 = undefined;
            try public.file.writeStreamingAll(io, try encodePublic(pk, &buffer));
            try public.file.sync(io);
            try public.link(io);
            try validateSigningPair(allocator, io, dir, &key, pk);
            return .{ .secret = secret, .public = pk };
        },
        else => return err,
    };
    defer allocator.free(public_text);
    var keys: [1]minizign.PublicKey = undefined;
    const decoded = try minizign.PublicKey.decode(&keys, public_text);
    if (decoded.len != 1 or !std.mem.eql(u8, &decoded[0].key_id, &pk.key_id) or
        !std.mem.eql(u8, &decoded[0].key, &pk.key)) return error.LocalKeyPairMismatch;
    try validateSigningPair(allocator, io, dir, &key, pk);
    return .{ .secret = secret, .public = pk };
}

fn validateSigningPair(allocator: Allocator, io: Io, dir: Dir, key: *const minizign.SecretKey, public: minizign.PublicKey) !void {
    const file = try dir.openFile(io, public_path, .{ .follow_symlinks = false, .allow_directory = false });
    defer file.close(io);
    var signature = key.signFile(allocator, io, file, true, "ghr local key recovery check") catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return error.InvalidLocalSigningKey,
    };
    defer signature.deinit();
    public.verifyFile(allocator, io, file, signature, true) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return error.InvalidLocalSigningKey,
    };
}

fn protectPrivate(io: Io, atomic: *File.Atomic) !void {
    if (builtin.os.tag == .windows) {
        try WindowsAcl.verify(atomic.file);
    } else if (@hasDecl(File.Permissions, "fromMode")) {
        try atomic.file.setPermissions(io, .fromMode(0o600));
    } else {
        return error.SecurePrivateFilesUnsupported;
    }
    try verifyPrivate(io, atomic.file);
}

fn verifyPrivate(io: Io, file: File) !void {
    if (builtin.os.tag == .windows) {
        try WindowsAcl.verify(file);
    } else if (@hasDecl(File.Permissions, "toMode")) {
        const mode = (try file.stat(io)).permissions.toMode() & 0o7777;
        if (mode != 0o600 and mode != 0o400) return error.UnsafePrivateKeyPermissions;
    } else {
        return error.SecurePrivateFilesUnsupported;
    }
}

const WindowsAcl = struct {
    const windows = std.os.windows;
    // Self-relative SD: protected DACL, one FILE_ALL_ACCESS ACE for OWNER RIGHTS.
    const descriptor align(4) = [_]u8{
        1, 0, 4,  144, 0, 0, 0, 0, 0, 0, 0,  0, 0,   0, 0,  0, 20, 0, 0, 0,
        2, 0, 28, 0,   1, 0, 0, 0, 0, 0, 20, 0, 255, 1, 31, 0, 1,  1, 0, 0,
        0, 0, 0,  3,   4, 0, 0, 0,
    };

    extern "ntdll" fn NtQuerySecurityObject(windows.HANDLE, u32, *anyopaque, u32, *u32) callconv(.winapi) windows.NTSTATUS;

    fn create(io: Io, dir: Dir) !File.Atomic {
        // Supply the DACL at creation, not afterwards: a reader could otherwise
        // retain a handle opened during the initially permissive interval.
        for (0..128) |_| {
            var random: [8]u8 = undefined;
            io.random(&random);
            const id = std.mem.readInt(u64, &random, .little);
            const basename = std.fmt.hex(id);
            var wide: [16]u16 = undefined;
            for (basename, 0..) |c, i| wide[i] = c;
            var name = windows.UNICODE_STRING.init(&wide);
            var handle: windows.HANDLE = undefined;
            var status_block: windows.IO_STATUS_BLOCK = undefined;
            const status = windows.ntdll.NtCreateFile(&handle, .{
                .STANDARD = .{ .SYNCHRONIZE = true },
                .GENERIC = .{ .READ = true, .WRITE = true },
            }, &.{
                .RootDirectory = dir.handle,
                .ObjectName = &name,
                .SecurityDescriptor = @ptrCast(@constCast(&descriptor)),
            }, &status_block, null, .{ .NORMAL = true }, .{}, .CREATE, .{
                .NON_DIRECTORY_FILE = true,
                .OPEN_REPARSE_POINT = true,
                .IO = .SYNCHRONOUS_NONALERT,
            }, null, 0);
            switch (status) {
                .SUCCESS => return .{
                    .file = .{ .handle = handle, .flags = .{ .nonblocking = false } },
                    .file_basename_hex = id,
                    .file_open = true,
                    .file_exists = true,
                    .dir = dir,
                    .close_dir_on_deinit = false,
                    .dest_sub_path = private_path,
                },
                .OBJECT_NAME_COLLISION => continue,
                .ACCESS_DENIED => return error.AccessDenied,
                .CANCELLED => return error.Canceled,
                else => return error.SecurePrivateFileCreationFailed,
            }
        }
        return error.PathAlreadyExists;
    }

    fn verify(file: File) !void {
        var buffer: [4096]u8 align(4) = undefined;
        var length: u32 = 0;
        if (NtQuerySecurityObject(file.handle, 4, &buffer, buffer.len, &length) != .SUCCESS or length < 20 or length > buffer.len)
            return error.PrivateKeyAclAccessDenied;
        const control = std.mem.readInt(u16, buffer[2..4], .little);
        if (control & 0x9004 != 0x9004) return error.UnsafePrivateKeyPermissions;
        const offset = std.mem.readInt(u32, buffer[16..20], .little);
        if (offset < 20 or offset > length or length - offset < descriptor.len - 20 or
            !std.mem.eql(u8, buffer[offset..][0 .. descriptor.len - 20], descriptor[20..]))
            return error.UnsafePrivateKeyPermissions;
    }
};

fn readPipe(io: Io, file: File, buffer: []u8) !usize {
    var reader = file.reader(io, &.{});
    const count = try reader.interface.readSliceShort(buffer);
    if (count == buffer.len) {
        var extra: [1]u8 = undefined;
        defer std.crypto.secureZero(u8, &extra);
        if (try reader.interface.readSliceShort(&extra) != 0) return error.StreamTooLong;
    }
    return count;
}

fn feedPipe(io: Io, child: *std.process.Child, input: []const u8) !void {
    // Streaming writes have no buffered bytes; close delivers EOF to gh.
    try child.stdin.?.writeStreamingAll(io, input);
    child.stdin.?.close(io);
    child.stdin = null;
}

fn collectProcess(io: Io, environ: *const Environ, argv: []const []const u8, input: []const u8, stdout: []u8, stderr: []u8, stdout_len: *usize) anyerror!std.process.Child.Term {
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .environ_map = environ,
        .stdin = .pipe,
        .stdout = .pipe,
        .stderr = .pipe,
        .create_no_window = true,
    });
    defer child.kill(io);
    const Event = union(enum) { stdout: anyerror!usize, stderr: anyerror!usize, stdin: anyerror!void };
    var events: [3]Event = undefined;
    var select: Io.Select(Event) = .init(io, &events);
    defer select.cancelDiscard();
    try select.concurrent(.stdout, readPipe, .{ io, child.stdout.?, stdout });
    try select.concurrent(.stderr, readPipe, .{ io, child.stderr.?, stderr });
    try select.concurrent(.stdin, feedPipe, .{ io, &child, input });
    for (0..3) |_| {
        switch (try select.await()) {
            .stdout => |result| stdout_len.* = try result,
            .stderr => |result| _ = try result,
            .stdin => |result| try result,
        }
    }
    return child.wait(io);
}

fn runGh(_: ?*anyopaque, allocator: Allocator, io: Io, environ: *const Environ, argv: []const []const u8, input: []const u8) anyerror!Result {
    return runProcess(allocator, io, environ, argv, input, .fromSeconds(60));
}

fn runProcess(allocator: Allocator, io: Io, environ: *const Environ, argv: []const []const u8, input: []const u8, timeout: Io.Duration) !Result {
    const stdout = try allocator.alloc(u8, output_limit);
    defer {
        std.crypto.secureZero(u8, stdout);
        allocator.free(stdout);
    }
    const stderr = try allocator.alloc(u8, output_limit);
    defer {
        std.crypto.secureZero(u8, stderr);
        allocator.free(stderr);
    }
    var stdout_len: usize = 0;
    const Event = union(enum) { complete: anyerror!std.process.Child.Term, deadline: Io.Cancelable!void };
    var events: [2]Event = undefined;
    var select: Io.Select(Event) = .init(io, &events);
    defer select.cancelDiscard();
    try select.concurrent(.complete, collectProcess, .{ io, environ, argv, input, stdout, stderr, &stdout_len });
    try select.concurrent(.deadline, Io.sleep, .{ io, timeout, .awake });
    const term = switch (try select.await()) {
        .complete => |result| try result,
        .deadline => |result| {
            try result;
            return error.Timeout;
        },
    };
    return .{ .stdout = try allocator.dupe(u8, stdout[0..stdout_len]), .term = term };
}

const TestFixture = struct {
    dir: Dir,
    path: []u8,

    fn init() !TestFixture {
        var random: [8]u8 = undefined;
        std.testing.io.random(&random);
        const path = try std.testing.allocator.print(".generate-test-{s}", .{std.fmt.hex(std.mem.readInt(u64, &random, .little))});
        errdefer std.testing.allocator.free(path);
        try Dir.cwd().createDir(std.testing.io, path, if (@hasDecl(File.Permissions, "fromMode")) .fromMode(0o700) else .default_dir);
        return .{ .path = path, .dir = try Dir.cwd().openDir(std.testing.io, path, .{}) };
    }

    fn deinit(self: TestFixture) void {
        self.dir.close(std.testing.io);
        Dir.cwd().deleteTree(std.testing.io, self.path) catch @panic("failed to clean generation fixture");
        std.testing.allocator.free(self.path);
    }
};

const MockGh = struct {
    override: ?[]const u8 = null,
    repo: []const u8 = "octocat/releases",
    repo_reply: ?[]const u8 = null,
    api_reply: []const u8 = "{\"key_id\":\"123\",\"key\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"}",
    list_reply: []const u8 = "[]",
    permission: []const u8 = "ADMIN",
    auth_exit: u8 = 0,
    access_exit: u8 = 0,
    list_exit: u8 = 0,
    fail_key: bool = false,
    fail_password: bool = false,
    transport_fail: ?usize = null,
    calls: usize = 0,
    key: ?[]u8 = null,
    password: ?[]u8 = null,

    fn runner(self: *MockGh) Runner {
        return .{ .context = self, .call = call };
    }

    fn deinit(self: *MockGh) void {
        for ([_]?[]u8{ self.key, self.password }) |value| {
            if (value) |bytes| {
                std.crypto.secureZero(u8, bytes);
                std.testing.allocator.free(bytes);
            }
        }
    }

    fn expectArgs(expected: []const []const u8, actual: []const []const u8) !void {
        try std.testing.expectEqual(expected.len, actual.len);
        for (expected, actual) |want, got| try std.testing.expectEqualStrings(want, got);
    }

    fn call(context: ?*anyopaque, allocator: Allocator, _: Io, environ: *const Environ, argv: []const []const u8, input: []const u8) anyerror!Result {
        const self: *MockGh = @ptrCast(@alignCast(context.?));
        const stage = self.calls;
        self.calls += 1;
        try std.testing.expect(environ.get("MINISIGN_SECRET_KEY") == null);
        try std.testing.expect(environ.get("MINISIGN_PASSWORD") == null);
        try std.testing.expect(environ.get("GH_DEBUG") == null);
        try std.testing.expectEqualStrings("1", environ.get("GH_PROMPT_DISABLED").?);
        if (self.transport_fail == stage) return error.ReadFailed;
        const qualified = try allocator.print("github.com/{s}", .{self.repo});
        defer allocator.free(qualified);
        var reply: []const u8 = "";
        var owned_reply: ?[]u8 = null;
        defer if (owned_reply) |bytes| allocator.free(bytes);
        var exit_code: u8 = 0;
        switch (stage) {
            0 => {
                try expectArgs(if (self.override) |repo|
                    &.{ "gh", "repo", "view", repo, "--json", "nameWithOwner,url,viewerPermission" }
                else
                    &.{ "gh", "repo", "view", "--json", "nameWithOwner,url,viewerPermission" }, argv);
                if (self.repo_reply) |json| {
                    reply = json;
                } else {
                    owned_reply = try allocator.print("{{\"nameWithOwner\":\"{s}\",\"url\":\"https://github.com/{s}\",\"viewerPermission\":\"{s}\"}}", .{ self.repo, self.repo, self.permission });
                    reply = owned_reply.?;
                }
            },
            1 => {
                try expectArgs(&.{ "gh", "auth", "status", "--active", "--hostname", "github.com" }, argv);
                exit_code = self.auth_exit;
            },
            2 => {
                const endpoint = try allocator.print("repos/{s}/actions/secrets/public-key", .{self.repo});
                defer allocator.free(endpoint);
                try expectArgs(&.{ "gh", "api", "--hostname", "github.com", "--method", "GET", endpoint }, argv);
                reply = self.api_reply;
                exit_code = self.access_exit;
            },
            3 => {
                try expectArgs(&.{ "gh", "secret", "list", "--repo", qualified, "--app", "actions", "--json", "name" }, argv);
                reply = self.list_reply;
                exit_code = self.list_exit;
            },
            4 => {
                try expectArgs(&.{ "gh", "secret", "set", "MINISIGN_SECRET_KEY", "--repo", qualified, "--app", "actions" }, argv);
                var decoded = try minizign.SecretKey.decode(allocator, input);
                decoded.deinit();
                self.key = try allocator.dupe(u8, input);
                exit_code = if (self.fail_key) 1 else 0;
            },
            5 => {
                try expectArgs(&.{ "gh", "secret", "set", "MINISIGN_PASSWORD", "--repo", qualified, "--app", "actions" }, argv);
                try std.testing.expect(input.len > 0);
                self.password = try allocator.dupe(u8, input);
                exit_code = if (self.fail_password) 1 else 0;
            },
            else => return error.UnexpectedGhInvocation,
        }
        if (stage < 4) try std.testing.expectEqual(@as(usize, 0), input.len);
        return .{ .stdout = try allocator.dupe(u8, reply), .term = .{ .exited = exit_code } };
    }
};

fn testGenerate(fixture: TestFixture, env: *const Environ, options: Options, mock: *MockGh, out: *Writer.Allocating, err: *Writer.Allocating) !void {
    try generate(std.testing.allocator, std.testing.io, env, fixture.dir, options, mock.runner(), &out.writer, &err.writer);
}

test "generate uses gh current context and uploads only the in-process unencrypted key" {
    var fixture = try TestFixture.init();
    defer fixture.deinit();
    var env: Environ = .init(std.testing.allocator);
    defer env.deinit();
    var mock: MockGh = .{};
    defer mock.deinit();
    var out: Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var err: Writer.Allocating = .init(std.testing.allocator);
    defer err.deinit();
    try testGenerate(fixture, &env, .{}, &mock, &out, &err);
    try std.testing.expectEqual(@as(usize, 5), mock.calls);
    try std.testing.expect(mock.password == null);
    try std.testing.expectEqual(@as(usize, 0), err.written().len);
    const saved = try readLocal(std.testing.allocator, std.testing.io, fixture.dir, private_path, true);
    defer {
        std.crypto.secureZero(u8, saved);
        std.testing.allocator.free(saved);
    }
    try std.testing.expectEqualSlices(u8, saved, mock.key.?);
    var key = try minizign.SecretKey.decode(std.testing.allocator, saved);
    defer key.deinit();
    try std.testing.expectEqualStrings("\x00\x00", &key.kdf_algorithm);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), mock.key.?) == null);

    // The produced key signs and verifies through the library, not an executable.
    var payload = try fixture.dir.createFile(std.testing.io, "payload", .{ .read = true });
    defer payload.close(std.testing.io);
    try payload.writeStreamingAll(std.testing.io, "generated key signing fixture");
    var signature = try key.signFile(std.testing.allocator, std.testing.io, payload, true, "generation test");
    defer signature.deinit();
    try key.getPublicKey().verifyFile(std.testing.allocator, std.testing.io, payload, signature, true);
}

test "explicit repository is honored and default ignores password even during replacement" {
    var fixture = try TestFixture.init();
    defer fixture.deinit();
    var env: Environ = .init(std.testing.allocator);
    defer env.deinit();
    try env.put("MINISIGN_PASSWORD", "unused-test-password");
    try env.put("MINISIGN_SECRET_KEY", "unused-test-key");
    try env.put("GH_DEBUG", "api");
    var mock: MockGh = .{
        .override = "alice/other",
        .repo = "alice/other",
        .list_reply = "[{\"name\":\"MINISIGN_PASSWORD\"},{\"name\":\"MINISIGN_SECRET_KEY\"}]",
    };
    defer mock.deinit();
    var out: Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var err: Writer.Allocating = .init(std.testing.allocator);
    defer err.deinit();
    try testGenerate(fixture, &env, .{ .repo = mock.override, .replace = true }, &mock, &out, &err);
    try std.testing.expectEqual(@as(usize, 5), mock.calls);
    try std.testing.expect(mock.password == null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "github.com/alice/other") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "unused-test-password") == null);
}

test "auth, access, malformed JSON, read errors, and existing secrets fail before key writes" {
    var env: Environ = .init(std.testing.allocator);
    defer env.deinit();
    const cases = [_]MockGh{
        .{ .auth_exit = 1 },
        .{ .access_exit = 4 },
        .{ .list_exit = 1 },
        .{ .repo_reply = "{}" },
        .{ .repo_reply = "{\"nameWithOwner\":\"../../bad\",\"url\":\"https://github.com/../../bad\",\"viewerPermission\":\"ADMIN\"}" },
        .{ .permission = "READ" },
        .{ .api_reply = "{\"key_id\":\"123\",\"key\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\"}" },
        .{ .list_reply = "{}" },
        .{ .list_reply = "[{\"name\":\"MINISIGN_PASSWORD\"}]" },
        .{ .list_reply = "[{\"name\":\"MINISIGN_SECRET_KEY\"}]" },
        .{ .override = "alice/other" },
        .{ .transport_fail = 0 },
        .{ .transport_fail = 3 },
    };
    for (cases) |case| {
        var fixture = try TestFixture.init();
        defer fixture.deinit();
        var mock = case;
        defer mock.deinit();
        var out: Writer.Allocating = .init(std.testing.allocator);
        defer out.deinit();
        var err: Writer.Allocating = .init(std.testing.allocator);
        defer err.deinit();
        try std.testing.expectError(error.GenerateFailed, testGenerate(fixture, &env, .{ .repo = mock.override }, &mock, &out, &err));
        try requireAbsent(std.testing.io, fixture.dir, private_path);
        try requireAbsent(std.testing.io, fixture.dir, public_path);
        try std.testing.expect(mock.key == null);
        try std.testing.expectEqual(@as(usize, 0), out.written().len);
        try std.testing.expect(std.mem.startsWith(u8, err.written(), "error: "));
    }
}

test "local existing files and dangling symlinks are never overwritten" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var env: Environ = .init(std.testing.allocator);
    defer env.deinit();
    for ([_]bool{ false, true }) |symlink| {
        var fixture = try TestFixture.init();
        defer fixture.deinit();
        if (symlink) {
            try fixture.dir.symLink(std.testing.io, "absent", private_path, .{});
        } else {
            try fixture.dir.writeFile(std.testing.io, .{ .sub_path = public_path, .data = "existing public key" });
        }
        var mock: MockGh = .{};
        defer mock.deinit();
        var out: Writer.Allocating = .init(std.testing.allocator);
        defer out.deinit();
        var err: Writer.Allocating = .init(std.testing.allocator);
        defer err.deinit();
        try std.testing.expectError(error.GenerateFailed, testGenerate(fixture, &env, .{ .replace = true }, &mock, &out, &err));
        try std.testing.expectEqual(@as(usize, 4), mock.calls);
        try std.testing.expect(mock.key == null);
        if (!symlink) {
            var buffer: [64]u8 = undefined;
            try std.testing.expectEqualStrings("existing public key", try fixture.dir.readFile(std.testing.io, public_path, &buffer));
        }
    }
}

test "partial encrypted upload fails and explicit retry reuses exactly the same keypair" {
    var fixture = try TestFixture.init();
    defer fixture.deinit();
    var env: Environ = .init(std.testing.allocator);
    defer env.deinit();
    try env.put("MINISIGN_PASSWORD", "fixture-password-not-a-credential");
    var first: MockGh = .{ .fail_password = true };
    defer first.deinit();
    var out: Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var err: Writer.Allocating = .init(std.testing.allocator);
    defer err.deinit();
    try std.testing.expectError(error.GenerateFailed, testGenerate(fixture, &env, .{ .encrypt = true }, &first, &out, &err));
    try std.testing.expectEqual(@as(usize, 6), first.calls);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "provisioned") == null);
    try std.testing.expect(std.mem.indexOf(u8, err.written(), "NOT success") != null);
    try std.testing.expect(std.mem.indexOf(u8, err.written(), first.key.?) == null);
    try std.testing.expect(std.mem.indexOf(u8, err.written(), first.password.?) == null);
    var retry: MockGh = .{ .list_reply = "[{\"name\":\"MINISIGN_SECRET_KEY\"}]" };
    defer retry.deinit();
    try testGenerate(fixture, &env, .{ .encrypt = true, .reuse = true, .replace = true }, &retry, &out, &err);
    try std.testing.expectEqualSlices(u8, first.key.?, retry.key.?);
    try std.testing.expectEqualSlices(u8, first.password.?, retry.password.?);
}

test "key upload failure preserves recovery and reuse reconstructs missing public file" {
    var fixture = try TestFixture.init();
    defer fixture.deinit();
    var env: Environ = .init(std.testing.allocator);
    defer env.deinit();
    var first: MockGh = .{ .fail_key = true };
    defer first.deinit();
    var out: Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var err: Writer.Allocating = .init(std.testing.allocator);
    defer err.deinit();
    try std.testing.expectError(error.GenerateFailed, testGenerate(fixture, &env, .{}, &first, &out, &err));
    try fixture.dir.deleteFile(std.testing.io, public_path);
    var retry: MockGh = .{};
    defer retry.deinit();
    try testGenerate(fixture, &env, .{ .reuse = true, .replace = true }, &retry, &out, &err);
    try std.testing.expectEqualSlices(u8, first.key.?, retry.key.?);
    const recovered = try reusePair(std.testing.allocator, std.testing.io, fixture.dir, .{}, "");
    defer recovered.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, first.key.?, recovered.secret);
}

test "reuse rejects mismatched public key, unsafe permissions and wrong encryption mode" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var first_fixture = try TestFixture.init();
    defer first_fixture.deinit();
    var other_fixture = try TestFixture.init();
    defer other_fixture.deinit();
    const first = try createPair(std.testing.allocator, std.testing.io, first_fixture.dir, null);
    defer first.deinit(std.testing.allocator);
    const other = try createPair(std.testing.allocator, std.testing.io, other_fixture.dir, null);
    defer other.deinit(std.testing.allocator);
    try std.testing.expectError(error.EncryptionOptionDoesNotMatchLocalKey, reusePair(std.testing.allocator, std.testing.io, first_fixture.dir, .{ .encrypt = true }, "fixture"));
    var corrupt_key = try minizign.SecretKey.decode(std.testing.allocator, first.secret);
    defer corrupt_key.deinit();
    corrupt_key.secret_key[0] ^= 1;
    const corrupt_text = try encodeSecret(std.testing.allocator, &corrupt_key);
    defer {
        std.crypto.secureZero(u8, corrupt_text);
        std.testing.allocator.free(corrupt_text);
    }
    try first_fixture.dir.writeFile(std.testing.io, .{ .sub_path = private_path, .data = corrupt_text });
    try std.testing.expectError(error.InvalidLocalSigningKey, reusePair(std.testing.allocator, std.testing.io, first_fixture.dir, .{}, ""));
    try first_fixture.dir.writeFile(std.testing.io, .{ .sub_path = private_path, .data = first.secret });
    var bytes: [128]u8 = undefined;
    try first_fixture.dir.writeFile(std.testing.io, .{ .sub_path = public_path, .data = try encodePublic(other.public, &bytes) });
    try std.testing.expectError(error.LocalKeyPairMismatch, reusePair(std.testing.allocator, std.testing.io, first_fixture.dir, .{}, ""));
    try first_fixture.dir.setFilePermissions(std.testing.io, private_path, .fromMode(0o644), .{ .follow_symlinks = false });
    try std.testing.expectError(error.UnsafePrivateKeyPermissions, reusePair(std.testing.allocator, std.testing.io, first_fixture.dir, .{}, ""));
}

test "encrypt requires a nonempty password before invoking gh" {
    var fixture = try TestFixture.init();
    defer fixture.deinit();
    var env: Environ = .init(std.testing.allocator);
    defer env.deinit();
    var mock: MockGh = .{};
    defer mock.deinit();
    var out: Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var err: Writer.Allocating = .init(std.testing.allocator);
    defer err.deinit();
    try std.testing.expectError(error.GenerateFailed, testGenerate(fixture, &env, .{ .encrypt = true }, &mock, &out, &err));
    try env.put("MINISIGN_PASSWORD", "");
    try std.testing.expectError(error.GenerateFailed, testGenerate(fixture, &env, .{ .encrypt = true }, &mock, &out, &err));
    try std.testing.expectEqual(@as(usize, 0), mock.calls);
}

test "wrong encryption password on reuse never uploads or replaces local keys" {
    var fixture = try TestFixture.init();
    defer fixture.deinit();
    const pair = try createPair(std.testing.allocator, std.testing.io, fixture.dir, "original-fixture-password");
    defer pair.deinit(std.testing.allocator);
    var env: Environ = .init(std.testing.allocator);
    defer env.deinit();
    try env.put("MINISIGN_PASSWORD", "wrong-fixture-password");
    var mock: MockGh = .{};
    defer mock.deinit();
    var out: Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var err: Writer.Allocating = .init(std.testing.allocator);
    defer err.deinit();
    try std.testing.expectError(error.GenerateFailed, testGenerate(fixture, &env, .{ .encrypt = true, .reuse = true }, &mock, &out, &err));
    try std.testing.expectEqual(@as(usize, 4), mock.calls);
    try std.testing.expect(mock.key == null);
    try std.testing.expect(std.mem.indexOf(u8, err.written(), "reuse the original password") != null);
    const saved = try readLocal(std.testing.allocator, std.testing.io, fixture.dir, private_path, true);
    defer {
        std.crypto.secureZero(u8, saved);
        std.testing.allocator.free(saved);
    }
    try std.testing.expectEqualSlices(u8, pair.secret, saved);
}

test "generate parser rejects malformed overrides, missing values, duplicate repositories and unknown options" {
    const ListArgs = struct {
        values: []const []const u8,
        index: usize = 0,
        fn next(self: *@This()) ?[]const u8 {
            if (self.index == self.values.len) return null;
            defer self.index += 1;
            return self.values[self.index];
        }
    };
    const cases = [_][]const []const u8{
        &.{"--repo"},
        &.{ "--repo", "../repo" },
        &.{ "--repo", "owner/repo;bad" },
        &.{ "--repo", "owner/repo", "--repo", "owner/other" },
        &.{"--unknown"},
    };
    var err: Writer.Allocating = .init(std.testing.allocator);
    defer err.deinit();
    for (cases) |values| {
        var args: ListArgs = .{ .values = values };
        try std.testing.expectError(error.GenerateFailed, parseOptions(&args, &err.writer));
    }
    var args: ListArgs = .{ .values = &.{ "--repo", "owner/valid.repo", "--encrypt", "--replace-existing-secrets", "--reuse-existing-local-pair" } };
    const options = try parseOptions(&args, &err.writer);
    try std.testing.expectEqualStrings("owner/valid.repo", options.repo.?);
    try std.testing.expect(options.encrypt and options.replace and options.reuse);
}

test "generate command help consumes the public iterator and reports usage without provisioning" {
    const raw: std.process.Args = .{ .vector = if (builtin.os.tag == .windows)
        std.unicode.utf8ToUtf16LeStringLiteral("--help")
    else
        &.{"--help"} };
    var args = try std.process.Args.Iterator.initAllocator(raw, std.testing.allocator);
    defer args.deinit();
    var env: Environ = .init(std.testing.allocator);
    defer env.deinit();
    var out: Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var err: Writer.Allocating = .init(std.testing.allocator);
    defer err.deinit();
    try cmdGenerate(std.testing.allocator, std.testing.io, &env, &args, &out.writer, &err.writer);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "--reuse-existing-local-pair") != null);
    try std.testing.expectEqual(@as(usize, 0), err.written().len);
}

test "process runner closes stdin, concurrently drains both outputs and checks exit status" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var env: Environ = .init(std.testing.allocator);
    defer env.deinit();
    const result = try runProcess(std.testing.allocator, std.testing.io, &env, &.{ "/bin/sh", "-c", "cat; printf 'diagnostic' >&2; exit 7" }, "stdin fixture", .fromSeconds(5));
    defer result.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("stdin fixture", result.stdout);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 7 }, result.term);
}

test "process runner bounds output and times out even after pipes close" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var env: Environ = .init(std.testing.allocator);
    defer env.deinit();
    try std.testing.expectError(error.StreamTooLong, runProcess(std.testing.allocator, std.testing.io, &env, &.{ "/bin/sh", "-c", "while :; do printf '01234567890123456789012345678901'; done" }, "", .fromSeconds(5)));
    try std.testing.expectError(error.Timeout, runProcess(std.testing.allocator, std.testing.io, &env, &.{ "/bin/sh", "-c", "exec 0<&- 1>&- 2>&-; while :; do :; done" }, "", .fromMilliseconds(50)));
}
