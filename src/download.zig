const std = @import("std");
const builtin = @import("builtin");
const http = @import("http.zig");
const archive = @import("archive.zig");
const auth = @import("auth.zig");
const release_mod = @import("release.zig");
const Dirs = @import("dirs.zig").Dirs;

const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;
const Writer = Io.Writer;
const EnvironMap = std.process.Environ.Map;
const Args = std.process.Args;

const Sha256 = std.crypto.hash.sha2.Sha256;
const sha256_hex_len = Sha256.digest_length * 2;

/// Exit codes used by `cmdDownload`.
pub const exit_arg_error: u8 = 1;
pub const exit_io_error: u8 = 1;
pub const exit_http_error: u8 = 2;
pub const exit_sha256_mismatch: u8 = 3;

/// Parsed `download` command-line options.
pub const Options = struct {
    /// Positional argument: a URL, `owner/repo[@tag]`, or
    /// `owner/repo/file[@tag]`.
    target: []const u8,
    output: ?[]const u8 = null,
    extract: ?[]const u8 = null,
    sha256: ?[]const u8 = null,
    strip_components: u32 = 0,
    keep_archive: bool = false,
    quiet: bool = false,
    no_auth: bool = false,
    skip_verify: bool = false,
    /// Raw base64 minisign public key (single token). When set, ghr fetches
    /// `<asset>.minisig` from the release and verifies it; missing sidecar
    /// is treated as a verification failure (fail-closed).
    minisign_pubkey: ?[]const u8 = null,
    debug: bool = false,

    /// No-op today (parseArgs holds slices into argv). Kept so callers can
    /// always `defer opts.deinit(allocator);` and we can add allocations later
    /// without churning the call sites.
    pub fn deinit(self: Options, allocator: std.mem.Allocator) void {
        _ = self;
        _ = allocator;
    }
};

/// Internal: target resolved from `Options.target` plus any release context
/// needed for verification.
const ResolvedTarget = struct {
    /// Final URL to download from. Borrows from argv (URL form) or from
    /// `release.parsed.value.assets[*].browser_download_url` (spec form).
    download_url: []const u8,
    /// Default output filename. When null, the caller derives one from the URL.
    default_filename: ?[]const u8,
    /// Release context for verification, when known.
    release: ?release_mod.ParsedRelease,
    /// Asset name within `release.parsed.value.assets`, when release is set.
    asset_name: ?[]const u8,
    /// Allocated buffer for parseGitHubReleaseUrl results (URL form only).
    url_decoded: ?release_mod.ParsedReleaseUrl,

    fn deinit(self: *ResolvedTarget, allocator: std.mem.Allocator) void {
        if (self.release) |*r| r.deinit();
        if (self.url_decoded) |*u| u.deinit(allocator);
    }
};

pub fn cmdDownload(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    args: *Args.Iterator,
    w: *Writer,
    err_w: *Writer,
) !void {
    const opts = parseArgs(allocator, args, err_w) catch |err| switch (err) {
        error.HelpRequested => {
            try printDownloadUsage(w);
            return;
        },
        error.MissingValue, error.InvalidArgument, error.MissingTarget => std.process.exit(exit_arg_error),
        else => return err,
    };
    defer opts.deinit(allocator);

    const debug_w: ?*Writer = if (opts.debug) err_w else null;

    // 0) Classify positional + resolve release context (for spec forms, or
    //    for URL form when it's a github release URL).
    var target = resolveTarget(allocator, io, environ, opts, w, err_w) catch |err| switch (err) {
        error.InvalidArgument => std.process.exit(exit_arg_error),
        error.ReleaseLookupFailed, error.AssetMatchFailed => std.process.exit(exit_http_error),
        else => return err,
    };
    defer target.deinit(allocator);

    // 1) Determine output and archive-on-disk paths.
    const paths = resolvePaths(allocator, io, opts, target.download_url, target.default_filename, err_w) catch |err| switch (err) {
        error.InvalidUrl, error.NoFilename, error.UnsupportedScheme => std.process.exit(exit_arg_error),
        else => return err,
    };
    defer paths.deinit(allocator);

    // 2) If extracting, ensure destination dir exists.
    if (paths.extract_dir) |edir| {
        Dir.cwd().createDirPath(io, edir) catch |err| {
            try err_w.print("error: failed to create extract dir '{s}': {}\n", .{ edir, err });
            try err_w.flush();
            std.process.exit(exit_io_error);
        };
    }

    // 3) Resolve auth header (only for github-owned hosts, unless --no-auth).
    const uri = std.Uri.parse(target.download_url) catch unreachable; // already validated
    var host_buf: [std.Io.net.HostName.max_len]u8 = undefined;
    const host = (uri.getHost(&host_buf) catch null) orelse blk: {
        // No host (shouldn't happen for http/https URLs we accept) — treat as non-github.
        break :blk std.Io.net.HostName{ .bytes = "" };
    };

    var resolved = auth.Resolved{ .token = null, .owns_token = false, .source = "skipped" };
    if (auth.isGithubHost(host.bytes)) {
        resolved = auth.resolveGithubToken(allocator, io, environ, opts.no_auth);
    }
    defer resolved.deinit(allocator);
    const auth_header = try auth.bearerHeader(allocator, resolved);
    defer if (auth_header) |h| allocator.free(h);

    if (opts.debug) {
        try err_w.print("debug: url: {s}\n", .{target.download_url});
        try err_w.print("debug: host: {s}\n", .{host.bytes});
        try err_w.print("debug: auth: {s}\n", .{resolved.source});
        try err_w.print("debug: archive_path: {s}\n", .{paths.archive_path});
        if (paths.extract_dir) |e| try err_w.print("debug: extract_dir: {s}\n", .{e});
        try err_w.flush();
    }

    // 4) Download to a `.part` file beside the destination so a partial file
    //    never appears at the user-visible path.
    const part_path = try std.fmt.allocPrint(allocator, "{s}.part", .{paths.archive_path});
    defer allocator.free(part_path);

    Dir.deleteFileAbsolute(io, part_path) catch {};

    var hasher: ?Sha256 = if (opts.sha256 != null) Sha256.init(.{}) else null;

    if (!opts.quiet) {
        try w.print("downloading {s} ...\n", .{target.download_url});
        try w.flush();
    }

    http.downloadToFile(allocator, io, target.download_url, part_path, .{
        .auth_header = auth_header,
        .debug_w = debug_w,
        .hasher = if (hasher != null) &hasher.? else null,
    }) catch |err| {
        Dir.deleteFileAbsolute(io, part_path) catch {};
        try err_w.print("error: download failed: {}\n", .{err});
        try err_w.print("  url: {s}\n", .{target.download_url});
        try err_w.flush();
        std.process.exit(exit_http_error);
    };

    // 5) Verify SHA-256 if --sha256 was passed.
    if (opts.sha256) |expected_hex| {
        var digest: [Sha256.digest_length]u8 = undefined;
        hasher.?.final(&digest);
        var got_hex_buf: [sha256_hex_len]u8 = undefined;
        const got_hex = bytesToHexLower(&digest, &got_hex_buf);
        if (!std.ascii.eqlIgnoreCase(got_hex, expected_hex)) {
            Dir.deleteFileAbsolute(io, part_path) catch {};
            try err_w.print("error: sha256 mismatch\n", .{});
            try err_w.print("  expected: {s}\n", .{expected_hex});
            try err_w.print("  actual:   {s}\n", .{got_hex});
            try err_w.flush();
            std.process.exit(exit_sha256_mismatch);
        }
        if (!opts.quiet) {
            try w.print("sha256 ok\n", .{});
            try w.flush();
        }
    }

    // 5b) Auto-verify against release manifest (sha256 / sigstore) when we
    //     have a release context. `--skip-verify` bypasses this. An explicit
    //     `--sha256` already validated the bytes, so we still attempt
    //     sigstore verification but allow `.no_verification` outcomes to be
    //     silent.
    if (target.release != null and target.asset_name != null) {
        const r = &target.release.?;
        const d = try Dirs.detect(allocator, environ);
        defer d.deinit();
        if (std.fs.path.dirname(d.cache)) |parent| {
            Dir.createDirAbsolute(io, parent, .default_dir) catch {};
        }
        Dir.createDirAbsolute(io, d.cache, .default_dir) catch {};
        const outcome = release_mod.verifyAssetOnDisk(
            allocator,
            io,
            d.cache,
            r.parsed.value.assets,
            target.asset_name.?,
            part_path,
            debug_w,
            auth_header,
            opts.skip_verify,
            opts.minisign_pubkey,
            w,
            err_w,
        ) catch |verr| {
            Dir.deleteFileAbsolute(io, part_path) catch {};
            switch (verr) {
                error.ChecksumMismatch,
                error.ChecksumDownloadFailed,
                error.ChecksumEntryMissing,
                error.MinisignSidecarMissing,
                error.MinisignKeyIdMismatch,
                error.MinisignSignatureMismatch,
                error.MinisignGlobalSigMismatch,
                => std.process.exit(exit_sha256_mismatch),
                error.MinisignDownloadFailed,
                => std.process.exit(exit_http_error),
                else => {
                    try err_w.print("error: verification failed: {}\n", .{verr});
                    try err_w.flush();
                    std.process.exit(exit_http_error);
                },
            }
        };
        _ = outcome;
    }

    // 6) Atomic rename into place.
    Dir.renameAbsolute(part_path, paths.archive_path, io) catch |err| {
        Dir.deleteFileAbsolute(io, part_path) catch {};
        try err_w.print("error: failed to finalise output '{s}': {}\n", .{ paths.archive_path, err });
        try err_w.flush();
        std.process.exit(exit_io_error);
    };

    // 7) Print download size summary.
    if (!opts.quiet) {
        const f = Dir.openFileAbsolute(io, paths.archive_path, .{}) catch null;
        if (f) |file| {
            defer file.close(io);
            const size = file.length(io) catch 0;
            if (size > 0) {
                try w.print("downloaded {d:.1} MB to {s}\n", .{
                    @as(f64, @floatFromInt(size)) / 1024.0 / 1024.0,
                    paths.archive_path,
                });
            } else {
                try w.print("downloaded to {s}\n", .{paths.archive_path});
            }
        } else {
            try w.print("downloaded to {s}\n", .{paths.archive_path});
        }
        try w.flush();
    }

    // 8) Optional extraction.
    if (paths.extract_dir) |edir| {
        const fmt = archive.detectFormat(paths.archive_name);
        if (fmt == .unknown) {
            try err_w.print("error: cannot extract '{s}': unrecognised archive format\n", .{paths.archive_name});
            try err_w.print("  supported formats: .zip, .tar.gz, .tgz, .tar.xz, .txz\n", .{});
            try err_w.flush();
            std.process.exit(exit_arg_error);
        }

        if (!opts.quiet) {
            try w.print("extracting to {s} ...\n", .{edir});
            try w.flush();
        }

        var dest_dir = Dir.openDirAbsolute(io, edir, .{}) catch |err| {
            try err_w.print("error: failed to open extract dir '{s}': {}\n", .{ edir, err });
            try err_w.flush();
            std.process.exit(exit_io_error);
        };
        defer dest_dir.close(io);

        archive.extractAuto(allocator, io, dest_dir, paths.archive_path, opts.strip_components) catch |err| {
            try err_w.print("error: extraction failed: {}\n", .{err});
            try err_w.flush();
            std.process.exit(exit_io_error);
        };

        if (!opts.keep_archive and !paths.user_supplied_output) {
            Dir.deleteFileAbsolute(io, paths.archive_path) catch {};
        }
    }
}

/// Resolve the positional argument into an actual download URL, optional
/// default output filename, and optional release context for verification.
fn resolveTarget(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    opts: Options,
    w: *Writer,
    err_w: *Writer,
) !ResolvedTarget {
    const classified = release_mod.classifyArg(opts.target) catch {
        try err_w.print("error: invalid argument '{s}'\n", .{opts.target});
        try err_w.print("  expected: owner/repo[@tag] or owner/repo/file[@tag]\n", .{});
        try err_w.flush();
        return error.InvalidArgument;
    };

    switch (classified) {
        .url => |u| {
            // Try to extract a github release context for opportunistic
            // verification. Failure is silent — non-github URLs and odd
            // shapes simply skip verification.
            const gh_opt = release_mod.parseGitHubReleaseUrl(allocator, u) catch null;
            if (gh_opt == null) {
                return .{
                    .download_url = u,
                    .default_filename = null,
                    .release = null,
                    .asset_name = null,
                    .url_decoded = null,
                };
            }
            const gh = gh_opt.?;

            const rel_opt = fetchRelease(allocator, io, environ, opts, gh.owner, gh.repo, gh.tag, w, err_w) catch null;
            if (rel_opt) |rel| {
                return .{
                    .download_url = u,
                    .default_filename = null,
                    .release = rel,
                    .asset_name = gh.file,
                    .url_decoded = gh,
                };
            }
            // Couldn't fetch release context; download anyway, no verify.
            var gh_mut = gh;
            gh_mut.deinit(allocator);
            return .{
                .download_url = u,
                .default_filename = null,
                .release = null,
                .asset_name = null,
                .url_decoded = null,
            };
        },
        .repo_spec => |rs| {
            var rel = try fetchRelease(allocator, io, environ, opts, rs.owner, rs.repo, rs.tag, w, err_w);
            errdefer rel.deinit();

            const asset = release_mod.findBestAsset(rel.parsed.value.assets) catch {
                try err_w.print("error: no matching asset for this platform\n", .{});
                try err_w.print("available assets:\n", .{});
                for (rel.parsed.value.assets) |a| try err_w.print("  {s}\n", .{a.name});
                try err_w.flush();
                return error.AssetMatchFailed;
            };
            return .{
                .download_url = asset.browser_download_url,
                .default_filename = asset.name,
                .release = rel,
                .asset_name = asset.name,
                .url_decoded = null,
            };
        },
        .file_spec => |fs| {
            var rel = try fetchRelease(allocator, io, environ, opts, fs.owner, fs.repo, fs.tag, w, err_w);
            errdefer rel.deinit();

            const m = release_mod.findAssetByName(allocator, rel.parsed.value.assets, fs.file) catch |err| {
                try err_w.print("error: failed to match asset by name: {}\n", .{err});
                try err_w.flush();
                return error.AssetMatchFailed;
            };
            switch (m) {
                .one => |asset| return .{
                    .download_url = asset.browser_download_url,
                    .default_filename = asset.name,
                    .release = rel,
                    .asset_name = asset.name,
                    .url_decoded = null,
                },
                .none => {
                    try err_w.print("error: no asset matching '{s}' in {s}/{s}@{s}\n", .{
                        fs.file, fs.owner, fs.repo, rel.parsed.value.tag_name,
                    });
                    try err_w.print("available assets:\n", .{});
                    for (rel.parsed.value.assets) |a| try err_w.print("  {s}\n", .{a.name});
                    try err_w.flush();
                    return error.AssetMatchFailed;
                },
                .ambiguous => |list| {
                    defer allocator.free(list);
                    try err_w.print("error: '{s}' matches multiple assets in {s}/{s}@{s}:\n", .{
                        fs.file, fs.owner, fs.repo, rel.parsed.value.tag_name,
                    });
                    for (list) |a| try err_w.print("  {s}\n", .{a.name});
                    try err_w.flush();
                    return error.AssetMatchFailed;
                },
            }
        },
    }
}

/// Fetch a release via the GitHub API. Logs progress lines mimicking
/// `cmdInstall`'s output.
fn fetchRelease(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    opts: Options,
    owner: []const u8,
    repo: []const u8,
    tag: ?[]const u8,
    w: *Writer,
    err_w: *Writer,
) !release_mod.ParsedRelease {
    const auth_resolved = auth.resolveGithubToken(allocator, io, environ, opts.no_auth);
    defer auth_resolved.deinit(allocator);
    const auth_header = try auth.bearerHeader(allocator, auth_resolved);
    defer if (auth_header) |h| allocator.free(h);

    if (!opts.quiet) {
        try w.print("resolving {s}/{s}", .{ owner, repo });
        if (tag) |t| try w.print("@{s}", .{t});
        try w.print(" ...\n", .{});
        try w.flush();
    }

    var client: std.http.Client = .{
        .allocator = allocator,
        .io = io,
        .write_buffer_size = http.http_write_buffer_size,
    };
    defer client.deinit();

    const rel = release_mod.getRelease(allocator, &client, owner, repo, tag, auth_header) catch |err| {
        switch (err) {
            error.GitHubApiError => {
                try err_w.print("error: release not found for {s}/{s}", .{ owner, repo });
                if (tag) |t| try err_w.print("@{s}", .{t});
                try err_w.print("\n", .{});
            },
            else => try err_w.print("error: failed to fetch release: {}\n", .{err}),
        }
        try err_w.flush();
        return error.ReleaseLookupFailed;
    };
    if (!opts.quiet) {
        try w.print("found release {s}\n", .{rel.parsed.value.tag_name});
        try w.flush();
    }
    return rel;
}

const ResolvedPaths = struct {
    /// Absolute path to the downloaded archive on disk.
    archive_path: []const u8,
    /// Filename portion of `archive_path` (used for format detection).
    archive_name: []const u8,
    /// Absolute path of the extraction destination, or null when no `--extract`.
    extract_dir: ?[]const u8,
    /// True when the user passed `-o`. When set we never auto-delete the
    /// archive after extraction; the user explicitly asked for that file.
    user_supplied_output: bool,

    fn deinit(self: ResolvedPaths, allocator: std.mem.Allocator) void {
        allocator.free(self.archive_path);
        if (self.extract_dir) |e| allocator.free(e);
    }
};

fn resolvePaths(
    allocator: std.mem.Allocator,
    io: Io,
    opts: Options,
    download_url: []const u8,
    default_filename: ?[]const u8,
    err_w: *Writer,
) !ResolvedPaths {
    const uri = std.Uri.parse(download_url) catch {
        try err_w.print("error: invalid URL: {s}\n", .{download_url});
        try err_w.flush();
        return error.InvalidUrl;
    };
    if (!isHttpScheme(uri.scheme)) {
        try err_w.print("error: unsupported URL scheme '{s}' (only http/https)\n", .{uri.scheme});
        try err_w.flush();
        return error.UnsupportedScheme;
    }

    const archive_path = if (opts.output) |out|
        try toAbsolute(allocator, io, out)
    else if (default_filename) |name|
        try toAbsolute(allocator, io, name)
    else blk: {
        const default_name = derivedFilename(uri) catch {
            try err_w.print("error: cannot derive output filename from URL; pass -o <path>\n", .{});
            try err_w.flush();
            return error.NoFilename;
        };
        break :blk try toAbsolute(allocator, io, default_name);
    };
    errdefer allocator.free(archive_path);

    const archive_name = std.fs.path.basename(archive_path);

    const extract_dir: ?[]const u8 = if (opts.extract) |e|
        try toAbsolute(allocator, io, e)
    else
        null;

    return .{
        .archive_path = archive_path,
        .archive_name = archive_name,
        .extract_dir = extract_dir,
        .user_supplied_output = opts.output != null,
    };
}

fn isHttpScheme(scheme: []const u8) bool {
    return std.ascii.eqlIgnoreCase(scheme, "http") or std.ascii.eqlIgnoreCase(scheme, "https");
}

/// Derive an output filename from a URI's path component. Strips trailing
/// slashes and rejects empty/path-traversing names.
pub fn derivedFilename(uri: std.Uri) ![]const u8 {
    var raw_buf: [Dir.max_path_bytes]u8 = undefined;
    const raw_path = uri.path.toRaw(&raw_buf) catch return error.NoFilename;
    var path = raw_path;
    while (path.len > 0 and path[path.len - 1] == '/') path = path[0 .. path.len - 1];
    if (path.len == 0) return error.NoFilename;

    const last_slash = std.mem.lastIndexOfScalar(u8, path, '/');
    const name = if (last_slash) |i| path[i + 1 ..] else path;

    if (name.len == 0) return error.NoFilename;
    if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return error.NoFilename;
    if (std.mem.indexOfAny(u8, name, "/\\") != null) return error.NoFilename;

    // The slice is into raw_buf which is a stack buffer; the caller must dupe
    // before raw_buf is reused. We dupe by always copying via toAbsolute.
    return try staticDupeName(name);
}

threadlocal var derived_name_buf: [Dir.max_path_bytes]u8 = undefined;
fn staticDupeName(name: []const u8) ![]const u8 {
    if (name.len > derived_name_buf.len) return error.NoFilename;
    @memcpy(derived_name_buf[0..name.len], name);
    return derived_name_buf[0..name.len];
}

fn toAbsolute(allocator: std.mem.Allocator, io: Io, path: []const u8) ![]const u8 {
    if (std.fs.path.isAbsolute(path)) {
        return try allocator.dupe(u8, path);
    }
    var cwd_buf: [Dir.max_path_bytes]u8 = undefined;
    const cwd_len = try std.process.currentPath(io, &cwd_buf);
    const cwd = cwd_buf[0..cwd_len];
    return try std.fs.path.join(allocator, &.{ cwd, path });
}

fn bytesToHexLower(bytes: []const u8, out: []u8) []const u8 {
    std.debug.assert(out.len >= bytes.len * 2);
    const hex = "0123456789abcdef";
    for (bytes, 0..) |b, i| {
        out[i * 2] = hex[b >> 4];
        out[i * 2 + 1] = hex[b & 0x0f];
    }
    return out[0 .. bytes.len * 2];
}

fn parseArgs(allocator: std.mem.Allocator, args: *Args.Iterator, err_w: *Writer) !Options {
    _ = allocator; // reserved for future flags that allocate
    var opts: Options = .{ .target = "" };
    var positional: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (eql(arg, "-h") or eql(arg, "--help")) {
            return error.HelpRequested;
        } else if (eql(arg, "-o") or eql(arg, "--output")) {
            opts.output = try takeValue(args, "-o", err_w);
        } else if (eql(arg, "--extract")) {
            opts.extract = try takeValue(args, "--extract", err_w);
        } else if (eql(arg, "--strip-components")) {
            const v = try takeValue(args, "--strip-components", err_w);
            opts.strip_components = std.fmt.parseInt(u32, v, 10) catch {
                try err_w.print("error: --strip-components requires a non-negative integer (got '{s}')\n", .{v});
                try err_w.flush();
                return error.InvalidArgument;
            };
        } else if (eql(arg, "--sha256")) {
            const v = try takeValue(args, "--sha256", err_w);
            if (v.len != sha256_hex_len or !isHex(v)) {
                try err_w.print("error: --sha256 requires {d} hex characters\n", .{sha256_hex_len});
                try err_w.flush();
                return error.InvalidArgument;
            }
            opts.sha256 = v;
        } else if (eql(arg, "--keep-archive")) {
            opts.keep_archive = true;
        } else if (eql(arg, "--quiet")) {
            opts.quiet = true;
        } else if (eql(arg, "--no-auth")) {
            opts.no_auth = true;
        } else if (eql(arg, "--skip-verify")) {
            opts.skip_verify = true;
        } else if (eql(arg, "--minisign")) {
            opts.minisign_pubkey = try takeValue(args, "--minisign", err_w);
        } else if (eql(arg, "--debug")) {
            opts.debug = true;
        } else if (std.mem.startsWith(u8, arg, "-")) {
            try err_w.print("error: unknown flag '{s}' for 'ghr download'\n", .{arg});
            try err_w.flush();
            return error.InvalidArgument;
        } else if (positional == null) {
            positional = arg;
        } else {
            try err_w.print("error: unexpected argument '{s}'; only one positional is supported\n", .{arg});
            try err_w.flush();
            return error.InvalidArgument;
        }
    }

    opts.target = positional orelse {
        try err_w.print("error: 'ghr download' requires owner/repo[@tag] or owner/repo/file[@tag]\n", .{});
        try err_w.flush();
        return error.MissingTarget;
    };

    return opts;
}

fn takeValue(args: *Args.Iterator, flag: []const u8, err_w: *Writer) ![]const u8 {
    const v = args.next() orelse {
        try err_w.print("error: '{s}' requires a value\n", .{flag});
        try err_w.flush();
        return error.MissingValue;
    };
    return v;
}

fn isHex(s: []const u8) bool {
    for (s) |c| {
        const ok = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
        if (!ok) return false;
    }
    return true;
}

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn printDownloadUsage(w: *Writer) !void {
    try w.print(
        \\ghr download - download a release asset, optionally extracting it
        \\
        \\USAGE:
        \\    ghr download <owner/repo[@tag]> [options]
        \\    ghr download <owner/repo/file[@tag]> [options]
        \\
        \\Picks the asset that 'ghr install' would install (first form), or the
        \\named asset (second form, exact match preferred, otherwise unique
        \\substring). The download is auto-verified against any sigstore bundle
        \\or sha256 checksum file published with the release. Pass
        \\`--minisign <base64-pubkey>` to also require minisign signature
        \\verification against a `<asset>.minisig` sidecar.
        \\
        \\OPTIONS:
        \\    -o, --output <path>        Output file path (default: asset name in cwd)
        \\        --extract <dir>        Extract archive into <dir> after download
        \\        --strip-components <N> Strip N leading path components when extracting
        \\        --sha256 <hex>         Verify download against SHA-256 digest (64 hex chars)
        \\        --minisign <pubkey>    Require minisign signature; <pubkey> is a base64 minisign public key
        \\        --skip-verify          Skip sigstore + sha256 + minisign release verification
        \\        --keep-archive         Keep archive on disk after extraction
        \\        --quiet                Suppress progress output
        \\        --no-auth              Do not send GitHub auth even for github.com URLs
        \\        --debug                Verbose diagnostic output
        \\    -h, --help                 Show this help
        \\
        \\EXIT CODES:
        \\    0 success
        \\    1 argument or IO error
        \\    2 HTTP / network error after retries
        \\    3 sha256 mismatch
        \\
    , .{});
    try w.flush();
}

// Public helpers re-exported for tests in main.
const Options_for_test = Options;

// ---------- tests ----------

test "derivedFilename extracts last path segment" {
    const cases = [_]struct { url: []const u8, want: []const u8 }{
        .{ .url = "https://github.com/foo/bar/baz.tar.gz", .want = "baz.tar.gz" },
        .{ .url = "https://example.com/path/to/file.zip", .want = "file.zip" },
        .{ .url = "https://example.com/file.txt?token=abc", .want = "file.txt" },
        .{ .url = "https://example.com/file.txt#frag", .want = "file.txt" },
        .{ .url = "https://example.com/dir/", .want = "dir" },
    };
    for (cases) |c| {
        const uri = try std.Uri.parse(c.url);
        const got = try derivedFilename(uri);
        try std.testing.expectEqualStrings(c.want, got);
    }
}

test "derivedFilename rejects empty or unsafe names" {
    const bad_urls = [_][]const u8{
        "https://example.com/",
        "https://example.com",
        "https://example.com/..",
        "https://example.com/path/.",
    };
    for (bad_urls) |u| {
        const uri = try std.Uri.parse(u);
        try std.testing.expectError(error.NoFilename, derivedFilename(uri));
    }
}

test "isHex accepts only hex digits" {
    try std.testing.expect(isHex("0123456789abcdefABCDEF"));
    try std.testing.expect(isHex(""));
    try std.testing.expect(!isHex("g"));
    try std.testing.expect(!isHex("0x123"));
    try std.testing.expect(!isHex(" "));
}

test "bytesToHexLower formats sha256 output" {
    var buf: [4]u8 = undefined;
    const got = bytesToHexLower(&[_]u8{ 0x0a, 0xff }, &buf);
    try std.testing.expectEqualStrings("0aff", got);
}

test "isHttpScheme accepts http and https" {
    try std.testing.expect(isHttpScheme("http"));
    try std.testing.expect(isHttpScheme("https"));
    try std.testing.expect(isHttpScheme("HTTPS"));
    try std.testing.expect(!isHttpScheme("ftp"));
    try std.testing.expect(!isHttpScheme("file"));
    try std.testing.expect(!isHttpScheme(""));
}
