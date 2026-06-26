//! `ghr minisign sign` — produce a minisign `.minisig` sidecar without an
//! external `minisign` binary, an `expect` script, or a key file on disk.
//!
//! It is CI-first: the secret key and its password are read from
//! environment variables (`MINISIGN_SECRET_KEY` / `MINISIGN_PASSWORD`) by
//! default, so a release workflow collapses to a single `run:` step. The
//! password may also be piped on stdin; it is never read from `/dev/tty`,
//! so no pseudo-terminal trick is needed.
//!
//! Crypto lives in `minisign.zig`; this module is just argument parsing,
//! key/password sourcing, and sidecar writing.

const std = @import("std");
const minisign = @import("minisign.zig");

const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;
const Writer = Io.Writer;
const EnvironMap = std.process.Environ.Map;

const default_untrusted_comment = "signature from ghr minisign";
const max_secret_key_bytes = 4 * 1024;

/// Entry point for `ghr minisign <subcommand> ...`.
pub fn cmdMinisign(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    args: *std.process.Args.Iterator,
    w: *Writer,
    err_w: *Writer,
) !void {
    const sub = args.next() orelse {
        try printUsage(err_w);
        try err_w.flush();
        std.process.exit(1);
    };

    if (std.mem.eql(u8, sub, "help")) {
        try printUsage(w);
        return;
    }

    if (std.mem.eql(u8, sub, "sign")) {
        try cmdSign(allocator, io, environ, args, w, err_w);
        return;
    }

    try err_w.print("error: unknown subcommand '{s}' for 'ghr minisign'\n\n", .{sub});
    try printUsage(err_w);
    try err_w.flush();
    std.process.exit(1);
}

fn fail(err_w: *Writer, comptime fmt: []const u8, args: anytype) noreturn {
    err_w.print("error: " ++ fmt ++ "\n", args) catch {};
    err_w.flush() catch {};
    std.process.exit(1);
}

fn cmdSign(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    args: *std.process.Args.Iterator,
    w: *Writer,
    err_w: *Writer,
) !void {
    var inputs: std.ArrayListUnmanaged([]const u8) = .empty;
    defer inputs.deinit(allocator);

    var secret_key_path: ?[]const u8 = null;
    var output_path: ?[]const u8 = null;
    var trusted_comment: ?[]const u8 = null;
    var untrusted_comment: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "help") or std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            try printSignUsage(w);
            return;
        } else if (eqOpt(arg, "-m", "--input")) {
            inputs.append(allocator, nextValue(args, err_w, arg)) catch return error.OutOfMemory;
        } else if (eqOpt(arg, "-s", "--secret-key")) {
            secret_key_path = nextValue(args, err_w, arg);
        } else if (eqOpt(arg, "-x", "--output")) {
            output_path = nextValue(args, err_w, arg);
        } else if (eqOpt(arg, "-t", "--trusted-comment")) {
            trusted_comment = nextValue(args, err_w, arg);
        } else if (eqOpt(arg, "-c", "--untrusted-comment")) {
            untrusted_comment = nextValue(args, err_w, arg);
        } else if (std.mem.startsWith(u8, arg, "-")) {
            fail(err_w, "unknown option '{s}' for 'ghr minisign sign'", .{arg});
        } else {
            // Bare positional: treat as an input file for convenience.
            inputs.append(allocator, arg) catch return error.OutOfMemory;
        }
    }

    if (inputs.items.len == 0) {
        fail(err_w, "'ghr minisign sign' requires at least one input (-m <file>)", .{});
    }
    if (output_path != null and inputs.items.len > 1) {
        fail(err_w, "-x/--output cannot be combined with multiple inputs", .{});
    }
    if (trusted_comment != null and inputs.items.len > 1) {
        fail(err_w, "-t/--trusted-comment cannot be combined with multiple inputs", .{});
    }

    // Source the secret key: -s file wins, else MINISIGN_SECRET_KEY env.
    const sk_bytes = blk: {
        if (secret_key_path) |p| {
            break :blk readWholeFile(allocator, io, p, max_secret_key_bytes) catch |err| {
                fail(err_w, "failed to read secret key '{s}': {s}", .{ p, @errorName(err) });
            };
        }
        if (environ.get("MINISIGN_SECRET_KEY")) |env_key| {
            break :blk allocator.dupe(u8, env_key) catch return error.OutOfMemory;
        }
        fail(err_w, "no secret key: pass -s <file> or set MINISIGN_SECRET_KEY", .{});
    };
    defer {
        std.crypto.secureZero(u8, sk_bytes);
        allocator.free(sk_bytes);
    }

    var sk = minisign.parseSecretKey(sk_bytes) catch |err| {
        fail(err_w, "invalid secret key: {s}", .{@errorName(err)});
    };
    defer sk.deinit();

    if (sk.isEncrypted()) {
        const password = try sourcePassword(allocator, io, environ, err_w);
        defer {
            std.crypto.secureZero(u8, password);
            allocator.free(password);
        }
        sk.decrypt(allocator, password) catch |err| switch (err) {
            error.MinisignWrongPassword => fail(err_w, "wrong password for the secret key", .{}),
            else => fail(err_w, "failed to decrypt secret key: {s}", .{@errorName(err)}),
        };
    } else {
        try sk.decrypt(allocator, "");
    }

    for (inputs.items) |input| {
        try signOne(allocator, io, &sk, input, output_path, trusted_comment, untrusted_comment, w, err_w);
    }
    try w.flush();
}

fn signOne(
    allocator: std.mem.Allocator,
    io: Io,
    sk: *const minisign.SecretKey,
    input: []const u8,
    output_path: ?[]const u8,
    trusted_comment: ?[]const u8,
    untrusted_comment: ?[]const u8,
    w: *Writer,
    err_w: *Writer,
) !void {
    var file = openFile(io, input) catch |err| {
        fail(err_w, "failed to open '{s}': {s}", .{ input, @errorName(err) });
    };
    defer file.close(io);

    const tc = trusted_comment orelse try defaultTrustedComment(allocator, io, input);
    const owns_tc = trusted_comment == null;
    defer if (owns_tc) allocator.free(tc);

    const uc = untrusted_comment orelse default_untrusted_comment;

    const sidecar = sk.signArtifact(allocator, io, file, tc, uc) catch |err| {
        fail(err_w, "failed to sign '{s}': {s}", .{ input, @errorName(err) });
    };
    defer allocator.free(sidecar);

    const out = output_path orelse try std.fmt.allocPrint(allocator, "{s}.minisig", .{input});
    const owns_out = output_path == null;
    defer if (owns_out) allocator.free(out);

    writeWholeFile(io, out, sidecar) catch |err| {
        fail(err_w, "failed to write '{s}': {s}", .{ out, @errorName(err) });
    };

    try w.print("signed {s} -> {s} (trusted comment: {s})\n", .{ input, out, tc });
}

/// minisign's default trusted comment for a prehashed signature:
/// `timestamp:<unix>\tfile:<basename>\thashed`.
fn defaultTrustedComment(allocator: std.mem.Allocator, io: Io, input: []const u8) ![]u8 {
    const now = Io.Clock.now(.real, io);
    const secs: i64 = @intCast(@divFloor(now.nanoseconds, std.time.ns_per_s));
    const base = std.fs.path.basename(input);
    return std.fmt.allocPrint(allocator, "timestamp:{d}\tfile:{s}\thashed", .{ secs, base });
}

/// Resolve the secret-key password: `MINISIGN_PASSWORD` env wins; otherwise
/// read a single line from stdin. Never touches `/dev/tty`.
fn sourcePassword(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    err_w: *Writer,
) ![]u8 {
    if (environ.get("MINISIGN_PASSWORD")) |p| {
        return allocator.dupe(u8, p) catch return error.OutOfMemory;
    }

    var stdin = File.stdin();
    var buf: [1024]u8 = undefined;
    var reader = stdin.reader(io, &buf);
    const line = reader.interface.takeDelimiterExclusive('\n') catch |err| switch (err) {
        error.EndOfStream => fail(err_w, "secret key is encrypted but no password was provided (set MINISIGN_PASSWORD or pipe it on stdin)", .{}),
        else => return err,
    };
    const trimmed = std.mem.trimEnd(u8, line, "\r");
    return allocator.dupe(u8, trimmed) catch return error.OutOfMemory;
}

// ---------------------------------------------------------------------------
// Small filesystem helpers (tolerate absolute or cwd-relative paths).
// ---------------------------------------------------------------------------

fn openFile(io: Io, path: []const u8) !File {
    if (std.fs.path.isAbsolute(path)) return Dir.openFileAbsolute(io, path, .{});
    return Dir.cwd().openFile(io, path, .{});
}

fn readWholeFile(allocator: std.mem.Allocator, io: Io, path: []const u8, limit: usize) ![]u8 {
    // Dir.readFileAlloc opens with size-known reader semantics; on POSIX an
    // absolute sub_path resolves correctly via openat regardless of dir.
    return Dir.cwd().readFileAlloc(io, path, allocator, Io.Limit.limited(limit));
}

fn writeWholeFile(io: Io, path: []const u8, bytes: []const u8) !void {
    var file = if (std.fs.path.isAbsolute(path))
        try Dir.createFileAbsolute(io, path, .{})
    else
        try Dir.cwd().createFile(io, path, .{});
    defer file.close(io);
    try file.writeStreamingAll(io, bytes);
}

// ---------------------------------------------------------------------------
// Argument helpers.
// ---------------------------------------------------------------------------

fn eqOpt(arg: []const u8, short: []const u8, long: []const u8) bool {
    return std.mem.eql(u8, arg, short) or std.mem.eql(u8, arg, long);
}

fn nextValue(args: *std.process.Args.Iterator, err_w: *Writer, flag: []const u8) []const u8 {
    return args.next() orelse fail(err_w, "option '{s}' requires a value", .{flag});
}

// ---------------------------------------------------------------------------
// Usage.
// ---------------------------------------------------------------------------

pub fn printUsage(w: *Writer) !void {
    try w.print(
        \\ghr minisign - sign release artifacts with a minisign key
        \\
        \\USAGE:
        \\    ghr minisign <SUBCOMMAND> [OPTIONS]
        \\
        \\SUBCOMMANDS:
        \\    sign     Sign one or more files, writing <file>.minisig sidecars
        \\    help     Show this help
        \\
        \\Run 'ghr minisign sign help' for signing options.
        \\
    , .{});
}

fn printSignUsage(w: *Writer) !void {
    try w.print(
        \\ghr minisign sign - write a minisign .minisig sidecar (no external binary)
        \\
        \\USAGE:
        \\    ghr minisign sign -m <file> [-m <file> ...] [OPTIONS]
        \\
        \\The secret key and password are read from the environment by
        \\default, so CI never needs a key file or an `expect` script:
        \\
        \\    MINISIGN_SECRET_KEY   secret key (file contents or base64 line)
        \\    MINISIGN_PASSWORD     password for an encrypted key
        \\
        \\If MINISIGN_PASSWORD is unset and the key is encrypted, the
        \\password is read from stdin (one line). It is never read from a tty.
        \\
        \\OPTIONS:
        \\    -m, --input <file>             File to sign (repeatable)
        \\    -s, --secret-key <file>        Secret key file (overrides env)
        \\    -x, --output <file>            Sidecar path (default <file>.minisig;
        \\                                   single input only)
        \\    -t, --trusted-comment <text>   Trusted comment (signed); default
        \\                                   timestamp:<unix>\tfile:<name>\thashed
        \\    -c, --untrusted-comment <text> Untrusted comment (not signed)
        \\    -h, --help                     Show this help
        \\
        \\Signatures use the prehashed (ED / Blake2b-512) format and are
        \\deterministic, matching `minisign -S` output.
        \\
        \\EXAMPLE (GitHub Actions):
        \\    - run: ghr minisign sign -m hello.wasm -t "tag:${{ github.ref_name }}"
        \\      env:
        \\        MINISIGN_SECRET_KEY: ${{ secrets.MINISIGN_SECRET_KEY }}
        \\        MINISIGN_PASSWORD:   ${{ secrets.MINISIGN_PASSWORD }}
        \\
    , .{});
}

test {
    _ = @import("minisign.zig");
}
