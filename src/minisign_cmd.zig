//! `ghr minisign sign` — produce a minisign `.minisig` sidecar without an
//! external `minisign` binary, an `expect` script, or a key file on disk.
//!
//! It is intentionally rigid and CI-only: the secret key MUST come from the
//! `MINISIGN_SECRET_KEY` environment variable, and an encrypted key's
//! password from `MINISIGN_PASSWORD`. Neither is read from a file flag, a
//! tty, or stdin. Inputs are bare positional file paths; each `<file>` is
//! signed to `<file>.minisig`.
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

    var trusted_comment: ?[]const u8 = null;
    var untrusted_comment: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "help") or std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            try printSignUsage(w);
            return;
        } else if (std.mem.eql(u8, arg, "-t")) {
            trusted_comment = nextValue(args, err_w, arg);
        } else if (std.mem.eql(u8, arg, "-c")) {
            untrusted_comment = nextValue(args, err_w, arg);
        } else if (std.mem.startsWith(u8, arg, "-") and arg.len > 1) {
            fail(err_w, "unknown option '{s}' for 'ghr minisign sign'", .{arg});
        } else {
            // Inputs are bare positional file paths.
            inputs.append(allocator, arg) catch return error.OutOfMemory;
        }
    }

    if (inputs.items.len == 0) {
        fail(err_w, "'ghr minisign sign' requires at least one input file", .{});
    }

    // The secret key MUST come from the environment — no file flag.
    const env_key = environ.get("MINISIGN_SECRET_KEY") orelse {
        fail(err_w, "MINISIGN_SECRET_KEY is not set (the secret key must come from the environment)", .{});
    };
    const sk_bytes = allocator.dupe(u8, env_key) catch return error.OutOfMemory;
    defer {
        std.crypto.secureZero(u8, sk_bytes);
        allocator.free(sk_bytes);
    }

    var sk = minisign.parseSecretKey(sk_bytes) catch |err| {
        fail(err_w, "invalid MINISIGN_SECRET_KEY: {s}", .{@errorName(err)});
    };
    defer sk.deinit();

    if (sk.isEncrypted()) {
        const env_pw = environ.get("MINISIGN_PASSWORD") orelse {
            fail(err_w, "the secret key is encrypted but MINISIGN_PASSWORD is not set", .{});
        };
        const password = allocator.dupe(u8, env_pw) catch return error.OutOfMemory;
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
        try signOne(allocator, io, &sk, input, trusted_comment, untrusted_comment, w, err_w);
    }
    try w.flush();
}

fn signOne(
    allocator: std.mem.Allocator,
    io: Io,
    sk: *const minisign.SecretKey,
    input: []const u8,
    trusted_comment: ?[]const u8,
    untrusted_comment: ?[]const u8,
    w: *Writer,
    err_w: *Writer,
) !void {
    var file = openFile(io, input) catch |err| {
        fail(err_w, "failed to open '{s}': {s}", .{ input, @errorName(err) });
    };
    defer file.close(io);

    // Match minisign: an absent OR empty -t falls back to the default
    // per-file trusted comment; an explicit -t applies to every input.
    const use_default = trusted_comment == null or trusted_comment.?.len == 0;
    const tc = if (use_default)
        try defaultTrustedComment(allocator, io, input)
    else
        trusted_comment.?;
    defer if (use_default) allocator.free(tc);

    const uc = untrusted_comment orelse default_untrusted_comment;

    const sidecar = sk.signArtifact(allocator, io, file, tc, uc) catch |err| {
        fail(err_w, "failed to sign '{s}': {s}", .{ input, @errorName(err) });
    };
    defer allocator.free(sidecar);

    const out = try std.fmt.allocPrint(allocator, "{s}.minisig", .{input});
    defer allocator.free(out);

    writeWholeFile(io, out, sidecar) catch |err| {
        fail(err_w, "failed to write '{s}': {s}", .{ out, @errorName(err) });
    };

    try w.print("signed {s} -> {s} (trusted comment: {s})\n", .{ input, out, tc });
}

/// minisign's default trusted comment for a prehashed signature:
/// `timestamp:<unix>\tfile:<basename>\thashed`. ghr always signs prehashed,
/// so the `\thashed` suffix is always present (matching `minisign -S`).
fn defaultTrustedComment(allocator: std.mem.Allocator, io: Io, input: []const u8) ![]u8 {
    const now = Io.Clock.now(.real, io);
    const secs: i64 = @intCast(@divFloor(now.nanoseconds, std.time.ns_per_s));
    const base = std.fs.path.basename(input);
    return std.fmt.allocPrint(allocator, "timestamp:{d}\tfile:{s}\thashed", .{ secs, base });
}

// ---------------------------------------------------------------------------
// Small filesystem helpers (tolerate absolute or cwd-relative paths).
// ---------------------------------------------------------------------------

fn openFile(io: Io, path: []const u8) !File {
    if (std.fs.path.isAbsolute(path)) return Dir.openFileAbsolute(io, path, .{});
    return Dir.cwd().openFile(io, path, .{});
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
        \\Run 'ghr minisign sign help' for signing usage and the required
        \\MINISIGN_SECRET_KEY / MINISIGN_PASSWORD environment variables.
        \\
    , .{});
}

fn printSignUsage(w: *Writer) !void {
    try w.print(
        \\ghr minisign sign - write a minisign .minisig sidecar (no external binary)
        \\
        \\USAGE:
        \\    ghr minisign sign <file> [<file> ...] [-t <comment>] [-c <comment>]
        \\
        \\Each <file> is signed to <file>.minisig. Input files are given as
        \\bare positional arguments (no -m flag). An explicit -t is applied to
        \\every input; when omitted it defaults per-file (see below).
        \\
        \\REQUIRED ENVIRONMENT:
        \\    MINISIGN_SECRET_KEY   secret key contents (the .key file body)
        \\    MINISIGN_PASSWORD     password for the encrypted key
        \\
        \\Both the secret key and the password MUST come from the environment
        \\— there is no key-file flag, and the password is never read from a
        \\tty or stdin, so no `expect` script is needed. MINISIGN_PASSWORD is
        \\not required for an unencrypted key.
        \\
        \\OPTIONS:
        \\    -t <text>   Trusted comment, signed. Defaults (like minisign) to
        \\                timestamp:<unix>\tfile:<name>\thashed per input.
        \\    -c <text>   Untrusted comment, not signed (default:
        \\                "signature from ghr minisign").
        \\    -h, --help  Show this help
        \\
        \\Signatures use the prehashed (ED / Blake2b-512) format and are
        \\deterministic, matching `minisign -S` output.
        \\
        \\EXAMPLE (GitHub Actions):
        \\    - run: ghr minisign sign hello.wasm -t "tag:${{{{ github.ref_name }}}}"
        \\      env:
        \\        MINISIGN_SECRET_KEY: ${{{{ secrets.MINISIGN_SECRET_KEY }}}}
        \\        MINISIGN_PASSWORD:   ${{{{ secrets.MINISIGN_PASSWORD }}}}
        \\
    , .{});
}

test {
    _ = @import("minisign.zig");
}

test "defaultTrustedComment: matches minisign's per-file shape" {
    const io = std.testing.io;
    const tc = try defaultTrustedComment(std.testing.allocator, io, "dir/sub/hello.wasm");
    defer std.testing.allocator.free(tc);

    // timestamp:<digits>\tfile:<basename>\thashed — basename only, tab-separated.
    try std.testing.expect(std.mem.startsWith(u8, tc, "timestamp:"));
    try std.testing.expect(std.mem.endsWith(u8, tc, "\tfile:hello.wasm\thashed"));
    const ts = tc["timestamp:".len .. std.mem.indexOfScalar(u8, tc, '\t').?];
    try std.testing.expect(ts.len > 0);
    for (ts) |c| try std.testing.expect(c >= '0' and c <= '9');
}
