//! `ghr minisign sign` — produce a minisign `.minisig` sidecar without an
//! external `minisign` binary, an `expect` script, or a key file on disk.
//!
//! It is intentionally rigid and CI-only: the secret key MUST come from the
//! `MINISIGN_SECRET_KEY` environment variable, and an encrypted key's
//! password from `MINISIGN_PASSWORD`. Neither is read from a file flag, a
//! tty, or stdin. Inputs are bare positional file paths; each `<file>` is
//! signed to `<file>.minisig`.
//!
//! `minisign.zig` adapts the in-process minizign library; this module is
//! just argument parsing, key/password sourcing, and sidecar writing.

const std = @import("std");
const minisign = @import("minisign.zig");
const generate = @import("minisign_generate.zig");

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

    if (std.mem.eql(u8, sub, "generate")) {
        generate.cmdGenerate(allocator, io, environ, args, w, err_w) catch |err| switch (err) {
            error.GenerateFailed => std.process.exit(1),
            else => return err,
        };
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
        if (std.mem.eql(u8, arg, "-t")) {
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

    var signature = sk.signFile(allocator, io, file, tc) catch |err| {
        fail(err_w, "failed to sign '{s}': {s}", .{ input, @errorName(err) });
    };
    defer signature.deinit();

    const out = try allocator.print("{s}.minisig", .{input});
    defer allocator.free(out);

    signature.toFile(io, out, uc) catch |err| {
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
    return allocator.print("timestamp:{d}\tfile:{s}\thashed", .{ secs, base });
}

// ---------------------------------------------------------------------------
// Small filesystem helpers (tolerate absolute or cwd-relative paths).
// ---------------------------------------------------------------------------

fn openFile(io: Io, path: []const u8) !File {
    if (std.fs.path.isAbsolute(path)) return Dir.openFileAbsolute(io, path, .{});
    return Dir.cwd().openFile(io, path, .{});
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
        \\ghr minisign - generate signing keys or sign release artifacts
        \\
        \\USAGE:
        \\    ghr minisign <SUBCOMMAND> [OPTIONS]
        \\
        \\SUBCOMMANDS:
        \\    generate Generate a key and provision the repository signing secret
        \\    sign     Sign one or more files, writing <file>.minisig sidecars
        \\
        \\Run 'ghr minisign generate --help' or 'ghr minisign sign --help'
        \\for usage. Signing requires MINISIGN_SECRET_KEY; MINISIGN_PASSWORD
        \\is needed only for an encrypted key.
        \\
        \\OPTIONS:
        \\    -h, --help  Show this help
        \\
    , .{});
}

pub fn printGenerateUsage(w: *Writer) !void {
    try generate.printUsage(w);
}

pub fn printSignUsage(w: *Writer) !void {
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
        \\
        \\OPTIONAL ENVIRONMENT:
        \\    MINISIGN_PASSWORD     password, only when the key is encrypted
        \\
        \\Key contents and an encrypted key's password come from the environment.
        \\There is no key-file flag or tty/stdin password prompt.
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
    const ts = tc["timestamp:".len..std.mem.indexOfScalar(u8, tc, '\t').?];
    try std.testing.expect(ts.len > 0);
    for (ts) |c| try std.testing.expect(c >= '0' and c <= '9');
}
