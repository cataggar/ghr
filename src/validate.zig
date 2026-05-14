//! `ghr validate` — checks performed against a previously published
//! release asset. Currently a single action:
//!
//!   ghr validate strip-authenticode <input.exe> <output.exe>
//!
//! Strips the Authenticode signature off a signed PE/COFF binary and
//! writes the resulting bit-identical-to-unsigned bytes to
//! `<output.exe>`. Used by the reproducibility workflow (issue #78
//! Option E) to compare a published signed `.exe` against a
//! source-rebuilt unsigned `.exe`, without publishing a separate
//! pre-sign artifact.

const std = @import("std");
const authenticode = @import("authenticode.zig");

const Io = std.Io;
const Dir = Io.Dir;
const Writer = Io.Writer;

/// Entry point for `ghr validate <subcommand> ...`. Consumes args
/// from the caller's iterator.
pub fn cmdValidate(
    allocator: std.mem.Allocator,
    io: Io,
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

    if (std.mem.eql(u8, sub, "strip-authenticode")) {
        try cmdStripAuthenticode(allocator, io, args, w, err_w);
        return;
    }

    try err_w.print("error: unknown subcommand '{s}' for 'ghr validate'\n\n", .{sub});
    try printUsage(err_w);
    try err_w.flush();
    std.process.exit(1);
}

fn cmdStripAuthenticode(
    allocator: std.mem.Allocator,
    io: Io,
    args: *std.process.Args.Iterator,
    w: *Writer,
    err_w: *Writer,
) !void {
    var input_path: ?[]const u8 = null;
    var output_path: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "help")) {
            try printStripUsage(w);
            return;
        }
        if (std.mem.eql(u8, arg, "--quiet")) {
            // Reserved for future use.
            continue;
        }
        if (input_path == null) {
            input_path = arg;
        } else if (output_path == null) {
            output_path = arg;
        } else {
            try err_w.print("error: unexpected argument '{s}' for 'ghr validate strip-authenticode'\n", .{arg});
            try err_w.flush();
            std.process.exit(1);
        }
    }

    const input = input_path orelse {
        try err_w.print(
            "error: 'ghr validate strip-authenticode' requires <input.exe> <output.exe>\n",
            .{},
        );
        try err_w.flush();
        std.process.exit(1);
    };
    const output = output_path orelse {
        try err_w.print(
            "error: 'ghr validate strip-authenticode' requires <output.exe> after <input.exe>\n",
            .{},
        );
        try err_w.flush();
        std.process.exit(1);
    };

    // Read input into a heap buffer. The reproducibility workflow only
    // ever uses this on a fresh `.exe` extracted from a release zip;
    // PE sizes are well within the same in-memory ceiling we use for
    // verification (200 MiB; see authenticode.max_entry_size).
    const input_abs = try absolutise(allocator, io, input);
    defer allocator.free(input_abs);
    const output_abs = try absolutise(allocator, io, output);
    defer allocator.free(output_abs);

    var in_file = Dir.openFileAbsolute(io, input_abs, .{}) catch |err| {
        try err_w.print("error: failed to open '{s}': {s}\n", .{ input, @errorName(err) });
        try err_w.flush();
        std.process.exit(1);
    };
    defer in_file.close(io);

    const stat = try in_file.stat(io);
    if (stat.size > authenticode.max_entry_size) {
        try err_w.print(
            "error: '{s}' is {d} bytes (exceeds {d}-byte cap)\n",
            .{ input, stat.size, authenticode.max_entry_size },
        );
        try err_w.flush();
        std.process.exit(1);
    }

    var read_buf: [64 * 1024]u8 = undefined;
    var fr = in_file.reader(io, &read_buf);
    const bytes = try allocator.alloc(u8, @intCast(stat.size));
    defer allocator.free(bytes);
    try fr.interface.readSliceAll(bytes);

    const outcome = authenticode.stripAuthenticodeIntoBuffer(allocator, bytes) catch |err| {
        switch (err) {
            error.NotSigned => try err_w.print(
                "error: '{s}' is not Authenticode-signed (no certificate table)\n",
                .{input},
            ),
            error.CertTableNotAtEnd, error.InvalidCertTable => try err_w.print(
                "error: '{s}' has a certificate table that is not at end of file; refusing to strip\n",
                .{input},
            ),
            error.NotPeImage,
            error.TruncatedDosHeader,
            error.TruncatedNtHeader,
            error.BadNtSignature,
            error.TruncatedFileHeader,
            error.TruncatedOptionalHeader,
            error.UnknownOptionalHeaderMagic,
            error.TruncatedDataDirectory,
            => try err_w.print("error: '{s}' is not a valid PE/COFF binary ({s})\n", .{ input, @errorName(err) }),
            else => try err_w.print("error: strip failed for '{s}': {s}\n", .{ input, @errorName(err) }),
        }
        try err_w.flush();
        std.process.exit(1);
    };
    defer allocator.free(outcome.bytes);

    var out_file = Dir.createFileAbsolute(io, output_abs, .{}) catch |err| {
        try err_w.print("error: failed to create '{s}': {s}\n", .{ output, @errorName(err) });
        try err_w.flush();
        std.process.exit(1);
    };
    defer out_file.close(io);
    try out_file.writeStreamingAll(io, outcome.bytes);

    try w.print(
        "stripped {s} -> {s}: dropped {d} bytes (cert table at offset 0x{x})\n",
        .{ input, output, outcome.stripped_bytes, outcome.stripped_at },
    );
    try w.flush();
}

fn absolutise(allocator: std.mem.Allocator, io: Io, path: []const u8) ![]u8 {
    if (std.fs.path.isAbsolute(path)) {
        return allocator.dupe(u8, path);
    }
    var cwd_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const cwd_len = try std.process.currentPath(io, &cwd_buf);
    const cwd = cwd_buf[0..cwd_len];
    return std.fs.path.join(allocator, &.{ cwd, path });
}

pub fn printUsage(w: *Writer) !void {
    try w.print(
        \\ghr validate - run validations against published release artifacts
        \\
        \\USAGE:
        \\    ghr validate <SUBCOMMAND> [OPTIONS]
        \\
        \\SUBCOMMANDS:
        \\    strip-authenticode <input.exe> <output.exe>
        \\        Strip the Authenticode signature from a signed PE/COFF
        \\        binary, writing a bit-identical-to-unsigned copy to
        \\        <output.exe>. Used by the reproducibility workflow to
        \\        compare a published signed .exe against a source rebuild.
        \\    help                 Show this help
        \\
    , .{});
}

fn printStripUsage(w: *Writer) !void {
    try w.print(
        \\ghr validate strip-authenticode - strip Authenticode signature from a PE
        \\
        \\USAGE:
        \\    ghr validate strip-authenticode <input.exe> <output.exe>
        \\
        \\Reads <input.exe>, removes the embedded WIN_CERTIFICATE table at
        \\end of file, zeroes the IMAGE_DIRECTORY_ENTRY_SECURITY entry, and
        \\zeroes OptionalHeader.CheckSum. Writes the result to <output.exe>.
        \\
        \\For a deterministic Zig-built unsigned PE, signing-then-stripping
        \\returns the exact bytes the compiler emitted — this is the
        \\foundation of issue #78 Option E (verify Windows reproducibility
        \\without publishing a separate pre-sign artifact).
        \\
        \\ERRORS (non-zero exit, diagnostic on stderr):
        \\    not Authenticode-signed
        \\    certificate table not at end of file (refuses to guess)
        \\    not a valid PE/COFF binary
        \\
    , .{});
}

test {
    _ = @import("authenticode.zig");
}
