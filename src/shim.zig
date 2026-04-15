/// Windows shim executable for ghr.
///
/// Each installed tool gets a copy of this exe (e.g. zig.exe) plus a companion
/// .shim text file (e.g. zig.shim) containing the absolute path to the real
/// executable. This approach works in cmd, PowerShell, Nushell, and any other
/// shell — unlike .cmd wrappers which only work in cmd.exe.
///
/// This is the same technique used by npm and Scoop on Windows.
const std = @import("std");
const windows = std.os.windows;

const Io = std.Io;

extern "kernel32" fn GetModuleFileNameW(
    hModule: ?windows.HANDLE,
    lpFilename: [*]u16,
    nSize: windows.DWORD,
) callconv(.winapi) windows.DWORD;

fn exitWithError(stderr: *Io.Writer, comptime fmt: []const u8, args: anytype) noreturn {
    stderr.print(fmt, args) catch {};
    stderr.flush() catch {};
    std.process.exit(1);
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var stderr_buf: [4096]u8 = undefined;
    var stderr = Io.File.stderr().writer(io, &stderr_buf);

    // Get own exe path via Win32 API
    var path_buf_w: [std.Io.Dir.max_path_bytes / 2]u16 = undefined;
    const len = GetModuleFileNameW(null, &path_buf_w, path_buf_w.len);
    if (len == 0) {
        exitWithError(&stderr.interface, "shim: cannot determine own path\n", .{});
    }
    const self_path_w = path_buf_w[0..len];

    // Convert to UTF-8
    var self_path_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const self_path_len = std.unicode.wtf16LeToWtf8(&self_path_buf, self_path_w);
    const self_path = self_path_buf[0..self_path_len];

    // Replace .exe with .shim
    const stem = if (std.mem.endsWith(u8, self_path, ".exe") or std.mem.endsWith(u8, self_path, ".EXE"))
        self_path[0 .. self_path.len - 4]
    else
        self_path;

    var shim_path_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const shim_path = std.fmt.bufPrint(&shim_path_buf, "{s}.shim", .{stem}) catch {
        exitWithError(&stderr.interface, "shim: path too long\n", .{});
    };

    // Read target path from .shim file
    const shim_contents = Io.Dir.cwd().readFileAlloc(io, shim_path, allocator, Io.Limit.limited(Io.Dir.max_path_bytes)) catch {
        exitWithError(&stderr.interface, "shim: cannot read {s}\n", .{shim_path});
    };
    defer allocator.free(shim_contents);

    // Trim whitespace/CRLF
    const target_path = std.mem.trim(u8, shim_contents, &[_]u8{ ' ', '\t', '\r', '\n' });
    if (target_path.len == 0) {
        exitWithError(&stderr.interface, "shim: empty target in {s}\n", .{shim_path});
    }

    // Build argv: target_path + original args (skip argv[0])
    var argv = std.ArrayListUnmanaged([]const u8).empty;
    defer argv.deinit(allocator);

    try argv.append(allocator, target_path);

    var args = try init.minimal.args.iterateAllocator(allocator);
    defer args.deinit();
    _ = args.skip(); // skip shim's own name
    while (args.next()) |arg| {
        try argv.append(allocator, arg);
    }

    // Spawn the target process (inherits stdin/stdout/stderr)
    var child = std.process.spawn(io, .{
        .argv = argv.items,
    }) catch {
        exitWithError(&stderr.interface, "shim: cannot start {s}\n", .{target_path});
    };

    const term = child.wait(io) catch {
        exitWithError(&stderr.interface, "shim: wait failed\n", .{});
    };

    switch (term) {
        .exited => |code| std.process.exit(code),
        else => std.process.exit(1),
    }
}
