const std = @import("std");
const build_options = @import("build_options");
const Dirs = @import("dirs.zig").Dirs;
const install = @import("install.zig");

pub const version = build_options.version;

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args = std.process.argsWithAllocator(allocator) catch @panic("failed to read args");
    defer args.deinit();
    _ = args.skip();

    var stdout_buf: [4096]u8 = undefined;
    var stdout = std.fs.File.stdout().writer(&stdout_buf);
    defer stdout.interface.flush() catch {};

    var stderr_buf: [4096]u8 = undefined;
    var stderr = std.fs.File.stderr().writer(&stderr_buf);
    defer stderr.interface.flush() catch {};

    const cmd_str = args.next() orelse {
        try printUsage(&stdout.interface);
        return;
    };

    if (eql(cmd_str, "--help") or eql(cmd_str, "-h")) {
        try printUsage(&stdout.interface);
        return;
    }
    if (eql(cmd_str, "--version") or eql(cmd_str, "-V")) {
        try stdout.interface.print("ghr {s}\n", .{version});
        return;
    }

    if (eql(cmd_str, "dir")) {
        try cmdDir(allocator, &args, &stdout.interface, &stderr.interface);
    } else if (eql(cmd_str, "list")) {
        try cmdList(allocator, &stdout.interface);
    } else if (eql(cmd_str, "install")) {
        const spec = args.next() orelse {
            try stderr.interface.print("error: 'ghr install' requires <owner/repo[@tag]>\n", .{});
            try stderr.interface.flush();
            std.process.exit(1);
        };
        try install.cmdInstall(allocator, spec, &stdout.interface, &stderr.interface);
    } else if (eql(cmd_str, "uninstall")) {
        const spec = args.next() orelse {
            try stderr.interface.print("error: 'ghr uninstall' requires <owner/repo>\n", .{});
            try stderr.interface.flush();
            std.process.exit(1);
        };
        try install.cmdUninstall(allocator, spec, &stdout.interface, &stderr.interface);
    } else if (eql(cmd_str, "upgrade")) {
        try stderr.interface.print("error: upgrade not yet implemented\n", .{});
        try stderr.interface.flush();
        std.process.exit(1);
    } else if (eql(cmd_str, "help")) {
        try printUsage(&stdout.interface);
    } else {
        try stderr.interface.print("error: unknown command '{s}'\n\n", .{cmd_str});
        try printUsage(&stderr.interface);
        try stderr.interface.flush();
        std.process.exit(1);
    }
}

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn cmdDir(
    allocator: std.mem.Allocator,
    args: *std.process.ArgIterator,
    w: *std.io.Writer,
    err_w: *std.io.Writer,
) !void {
    const d = try Dirs.detect(allocator);
    defer d.deinit();

    const flag = args.next();
    if (flag == null) {
        try w.print("{s}\n", .{d.tools});
        return;
    }
    if (eql(flag.?, "--bin")) {
        try w.print("{s}\n", .{d.bin});
    } else if (eql(flag.?, "--cache")) {
        try w.print("{s}\n", .{d.cache});
    } else {
        try err_w.print("error: unknown flag '{s}' for 'ghr dir'\n", .{flag.?});
        try err_w.flush();
        std.process.exit(1);
    }
}

fn cmdList(allocator: std.mem.Allocator, w: *std.io.Writer) !void {
    const d = try Dirs.detect(allocator);
    defer d.deinit();

    var dir = std.fs.openDirAbsolute(d.tools, .{ .iterate = true }) catch {
        try w.print("No tools installed.\n", .{});
        return;
    };
    defer dir.close();

    var found = false;
    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind != .directory) continue;
        var owner_dir = dir.openDir(entry.name, .{ .iterate = true }) catch continue;
        defer owner_dir.close();
        var repo_iter = owner_dir.iterate();
        while (try repo_iter.next()) |repo_entry| {
            if (repo_entry.kind != .directory) continue;
            const tag = readToolTag(allocator, owner_dir, repo_entry.name);
            defer if (tag) |t| allocator.free(t);
            if (tag) |t| {
                try w.print("{s}/{s} @ {s}\n", .{ entry.name, repo_entry.name, t });
            } else {
                try w.print("{s}/{s}\n", .{ entry.name, repo_entry.name });
            }
            found = true;
        }
    }

    if (!found) {
        try w.print("No tools installed.\n", .{});
    }
}

fn readToolTag(allocator: std.mem.Allocator, owner_dir: std.fs.Dir, repo_name: []const u8) ?[]const u8 {
    var repo_dir = owner_dir.openDir(repo_name, .{}) catch return null;
    defer repo_dir.close();

    const json_bytes = repo_dir.readFileAlloc(allocator, "ghr.json", 8192) catch return null;
    defer allocator.free(json_bytes);

    const parsed = std.json.parseFromSlice(
        struct { tag: []const u8 },
        allocator,
        json_bytes,
        .{},
    ) catch return null;
    defer parsed.deinit();

    return allocator.dupe(u8, parsed.value.tag) catch return null;
}

fn printUsage(w: *std.io.Writer) !void {
    try w.print(
        \\ghr - Install tools from GitHub releases
        \\
        \\USAGE:
        \\    ghr <COMMAND> [OPTIONS]
        \\
        \\COMMANDS:
        \\    install <owner/repo[@tag]>   Install a tool from a GitHub release
        \\    uninstall <owner/repo>       Remove an installed tool
        \\    list                         List installed tools
        \\    upgrade [name]               Upgrade installed tools
        \\    dir [--bin] [--cache]        Show ghr directories
        \\
        \\OPTIONS:
        \\    -h, --help      Print help
        \\    -V, --version   Print version
        \\
    , .{});
}
