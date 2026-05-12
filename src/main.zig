const std = @import("std");
const build_options = @import("build_options");
const Dirs = @import("dirs.zig").Dirs;
const install = @import("install.zig");
const download = @import("download.zig");
const ensurepath = @import("ensurepath.zig");

pub const version = build_options.version;

const Io = std.Io;
const Writer = Io.Writer;

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const environ = init.environ_map;

    var args = try init.minimal.args.iterateAllocator(allocator);
    defer args.deinit();
    _ = args.skip();

    var stdout_buf: [4096]u8 = undefined;
    var stdout = Io.File.stdout().writer(io, &stdout_buf);
    defer stdout.interface.flush() catch {};

    var stderr_buf: [4096]u8 = undefined;
    var stderr = Io.File.stderr().writer(io, &stderr_buf);
    defer stderr.interface.flush() catch {};

    const cmd_str = args.next() orelse {
        try printUsage(&stdout.interface);
        return;
    };

    if (eql(cmd_str, "version")) {
        try stdout.interface.print("{s}\n", .{version});
        return;
    }
    if (eql(cmd_str, "help")) {
        try printUsage(&stdout.interface);
        return;
    }

    if (eql(cmd_str, "path")) {
        try cmdPath(allocator, io, environ, &args, &stdout.interface, &stderr.interface);
    } else if (eql(cmd_str, "list")) {
        try cmdList(allocator, environ, io, &stdout.interface);
    } else if (eql(cmd_str, "install")) {
        var debug = false;
        var no_auth = false;
        var skip_verify = false;
        var minisign_pubkey: ?[]const u8 = null;
        var spec: ?[]const u8 = null;
        while (args.next()) |arg| {
            if (eql(arg, "--debug")) {
                debug = true;
            } else if (eql(arg, "--no-auth")) {
                no_auth = true;
            } else if (eql(arg, "--skip-verify")) {
                skip_verify = true;
            } else if (eql(arg, "--minisign")) {
                const v = args.next() orelse {
                    try stderr.interface.print("error: '--minisign' requires a base64 minisign public key value\n", .{});
                    try stderr.interface.flush();
                    std.process.exit(1);
                };
                minisign_pubkey = v;
            } else if (spec == null) {
                spec = arg;
            }
        }
        const spec_val = spec orelse {
            try stderr.interface.print("error: 'ghr install' requires <owner/repo[@tag]> or <owner/repo/file[@tag]>\n", .{});
            try stderr.interface.flush();
            std.process.exit(1);
        };
        try install.cmdInstall(allocator, io, environ, spec_val, &stdout.interface, &stderr.interface, debug, no_auth, skip_verify, minisign_pubkey);
    } else if (eql(cmd_str, "uninstall")) {
        const spec = args.next() orelse {
            try stderr.interface.print("error: 'ghr uninstall' requires <owner/repo>\n", .{});
            try stderr.interface.flush();
            std.process.exit(1);
        };
        try install.cmdUninstall(allocator, io, environ, spec, &stdout.interface, &stderr.interface);
    } else if (eql(cmd_str, "download")) {
        try download.cmdDownload(allocator, io, environ, &args, &stdout.interface, &stderr.interface);
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

fn cmdPath(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const std.process.Environ.Map,
    args: *std.process.Args.Iterator,
    w: *Writer,
    err_w: *Writer,
) !void {
    const sub = args.next() orelse {
        try printPathUsage(err_w);
        try err_w.flush();
        std.process.exit(1);
    };

    if (eql(sub, "ensure")) {
        var dry_run = false;
        while (args.next()) |arg| {
            if (eql(arg, "--dry-run")) {
                dry_run = true;
            } else {
                try err_w.print("error: unknown flag '{s}' for 'ghr path ensure'\n", .{arg});
                try err_w.flush();
                std.process.exit(1);
            }
        }
        try ensurepath.cmdEnsurePath(allocator, io, environ, dry_run, w, err_w);
        return;
    }

    if (eql(sub, "bin") or eql(sub, "tools") or eql(sub, "cache")) {
        if (args.next()) |arg| {
            try err_w.print("error: unexpected argument '{s}' for 'ghr path {s}'\n", .{ arg, sub });
            try err_w.flush();
            std.process.exit(1);
        }
        const d = try Dirs.detect(allocator, environ);
        defer d.deinit();
        if (eql(sub, "bin")) {
            try w.print("{s}\n", .{d.bin});
        } else if (eql(sub, "tools")) {
            try w.print("{s}\n", .{d.tools});
        } else {
            try w.print("{s}\n", .{d.cache});
        }
        return;
    }

    if (eql(sub, "-h") or eql(sub, "--help") or eql(sub, "help")) {
        try printPathUsage(w);
        return;
    }

    try err_w.print("error: unknown subcommand '{s}' for 'ghr path'\n\n", .{sub});
    try printPathUsage(err_w);
    try err_w.flush();
    std.process.exit(1);
}

fn printPathUsage(w: *Writer) !void {
    try w.print(
        \\ghr path - Show ghr directories and manage PATH
        \\
        \\USAGE:
        \\    ghr path <SUBCOMMAND> [OPTIONS]
        \\
        \\SUBCOMMANDS:
        \\    ensure [--dry-run]   Add ghr's bin dir to your user PATH
        \\    bin                  Print the bin directory
        \\    tools                Print the tool storage directory
        \\    cache                Print the cache directory
        \\
    , .{});
}

fn cmdList(allocator: std.mem.Allocator, environ: *const std.process.Environ.Map, io: Io, w: *Writer) !void {
    const d = try Dirs.detect(allocator, environ);
    defer d.deinit();

    var dir = Io.Dir.openDirAbsolute(io, d.tools, .{ .iterate = true }) catch {
        try w.print("No tools installed.\n", .{});
        return;
    };
    defer dir.close(io);

    var lines: std.ArrayListUnmanaged([]u8) = .empty;
    defer {
        for (lines.items) |line| allocator.free(line);
        lines.deinit(allocator);
    }

    var iter = dir.iterate();
    while (try iter.next(io)) |entry| {
        if (entry.kind != .directory) continue;
        if (std.mem.endsWith(u8, entry.name, ".old")) continue; // skip tombstones
        var owner_dir = dir.openDir(io, entry.name, .{ .iterate = true }) catch continue;
        defer owner_dir.close(io);
        var repo_iter = owner_dir.iterate();
        while (try repo_iter.next(io)) |repo_entry| {
            if (repo_entry.kind != .directory) continue;
            if (std.mem.endsWith(u8, repo_entry.name, ".old")) continue; // skip tombstones
            const tag = readToolTag(allocator, io, owner_dir, repo_entry.name);
            defer if (tag) |t| allocator.free(t);
            const line = if (tag) |t|
                try std.fmt.allocPrint(allocator, "{s}/{s}@{s}", .{ entry.name, repo_entry.name, t })
            else
                try std.fmt.allocPrint(allocator, "{s}/{s}", .{ entry.name, repo_entry.name });
            errdefer allocator.free(line);
            try lines.append(allocator, line);
        }
    }

    if (lines.items.len == 0) {
        try w.print("No tools installed.\n", .{});
        return;
    }

    std.mem.sort([]u8, lines.items, {}, struct {
        fn lt(_: void, a: []u8, b: []u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lt);

    for (lines.items) |line| {
        try w.print("{s}\n", .{line});
    }
}

fn readToolTag(allocator: std.mem.Allocator, io: Io, owner_dir: Io.Dir, repo_name: []const u8) ?[]const u8 {
    var repo_dir = owner_dir.openDir(io, repo_name, .{}) catch return null;
    defer repo_dir.close(io);

    const json_bytes = repo_dir.readFileAlloc(io, "ghr.json", allocator, Io.Limit.limited(8192)) catch return null;
    defer allocator.free(json_bytes);

    const parsed = std.json.parseFromSlice(
        struct { tag: []const u8 },
        allocator,
        json_bytes,
        .{ .ignore_unknown_fields = true },
    ) catch return null;
    defer parsed.deinit();

    return allocator.dupe(u8, parsed.value.tag) catch return null;
}

fn printUsage(w: *Writer) !void {
    try w.print(
        \\ghr - A toolkit for GitHub releases
        \\
        \\USAGE:
        \\    ghr <COMMAND> [OPTIONS]
        \\
        \\COMMANDS:
        \\    list                                 List installed tools
        \\    install <owner/repo[@tag]>           Install a tool from a GitHub release
        \\    install <owner/repo/file[@tag]>      Install a specific asset by name
        \\    uninstall <owner/repo>               Remove an installed tool
        \\    download <owner/repo[@tag]>          Download the asset 'install' would pick
        \\    download <owner/repo/file[@tag]>     Download a specific asset by name
        \\    path ensure [--dry-run]              Add ghr's bin dir to your user PATH
        \\    path [bin|tools|cache]               Show ghr directories
        \\    version                              Print version and exit
        \\    help                                 Print this help and exit
        \\
        \\OPTIONS:
        \\    --debug                 Show diagnostic output for debugging
        \\    --no-auth               Skip GitHub authentication
        \\    --skip-verify           Skip sigstore + SHA256 + minisign verification
        \\    --minisign <pubkey>     Require minisign signature (install/download only);
        \\                            <pubkey> is a base64 minisign public key string
        \\
    , .{});
}

test {
    // Ensure tests in imported modules are discovered by `zig build test`.
    // Zig 0.16 does not auto-include tests from indirectly referenced files.
    _ = @import("install.zig");
    _ = @import("release.zig");
    _ = @import("ensurepath.zig");
    _ = @import("dirs.zig");
    _ = @import("http.zig");
    _ = @import("archive.zig");
    _ = @import("auth.zig");
    _ = @import("download.zig");
}
