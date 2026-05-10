const std = @import("std");
const builtin = @import("builtin");
const Dirs = @import("dirs.zig").Dirs;
const http = @import("http.zig");
const archive = @import("archive.zig");
const auth = @import("auth.zig");
const release_mod = @import("release.zig");
const version = @import("build_options").version;

const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;
const Writer = Io.Writer;
const Environ = std.process.Environ;
const EnvironMap = Environ.Map;

const http_write_buffer_size = http.http_write_buffer_size;
const debugLog = http.debugLog;
const isTransientStatus = http.isTransientStatus;

const Asset = release_mod.Asset;
const Spec = release_mod.RepoSpec;
const parseSpec = release_mod.parseRepoSpec;
const getRelease = release_mod.getRelease;
const findBestAsset = release_mod.findBestAsset;
const isInstallableAsset = release_mod.isInstallableAssetName;
const verifyDownloadedAssetSha256 = release_mod.verifyDownloadedAssetSha256;
const verifyDownloadedAssetSigstore = release_mod.verifyDownloadedAssetSigstore;

/// Delete an absolute path's directory tree. Zig 0.16 removed Dir.deleteTreeAbsolute,
/// so we open the parent dir and call deleteTree on the basename.
fn deleteTreeAbsolute(io: Io, abs_path: []const u8) !void {
    const parent = std.fs.path.dirname(abs_path) orelse return error.InvalidPath;
    const basename = std.fs.path.basename(abs_path);
    var dir = try Dir.openDirAbsolute(io, parent, .{});
    defer dir.close(io);
    try dir.deleteTree(io, basename);
}


/// Returns true if the file is a shared library (not a program executable).
fn isSharedLibrary(name: []const u8) bool {
    if (std.mem.endsWith(u8, name, ".dylib")) return true;
    if (std.mem.endsWith(u8, name, ".dll")) return true;
    // Check for .so or .so.N.N.N patterns
    if (std.mem.endsWith(u8, name, ".so")) return true;
    if (std.mem.indexOf(u8, name, ".so.") != null) return true;
    return false;
}

/// Returns true if the directory contains shared libraries rather than executables.
fn isLibraryDir(name: []const u8) bool {
    if (std.mem.endsWith(u8, name, ".framework")) return true;
    if (std.mem.eql(u8, name, "lib")) return true;
    if (std.mem.eql(u8, name, "Frameworks")) return true;
    if (std.mem.eql(u8, name, "PlugIns")) return true;
    return false;
}

/// For bare-binary assets whose name follows the `<name>-<arch>-<triple>...`
/// convention (e.g. `wash-aarch64-unknown-linux-musl`), extract `<name>` so
/// the resulting link in `~/.ghr/bin/` is the natural command the user
/// expects to run. Falls back to `repo` if the pattern doesn't match (e.g.
/// `cosign-linux-amd64`, where the arch is not directly after the stem).
fn deriveBareBinaryName(
    allocator: std.mem.Allocator,
    asset_name: []const u8,
    repo: []const u8,
    is_windows: bool,
) ![]u8 {
    var name = asset_name;
    if (std.mem.endsWith(u8, name, ".exe")) name = name[0 .. name.len - 4];

    // Find the first '-' or '_' separator.
    var sep_idx: ?usize = null;
    for (name, 0..) |c, i| {
        if (c == '-' or c == '_') { sep_idx = i; break; }
    }

    if (sep_idx) |si| {
        if (si > 0 and si + 1 < name.len) {
            const stem = name[0..si];
            const after = name[si + 1 ..];
            const archs = [_][]const u8{
                "x86_64", "x64",    "amd64",
                "aarch64", "arm64",
                "armv7l", "armv7",  "armv6",
                "x86",    "i686",   "i386",
                "ppc64le", "ppc64", "s390x", "riscv64",
            };
            for (archs) |a| {
                if (after.len < a.len) continue;
                if (!std.ascii.eqlIgnoreCase(after[0..a.len], a)) continue;
                if (after.len > a.len) {
                    const nc = after[a.len];
                    if (nc != '-' and nc != '_' and nc != '.') continue;
                }
                if (is_windows) {
                    return std.fmt.allocPrint(allocator, "{s}.exe", .{stem});
                }
                return allocator.dupe(u8, stem);
            }
        }
    }

    if (is_windows) return std.fmt.allocPrint(allocator, "{s}.exe", .{repo});
    return allocator.dupe(u8, repo);
}


/// Copy a bare executable from the cache into the staging directory,
/// renaming it to `dest_name` and setting executable permissions.
fn stageBareExecutable(
    allocator: std.mem.Allocator,
    io: Io,
    cache_path: []const u8,
    asset_name: []const u8,
    staging_dir: Dir,
    dest_name: []const u8,
) !void {
    var cache_dir = try Dir.openDirAbsolute(io, cache_path, .{});
    defer cache_dir.close(io);
    const content = try cache_dir.readFileAlloc(io, asset_name, allocator, Io.Limit.limited(256 * 1024 * 1024));
    defer allocator.free(content);

    var dest = try staging_dir.createFile(io, dest_name, .{ .permissions = .executable_file });
    defer dest.close(io);
    try dest.writeStreamingAll(io, content);
}

/// Scan directory recursively for executable files and return their relative paths.
fn findExecutables(allocator: std.mem.Allocator, io: Io, dir: Dir) !std.ArrayListUnmanaged([]const u8) {
    var result: std.ArrayListUnmanaged([]const u8) = .empty;
    try scanForExecutables(allocator, io, dir, &result, "");
    return result;
}

fn scanForExecutables(
    allocator: std.mem.Allocator,
    io: Io,
    dir: Dir,
    result: *std.ArrayListUnmanaged([]const u8),
    prefix: []const u8,
) !void {
    var iter = dir.iterate();
    while (try iter.next(io)) |entry| {
        const rel_name = if (prefix.len > 0)
            try std.fmt.allocPrint(allocator, "{s}{c}{s}", .{ prefix, std.fs.path.sep, entry.name })
        else
            try allocator.dupe(u8, entry.name);

        if (entry.kind == .directory) {
            if (isMacAppBundle(io, dir, entry.name)) {
                // Only scan Contents/MacOS/ inside .app bundles
                try scanAppBundle(allocator, io, dir, entry.name, result, rel_name);
                allocator.free(rel_name);
            } else if (isLibraryDir(entry.name)) {
                // Skip directories that contain shared libraries, not executables
                allocator.free(rel_name);
            } else {
                var sub = dir.openDir(io, entry.name, .{ .iterate = true }) catch {
                    allocator.free(rel_name);
                    continue;
                };
                defer sub.close(io);
                try scanForExecutables(allocator, io, sub, result, rel_name);
                allocator.free(rel_name);
            }
        } else if (entry.kind == .file) {
            if (isSharedLibrary(entry.name)) {
                allocator.free(rel_name);
                continue;
            }
            const is_exe = if (builtin.os.tag == .windows)
                std.mem.endsWith(u8, entry.name, ".exe")
            else blk: {
                const stat = dir.statFile(io, entry.name, .{}) catch {
                    allocator.free(rel_name);
                    continue;
                };
                break :blk (@as(u32, @intFromEnum(stat.permissions)) & 0o111) != 0;
            };
            if (is_exe) {
                try result.append(allocator, rel_name);
            } else {
                allocator.free(rel_name);
            }
        } else {
            allocator.free(rel_name);
        }
    }
}

/// Check if a directory is a macOS .app bundle (has Contents/MacOS/ inside).
fn isMacAppBundle(io: Io, parent: Dir, name: []const u8) bool {
    if (!std.mem.endsWith(u8, name, ".app")) return false;
    // Verify it has the expected bundle structure
    var app_dir = parent.openDir(io, name, .{}) catch return false;
    defer app_dir.close(io);
    app_dir.access(io, "Contents/MacOS", .{}) catch return false;
    return true;
}

/// Scan only the Contents/MacOS/ directory inside a .app bundle for executables.
fn scanAppBundle(
    allocator: std.mem.Allocator,
    io: Io,
    parent: Dir,
    app_name: []const u8,
    result: *std.ArrayListUnmanaged([]const u8),
    app_prefix: []const u8,
) !void {
    const macos_rel = try std.fmt.allocPrint(allocator, "{s}/Contents/MacOS", .{app_name});
    defer allocator.free(macos_rel);
    var macos_dir = parent.openDir(io, macos_rel, .{ .iterate = true }) catch return;
    defer macos_dir.close(io);

    const prefix = try std.fmt.allocPrint(allocator, "{s}/Contents/MacOS", .{app_prefix});
    defer allocator.free(prefix);

    var iter = macos_dir.iterate();
    while (try iter.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (isSharedLibrary(entry.name)) continue;
        const is_exe = if (builtin.os.tag == .windows)
            std.mem.endsWith(u8, entry.name, ".exe")
        else blk: {
            const stat = macos_dir.statFile(io, entry.name, .{}) catch continue;
            break :blk (@as(u32, @intFromEnum(stat.permissions)) & 0o111) != 0;
        };
        if (is_exe) {
            const rel_name = try std.fmt.allocPrint(allocator, "{s}{c}{s}", .{ prefix, std.fs.path.sep, entry.name });
            try result.append(allocator, rel_name);
        }
    }
}

/// Link or copy an executable to the bin directory.
fn linkToBin(
    allocator: std.mem.Allocator,
    io: Io,
    tool_dir_path: []const u8,
    bin_dir: Dir,
    exe_rel_path: []const u8,
    w: *Writer,
) !void {
    _ = allocator;
    const exe_name = std.fs.path.basename(exe_rel_path);
    var src_path_buf: [Dir.max_path_bytes]u8 = undefined;
    const src_path = std.fmt.bufPrint(&src_path_buf, "{s}{c}{s}", .{
        tool_dir_path,
        std.fs.path.sep,
        exe_rel_path,
    }) catch return error.PathTooLong;

    if (builtin.os.tag == .windows) {
        // Use a shim .exe + .shim file instead of a .cmd wrapper.
        // The shim is embedded in ghr at build time so it's always available,
        // regardless of how ghr is installed (PyPI, GitHub release, etc.).
        // This is the same technique used by npm and Scoop on Windows.
        const shim_exe_bytes = @import("shim_exe").bytes;

        const stem = if (std.mem.endsWith(u8, exe_name, ".exe"))
            exe_name[0 .. exe_name.len - 4]
        else
            exe_name;

        // Write the .shim file with the target path
        var shim_name_buf: [Dir.max_path_bytes]u8 = undefined;
        const shim_name = std.fmt.bufPrint(&shim_name_buf, "{s}.shim", .{stem}) catch return error.PathTooLong;
        bin_dir.deleteFile(io, shim_name) catch {};
        var shim_file = bin_dir.createFile(io, shim_name, .{}) catch return error.CreateFailed;
        defer shim_file.close(io);
        var shim_buf: [4096]u8 = undefined;
        var shim_w = shim_file.writer(io, &shim_buf);
        shim_w.interface.print("{s}", .{src_path}) catch return error.WriteFailed;
        shim_w.end() catch return error.WriteFailed;

        // Write the embedded shim exe as <name>.exe
        const shim_exe_name = if (std.mem.endsWith(u8, exe_name, ".exe"))
            exe_name
        else blk: {
            var name_buf: [Dir.max_path_bytes]u8 = undefined;
            break :blk std.fmt.bufPrint(&name_buf, "{s}.exe", .{stem}) catch return error.PathTooLong;
        };
        bin_dir.deleteFile(io, shim_exe_name) catch {
            // On Windows a running shim exe cannot be deleted; rename it out of the way.
            var old_name_buf: [Dir.max_path_bytes]u8 = undefined;
            const old_name = std.fmt.bufPrint(&old_name_buf, "{s}.old", .{shim_exe_name}) catch return error.PathTooLong;
            bin_dir.deleteFile(io, old_name) catch {};
            bin_dir.rename(shim_exe_name, bin_dir, old_name, io) catch {};
        };
        if (bin_dir.createFile(io, shim_exe_name, .{})) |*exe_file| {
            defer exe_file.close(io);
            exe_file.writeStreamingAll(io, shim_exe_bytes) catch return error.WriteFailed;
        } else |_| {
            // The shim exe is locked (self-update). The .shim file has already
            // been updated with the new target path, so the existing shim exe
            // will work correctly on the next invocation. Skip replacing it.
        }

        // Clean up any legacy .cmd wrapper from previous installs
        var cmd_name_buf: [Dir.max_path_bytes]u8 = undefined;
        const cmd_name = std.fmt.bufPrint(&cmd_name_buf, "{s}.cmd", .{stem}) catch return error.PathTooLong;
        bin_dir.deleteFile(io, cmd_name) catch {};
    } else {
        // Unix: symlink
        bin_dir.deleteFile(io, exe_name) catch {};
        try bin_dir.symLink(io, src_path, exe_name, .{});
    }
    try w.print("  linked {s}\n", .{exe_name});
}

/// Find .app bundles recursively in a directory. Returns relative paths from the root.
fn findAppBundles(allocator: std.mem.Allocator, io: Io, dir: Dir) !std.ArrayListUnmanaged([]const u8) {
    var result: std.ArrayListUnmanaged([]const u8) = .empty;
    try scanForAppBundles(allocator, io, dir, &result, "");
    return result;
}

fn scanForAppBundles(
    allocator: std.mem.Allocator,
    io: Io,
    dir: Dir,
    result: *std.ArrayListUnmanaged([]const u8),
    prefix: []const u8,
) !void {
    var iter = dir.iterate();
    while (try iter.next(io)) |entry| {
        if (entry.kind != .directory) continue;
        const rel_name = if (prefix.len > 0)
            try std.fmt.allocPrint(allocator, "{s}/{s}", .{ prefix, entry.name })
        else
            try allocator.dupe(u8, entry.name);

        if (isMacAppBundle(io, dir, entry.name)) {
            try result.append(allocator, rel_name);
            // Don't recurse into .app bundles
        } else {
            var sub = dir.openDir(io, entry.name, .{ .iterate = true }) catch {
                allocator.free(rel_name);
                continue;
            };
            defer sub.close(io);
            try scanForAppBundles(allocator, io, sub, result, rel_name);
            allocator.free(rel_name);
        }
    }
}

/// Marker file placed inside copied .app bundles to track ghr ownership.
const ghr_marker = "Contents/.ghr-source";

/// On macOS, copy .app bundles into ~/Applications for Spotlight and Launchpad discovery.
/// Symlinks are not indexed by Spotlight, so a real copy is required.
fn installAppBundles(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    app_paths: []const []const u8,
    tool_dir_path: []const u8,
    w: *Writer,
) !void {
    if (app_paths.len == 0) return;

    const home = environ.get("HOME") orelse return;
    const apps_dir_path = try std.fmt.allocPrint(allocator, "{s}/Applications", .{home});
    defer allocator.free(apps_dir_path);
    Dir.createDirAbsolute(io, apps_dir_path, .default_dir) catch {};

    var apps_dir = Dir.openDirAbsolute(io, apps_dir_path, .{}) catch return;
    defer apps_dir.close(io);

    for (app_paths) |rel_path| {
        const app_name = std.fs.path.basename(rel_path);
        const app_src = std.fmt.allocPrint(allocator, "{s}/{s}", .{ tool_dir_path, rel_path }) catch continue;
        defer allocator.free(app_src);

        // If an existing app is present, only replace it if we own it (has our marker or is a legacy symlink)
        const existing = apps_dir.statFile(io, app_name, .{}) catch null;
        if (existing) |_| {
            if (isLegacyAppSymlink(allocator, io, apps_dir, app_name, tool_dir_path, rel_path)) {
                apps_dir.deleteFile(io, app_name) catch continue;
            } else if (isOwnedAppBundle(io, apps_dir, app_name, tool_dir_path)) {
                apps_dir.deleteTree(io, app_name) catch continue;
            } else {
                w.print("  skipped ~/Applications/{s} (not owned by ghr)\n", .{app_name}) catch {};
                continue;
            }
        }

        // Copy to a staging name, then rename for atomicity
        const staging_name = std.fmt.allocPrint(allocator, ".ghr-staging-{s}", .{app_name}) catch continue;
        defer allocator.free(staging_name);
        apps_dir.deleteTree(io, staging_name) catch {};

        // Open source .app directory
        var src_dir = Dir.openDirAbsolute(io, app_src, .{ .iterate = true }) catch continue;
        defer src_dir.close(io);

        // Create staging directory and copy
        apps_dir.createDir(io, staging_name, .default_dir) catch continue;
        var staging_dir = apps_dir.openDir(io, staging_name, .{}) catch continue;
        defer staging_dir.close(io);

        copyDirRecursive(io, src_dir, staging_dir) catch {
            apps_dir.deleteTree(io, staging_name) catch {};
            continue;
        };

        // Write ownership marker (remove first in case archive contained one as a symlink)
        staging_dir.deleteFile(io, ghr_marker) catch {};
        writeMarkerFile(io, staging_dir, tool_dir_path) catch {
            apps_dir.deleteTree(io, staging_name) catch {};
            continue;
        };

        // Atomic rename into place
        apps_dir.rename(staging_name, apps_dir, app_name, io) catch {
            apps_dir.deleteTree(io, staging_name) catch {};
            continue;
        };

        try w.print("  installed ~/Applications/{s}\n", .{app_name});
    }
}

/// Remove ~/Applications .app bundles owned by this tool.
fn uninstallAppBundles(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    app_paths: []const []const u8,
    tool_dir_path: []const u8,
    w: *Writer,
) void {
    if (app_paths.len == 0) return;

    const home = environ.get("HOME") orelse return;
    const apps_dir_path = std.fmt.allocPrint(allocator, "{s}/Applications", .{home}) catch return;
    defer allocator.free(apps_dir_path);

    var apps_dir = Dir.openDirAbsolute(io, apps_dir_path, .{}) catch return;
    defer apps_dir.close(io);

    for (app_paths) |rel_path| {
        const app_name = std.fs.path.basename(rel_path);

        // Handle legacy symlinks from older ghr versions
        if (isLegacyAppSymlink(allocator, io, apps_dir, app_name, tool_dir_path, rel_path)) {
            apps_dir.deleteFile(io, app_name) catch continue;
            w.print("  uninstalled ~/Applications/{s}\n", .{app_name}) catch {};
            continue;
        }

        if (!isOwnedAppBundle(io, apps_dir, app_name, tool_dir_path)) continue;

        apps_dir.deleteTree(io, app_name) catch continue;
        w.print("  uninstalled ~/Applications/{s}\n", .{app_name}) catch {};
    }
}

/// Check if an .app bundle in ~/Applications is owned by ghr for the given tool path.
fn isOwnedAppBundle(io: Io, apps_dir: Dir, app_name: []const u8, tool_dir_path: []const u8) bool {
    // Build path to marker: <app_name>/Contents/.ghr-source
    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const marker_path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ app_name, ghr_marker }) catch return false;

    // Verify marker is a regular file, not a symlink
    const stat = apps_dir.statFile(io, marker_path, .{}) catch return false;
    if (stat.kind == .sym_link) return false;

    // Read and compare source path
    var content_buf: [Dir.max_path_bytes]u8 = undefined;
    const file = apps_dir.openFile(io, marker_path, .{}) catch return false;
    defer file.close(io);
    const len = file.readPositionalAll(io, &content_buf, 0) catch return false;
    return std.mem.eql(u8, content_buf[0..len], tool_dir_path);
}

/// Check if an entry is a legacy symlink (from older ghr versions) pointing to our tool.
fn isLegacyAppSymlink(
    allocator: std.mem.Allocator,
    io: Io,
    apps_dir: Dir,
    app_name: []const u8,
    tool_dir_path: []const u8,
    rel_path: []const u8,
) bool {
    var link_buf: [Dir.max_path_bytes]u8 = undefined;
    const len = apps_dir.readLink(io, app_name, &link_buf) catch return false;
    const link_target = link_buf[0..len];
    const expected = std.fmt.allocPrint(allocator, "{s}/{s}", .{ tool_dir_path, rel_path }) catch return false;
    defer allocator.free(expected);
    return std.mem.eql(u8, link_target, expected);
}

/// Write the ghr ownership marker file.
fn writeMarkerFile(io: Io, dir: Dir, tool_dir_path: []const u8) !void {
    var file = try dir.createFile(io, ghr_marker, .{});
    defer file.close(io);
    try file.writeStreamingAll(io, tool_dir_path);
}

/// Recursively copy a directory tree, preserving symlinks without following them.
fn copyDirRecursive(io: Io, src_dir: Dir, dest_dir: Dir) !void {
    var iter = src_dir.iterate();
    while (try iter.next(io)) |entry| {
        switch (entry.kind) {
            .file => {
                try src_dir.copyFile(entry.name, dest_dir, entry.name, io, .{});
            },
            .directory => {
                dest_dir.createDir(io, entry.name, .default_dir) catch |err| switch (err) {
                    error.PathAlreadyExists => {},
                    else => return err,
                };
                var child_src = try src_dir.openDir(io, entry.name, .{ .iterate = true });
                defer child_src.close(io);
                var child_dest = try dest_dir.openDir(io, entry.name, .{});
                defer child_dest.close(io);
                try copyDirRecursive(io, child_src, child_dest);
            },
            .sym_link => {
                var buf: [Dir.max_path_bytes]u8 = undefined;
                const len = try src_dir.readLink(io, entry.name, &buf);
                dest_dir.symLink(io, buf[0..len], entry.name, .{}) catch {};
            },
            else => {},
        }
    }
}

/// Write ghr.json metadata.
fn writeMetadata(
    allocator: std.mem.Allocator,
    io: Io,
    tool_dir: Dir,
    tag: []const u8,
    asset_name: []const u8,
    bins: []const []const u8,
    apps: []const []const u8,
    verified: []const u8,
) !void {
    _ = allocator;
    var file = try tool_dir.createFile(io, "ghr.json", .{});
    defer file.close(io);
    var buf: [4096]u8 = undefined;
    var fw = file.writer(io, &buf);
    const w = &fw.interface;
    try w.print("{{\"tag\":\"{s}\",\"asset\":\"{s}\",\"verified\":\"{s}\",\"bins\":[", .{ tag, asset_name, verified });
    for (bins, 0..) |bin, i| {
        if (i > 0) try w.print(",", .{});
        try w.print("\"", .{});
        try writeJsonEscaped(w, bin);
        try w.print("\"", .{});
    }
    try w.print("],\"apps\":[", .{});
    for (apps, 0..) |app, i| {
        if (i > 0) try w.print(",", .{});
        try w.print("\"", .{});
        try writeJsonEscaped(w, app);
        try w.print("\"", .{});
    }
    try w.print("]}}\n", .{});
    try fw.end();
}

/// Write a string with JSON escaping (backslashes and quotes).
fn writeJsonEscaped(w: *Writer, s: []const u8) !void {
    for (s) |c| {
        switch (c) {
            '\\' => try w.print("\\\\", .{}),
            '"' => try w.print("\\\"", .{}),
            else => try w.print("{c}", .{c}),
        }
    }
}

/// Metadata stored in ghr.json.
const Metadata = struct {
    tag: []const u8,
    asset: []const u8,
    verified: []const u8 = "none",
    bins: []const []const u8 = &.{},
    apps: []const []const u8 = &.{},
};

/// Read ghr.json metadata from a tool directory.
fn readMetadata(allocator: std.mem.Allocator, io: Io, tool_dir_path: []const u8) ?struct {
    parsed: std.json.Parsed(Metadata),
    body: []const u8,
} {
    var dir = Dir.openDirAbsolute(io, tool_dir_path, .{}) catch return null;
    defer dir.close(io);
    const body = dir.readFileAlloc(io, "ghr.json", allocator, Io.Limit.limited(65536)) catch return null;
    const parsed = std.json.parseFromSlice(Metadata, allocator, body, .{ .ignore_unknown_fields = true }) catch {
        allocator.free(body);
        return null;
    };
    return .{ .parsed = parsed, .body = body };
}

/// Clean up old install's bin symlinks and app bundles before replacing.
fn cleanupOldInstall(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    tool_path: []const u8,
    bin_path: []const u8,
    w: *Writer,
) void {
    const meta = readMetadata(allocator, io, tool_path) orelse return;
    defer meta.parsed.deinit();
    defer allocator.free(meta.body);

    var bin_dir = Dir.openDirAbsolute(io, bin_path, .{}) catch return;
    defer bin_dir.close(io);
    for (meta.parsed.value.bins) |exe_rel| {
        const exe_name = std.fs.path.basename(exe_rel);
        if (builtin.os.tag == .windows) {
            cleanupWindowsBinEntry(io, bin_dir, exe_name, tool_path);
        } else {
            // Verify the symlink points to our tool dir before removing
            var link_buf: [Dir.max_path_bytes]u8 = undefined;
            const len = bin_dir.readLink(io, exe_name, &link_buf) catch continue;
            const link_target = link_buf[0..len];
            if (std.mem.startsWith(u8, link_target, tool_path) and
                (link_target.len == tool_path.len or link_target[tool_path.len] == '/'))
            {
                bin_dir.deleteFile(io, exe_name) catch {};
            }
        }
    }

    // Remove old app bundle copies (macOS)
    if (comptime builtin.os.tag.isDarwin()) {
        uninstallAppBundles(allocator, io, environ, meta.parsed.value.apps, tool_path, w);
    }
}

/// Remove shim .exe + .shim files or legacy .cmd for a single bin entry on Windows.
fn cleanupWindowsBinEntry(io: Io, bin_dir: Dir, exe_name: []const u8, tool_path: []const u8) void {
    const stem = if (std.mem.endsWith(u8, exe_name, ".exe"))
        exe_name[0 .. exe_name.len - 4]
    else
        exe_name;

    // Remove .shim file if it points to our tool dir
    var shim_name_buf: [Dir.max_path_bytes]u8 = undefined;
    const shim_name = std.fmt.bufPrint(&shim_name_buf, "{s}.shim", .{stem}) catch return;
    if (shimPointsToToolDir(io, bin_dir, shim_name, tool_path)) {
        bin_dir.deleteFile(io, shim_name) catch {};
        // Remove the companion shim .exe
        const shim_exe_name = if (std.mem.endsWith(u8, exe_name, ".exe")) exe_name else blk: {
            var name_buf: [Dir.max_path_bytes]u8 = undefined;
            break :blk std.fmt.bufPrint(&name_buf, "{s}.exe", .{stem}) catch return;
        };
        bin_dir.deleteFile(io, shim_exe_name) catch {};
    }

    // Also remove legacy .cmd wrapper if present
    var cmd_name_buf: [Dir.max_path_bytes]u8 = undefined;
    const cmd_name = std.fmt.bufPrint(&cmd_name_buf, "{s}.cmd", .{stem}) catch return;
    bin_dir.deleteFile(io, cmd_name) catch {};
}

/// Check if a .shim file's target path starts with tool_path.
fn shimPointsToToolDir(io: Io, bin_dir: Dir, shim_name: []const u8, tool_path: []const u8) bool {
    var content_buf: [Dir.max_path_bytes]u8 = undefined;
    const file = bin_dir.openFile(io, shim_name, .{}) catch return false;
    defer file.close(io);
    const len = file.readPositionalAll(io, &content_buf, 0) catch return false;
    const content = std.mem.trim(u8, content_buf[0..len], &[_]u8{ ' ', '\t', '\r', '\n' });
    return std.mem.startsWith(u8, content, tool_path) and
        (content.len == tool_path.len or content[tool_path.len] == '\\' or content[tool_path.len] == '/');
}

/// Remove bin entries from a previous install that are NOT present in the new install.
/// Called after new bins are already linked so the active install is never broken.
fn cleanupStaleBinEntries(
    io: Io,
    bin_dir: Dir,
    old_bins: []const []const u8,
    new_bins: []const []const u8,
    old_tool_path: []const u8,
) void {
    for (old_bins) |old_exe_rel| {
        const old_name = std.fs.path.basename(old_exe_rel);
        // Skip if this bin is also in the new install (already overwritten by linkToBin)
        var dominated = false;
        for (new_bins) |new_exe_rel| {
            if (std.mem.eql(u8, std.fs.path.basename(new_exe_rel), old_name)) {
                dominated = true;
                break;
            }
        }
        if (dominated) continue;
        if (builtin.os.tag == .windows) {
            cleanupWindowsBinEntry(io, bin_dir, old_name, old_tool_path);
        } else {
            var link_buf: [Dir.max_path_bytes]u8 = undefined;
            const len = bin_dir.readLink(io, old_name, &link_buf) catch continue;
            const link_target = link_buf[0..len];
            if (std.mem.startsWith(u8, link_target, old_tool_path) and
                (link_target.len == old_tool_path.len or link_target[old_tool_path.len] == '/'))
            {
                bin_dir.deleteFile(io, old_name) catch {};
            }
        }
    }
}

pub fn cmdUninstall(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    spec_str: []const u8,
    w: *Writer,
    err_w: *Writer,
) !void {
    const spec = parseSpec(spec_str) catch {
        try err_w.print("error: invalid spec '{s}', expected owner/repo\n", .{spec_str});
        try err_w.flush();
        std.process.exit(1);
    };

    const d = try Dirs.detect(allocator, environ);
    defer d.deinit();

    const tool_path = try std.fmt.allocPrint(allocator, "{s}{c}{s}{c}{s}", .{
        d.tools, std.fs.path.sep, spec.owner, std.fs.path.sep, spec.repo,
    });
    defer allocator.free(tool_path);

    // Check the tool exists
    Dir.accessAbsolute(io, tool_path, .{}) catch {
        try err_w.print("error: {s}/{s} is not installed\n", .{ spec.owner, spec.repo });
        try err_w.flush();
        std.process.exit(1);
    };

    // Read metadata to know what to clean up
    const meta = readMetadata(allocator, io, tool_path);
    defer if (meta) |m| {
        m.parsed.deinit();
        allocator.free(m.body);
    };

    // Remove bin symlinks
    var bin_dir = Dir.openDirAbsolute(io, d.bin, .{}) catch null;
    defer if (bin_dir) |*bd| bd.close(io);

    if (meta) |m| {
        for (m.parsed.value.bins) |exe_rel| {
            const exe_name = std.fs.path.basename(exe_rel);
            if (bin_dir) |bd| {
                if (builtin.os.tag == .windows) {
                    cleanupWindowsBinEntry(io, bd, exe_name, tool_path);
                    try w.print("  unlinked {s}\n", .{exe_name});
                } else {
                    var link_buf: [Dir.max_path_bytes]u8 = undefined;
                    const len = bd.readLink(io, exe_name, &link_buf) catch continue;
                    const link_target = link_buf[0..len];
                    if (std.mem.startsWith(u8, link_target, tool_path) and
                        (link_target.len == tool_path.len or link_target[tool_path.len] == '/'))
                    {
                        bd.deleteFile(io, exe_name) catch continue;
                        try w.print("  unlinked {s}\n", .{exe_name});
                    }
                }
            }
        }

        // Remove app bundle copies (macOS)
        if (comptime builtin.os.tag.isDarwin()) {
            uninstallAppBundles(allocator, io, environ, m.parsed.value.apps, tool_path, w);
        }
    }

    // Delete the tool directory
    deleteTreeAbsolute(io, tool_path) catch {
        try err_w.print("error: failed to remove {s}\n", .{tool_path});
        try err_w.flush();
        std.process.exit(1);
    };

    try w.print("uninstalled {s}/{s}\n", .{ spec.owner, spec.repo });
}

pub fn cmdInstall(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    spec_str: []const u8,
    w: *Writer,
    err_w: *Writer,
    debug: bool,
    no_auth: bool,
    skip_verify: bool,
    minisign_pubkey_b64: ?[]const u8,
) !void {
    const classified = release_mod.classifyArg(spec_str) catch {
        try err_w.print("error: invalid argument '{s}'\n", .{spec_str});
        try err_w.print("  expected: owner/repo[@tag] or owner/repo/file[@tag]\n", .{});
        try err_w.flush();
        std.process.exit(1);
    };

    var url_buf: ?release_mod.ParsedReleaseUrl = null;
    defer if (url_buf) |*u| u.deinit(allocator);

    var spec: Spec = undefined;
    var requested_file: ?[]const u8 = null;

    switch (classified) {
        .repo_spec => |rs| spec = rs,
        .file_spec => |fs| {
            spec = .{ .owner = fs.owner, .repo = fs.repo, .tag = fs.tag };
            requested_file = fs.file;
        },
        .url => |u| {
            const parsed_opt = release_mod.parseGitHubReleaseUrl(allocator, u) catch {
                try err_w.print("error: failed to parse URL '{s}'\n", .{u});
                try err_w.flush();
                std.process.exit(1);
            };
            const parsed = parsed_opt orelse {
                try err_w.print("error: install only accepts github.com release-download URLs (got: {s})\n", .{u});
                try err_w.print("  hint: use owner/repo[@tag] for auto-pick or owner/repo/file[@tag] for an explicit file\n", .{});
                try err_w.flush();
                std.process.exit(1);
            };
            url_buf = parsed;
            spec = .{ .owner = parsed.owner, .repo = parsed.repo, .tag = parsed.tag };
            requested_file = parsed.file;
        },
    }

    const d = try Dirs.detect(allocator, environ);
    defer d.deinit();

    // Resolve auth token: env vars first, then `gh auth token` as fallback
    const auth_resolved = auth.resolveGithubToken(allocator, io, environ, no_auth);
    defer auth_resolved.deinit(allocator);
    const auth_header = try auth.bearerHeader(allocator, auth_resolved);
    defer if (auth_header) |h| allocator.free(h);

    try w.print("resolving {s}/{s}", .{ spec.owner, spec.repo });
    if (spec.tag) |t| try w.print("@{s}", .{t});
    try w.print(" ...\n", .{});
    try w.flush();

    // Set up HTTP client
    var client: std.http.Client = .{
        .allocator = allocator,
        .io = io,
        .write_buffer_size = http_write_buffer_size,
    };
    defer client.deinit();

    // Get release info
    var release = getRelease(allocator, &client, spec.owner, spec.repo, spec.tag, auth_header) catch |err| {
        switch (err) {
            error.GitHubApiError => {
                try err_w.print("error: release not found for {s}/{s}", .{ spec.owner, spec.repo });
                if (spec.tag) |t| try err_w.print("@{s}", .{t});
                try err_w.print("\n", .{});
            },
            else => try err_w.print("error: failed to fetch release: {}\n", .{err}),
        }
        try err_w.flush();
        std.process.exit(1);
    };
    defer release.deinit();

    const tag_name = release.parsed.value.tag_name;
    try w.print("found release {s}\n", .{tag_name});

    // Find matching asset
    const asset = if (requested_file) |fname| blk: {
        const m = release_mod.findAssetByName(allocator, release.parsed.value.assets, fname) catch |err| {
            try err_w.print("error: failed to match asset by name: {}\n", .{err});
            try err_w.flush();
            std.process.exit(1);
        };
        switch (m) {
            .one => |a| break :blk a,
            .none => {
                try err_w.print("error: no asset matching '{s}' in {s}/{s}@{s}\n", .{ fname, spec.owner, spec.repo, tag_name });
                try err_w.print("available assets:\n", .{});
                for (release.parsed.value.assets) |a| {
                    try err_w.print("  {s}\n", .{a.name});
                }
                try err_w.flush();
                std.process.exit(1);
            },
            .ambiguous => |list| {
                defer allocator.free(list);
                try err_w.print("error: '{s}' matches multiple assets in {s}/{s}@{s}:\n", .{ fname, spec.owner, spec.repo, tag_name });
                for (list) |a| {
                    try err_w.print("  {s}\n", .{a.name});
                }
                try err_w.flush();
                std.process.exit(1);
            },
        }
    } else findBestAsset(release.parsed.value.assets) catch {
        try err_w.print("error: no matching asset for this platform\n", .{});
        try err_w.print("available assets:\n", .{});
        for (release.parsed.value.assets) |a| {
            try err_w.print("  {s}\n", .{a.name});
        }
        try err_w.flush();
        std.process.exit(1);
    };

    // Pre-flight verification check: if a `.minisig` sidecar exists but
    // the caller did not pass `--minisign` (and is not using
    // `--skip-verify`), abort BEFORE downloading. Mirrors the same check
    // in cmdDownload.
    release_mod.preflightVerification(
        release.parsed.value.assets,
        asset.name,
        skip_verify,
        minisign_pubkey_b64,
        err_w,
    ) catch std.process.exit(1);

    try w.print("downloading {s} ...\n", .{asset.name});
    try w.flush();

    // Ensure cache directory tree exists
    if (std.fs.path.dirname(d.cache)) |parent| {
        Dir.createDirAbsolute(io, parent, .default_dir) catch {};
    }
    Dir.createDirAbsolute(io, d.cache, .default_dir) catch {};

    // Download to cache file
    const download_path = try std.fmt.allocPrint(allocator, "{s}{c}{s}", .{
        d.cache, std.fs.path.sep, asset.name,
    });
    defer allocator.free(download_path);

    const debug_w: ?*Writer = if (debug) err_w else null;

    debugLog(debug_w, "debug: ghr {s}\n", .{version});
    debugLog(debug_w, "debug: auth: {s}\n", .{auth_resolved.source});
    debugLog(debug_w, "debug: url: {s}\n", .{asset.browser_download_url});
    debugLog(debug_w, "debug: cache: {s}\n", .{download_path});

    http.downloadToFile(allocator, io, asset.browser_download_url, download_path, .{
        .auth_header = auth_header,
        .debug_w = debug_w,
    }) catch |err| {
        try err_w.print("error: download failed: {}\n", .{err});
        try err_w.print("  url: {s}\n", .{asset.browser_download_url});
        try err_w.flush();
        std.process.exit(1);
    };
    defer Dir.deleteFileAbsolute(io, download_path) catch {};

    // Get file size for display
    {
        const stat = Dir.openFileAbsolute(io, download_path, .{}) catch null;
        if (stat) |f| {
            defer f.close(io);
            const size = f.length(io) catch 0;
            if (size > 0) {
                try w.print("downloaded {d:.1} MB\n", .{@as(f64, @floatFromInt(size)) / 1024.0 / 1024.0});
            }
        }
    }

    // Verification (issue #50 + issue #65). Runs after the asset is on
    // disk, before we extract or move anything. SHA256 (Phase 1), minisign
    // (issue #65, requires `--minisign`), and sigstore bundle (Phase 2)
    // are independent — all run when material is published. Outcome
    // precedence for the metadata label: sigstore > minisign > sha256.
    var verified_label: []const u8 = "none";
    if (skip_verify) {
        verified_label = "skipped";
        try w.print("note: verification skipped (--skip-verify)\n", .{});
    } else {
        const sha_outcome = verifyDownloadedAssetSha256(
            allocator,
            io,
            d.cache,
            release.parsed.value.assets,
            asset.name,
            download_path,
            debug_w,
            auth_header,
            w,
            err_w,
        ) catch |verr| {
            switch (verr) {
                error.ChecksumMismatch,
                error.ChecksumDownloadFailed,
                error.ChecksumEntryMissing,
                => {
                    Dir.deleteFileAbsolute(io, download_path) catch {};
                    std.process.exit(1);
                },
                else => {
                    try err_w.print("error: SHA256 verification failed: {}\n", .{verr});
                    try err_w.flush();
                    Dir.deleteFileAbsolute(io, download_path) catch {};
                    std.process.exit(1);
                },
            }
        };
        if (sha_outcome == .sha256_verified) verified_label = "sha256";

        const mini_outcome = release_mod.verifyDownloadedAssetMinisign(
            allocator,
            io,
            d.cache,
            release.parsed.value.assets,
            asset.name,
            download_path,
            debug_w,
            auth_header,
            minisign_pubkey_b64,
            w,
            err_w,
        ) catch {
            // Diagnostic was already printed by the verifier.
            Dir.deleteFileAbsolute(io, download_path) catch {};
            std.process.exit(1);
        };
        if (mini_outcome == .minisign_verified) verified_label = "minisign";

        const sig_outcome = verifyDownloadedAssetSigstore(
            allocator,
            io,
            d.cache,
            release.parsed.value.assets,
            asset.name,
            download_path,
            debug_w,
            auth_header,
            w,
            err_w,
        ) catch |verr| {
            try err_w.print("error: sigstore verification failed: {s}\n", .{@errorName(verr)});
            try err_w.flush();
            Dir.deleteFileAbsolute(io, download_path) catch {};
            std.process.exit(1);
        };
        if (sig_outcome == .sigstore_verified) verified_label = "sigstore";

        if (sha_outcome == .no_verification and
            mini_outcome == .no_verification and
            sig_outcome == .no_verification)
        {
            try w.print("note: download is unverified (no SHA256 checksum, minisign sidecar, or sigstore bundle published)\n", .{});
        }
        try w.flush();
    }

    // Stage extraction
    const staging_path = try std.fmt.allocPrint(allocator, "{s}{c}staging-{s}-{s}", .{
        d.cache, std.fs.path.sep, spec.owner, spec.repo,
    });
    defer allocator.free(staging_path);

    // Clean up any leftover staging dir
    deleteTreeAbsolute(io, staging_path) catch {};
    try Dir.createDirAbsolute(io, staging_path, .default_dir);

    var staging_dir = try Dir.openDirAbsolute(io, staging_path, .{ .iterate = true });
    defer staging_dir.close(io);

    // Extract
    try w.print("extracting ...\n", .{});
    try w.flush();

    switch (archive.detectFormat(asset.name)) {
        .zip, .tar_gz, .tar_xz => {
            archive.extractAuto(allocator, io, staging_dir, download_path, 0) catch |err| {
                try err_w.print("error: extraction failed: {}\n", .{err});
                try err_w.flush();
                std.process.exit(1);
            };
        },
        .unknown => {
            // Bare executable (e.g., cosign-windows-amd64.exe or cosign-linux-amd64).
            // Derive the command name from the asset (e.g. `wash` from
            // `wash-aarch64-unknown-linux-musl`) so the linked command is the
            // natural tool name. Falls back to repo when the pattern doesn't
            // fit (e.g. `cosign-linux-amd64` -> `cosign`).
            const exe_name = try deriveBareBinaryName(
                allocator,
                asset.name,
                spec.repo,
                builtin.os.tag == .windows,
            );
            defer allocator.free(exe_name);

            try stageBareExecutable(allocator, io, d.cache, asset.name, staging_dir, exe_name);
        },
    }

    // Find executables
    var exes = try findExecutables(allocator, io, staging_dir);
    defer {
        for (exes.items) |e| allocator.free(e);
        exes.deinit(allocator);
    }

    if (exes.items.len == 0) {
        try err_w.print("error: no executables found in archive\n", .{});
        try err_w.print("  selected asset: {s}\n", .{asset.name});
        try err_w.print("  other installable assets in this release:\n", .{});
        var listed: u32 = 0;
        for (release.parsed.value.assets) |a| {
            if (std.mem.eql(u8, a.name, asset.name)) continue;
            if (!isInstallableAsset(a.name)) continue;
            try err_w.print("    {s}\n", .{a.name});
            listed += 1;
        }
        if (listed == 0) {
            try err_w.print("    (none)\n", .{});
        }
        try err_w.flush();
        std.process.exit(1);
    }

    // Find .app bundles (macOS)
    var apps: std.ArrayListUnmanaged([]const u8) = .empty;
    if (comptime builtin.os.tag.isDarwin()) {
        apps = try findAppBundles(allocator, io, staging_dir);
    }
    defer {
        for (apps.items) |a| allocator.free(a);
        apps.deinit(allocator);
    }

    // Move staging to final tool dir
    const tool_path = try std.fmt.allocPrint(allocator, "{s}{c}{s}{c}{s}", .{
        d.tools, std.fs.path.sep, spec.owner, std.fs.path.sep, spec.repo,
    });
    defer allocator.free(tool_path);

    // Clean up tombstone from a previous self-update (Windows)
    if (comptime builtin.os.tag == .windows) {
        var tb: [Dir.max_path_bytes]u8 = undefined;
        if (std.fmt.bufPrint(&tb, "{s}.old", .{tool_path})) |t| {
            deleteTreeAbsolute(io, t) catch {};
        } else |_| {}
    }

    // Save old metadata before touching anything (for stale bin cleanup after install)
    const old_meta = readMetadata(allocator, io, tool_path);
    defer if (old_meta) |m| {
        m.parsed.deinit();
        allocator.free(m.body);
    };

    // Remove old tool directory. On Windows, running executables can be renamed
    // but not deleted, so fall back to renaming the old dir as a tombstone.
    deleteTreeAbsolute(io, tool_path) catch {
        if (comptime builtin.os.tag == .windows) {
            var tombstone_buf: [Dir.max_path_bytes]u8 = undefined;
            const tombstone = std.fmt.bufPrint(&tombstone_buf, "{s}.old", .{tool_path}) catch {
                try err_w.print("error: tool path too long\n", .{});
                try err_w.flush();
                std.process.exit(1);
            };
            deleteTreeAbsolute(io, tombstone) catch {};
            Dir.renameAbsolute(tool_path, tombstone, io) catch {
                try err_w.print("error: cannot replace tool directory (files may be locked by a running process)\n", .{});
                try err_w.flush();
                std.process.exit(1);
            };
        }
    };

    // Ensure tools and owner dirs exist (create full path)
    const owner_path = try std.fmt.allocPrint(allocator, "{s}{c}{s}", .{
        d.tools, std.fs.path.sep, spec.owner,
    });
    defer allocator.free(owner_path);
    // Create all parent directories
    var dir = Dir.openDirAbsolute(io, std.fs.path.dirname(d.tools) orelse ".", .{}) catch blk: {
        // Create parents manually
        if (std.fs.path.dirname(d.tools)) |parent| {
            if (std.fs.path.dirname(parent)) |grandparent| {
                Dir.createDirAbsolute(io, grandparent, .default_dir) catch {};
            }
            Dir.createDirAbsolute(io, parent, .default_dir) catch {};
        }
        Dir.createDirAbsolute(io, d.tools, .default_dir) catch {};
        break :blk try Dir.openDirAbsolute(io, d.tools, .{});
    };
    dir.close(io);
    Dir.createDirAbsolute(io, d.tools, .default_dir) catch {};
    Dir.createDirAbsolute(io, owner_path, .default_dir) catch {};

    // Rename staging to final
    Dir.renameAbsolute(staging_path, tool_path, io) catch {
        try err_w.print("error: failed to move staging directory to tool directory\n", .{});
        try err_w.flush();
        std.process.exit(1);
    };

    // Re-open the tool dir for metadata and linking
    var tool_dir = try Dir.openDirAbsolute(io, tool_path, .{});
    defer tool_dir.close(io);

    // Write metadata
    const bins_slice = exes.items;
    const apps_slice = apps.items;
    writeMetadata(allocator, io, tool_dir, tag_name, asset.name, bins_slice, apps_slice, verified_label) catch |err| {
        try err_w.print("warning: failed to write metadata: {}\n", .{err});
    };

    // Create bin dir and link executables
    Dir.createDirAbsolute(io, d.bin, .default_dir) catch {};
    var bin_dir = try Dir.openDirAbsolute(io, d.bin, .{});
    defer bin_dir.close(io);

    try w.print("linking executables:\n", .{});
    for (exes.items) |exe_name| {
        linkToBin(allocator, io, tool_path, bin_dir, exe_name, w) catch |err| {
            try err_w.print("warning: failed to link {s}: {}\n", .{ exe_name, err });
        };
    }

    // Clean up stale bin entries from old install that aren't in the new one
    if (old_meta) |m| {
        cleanupStaleBinEntries(io, bin_dir, m.parsed.value.bins, exes.items, tool_path);
    }

    // On macOS, copy .app bundles into ~/Applications for Spotlight discovery
    if (comptime builtin.os.tag.isDarwin()) {
        installAppBundles(allocator, io, environ, apps_slice, tool_path, w) catch |err| {
            try err_w.print("warning: failed to install .app bundle: {}\n", .{err});
        };
    }

    try w.print("installed {s}/{s}@{s}\n", .{ spec.owner, spec.repo, tag_name });
}

test "deriveBareBinaryName strips arch-triple from stem" {
    const a = std.testing.allocator;

    {
        const n = try deriveBareBinaryName(a, "wash-aarch64-unknown-linux-musl", "wasmCloud", false);
        defer a.free(n);
        try std.testing.expectEqualStrings("wash", n);
    }
    {
        const n = try deriveBareBinaryName(a, "wash-x86_64-pc-windows-msvc.exe", "wasmCloud", true);
        defer a.free(n);
        try std.testing.expectEqualStrings("wash.exe", n);
    }
    {
        // arch is not directly after stem -> fall back to repo.
        const n = try deriveBareBinaryName(a, "cosign-linux-amd64", "cosign", false);
        defer a.free(n);
        try std.testing.expectEqualStrings("cosign", n);
    }
    {
        const n = try deriveBareBinaryName(a, "cosign-windows-amd64.exe", "cosign", true);
        defer a.free(n);
        try std.testing.expectEqualStrings("cosign.exe", n);
    }
    {
        // Underscore separator.
        const n = try deriveBareBinaryName(a, "foo_aarch64-unknown-linux-gnu", "repo", false);
        defer a.free(n);
        try std.testing.expectEqualStrings("foo", n);
    }
    {
        // No separator at all -> fall back.
        const n = try deriveBareBinaryName(a, "singleword", "repo", false);
        defer a.free(n);
        try std.testing.expectEqualStrings("repo", n);
    }
}

test "stageBareExecutable copies file with executable permissions" {
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Create a fake "cache" subdir with a downloaded bare executable
    tmp.dir.createDirPath(tio, "cache") catch {};
    var cache_dir = try tmp.dir.openDir(tio, "cache", .{});
    defer cache_dir.close(tio);
    var src = try cache_dir.createFile(tio, "tool-windows-amd64.exe", .{});
    try src.writeStreamingAll(tio, "FAKE_EXE_CONTENT");
    src.close(tio);

    // Create a staging dir
    tmp.dir.createDirPath(tio, "staging") catch {};
    var staging = try tmp.dir.openDir(tio, "staging", .{ .iterate = true });
    defer staging.close(tio);

    // Stage the bare executable
    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const cache_path_len = try tmp.dir.realPathFile(tio, "cache", &path_buf);
    const cache_path = path_buf[0..cache_path_len];
    try stageBareExecutable(
        std.testing.allocator,
        tio,
        cache_path,
        "tool-windows-amd64.exe",
        staging,
        "tool.exe",
    );

    // Verify the staged file exists and has the right content
    const content = try staging.readFileAlloc(tio, "tool.exe", std.testing.allocator, Io.Limit.limited(4096));
    defer std.testing.allocator.free(content);
    try std.testing.expectEqualStrings("FAKE_EXE_CONTENT", content);

    // Verify findExecutables discovers it
    var exes = try findExecutables(std.testing.allocator, tio, staging);
    defer {
        for (exes.items) |e| std.testing.allocator.free(e);
        exes.deinit(std.testing.allocator);
    }
    try std.testing.expectEqual(@as(usize, 1), exes.items.len);
    try std.testing.expectEqualStrings("tool.exe", exes.items[0]);
}


test "findExecutables discovers executable files" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    // Create an executable file
    const exe_file = try tmp.dir.createFile(std.testing.io, "myapp", .{ .permissions = .executable_file });
    exe_file.close(std.testing.io);

    // Create a non-executable file
    const txt_file = try tmp.dir.createFile(std.testing.io, "readme.txt", .{});
    txt_file.close(std.testing.io);

    const allocator = std.testing.allocator;
    var exes = try findExecutables(allocator, std.testing.io, tmp.dir);
    defer {
        for (exes.items) |e| allocator.free(e);
        exes.deinit(allocator);
    }

    // Should find the executable but not the text file
    try std.testing.expectEqual(@as(usize, 1), exes.items.len);
    try std.testing.expectEqualStrings("myapp", exes.items[0]);
}

test "findExecutables discovers nested executables" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    // Create nested structure
    try tmp.dir.createDirPath(std.testing.io, "bin");
    const exe_file = try tmp.dir.createFile(std.testing.io, "bin/tool", .{ .permissions = .executable_file });
    exe_file.close(std.testing.io);

    const allocator = std.testing.allocator;
    var exes = try findExecutables(allocator, std.testing.io, tmp.dir);
    defer {
        for (exes.items) |e| allocator.free(e);
        exes.deinit(allocator);
    }

    try std.testing.expectEqual(@as(usize, 1), exes.items.len);
    try std.testing.expectEqualStrings("bin/tool", exes.items[0]);
}

test "findExecutables returns empty for no executables" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    const txt_file = try tmp.dir.createFile(std.testing.io, "readme.txt", .{});
    txt_file.close(std.testing.io);

    const allocator = std.testing.allocator;
    var exes = try findExecutables(allocator, std.testing.io, tmp.dir);
    defer {
        for (exes.items) |e| allocator.free(e);
        exes.deinit(allocator);
    }

    try std.testing.expectEqual(@as(usize, 0), exes.items.len);
}

test "isMacAppBundle detects valid .app bundles" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Valid .app bundle
    try tmp.dir.createDirPath(std.testing.io, "MyApp.app/Contents/MacOS");
    try std.testing.expect(isMacAppBundle(std.testing.io, tmp.dir, "MyApp.app"));

    // Not a .app (wrong extension)
    try tmp.dir.createDirPath(std.testing.io, "notapp/Contents/MacOS");
    try std.testing.expect(!isMacAppBundle(std.testing.io, tmp.dir, "notapp"));

    // .app without Contents/MacOS
    try tmp.dir.createDirPath(std.testing.io, "Broken.app/Contents");
    try std.testing.expect(!isMacAppBundle(std.testing.io, tmp.dir, "Broken.app"));
}

test "findExecutables only scans Contents/MacOS in .app bundles" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    const allocator = std.testing.allocator;

    // Create a .app bundle with main executable and framework binaries
    try tmp.dir.createDirPath(std.testing.io, "MyApp.app/Contents/MacOS");
    try tmp.dir.createDirPath(std.testing.io, "MyApp.app/Contents/Frameworks/QtCore.framework/Versions/A");
    try tmp.dir.createDirPath(std.testing.io, "MyApp.app/Contents/PlugIns/platforms");

    // Main executable
    const main_exe = try tmp.dir.createFile(std.testing.io, "MyApp.app/Contents/MacOS/myapp", .{ .permissions = .executable_file });
    main_exe.close(std.testing.io);

    // Framework binary (should NOT be found)
    const fw_exe = try tmp.dir.createFile(std.testing.io, "MyApp.app/Contents/Frameworks/QtCore.framework/Versions/A/QtCore", .{ .permissions = .executable_file });
    fw_exe.close(std.testing.io);

    // Plugin binary (should NOT be found)
    const plugin_exe = try tmp.dir.createFile(std.testing.io, "MyApp.app/Contents/PlugIns/platforms/libqcocoa.dylib", .{ .permissions = .executable_file });
    plugin_exe.close(std.testing.io);

    var exes = try findExecutables(allocator, std.testing.io, tmp.dir);
    defer {
        for (exes.items) |e| allocator.free(e);
        exes.deinit(allocator);
    }

    // Should only find the main executable, not framework/plugin binaries
    try std.testing.expectEqual(@as(usize, 1), exes.items.len);
    try std.testing.expectEqualStrings("MyApp.app/Contents/MacOS/myapp", exes.items[0]);
}

test "findExecutables handles .app bundle alongside regular executables" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    const allocator = std.testing.allocator;

    // A .app bundle
    try tmp.dir.createDirPath(std.testing.io, "MyApp.app/Contents/MacOS");
    const app_exe = try tmp.dir.createFile(std.testing.io, "MyApp.app/Contents/MacOS/myapp", .{ .permissions = .executable_file });
    app_exe.close(std.testing.io);

    // A regular executable next to the .app
    const cli_exe = try tmp.dir.createFile(std.testing.io, "mytool", .{ .permissions = .executable_file });
    cli_exe.close(std.testing.io);

    var exes = try findExecutables(allocator, std.testing.io, tmp.dir);
    defer {
        for (exes.items) |e| allocator.free(e);
        exes.deinit(allocator);
    }

    // Should find both
    try std.testing.expectEqual(@as(usize, 2), exes.items.len);

    // Sort for deterministic comparison
    std.mem.sort([]const u8, exes.items, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lt);
    try std.testing.expectEqualStrings("MyApp.app/Contents/MacOS/myapp", exes.items[0]);
    try std.testing.expectEqualStrings("mytool", exes.items[1]);
}

test "isSharedLibrary identifies shared libraries" {
    try std.testing.expect(isSharedLibrary("libfoo.dylib"));
    try std.testing.expect(isSharedLibrary("Qt6Core.dll"));
    try std.testing.expect(isSharedLibrary("libfoo.so"));
    try std.testing.expect(isSharedLibrary("libfoo.so.1"));
    try std.testing.expect(isSharedLibrary("libfoo.so.1.2.3"));
    try std.testing.expect(!isSharedLibrary("myapp"));
    try std.testing.expect(!isSharedLibrary("myapp.exe"));
    try std.testing.expect(!isSharedLibrary("README.md"));
}

test "isLibraryDir identifies library directories" {
    try std.testing.expect(isLibraryDir("QtCore.framework"));
    try std.testing.expect(isLibraryDir("lib"));
    try std.testing.expect(isLibraryDir("Frameworks"));
    try std.testing.expect(isLibraryDir("PlugIns"));
    try std.testing.expect(!isLibraryDir("bin"));
    try std.testing.expect(!isLibraryDir("Contents"));
    try std.testing.expect(!isLibraryDir("MacOS"));
}

test "findExecutables skips shared libraries" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    const allocator = std.testing.allocator;

    // Real executable
    const exe = try tmp.dir.createFile(std.testing.io, "pencil2d", .{ .permissions = .executable_file });
    exe.close(std.testing.io);

    // Shared libraries (should be skipped)
    try tmp.dir.createDirPath(std.testing.io, "lib");
    const dylib = try tmp.dir.createFile(std.testing.io, "lib/libfoo.dylib", .{ .permissions = .executable_file });
    dylib.close(std.testing.io);
    const so = try tmp.dir.createFile(std.testing.io, "lib/libbar.so", .{ .permissions = .executable_file });
    so.close(std.testing.io);

    var exes = try findExecutables(allocator, std.testing.io, tmp.dir);
    defer {
        for (exes.items) |e| allocator.free(e);
        exes.deinit(allocator);
    }

    try std.testing.expectEqual(@as(usize, 1), exes.items.len);
    try std.testing.expectEqualStrings("pencil2d", exes.items[0]);
}

test "writeJsonEscaped escapes backslashes and quotes" {
    const allocator = std.testing.allocator;
    var collected = std.Io.Writer.Allocating.init(allocator);
    defer collected.deinit();

    try writeJsonEscaped(&collected.writer, "no special chars");
    const plain = try collected.toOwnedSlice();
    defer allocator.free(plain);
    try std.testing.expectEqualStrings("no special chars", plain);

    var collected2 = std.Io.Writer.Allocating.init(allocator);
    defer collected2.deinit();
    try writeJsonEscaped(&collected2.writer, "path\\to\\file");
    const escaped = try collected2.toOwnedSlice();
    defer allocator.free(escaped);
    try std.testing.expectEqualStrings("path\\\\to\\\\file", escaped);

    var collected3 = std.Io.Writer.Allocating.init(allocator);
    defer collected3.deinit();
    try writeJsonEscaped(&collected3.writer, "say \"hello\"");
    const quoted = try collected3.toOwnedSlice();
    defer allocator.free(quoted);
    try std.testing.expectEqualStrings("say \\\"hello\\\"", quoted);
}

test "writeMetadata and readMetadata round-trip" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const bins = [_][]const u8{ "sub\\dir\\tool.exe", "other.exe" };
    const apps = [_][]const u8{};
    try writeMetadata(allocator, std.testing.io, tmp.dir, "v1.0.0", "tool-windows.zip", &bins, &apps, "sha256");

    // Verify it's valid JSON by reading it back
    const body = try tmp.dir.readFileAlloc(std.testing.io, "ghr.json", allocator, Io.Limit.limited(8192));
    defer allocator.free(body);

    // Backslashes must be escaped in JSON
    try std.testing.expect(std.mem.indexOf(u8, body, "sub\\\\dir\\\\tool.exe") != null);

    // Parse it back
    const parsed = try std.json.parseFromSlice(Metadata, allocator, body, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    try std.testing.expectEqualStrings("v1.0.0", parsed.value.tag);
    try std.testing.expectEqualStrings("tool-windows.zip", parsed.value.asset);
    try std.testing.expectEqualStrings("sha256", parsed.value.verified);
    try std.testing.expectEqual(@as(usize, 2), parsed.value.bins.len);
    try std.testing.expectEqualStrings("sub\\dir\\tool.exe", parsed.value.bins[0]);
    try std.testing.expectEqualStrings("other.exe", parsed.value.bins[1]);
}

test "writeMetadata round-trips the minisign verified label" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const bins = [_][]const u8{"tool"};
    const apps = [_][]const u8{};
    try writeMetadata(allocator, std.testing.io, tmp.dir, "v1.2.3", "tool-linux.tar.xz", &bins, &apps, "minisign");

    const body = try tmp.dir.readFileAlloc(std.testing.io, "ghr.json", allocator, Io.Limit.limited(8192));
    defer allocator.free(body);

    const parsed = try std.json.parseFromSlice(Metadata, allocator, body, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    try std.testing.expectEqualStrings("minisign", parsed.value.verified);
}

test "readMetadata returns null for missing file" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Get absolute path for the tmp dir
    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const tmp_path_len = tmp.dir.realPath(std.testing.io, &path_buf) catch return;
    const tmp_path = path_buf[0..tmp_path_len];
    const result = readMetadata(allocator, std.testing.io, tmp_path);
    try std.testing.expect(result == null);
}

test "shimPointsToToolDir validates path boundaries" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Create a .shim file pointing to a tool path
    var f = try tmp.dir.createFile(std.testing.io, "tool.shim", .{});
    var buf: [256]u8 = undefined;
    var fw = f.writer(std.testing.io, &buf);
    try fw.interface.print("C:\\tools\\owner\\repo\\bin\\tool.exe", .{});
    try fw.end();
    f.close(std.testing.io);

    // Exact tool path prefix should match
    try std.testing.expect(shimPointsToToolDir(
        std.testing.io,
        tmp.dir,
        "tool.shim",
        "C:\\tools\\owner\\repo",
    ));

    // Partial prefix that doesn't end at path boundary should NOT match
    try std.testing.expect(!shimPointsToToolDir(
        std.testing.io,
        tmp.dir,
        "tool.shim",
        "C:\\tools\\owner\\rep",
    ));

    // Non-matching prefix
    try std.testing.expect(!shimPointsToToolDir(
        std.testing.io,
        tmp.dir,
        "tool.shim",
        "C:\\other\\path",
    ));

    // Missing .shim file
    try std.testing.expect(!shimPointsToToolDir(
        std.testing.io,
        tmp.dir,
        "nonexistent.shim",
        "C:\\tools\\owner\\repo",
    ));
}

