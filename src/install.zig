const std = @import("std");
const builtin = @import("builtin");
const Dirs = @import("dirs.zig").Dirs;
const version = @import("build_options").version;

const Writer = std.io.Writer;

/// Parsed "owner/repo[@tag]" specification.
const Spec = struct {
    owner: []const u8,
    repo: []const u8,
    tag: ?[]const u8,
};

fn parseSpec(s: []const u8) !Spec {
    // Split on '/' to get owner and repo[@tag]
    const slash = std.mem.indexOfScalar(u8, s, '/') orelse return error.InvalidSpec;
    const owner = s[0..slash];
    const rest = s[slash + 1 ..];
    if (owner.len == 0 or rest.len == 0) return error.InvalidSpec;

    // Split repo[@tag]
    if (std.mem.indexOfScalar(u8, rest, '@')) |at| {
        const repo = rest[0..at];
        const tag = rest[at + 1 ..];
        if (repo.len == 0 or tag.len == 0) return error.InvalidSpec;
        return .{ .owner = owner, .repo = repo, .tag = tag };
    }
    return .{ .owner = owner, .repo = rest, .tag = null };
}

/// GitHub release asset from the API response.
const Asset = struct {
    name: []const u8,
    browser_download_url: []const u8,
};

/// Parsed release info.
const Release = struct {
    tag_name: []const u8,
    assets: []const Asset,
};

/// URL-encode a tag for use in the GitHub API path.
/// Handles '+' -> '%2B' and other special characters.
fn urlEncode(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    for (s) |c| {
        switch (c) {
            '+' => try buf.appendSlice(allocator, "%2B"),
            ' ' => try buf.appendSlice(allocator, "%20"),
            '#' => try buf.appendSlice(allocator, "%23"),
            '?' => try buf.appendSlice(allocator, "%3F"),
            '&' => try buf.appendSlice(allocator, "%26"),
            '%' => try buf.appendSlice(allocator, "%25"),
            else => try buf.append(allocator, c),
        }
    }
    return buf.toOwnedSlice(allocator);
}

const ParsedRelease = struct {
    parsed: std.json.Parsed(Release),
    body: []u8,
    allocator: std.mem.Allocator,

    fn deinit(self: *ParsedRelease) void {
        self.parsed.deinit();
        self.allocator.free(self.body);
    }
};

fn getRelease(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    owner: []const u8,
    repo: []const u8,
    tag: ?[]const u8,
) !ParsedRelease {
    const url = if (tag) |t| blk: {
        const encoded_tag = try urlEncode(allocator, t);
        defer allocator.free(encoded_tag);
        break :blk try std.fmt.allocPrint(allocator, "https://api.github.com/repos/{s}/{s}/releases/tags/{s}", .{ owner, repo, encoded_tag });
    } else try std.fmt.allocPrint(allocator, "https://api.github.com/repos/{s}/{s}/releases/latest", .{ owner, repo });
    defer allocator.free(url);

    var body_writer = std.Io.Writer.Allocating.init(allocator);
    errdefer body_writer.deinit();

    const result = try client.fetch(.{
        .location = .{ .url = url },
        .extra_headers = &.{
            .{ .name = "Accept", .value = "application/vnd.github+json" },
            .{ .name = "User-Agent", .value = "ghr/" ++ version },
        },
        .response_writer = &body_writer.writer,
    });

    if (result.status != .ok) {
        return error.GitHubApiError;
    }

    const body = try body_writer.toOwnedSlice();
    if (body.len == 0) {
        allocator.free(body);
        return error.EmptyResponse;
    }
    const parsed = try std.json.parseFromSlice(Release, allocator, body, .{ .ignore_unknown_fields = true });
    return .{ .parsed = parsed, .body = body, .allocator = allocator };
}

fn currentPlatformKeywords() struct { os: []const []const u8, arch: []const []const u8 } {
    const os_keywords: []const []const u8 = switch (builtin.os.tag) {
        .windows => &.{ "windows", "win" },
        .linux => &.{ "linux" },
        .macos => &.{ "macos", "darwin", "osx" },
        else => &.{},
    };
    const arch_keywords: []const []const u8 = switch (builtin.cpu.arch) {
        .x86_64 => &.{ "x86_64", "x64", "amd64" },
        .aarch64 => &.{ "aarch64", "arm64" },
        .x86 => &.{ "x86", "i686", "i386" },
        else => &.{},
    };
    return .{ .os = os_keywords, .arch = arch_keywords };
}

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        var match = true;
        for (0..needle.len) |j| {
            if (std.ascii.toLower(haystack[i + j]) != std.ascii.toLower(needle[j])) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

/// Returns true if the asset looks installable (zip, tar.gz, tgz).
fn isInstallableAsset(name: []const u8) bool {
    const lower_buf = name; // we'll check case-insensitively
    _ = lower_buf;
    if (std.mem.endsWith(u8, name, ".zip")) return true;
    if (std.mem.endsWith(u8, name, ".tar.gz")) return true;
    if (std.mem.endsWith(u8, name, ".tgz")) return true;
    return false;
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

fn findBestAsset(assets: []const Asset) !Asset {
    const plat = currentPlatformKeywords();
    var best: ?Asset = null;
    var best_score: u32 = 0;

    for (assets) |asset| {
        if (!isInstallableAsset(asset.name)) continue;

        var score: u32 = 0;
        for (plat.os) |kw| {
            if (containsIgnoreCase(asset.name, kw)) {
                score += 10;
                break;
            }
        }
        for (plat.arch) |kw| {
            if (containsIgnoreCase(asset.name, kw)) {
                score += 5;
                break;
            }
        }
        if (score > best_score) {
            best_score = score;
            best = asset;
        }
    }

    // If no platform match, check if there's exactly one installable asset
    if (best == null) {
        var count: u32 = 0;
        var single: ?Asset = null;
        for (assets) |asset| {
            if (isInstallableAsset(asset.name)) {
                count += 1;
                single = asset;
            }
        }
        if (count == 1) best = single;
    }

    return best orelse error.NoMatchingAsset;
}

fn downloadAsset(
    allocator: std.mem.Allocator,
    _: *std.http.Client,
    url: []const u8,
    dest_path: []const u8,
    debug_w: ?*Writer,
) !void {
    const max_retries: u8 = 5;
    var attempts: u8 = 0;
    while (attempts < max_retries) : (attempts += 1) {
        if (attempts > 0) {
            // Exponential backoff: 1s, 2s, 4s, 8s
            const delay_ns: u64 = @as(u64, 1_000_000_000) << @intCast(attempts - 1);
            debugLog(debug_w, "  retrying in {d}s ...\n", .{delay_ns / 1_000_000_000});
            std.Thread.sleep(delay_ns);
            std.fs.deleteFileAbsolute(dest_path) catch {};
        }

        // Fresh client per attempt to get a new connection and SAS token
        var client: std.http.Client = .{
            .allocator = allocator,
            .tls_buffer_size = 16384 * 2,
            .read_buffer_size = 16384,
        };
        defer client.deinit();

        var file = std.fs.createFileAbsolute(dest_path, .{}) catch return error.DownloadFailed;
        defer file.close();
        var file_buf: [8192]u8 = undefined;
        var file_writer = file.writer(&file_buf);

        const result = client.fetch(.{
            .location = .{ .url = url },
            .extra_headers = &.{
                .{ .name = "User-Agent", .value = "ghr/" ++ version },
            },
            .response_writer = &file_writer.interface,
        }) catch |err| {
            debugLog(debug_w, "  attempt {d}/{d} fetch error: {}\n", .{ attempts + 1, max_retries, err });
            if (attempts + 1 < max_retries) continue;
            return error.DownloadFailed;
        };

        file_writer.end() catch |err| {
            debugLog(debug_w, "  attempt {d}/{d} write error: {}\n", .{ attempts + 1, max_retries, err });
            if (attempts + 1 < max_retries) continue;
            return error.DownloadFailed;
        };

        if (result.status != .ok) {
            if (isTransientStatus(result.status)) {
                debugLog(debug_w, "  attempt {d}/{d} HTTP {d} ({s})\n", .{
                    attempts + 1,
                    max_retries,
                    @intFromEnum(result.status),
                    @tagName(result.status),
                });
                if (attempts + 1 < max_retries) continue;
            }
            std.log.err("download failed with HTTP {d} ({s})", .{
                @intFromEnum(result.status),
                @tagName(result.status),
            });
            return error.DownloadFailed;
        }
        if (attempts > 0) {
            debugLog(debug_w, "  succeeded on attempt {d}/{d}\n", .{ attempts + 1, max_retries });
        }
        return;
    }
}

fn debugLog(w: ?*Writer, comptime fmt: []const u8, args: anytype) void {
    if (w) |writer| {
        writer.print(fmt, args) catch {};
        writer.flush() catch {};
    }
}

fn isTransientStatus(status: std.http.Status) bool {
    return switch (status) {
        .bad_request, // GitHub CDN transiently returns 400
        .request_timeout,
        .too_many_requests,
        .internal_server_error,
        .bad_gateway,
        .service_unavailable,
        .gateway_timeout,
        => true,
        else => false,
    };
}

/// Validate that a zip entry path is safe (no path traversal).
fn isSafePath(name: []const u8) bool {
    if (name.len == 0) return false;
    // Reject absolute paths
    if (name[0] == '/' or name[0] == '\\') return false;
    if (name.len >= 2 and name[1] == ':') return false; // Windows drive letter
    // Reject path traversal
    var it = std.mem.splitScalar(u8, name, '/');
    while (it.next()) |component| {
        if (std.mem.eql(u8, component, "..")) return false;
    }
    return true;
}

fn extractZip(dest_dir: std.fs.Dir, file: *std.fs.File, diag: ?*std.zip.Diagnostics) !void {
    var buf: [8192]u8 = undefined;
    var reader = file.reader(&buf);
    try std.zip.extract(dest_dir, &reader, .{
        .allow_backslashes = true,
        .diagnostics = diag,
    });
}

fn extractTarGz(dest_dir: std.fs.Dir, file: *std.fs.File) !void {
    var file_buf: [8192]u8 = undefined;
    var file_reader = file.reader(&file_buf);
    var decompress_buf: [std.compress.flate.max_window_len]u8 = undefined;
    var decompress: std.compress.flate.Decompress = .init(
        &file_reader.interface,
        .gzip,
        &decompress_buf,
    );
    try std.tar.pipeToFileSystem(dest_dir, &decompress.reader, .{});
}

/// Scan directory recursively for executable files and return their relative paths.
fn findExecutables(allocator: std.mem.Allocator, dir: std.fs.Dir) !std.ArrayListUnmanaged([]const u8) {
    var result: std.ArrayListUnmanaged([]const u8) = .empty;
    try scanForExecutables(allocator, dir, &result, "");
    return result;
}

fn scanForExecutables(
    allocator: std.mem.Allocator,
    dir: std.fs.Dir,
    result: *std.ArrayListUnmanaged([]const u8),
    prefix: []const u8,
) !void {
    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        const rel_name = if (prefix.len > 0)
            try std.fmt.allocPrint(allocator, "{s}{c}{s}", .{ prefix, std.fs.path.sep, entry.name })
        else
            try allocator.dupe(u8, entry.name);

        if (entry.kind == .directory) {
            if (isMacAppBundle(dir, entry.name)) {
                // Only scan Contents/MacOS/ inside .app bundles
                try scanAppBundle(allocator, dir, entry.name, result, rel_name);
                allocator.free(rel_name);
            } else if (isLibraryDir(entry.name)) {
                // Skip directories that contain shared libraries, not executables
                allocator.free(rel_name);
            } else {
                var sub = dir.openDir(entry.name, .{ .iterate = true }) catch {
                    allocator.free(rel_name);
                    continue;
                };
                defer sub.close();
                try scanForExecutables(allocator, sub, result, rel_name);
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
                const stat = dir.statFile(entry.name) catch {
                    allocator.free(rel_name);
                    continue;
                };
                break :blk (stat.mode & 0o111) != 0;
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
fn isMacAppBundle(parent: std.fs.Dir, name: []const u8) bool {
    if (!std.mem.endsWith(u8, name, ".app")) return false;
    // Verify it has the expected bundle structure
    var app_dir = parent.openDir(name, .{}) catch return false;
    defer app_dir.close();
    app_dir.access("Contents/MacOS", .{}) catch return false;
    return true;
}

/// Scan only the Contents/MacOS/ directory inside a .app bundle for executables.
fn scanAppBundle(
    allocator: std.mem.Allocator,
    parent: std.fs.Dir,
    app_name: []const u8,
    result: *std.ArrayListUnmanaged([]const u8),
    app_prefix: []const u8,
) !void {
    const macos_rel = try std.fmt.allocPrint(allocator, "{s}/Contents/MacOS", .{app_name});
    defer allocator.free(macos_rel);
    var macos_dir = parent.openDir(macos_rel, .{ .iterate = true }) catch return;
    defer macos_dir.close();

    const prefix = try std.fmt.allocPrint(allocator, "{s}/Contents/MacOS", .{app_prefix});
    defer allocator.free(prefix);

    var iter = macos_dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind != .file) continue;
        if (isSharedLibrary(entry.name)) continue;
        const is_exe = if (builtin.os.tag == .windows)
            std.mem.endsWith(u8, entry.name, ".exe")
        else blk: {
            const stat = macos_dir.statFile(entry.name) catch continue;
            break :blk (stat.mode & 0o111) != 0;
        };
        if (is_exe) {
            const rel_name = try std.fmt.allocPrint(allocator, "{s}{c}{s}", .{ prefix, std.fs.path.sep, entry.name });
            try result.append(allocator, rel_name);
        }
    }
}

/// Link or copy an executable to the bin directory.
fn linkToBin(
    tool_dir_path: []const u8,
    bin_dir: std.fs.Dir,
    exe_rel_path: []const u8,
    w: *Writer,
) !void {
    const exe_name = std.fs.path.basename(exe_rel_path);
    var src_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const src_path = std.fmt.bufPrint(&src_path_buf, "{s}{c}{s}", .{
        tool_dir_path,
        std.fs.path.sep,
        exe_rel_path,
    }) catch return error.PathTooLong;

    if (builtin.os.tag == .windows) {
        // Create a .cmd wrapper that runs the exe in its original directory
        // so it can find sibling DLLs.
        var cmd_name_buf: [std.fs.max_path_bytes]u8 = undefined;
        const stem = if (std.mem.endsWith(u8, exe_name, ".exe"))
            exe_name[0 .. exe_name.len - 4]
        else
            exe_name;
        const cmd_name = std.fmt.bufPrint(&cmd_name_buf, "{s}.cmd", .{stem}) catch return error.PathTooLong;

        bin_dir.deleteFile(cmd_name) catch {};
        var cmd_file = bin_dir.createFile(cmd_name, .{}) catch return error.CreateFailed;
        defer cmd_file.close();
        var cmd_buf: [4096]u8 = undefined;
        var cmd_w = cmd_file.writer(&cmd_buf);
        cmd_w.interface.print("@\"{s}\" %*\r\n", .{src_path}) catch return error.WriteFailed;
        cmd_w.end() catch return error.WriteFailed;
    } else {
        // Unix: symlink
        bin_dir.deleteFile(exe_name) catch {};
        try bin_dir.symLink(src_path, exe_name, .{});
    }
    try w.print("  linked {s}\n", .{exe_name});
}

/// Find .app bundles recursively in a directory. Returns relative paths from the root.
fn findAppBundles(allocator: std.mem.Allocator, dir: std.fs.Dir) !std.ArrayListUnmanaged([]const u8) {
    var result: std.ArrayListUnmanaged([]const u8) = .empty;
    try scanForAppBundles(allocator, dir, &result, "");
    return result;
}

fn scanForAppBundles(
    allocator: std.mem.Allocator,
    dir: std.fs.Dir,
    result: *std.ArrayListUnmanaged([]const u8),
    prefix: []const u8,
) !void {
    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind != .directory) continue;
        const rel_name = if (prefix.len > 0)
            try std.fmt.allocPrint(allocator, "{s}/{s}", .{ prefix, entry.name })
        else
            try allocator.dupe(u8, entry.name);

        if (isMacAppBundle(dir, entry.name)) {
            try result.append(allocator, rel_name);
            // Don't recurse into .app bundles
        } else {
            var sub = dir.openDir(entry.name, .{ .iterate = true }) catch {
                allocator.free(rel_name);
                continue;
            };
            defer sub.close();
            try scanForAppBundles(allocator, sub, result, rel_name);
            allocator.free(rel_name);
        }
    }
}

/// On macOS, symlink .app bundles into ~/Applications for Spotlight and Launchpad discovery.
fn linkAppBundles(
    allocator: std.mem.Allocator,
    app_paths: []const []const u8,
    tool_dir_path: []const u8,
    w: *Writer,
) !void {
    if (app_paths.len == 0) return;

    const home = std.process.getEnvVarOwned(allocator, "HOME") catch return;
    defer allocator.free(home);
    const apps_dir_path = try std.fmt.allocPrint(allocator, "{s}/Applications", .{home});
    defer allocator.free(apps_dir_path);
    std.fs.makeDirAbsolute(apps_dir_path) catch {};

    var apps_dir = std.fs.openDirAbsolute(apps_dir_path, .{}) catch return;
    defer apps_dir.close();

    for (app_paths) |rel_path| {
        const app_name = std.fs.path.basename(rel_path);
        const app_src = std.fmt.allocPrint(allocator, "{s}/{s}", .{ tool_dir_path, rel_path }) catch continue;
        defer allocator.free(app_src);

        // Only replace existing symlinks, never regular directories
        var link_buf: [std.fs.max_path_bytes]u8 = undefined;
        if (apps_dir.readLink(app_name, &link_buf)) |_| {
            apps_dir.deleteFile(app_name) catch {};
        } else |_| {}

        apps_dir.symLink(app_src, app_name, .{ .is_directory = true }) catch continue;
        try w.print("  linked ~/Applications/{s}\n", .{app_name});
    }
}

/// Remove ~/Applications symlinks that point into the given tool directory.
fn unlinkAppBundles(
    allocator: std.mem.Allocator,
    app_paths: []const []const u8,
    tool_dir_path: []const u8,
    w: *Writer,
) void {
    if (app_paths.len == 0) return;

    const home = std.process.getEnvVarOwned(allocator, "HOME") catch return;
    defer allocator.free(home);
    const apps_dir_path = std.fmt.allocPrint(allocator, "{s}/Applications", .{home}) catch return;
    defer allocator.free(apps_dir_path);

    var apps_dir = std.fs.openDirAbsolute(apps_dir_path, .{}) catch return;
    defer apps_dir.close();

    for (app_paths) |rel_path| {
        const app_name = std.fs.path.basename(rel_path);
        const expected_target = std.fmt.allocPrint(allocator, "{s}/{s}", .{ tool_dir_path, rel_path }) catch continue;
        defer allocator.free(expected_target);

        // Only remove if it's a symlink pointing to our tool directory
        var link_buf: [std.fs.max_path_bytes]u8 = undefined;
        const link_target = apps_dir.readLink(app_name, &link_buf) catch continue;
        if (std.mem.eql(u8, link_target, expected_target)) {
            apps_dir.deleteFile(app_name) catch continue;
            w.print("  unlinked ~/Applications/{s}\n", .{app_name}) catch {};
        }
    }
}

/// Write ghr.json metadata.
fn writeMetadata(
    allocator: std.mem.Allocator,
    tool_dir: std.fs.Dir,
    tag: []const u8,
    asset_name: []const u8,
    bins: []const []const u8,
    apps: []const []const u8,
) !void {
    var file = try tool_dir.createFile("ghr.json", .{});
    defer file.close();
    var buf: [4096]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    const w = stream.writer();
    try w.print("{{\"tag\":\"{s}\",\"asset\":\"{s}\",\"bins\":[", .{ tag, asset_name });
    for (bins, 0..) |bin, i| {
        if (i > 0) try w.print(",", .{});
        try w.print("\"{s}\"", .{bin});
    }
    try w.print("],\"apps\":[", .{});
    for (apps, 0..) |app, i| {
        if (i > 0) try w.print(",", .{});
        try w.print("\"{s}\"", .{app});
    }
    try w.print("]}}\n", .{});
    const written = stream.getWritten();
    try file.writeAll(written);
    _ = allocator;
}

/// Metadata stored in ghr.json.
const Metadata = struct {
    tag: []const u8,
    asset: []const u8,
    bins: []const []const u8 = &.{},
    apps: []const []const u8 = &.{},
};

/// Read ghr.json metadata from a tool directory.
fn readMetadata(allocator: std.mem.Allocator, tool_dir_path: []const u8) ?struct {
    parsed: std.json.Parsed(Metadata),
    body: []const u8,
} {
    const json_path = std.fmt.allocPrint(allocator, "{s}/ghr.json", .{tool_dir_path}) catch return null;
    defer allocator.free(json_path);
    const body = std.fs.cwd().readFileAlloc(allocator, json_path, 65536) catch return null;
    const parsed = std.json.parseFromSlice(Metadata, allocator, body, .{ .ignore_unknown_fields = true }) catch {
        allocator.free(body);
        return null;
    };
    return .{ .parsed = parsed, .body = body };
}

/// Clean up old install's bin symlinks and app bundles before replacing.
fn cleanupOldInstall(
    allocator: std.mem.Allocator,
    tool_path: []const u8,
    bin_path: []const u8,
    w: *Writer,
) void {
    const meta = readMetadata(allocator, tool_path) orelse return;
    defer meta.parsed.deinit();
    defer allocator.free(meta.body);

    // Remove old bin symlinks
    var bin_dir = std.fs.openDirAbsolute(bin_path, .{}) catch return;
    defer bin_dir.close();
    for (meta.parsed.value.bins) |exe_rel| {
        const exe_name = std.fs.path.basename(exe_rel);
        // Verify the symlink points to our tool dir before removing
        var link_buf: [std.fs.max_path_bytes]u8 = undefined;
        const link_target = bin_dir.readLink(exe_name, &link_buf) catch continue;
        if (std.mem.startsWith(u8, link_target, tool_path)) {
            bin_dir.deleteFile(exe_name) catch {};
        }
    }

    // Remove old app bundle symlinks (macOS)
    if (comptime builtin.os.tag.isDarwin()) {
        unlinkAppBundles(allocator, meta.parsed.value.apps, tool_path, w);
    }
}

pub fn cmdUninstall(
    allocator: std.mem.Allocator,
    spec_str: []const u8,
    w: *Writer,
    err_w: *Writer,
) !void {
    const spec = parseSpec(spec_str) catch {
        try err_w.print("error: invalid spec '{s}', expected owner/repo\n", .{spec_str});
        try err_w.flush();
        std.process.exit(1);
    };

    const d = try Dirs.detect(allocator);
    defer d.deinit();

    const tool_path = try std.fmt.allocPrint(allocator, "{s}{c}{s}{c}{s}", .{
        d.tools, std.fs.path.sep, spec.owner, std.fs.path.sep, spec.repo,
    });
    defer allocator.free(tool_path);

    // Check the tool exists
    std.fs.accessAbsolute(tool_path, .{}) catch {
        try err_w.print("error: {s}/{s} is not installed\n", .{ spec.owner, spec.repo });
        try err_w.flush();
        std.process.exit(1);
    };

    // Read metadata to know what to clean up
    const meta = readMetadata(allocator, tool_path);
    defer if (meta) |m| {
        m.parsed.deinit();
        allocator.free(m.body);
    };

    // Remove bin symlinks
    var bin_dir = std.fs.openDirAbsolute(d.bin, .{}) catch null;
    defer if (bin_dir) |*bd| bd.close();

    if (meta) |m| {
        for (m.parsed.value.bins) |exe_rel| {
            const exe_name = std.fs.path.basename(exe_rel);
            if (bin_dir) |bd| {
                var link_buf: [std.fs.max_path_bytes]u8 = undefined;
                const link_target = bd.readLink(exe_name, &link_buf) catch continue;
                if (std.mem.startsWith(u8, link_target, tool_path)) {
                    bd.deleteFile(exe_name) catch continue;
                    try w.print("  unlinked {s}\n", .{exe_name});
                }
            }
        }

        // Remove app bundle symlinks (macOS)
        if (comptime builtin.os.tag.isDarwin()) {
            unlinkAppBundles(allocator, m.parsed.value.apps, tool_path, w);
        }
    }

    // Delete the tool directory
    std.fs.deleteTreeAbsolute(tool_path) catch {
        try err_w.print("error: failed to remove {s}\n", .{tool_path});
        try err_w.flush();
        std.process.exit(1);
    };

    try w.print("uninstalled {s}/{s}\n", .{ spec.owner, spec.repo });
}

pub fn cmdInstall(
    allocator: std.mem.Allocator,
    spec_str: []const u8,
    w: *Writer,
    err_w: *Writer,
    debug: bool,
) !void {
    const spec = parseSpec(spec_str) catch {
        try err_w.print("error: invalid spec '{s}', expected owner/repo[@tag]\n", .{spec_str});
        try err_w.flush();
        std.process.exit(1);
    };

    const d = try Dirs.detect(allocator);
    defer d.deinit();

    try w.print("resolving {s}/{s}", .{ spec.owner, spec.repo });
    if (spec.tag) |t| try w.print("@{s}", .{t});
    try w.print(" ...\n", .{});
    try w.flush();

    // Set up HTTP client
    var client: std.http.Client = .{
        .allocator = allocator,
        .tls_buffer_size = 16384 * 2,
        .read_buffer_size = 16384,
    };
    defer client.deinit();

    // Get release info
    var release = getRelease(allocator, &client, spec.owner, spec.repo, spec.tag) catch |err| {
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
    const asset = findBestAsset(release.parsed.value.assets) catch {
        try err_w.print("error: no matching asset for this platform\n", .{});
        try err_w.print("available assets:\n", .{});
        for (release.parsed.value.assets) |a| {
            try err_w.print("  {s}\n", .{a.name});
        }
        try err_w.flush();
        std.process.exit(1);
    };

    try w.print("downloading {s} ...\n", .{asset.name});
    try w.flush();

    // Ensure cache directory tree exists
    if (std.fs.path.dirname(d.cache)) |parent| {
        std.fs.makeDirAbsolute(parent) catch {};
    }
    std.fs.makeDirAbsolute(d.cache) catch {};

    // Download to cache file
    const download_path = try std.fmt.allocPrint(allocator, "{s}{c}{s}", .{
        d.cache, std.fs.path.sep, asset.name,
    });
    defer allocator.free(download_path);

    const debug_w: ?*Writer = if (debug) err_w else null;

    debugLog(debug_w, "debug: url: {s}\n", .{asset.browser_download_url});
    debugLog(debug_w, "debug: cache: {s}\n", .{download_path});

    downloadAsset(allocator, &client, asset.browser_download_url, download_path, debug_w) catch |err| {
        try err_w.print("error: download failed: {}\n", .{err});
        try err_w.print("  url: {s}\n", .{asset.browser_download_url});
        try err_w.flush();
        std.process.exit(1);
    };
    defer std.fs.deleteFileAbsolute(download_path) catch {};

    // Get file size for display
    {
        const stat = std.fs.openFileAbsolute(download_path, .{}) catch null;
        if (stat) |f| {
            defer f.close();
            const size = f.getEndPos() catch 0;
            if (size > 0) {
                try w.print("downloaded {d:.1} MB\n", .{@as(f64, @floatFromInt(size)) / 1024.0 / 1024.0});
            }
        }
    }

    // Stage extraction
    const staging_path = try std.fmt.allocPrint(allocator, "{s}{c}staging-{s}-{s}", .{
        d.cache, std.fs.path.sep, spec.owner, spec.repo,
    });
    defer allocator.free(staging_path);

    // Clean up any leftover staging dir
    std.fs.deleteTreeAbsolute(staging_path) catch {};
    try std.fs.makeDirAbsolute(staging_path);

    var staging_dir = try std.fs.openDirAbsolute(staging_path, .{ .iterate = true });
    defer staging_dir.close();

    // Extract
    try w.print("extracting ...\n", .{});
    try w.flush();

    if (std.mem.endsWith(u8, asset.name, ".zip")) {
        var zip_file = try std.fs.openFileAbsolute(download_path, .{});
        defer zip_file.close();

        extractZip(staging_dir, &zip_file, null) catch |err| {
            try err_w.print("error: extraction failed: {}\n", .{err});
            try err_w.flush();
            std.process.exit(1);
        };
    } else if (std.mem.endsWith(u8, asset.name, ".tar.gz") or std.mem.endsWith(u8, asset.name, ".tgz")) {
        var tar_file = try std.fs.openFileAbsolute(download_path, .{});
        defer tar_file.close();

        extractTarGz(staging_dir, &tar_file) catch |err| {
            try err_w.print("error: extraction failed: {}\n", .{err});
            try err_w.flush();
            std.process.exit(1);
        };
    }

    // Find executables
    var exes = try findExecutables(allocator, staging_dir);
    defer {
        for (exes.items) |e| allocator.free(e);
        exes.deinit(allocator);
    }

    if (exes.items.len == 0) {
        try err_w.print("error: no executables found in archive\n", .{});
        try err_w.flush();
        std.process.exit(1);
    }

    // Find .app bundles (macOS)
    var apps: std.ArrayListUnmanaged([]const u8) = .empty;
    if (comptime builtin.os.tag.isDarwin()) {
        apps = try findAppBundles(allocator, staging_dir);
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

    // Clean up old install's symlinks before deleting
    cleanupOldInstall(allocator, tool_path, d.bin, w);
    std.fs.deleteTreeAbsolute(tool_path) catch {};
    // Ensure tools and owner dirs exist (create full path)
    const owner_path = try std.fmt.allocPrint(allocator, "{s}{c}{s}", .{
        d.tools, std.fs.path.sep, spec.owner,
    });
    defer allocator.free(owner_path);
    // Create all parent directories
    var dir = std.fs.openDirAbsolute(std.fs.path.dirname(d.tools) orelse ".", .{}) catch blk: {
        // Create parents manually
        if (std.fs.path.dirname(d.tools)) |parent| {
            if (std.fs.path.dirname(parent)) |grandparent| {
                std.fs.makeDirAbsolute(grandparent) catch {};
            }
            std.fs.makeDirAbsolute(parent) catch {};
        }
        std.fs.makeDirAbsolute(d.tools) catch {};
        break :blk try std.fs.openDirAbsolute(d.tools, .{});
    };
    dir.close();
    std.fs.makeDirAbsolute(d.tools) catch {};
    std.fs.makeDirAbsolute(owner_path) catch {};

    // Rename staging to final
    std.fs.renameAbsolute(staging_path, tool_path) catch {
        // Cross-device: fall back to copy
        // For now, error out
        try err_w.print("error: failed to move staging directory to tool directory\n", .{});
        try err_w.flush();
        std.process.exit(1);
    };

    // Re-open the tool dir for metadata and linking
    var tool_dir = try std.fs.openDirAbsolute(tool_path, .{});
    defer tool_dir.close();

    // Write metadata
    const bins_slice = exes.items;
    const apps_slice = apps.items;
    writeMetadata(allocator, tool_dir, tag_name, asset.name, bins_slice, apps_slice) catch |err| {
        try err_w.print("warning: failed to write metadata: {}\n", .{err});
    };

    // Create bin dir and link executables
    std.fs.makeDirAbsolute(d.bin) catch {};
    var bin_dir = try std.fs.openDirAbsolute(d.bin, .{});
    defer bin_dir.close();

    try w.print("linking executables:\n", .{});
    for (exes.items) |exe_name| {
        linkToBin(tool_path, bin_dir, exe_name, w) catch |err| {
            try err_w.print("warning: failed to link {s}: {}\n", .{ exe_name, err });
        };
    }

    // On macOS, symlink .app bundles into ~/Applications for Spotlight discovery
    if (comptime builtin.os.tag.isDarwin()) {
        linkAppBundles(allocator, apps_slice, tool_path, w) catch |err| {
            try err_w.print("warning: failed to link .app bundle: {}\n", .{err});
        };
    }

    try w.print("installed {s}/{s} @ {s}\n", .{ spec.owner, spec.repo, tag_name });
}

test "parseSpec with tag" {
    const spec = try parseSpec("ctaggart/pencil2d@v0.8.0-dev.1");
    try std.testing.expectEqualStrings("ctaggart", spec.owner);
    try std.testing.expectEqualStrings("pencil2d", spec.repo);
    try std.testing.expectEqualStrings("v0.8.0-dev.1", spec.tag.?);
}

test "parseSpec without tag" {
    const spec = try parseSpec("ctaggart/pencil2d");
    try std.testing.expectEqualStrings("ctaggart", spec.owner);
    try std.testing.expectEqualStrings("pencil2d", spec.repo);
    try std.testing.expect(spec.tag == null);
}

test "parseSpec invalid" {
    try std.testing.expectError(error.InvalidSpec, parseSpec("noslash"));
    try std.testing.expectError(error.InvalidSpec, parseSpec("/repo"));
    try std.testing.expectError(error.InvalidSpec, parseSpec("owner/"));
}

test "isSafePath" {
    try std.testing.expect(isSafePath("foo/bar.txt"));
    try std.testing.expect(isSafePath("foo.exe"));
    try std.testing.expect(!isSafePath("../etc/passwd"));
    try std.testing.expect(!isSafePath("/absolute/path"));
    try std.testing.expect(!isSafePath("C:\\windows\\path"));
    try std.testing.expect(!isSafePath(""));
}

test "containsIgnoreCase" {
    try std.testing.expect(containsIgnoreCase("pencil2d-Windows.zip", "windows"));
    try std.testing.expect(containsIgnoreCase("pencil2d-LINUX.tar.gz", "linux"));
    try std.testing.expect(!containsIgnoreCase("pencil2d-macos.zip", "windows"));
}

test "isInstallableAsset" {
    try std.testing.expect(isInstallableAsset("foo.zip"));
    try std.testing.expect(isInstallableAsset("foo.tar.gz"));
    try std.testing.expect(isInstallableAsset("foo.tgz"));
    try std.testing.expect(!isInstallableAsset("checksums.txt"));
    try std.testing.expect(!isInstallableAsset("foo.sha256"));
}

/// Create a tar.gz test fixture using the system tar command.
fn createTestTarGz(tmp: *std.testing.TmpDir, names: []const []const u8, contents: []const []const u8) !std.fs.File {
    for (names, contents) |name, content| {
        if (std.fs.path.dirname(name)) |parent| {
            tmp.dir.makePath(parent) catch {};
        }
        var f = try tmp.dir.createFile(name, .{ .mode = 0o755 });
        try f.writeAll(content);
        f.close();
    }

    // Build argv: tar czf archive.tar.gz <names...>
    var argv = std.ArrayListUnmanaged([]const u8).empty;
    defer argv.deinit(std.testing.allocator);
    try argv.appendSlice(std.testing.allocator, &.{ "tar", "czf", "archive.tar.gz" });
    try argv.appendSlice(std.testing.allocator, names);

    var tar = std.process.Child.init(argv.items, std.testing.allocator);
    tar.cwd_dir = tmp.dir;
    _ = try tar.spawnAndWait();

    // Remove source files so extraction starts clean
    for (names) |name| {
        tmp.dir.deleteFile(name) catch {};
        if (std.fs.path.dirname(name)) |parent| {
            tmp.dir.deleteDir(parent) catch {};
        }
    }

    return try tmp.dir.openFile("archive.tar.gz", .{});
}

test "extractTarGz extracts files with correct contents" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var file = try createTestTarGz(&tmp, &.{ "myapp/README.md", "myapp/myapp" }, &.{ "readme\n", "#!/bin/sh\necho hello\n" });
    defer file.close();

    extractTarGz(tmp.dir, &file) catch |err| return err;

    // Verify files exist
    try std.testing.expect((try tmp.dir.statFile("myapp/README.md")).kind == .file);
    try std.testing.expect((try tmp.dir.statFile("myapp/myapp")).kind == .file);

    // Verify contents
    const content = try tmp.dir.readFileAlloc(std.testing.allocator, "myapp/README.md", 256);
    defer std.testing.allocator.free(content);
    try std.testing.expectEqualStrings("readme\n", content);
}

test "extractTarGz handles single file archive" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var file = try createTestTarGz(&tmp, &.{"tool"}, &.{"binary"});
    defer file.close();

    extractTarGz(tmp.dir, &file) catch |err| return err;

    try std.testing.expect((try tmp.dir.statFile("tool")).kind == .file);
}

test "findExecutables discovers executable files" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Create an executable file
    const exe_file = try tmp.dir.createFile("myapp", .{ .mode = 0o755 });
    exe_file.close();

    // Create a non-executable file
    const txt_file = try tmp.dir.createFile("readme.txt", .{ .mode = 0o644 });
    txt_file.close();

    const allocator = std.testing.allocator;
    var exes = try findExecutables(allocator, tmp.dir);
    defer {
        for (exes.items) |e| allocator.free(e);
        exes.deinit(allocator);
    }

    // Should find the executable but not the text file
    try std.testing.expectEqual(@as(usize, 1), exes.items.len);
    try std.testing.expectEqualStrings("myapp", exes.items[0]);
}

test "findExecutables discovers nested executables" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Create nested structure
    try tmp.dir.makePath("bin");
    const exe_file = try tmp.dir.createFile("bin/tool", .{ .mode = 0o755 });
    exe_file.close();

    const allocator = std.testing.allocator;
    var exes = try findExecutables(allocator, tmp.dir);
    defer {
        for (exes.items) |e| allocator.free(e);
        exes.deinit(allocator);
    }

    try std.testing.expectEqual(@as(usize, 1), exes.items.len);
    try std.testing.expectEqualStrings("bin/tool", exes.items[0]);
}

test "findExecutables returns empty for no executables" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const txt_file = try tmp.dir.createFile("readme.txt", .{ .mode = 0o644 });
    txt_file.close();

    const allocator = std.testing.allocator;
    var exes = try findExecutables(allocator, tmp.dir);
    defer {
        for (exes.items) |e| allocator.free(e);
        exes.deinit(allocator);
    }

    try std.testing.expectEqual(@as(usize, 0), exes.items.len);
}

test "ParsedRelease deinit frees all memory" {
    const allocator = std.testing.allocator;

    // Simulate what getRelease does: parse JSON from a body buffer
    const json_body = try allocator.dupe(u8,
        \\{"tag_name":"v1.0.0","assets":[{"name":"app.tar.gz","browser_download_url":"https://example.com/app.tar.gz"}]}
    );

    const parsed = try std.json.parseFromSlice(Release, allocator, json_body, .{ .ignore_unknown_fields = true });

    var pr: ParsedRelease = .{ .parsed = parsed, .body = json_body, .allocator = allocator };

    // Verify parsed data is accessible
    try std.testing.expectEqualStrings("v1.0.0", pr.parsed.value.tag_name);
    try std.testing.expectEqual(@as(usize, 1), pr.parsed.value.assets.len);
    try std.testing.expectEqualStrings("app.tar.gz", pr.parsed.value.assets[0].name);

    // deinit should free everything with no leaks (testing.allocator will catch leaks)
    pr.deinit();
}

test "isMacAppBundle detects valid .app bundles" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Valid .app bundle
    try tmp.dir.makePath("MyApp.app/Contents/MacOS");
    try std.testing.expect(isMacAppBundle(tmp.dir, "MyApp.app"));

    // Not a .app (wrong extension)
    try tmp.dir.makePath("notapp/Contents/MacOS");
    try std.testing.expect(!isMacAppBundle(tmp.dir, "notapp"));

    // .app without Contents/MacOS
    try tmp.dir.makePath("Broken.app/Contents");
    try std.testing.expect(!isMacAppBundle(tmp.dir, "Broken.app"));
}

test "findExecutables only scans Contents/MacOS in .app bundles" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const allocator = std.testing.allocator;

    // Create a .app bundle with main executable and framework binaries
    try tmp.dir.makePath("MyApp.app/Contents/MacOS");
    try tmp.dir.makePath("MyApp.app/Contents/Frameworks/QtCore.framework/Versions/A");
    try tmp.dir.makePath("MyApp.app/Contents/PlugIns/platforms");

    // Main executable
    const main_exe = try tmp.dir.createFile("MyApp.app/Contents/MacOS/myapp", .{ .mode = 0o755 });
    main_exe.close();

    // Framework binary (should NOT be found)
    const fw_exe = try tmp.dir.createFile("MyApp.app/Contents/Frameworks/QtCore.framework/Versions/A/QtCore", .{ .mode = 0o755 });
    fw_exe.close();

    // Plugin binary (should NOT be found)
    const plugin_exe = try tmp.dir.createFile("MyApp.app/Contents/PlugIns/platforms/libqcocoa.dylib", .{ .mode = 0o755 });
    plugin_exe.close();

    var exes = try findExecutables(allocator, tmp.dir);
    defer {
        for (exes.items) |e| allocator.free(e);
        exes.deinit(allocator);
    }

    // Should only find the main executable, not framework/plugin binaries
    try std.testing.expectEqual(@as(usize, 1), exes.items.len);
    try std.testing.expectEqualStrings("MyApp.app/Contents/MacOS/myapp", exes.items[0]);
}

test "findExecutables handles .app bundle alongside regular executables" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const allocator = std.testing.allocator;

    // A .app bundle
    try tmp.dir.makePath("MyApp.app/Contents/MacOS");
    const app_exe = try tmp.dir.createFile("MyApp.app/Contents/MacOS/myapp", .{ .mode = 0o755 });
    app_exe.close();

    // A regular executable next to the .app
    const cli_exe = try tmp.dir.createFile("mytool", .{ .mode = 0o755 });
    cli_exe.close();

    var exes = try findExecutables(allocator, tmp.dir);
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
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const allocator = std.testing.allocator;

    // Real executable
    const exe = try tmp.dir.createFile("pencil2d", .{ .mode = 0o755 });
    exe.close();

    // Shared libraries (should be skipped)
    try tmp.dir.makePath("lib");
    const dylib = try tmp.dir.createFile("lib/libfoo.dylib", .{ .mode = 0o755 });
    dylib.close();
    const so = try tmp.dir.createFile("lib/libbar.so", .{ .mode = 0o755 });
    so.close();

    var exes = try findExecutables(allocator, tmp.dir);
    defer {
        for (exes.items) |e| allocator.free(e);
        exes.deinit(allocator);
    }

    try std.testing.expectEqual(@as(usize, 1), exes.items.len);
    try std.testing.expectEqualStrings("pencil2d", exes.items[0]);
}
