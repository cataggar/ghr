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

fn getRelease(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    owner: []const u8,
    repo: []const u8,
    tag: ?[]const u8,
) !std.json.Parsed(Release) {
    const url = if (tag) |t| blk: {
        const encoded_tag = try urlEncode(allocator, t);
        defer allocator.free(encoded_tag);
        break :blk try std.fmt.allocPrint(allocator, "https://api.github.com/repos/{s}/{s}/releases/tags/{s}", .{ owner, repo, encoded_tag });
    } else try std.fmt.allocPrint(allocator, "https://api.github.com/repos/{s}/{s}/releases/latest", .{ owner, repo });
    defer allocator.free(url);

    var body_writer = std.Io.Writer.Allocating.init(allocator);

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

    const body = body_writer.writer.buffer[0..body_writer.writer.end];
    if (body.len == 0) return error.EmptyResponse;
    return std.json.parseFromSlice(Release, allocator, body, .{ .ignore_unknown_fields = true });
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
    client: *std.http.Client,
    url: []const u8,
    dest_path: []const u8,
) !void {
    const uri = try std.Uri.parse(url);
    var req = try client.request(.GET, uri, .{
        .redirect_behavior = @enumFromInt(3),
        .extra_headers = &.{
            .{ .name = "User-Agent", .value = "ghr/" ++ version },
        },
    });
    defer req.deinit();

    try req.sendBodiless();

    var redirect_buf: [8 * 1024]u8 = undefined;
    var response = try req.receiveHead(&redirect_buf);

    if (response.head.status != .ok) return error.DownloadFailed;

    var transfer_buf: [8192]u8 = undefined;
    var body_reader = response.reader(&transfer_buf);

    var file = try std.fs.createFileAbsolute(dest_path, .{});
    defer file.close();
    var file_buf: [8192]u8 = undefined;
    var file_writer = file.writer(&file_buf);

    const n = body_reader.streamRemaining(&file_writer.interface) catch return error.DownloadFailed;
    try file_writer.end();
    _ = n;
    _ = allocator;
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

fn extractTarGz(dest_dir: std.fs.Dir) !void {
    _ = dest_dir;
    return error.TarGzNotYetSupported;
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
            var sub = dir.openDir(entry.name, .{ .iterate = true }) catch {
                allocator.free(rel_name);
                continue;
            };
            defer sub.close();
            try scanForExecutables(allocator, sub, result, rel_name);
            allocator.free(rel_name);
        } else if (entry.kind == .file) {
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

    // Remove existing
    bin_dir.deleteFile(exe_name) catch {};

    if (builtin.os.tag == .windows) {
        // Copy on Windows (hardlinks/symlinks need admin or dev mode)
        const src_file = std.fs.openFileAbsolute(src_path, .{}) catch return error.SourceNotFound;
        defer src_file.close();
        const dst_file = bin_dir.createFile(exe_name, .{}) catch return error.CreateFailed;
        defer dst_file.close();
        var buf: [8192]u8 = undefined;
        var dst_buf: [8192]u8 = undefined;
        var file_writer = dst_file.writer(&dst_buf);
        var src_reader = src_file.reader(&buf);
        _ = src_reader.interface.streamRemaining(&file_writer.interface) catch return error.CopyFailed;
        file_writer.end() catch return error.CopyFailed;
    } else {
        // Unix: symlink
        try bin_dir.symLink(src_path, exe_name, .{});
    }
    try w.print("  linked {s}\n", .{exe_name});
}

/// Write ghr.json metadata.
fn writeMetadata(
    allocator: std.mem.Allocator,
    tool_dir: std.fs.Dir,
    tag: []const u8,
    asset_name: []const u8,
    bins: []const []const u8,
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
    try w.print("]}}\n", .{});
    const written = stream.getWritten();
    try file.writeAll(written);
    _ = allocator;
}

pub fn cmdInstall(
    allocator: std.mem.Allocator,
    spec_str: []const u8,
    w: *Writer,
    err_w: *Writer,
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
    };
    defer client.deinit();

    // Get release info
    const release = getRelease(allocator, &client, spec.owner, spec.repo, spec.tag) catch |err| {
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

    const tag_name = release.value.tag_name;
    try w.print("found release {s}\n", .{tag_name});

    // Find matching asset
    const asset = findBestAsset(release.value.assets) catch {
        try err_w.print("error: no matching asset for this platform\n", .{});
        try err_w.print("available assets:\n", .{});
        for (release.value.assets) |a| {
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

    downloadAsset(allocator, &client, asset.browser_download_url, download_path) catch |err| {
        try err_w.print("error: download failed: {}\n", .{err});
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
        extractTarGz(staging_dir) catch |err| {
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

    // Move staging to final tool dir
    const tool_path = try std.fmt.allocPrint(allocator, "{s}{c}{s}{c}{s}", .{
        d.tools, std.fs.path.sep, spec.owner, std.fs.path.sep, spec.repo,
    });
    defer allocator.free(tool_path);

    // Remove old install if present
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
    writeMetadata(allocator, tool_dir, tag_name, asset.name, bins_slice) catch |err| {
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
