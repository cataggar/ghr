const std = @import("std");
const builtin = @import("builtin");
const Dirs = @import("dirs.zig").Dirs;
const version = @import("build_options").version;

const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;
const Writer = Io.Writer;
const Environ = std.process.Environ;
const EnvironMap = Environ.Map;

/// Delete an absolute path's directory tree. Zig 0.16 removed Dir.deleteTreeAbsolute,
/// so we open the parent dir and call deleteTree on the basename.
fn deleteTreeAbsolute(io: Io, abs_path: []const u8) !void {
    const parent = std.fs.path.dirname(abs_path) orelse return error.InvalidPath;
    const basename = std.fs.path.basename(abs_path);
    var dir = try Dir.openDirAbsolute(io, parent, .{});
    defer dir.close(io);
    try dir.deleteTree(io, basename);
}

/// HTTP write buffer size for download clients. GitHub release downloads redirect
/// to CDN URLs with long signed query strings (~900 bytes). The default
/// write_buffer_size of 1024 is too small, causing the request to be truncated
/// and the CDN to return HTTP 400. We use 4096 to accommodate these URLs plus
/// the request line and headers.
const http_write_buffer_size = 4096;
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
    auth_header: ?[]const u8,
) !ParsedRelease {
    const url = if (tag) |t| blk: {
        const encoded_tag = try urlEncode(allocator, t);
        defer allocator.free(encoded_tag);
        break :blk try std.fmt.allocPrint(allocator, "https://api.github.com/repos/{s}/{s}/releases/tags/{s}", .{ owner, repo, encoded_tag });
    } else try std.fmt.allocPrint(allocator, "https://api.github.com/repos/{s}/{s}/releases/latest", .{ owner, repo });
    defer allocator.free(url);

    var body_writer = std.Io.Writer.Allocating.init(allocator);
    errdefer body_writer.deinit();

    const headers_with_auth = [_]std.http.Header{
        .{ .name = "Accept", .value = "application/vnd.github+json" },
        .{ .name = "User-Agent", .value = "ghr/" ++ version },
        .{ .name = "Authorization", .value = auth_header orelse "" },
    };
    const headers_without_auth = [_]std.http.Header{
        .{ .name = "Accept", .value = "application/vnd.github+json" },
        .{ .name = "User-Agent", .value = "ghr/" ++ version },
    };
    const headers: []const std.http.Header = if (auth_header != null)
        &headers_with_auth
    else
        &headers_without_auth;

    const result = try client.fetch(.{
        .location = .{ .url = url },
        .extra_headers = headers,
        .response_writer = &body_writer.writer,
    });

    if (result.status != .ok) {
        // Try to extract error message from response body
        const err_body = body_writer.toOwnedSlice() catch null;
        defer if (err_body) |b| allocator.free(b);

        if (err_body) |b| {
            if (std.json.parseFromSlice(
                struct { message: []const u8, documentation_url: []const u8 = "" },
                allocator,
                b,
                .{ .ignore_unknown_fields = true },
            )) |parsed| {
                defer parsed.deinit();
                const msg = parsed.value.message;
                // GitHub returns "API rate limit exceeded" for 403 when rate limited
                if (result.status == .forbidden or result.status == .too_many_requests) {
                    std.log.err("GitHub API: {s}", .{msg});
                    if (auth_header == null) {
                        std.log.err("hint: set GH_TOKEN for higher rate limits (5000/hr vs 60/hr)", .{});
                    }
                } else {
                    std.log.err("GitHub API HTTP {d}: {s}", .{ @intFromEnum(result.status), msg });
                }
            } else |_| {}
        }
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
    if (std.mem.endsWith(u8, name, ".tar.xz")) return true;
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
    io: Io,
    _: *std.http.Client,
    url: []const u8,
    dest_path: []const u8,
    debug_w: ?*Writer,
    auth_header: ?[]const u8,
) !void {
    const max_retries: u8 = 5;
    var attempts: u8 = 0;
    while (attempts < max_retries) : (attempts += 1) {
        if (attempts > 0) {
            // Exponential backoff: 1s, 2s, 4s, 8s
            const delay_s: i64 = @as(i64, 1) << @intCast(attempts - 1);
            debugLog(debug_w, "  retrying in {d}s ...\n", .{delay_s});
            io.sleep(Io.Duration.fromSeconds(delay_s), .real) catch {};
            Dir.deleteFileAbsolute(io, dest_path) catch {};
        }

        // Fresh client per attempt to get a new connection and SAS token.
        // GitHub redirects to CDN URLs with long signed query strings (~900 bytes),
        // so we need a larger write buffer than the 1024-byte default to avoid
        // truncating the request and getting HTTP 400.
        var client: std.http.Client = .{
            .allocator = allocator,
            .io = io,
            .write_buffer_size = http_write_buffer_size,
        };
        defer client.deinit();

        var file = Dir.createFileAbsolute(io, dest_path, .{}) catch return error.DownloadFailed;
        defer file.close(io);
        var file_buf: [8192]u8 = undefined;
        var file_writer = file.writer(io, &file_buf);

        const headers_with_auth = [_]std.http.Header{
            .{ .name = "User-Agent", .value = "ghr/" ++ version },
            .{ .name = "Authorization", .value = auth_header orelse "" },
        };
        const headers_without_auth = [_]std.http.Header{
            .{ .name = "User-Agent", .value = "ghr/" ++ version },
        };
        const headers: []const std.http.Header = if (auth_header != null)
            &headers_with_auth
        else
            &headers_without_auth;

        const result = client.fetch(.{
            .location = .{ .url = url },
            .extra_headers = headers,
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

/// Run `gh auth token` to get a GitHub token from the gh CLI.
/// Returns null if gh is not installed or the command fails.
fn ghAuthToken(allocator: std.mem.Allocator, io: Io) ?[]const u8 {
    const result = std.process.run(allocator, io, .{
        .argv = &.{ "gh", "auth", "token" },
        .stdout_limit = Io.Limit.limited(256),
        .stderr_limit = Io.Limit.limited(0),
    }) catch return null;
    defer allocator.free(result.stderr);

    if (result.term != .exited or result.term.exited != 0) {
        allocator.free(result.stdout);
        return null;
    }

    // Trim trailing newline/whitespace and return owned copy
    const trimmed = std.mem.trimEnd(u8, result.stdout, &[_]u8{ ' ', '\t', '\r', '\n' });
    if (trimmed.len == 0) {
        allocator.free(result.stdout);
        return null;
    }

    const token = allocator.dupe(u8, trimmed) catch {
        allocator.free(result.stdout);
        return null;
    };
    allocator.free(result.stdout);
    return token;
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

fn extractZip(io: Io, dest_dir: Dir, file: *File) !void {
    var buf: [8192]u8 = undefined;
    var reader = file.reader(io, &buf);
    try std.zip.extract(dest_dir, &reader, .{
        .allow_backslashes = true,
    });
}

fn extractTarGz(io: Io, dest_dir: Dir, file: *File) !void {
    var file_buf: [8192]u8 = undefined;
    var file_reader = file.reader(io, &file_buf);
    var decompress_buf: [std.compress.flate.max_window_len]u8 = undefined;
    var decompress: std.compress.flate.Decompress = .init(
        &file_reader.interface,
        .gzip,
        &decompress_buf,
    );
    try std.tar.extract(io, dest_dir, &decompress.reader, .{});
}

fn extractTarXz(allocator: std.mem.Allocator, io: Io, dest_dir: Dir, file: *File) !void {
    var file_buf: [8192]u8 = undefined;
    var file_reader = file.reader(io, &file_buf);
    // xz.Decompress takes ownership of the buffer and may resize it via the allocator,
    // so it must be heap-allocated (not stack).
    const xz_buf = try allocator.alloc(u8, 8192);
    var xz_decompress = try std.compress.xz.Decompress.init(&file_reader.interface, allocator, xz_buf);
    defer xz_decompress.deinit();
    try std.tar.extract(io, dest_dir, &xz_decompress.reader, .{});
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
        bin_dir.deleteFile(io, shim_exe_name) catch {};
        var exe_file = bin_dir.createFile(io, shim_exe_name, .{}) catch return error.CreateFailed;
        defer exe_file.close(io);
        exe_file.writeStreamingAll(io, shim_exe_bytes) catch return error.WriteFailed;

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
) !void {
    _ = allocator;
    var file = try tool_dir.createFile(io, "ghr.json", .{});
    defer file.close(io);
    var buf: [4096]u8 = undefined;
    var fw = file.writer(io, &buf);
    const w = &fw.interface;
    try w.print("{{\"tag\":\"{s}\",\"asset\":\"{s}\",\"bins\":[", .{ tag, asset_name });
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
) !void {
    const spec = parseSpec(spec_str) catch {
        try err_w.print("error: invalid spec '{s}', expected owner/repo[@tag]\n", .{spec_str});
        try err_w.flush();
        std.process.exit(1);
    };

    const d = try Dirs.detect(allocator, environ);
    defer d.deinit();

    // Resolve auth token: env vars first, then `gh auth token` as fallback
    const token = if (no_auth)
        @as(?[]const u8, null)
    else
        environ.get("GH_TOKEN") orelse environ.get("GITHUB_TOKEN") orelse ghAuthToken(allocator, io);
    defer if (token) |t| {
        // Only free if we allocated it (from ghAuthToken), not if it's from environ
        if (environ.get("GH_TOKEN") == null and environ.get("GITHUB_TOKEN") == null) {
            allocator.free(t);
        }
    };
    const auth_header: ?[]const u8 = if (token) |t|
        try std.fmt.allocPrint(allocator, "Bearer {s}", .{t})
    else
        null;
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
    const auth_source: []const u8 = if (no_auth) "disabled" else if (environ.get("GH_TOKEN") != null) "GH_TOKEN" else if (environ.get("GITHUB_TOKEN") != null) "GITHUB_TOKEN" else if (token != null) "gh" else "none";
    debugLog(debug_w, "debug: auth: {s}\n", .{auth_source});
    debugLog(debug_w, "debug: url: {s}\n", .{asset.browser_download_url});
    debugLog(debug_w, "debug: cache: {s}\n", .{download_path});

    downloadAsset(allocator, io, &client, asset.browser_download_url, download_path, debug_w, auth_header) catch |err| {
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

    if (std.mem.endsWith(u8, asset.name, ".zip")) {
        var zip_file = try Dir.openFileAbsolute(io, download_path, .{});
        defer zip_file.close(io);

        extractZip(io, staging_dir, &zip_file) catch |err| {
            try err_w.print("error: extraction failed: {}\n", .{err});
            try err_w.flush();
            std.process.exit(1);
        };
    } else if (std.mem.endsWith(u8, asset.name, ".tar.gz") or std.mem.endsWith(u8, asset.name, ".tgz")) {
        var tar_file = try Dir.openFileAbsolute(io, download_path, .{});
        defer tar_file.close(io);

        extractTarGz(io, staging_dir, &tar_file) catch |err| {
            try err_w.print("error: extraction failed: {}\n", .{err});
            try err_w.flush();
            std.process.exit(1);
        };
    } else if (std.mem.endsWith(u8, asset.name, ".tar.xz")) {
        var xz_file = try Dir.openFileAbsolute(io, download_path, .{});
        defer xz_file.close(io);

        extractTarXz(allocator, io, staging_dir, &xz_file) catch |err| {
            try err_w.print("error: extraction failed: {}\n", .{err});
            try err_w.flush();
            std.process.exit(1);
        };
    }

    // Find executables
    var exes = try findExecutables(allocator, io, staging_dir);
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

    // Clean up old install's symlinks before deleting
    cleanupOldInstall(allocator, io, environ, tool_path, d.bin, w);
    deleteTreeAbsolute(io, tool_path) catch {};
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
        // Cross-device: fall back to copy
        // For now, error out
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
    writeMetadata(allocator, io, tool_dir, tag_name, asset.name, bins_slice, apps_slice) catch |err| {
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

    // On macOS, copy .app bundles into ~/Applications for Spotlight discovery
    if (comptime builtin.os.tag.isDarwin()) {
        installAppBundles(allocator, io, environ, apps_slice, tool_path, w) catch |err| {
            try err_w.print("warning: failed to install .app bundle: {}\n", .{err});
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
    try std.testing.expect(isInstallableAsset("foo.tar.xz"));
    try std.testing.expect(!isInstallableAsset("checksums.txt"));
    try std.testing.expect(!isInstallableAsset("foo.sha256"));
}

/// Create a tar.gz test fixture using the system tar command.
fn createTestTarGz(tmp: *std.testing.TmpDir, names: []const []const u8, contents: []const []const u8) !File {
    const tio = std.testing.io;
    for (names, contents) |name, content| {
        if (std.fs.path.dirname(name)) |parent| {
            tmp.dir.createDirPath(tio, parent) catch {};
        }
        var f = try tmp.dir.createFile(tio, name, .{ .permissions = .executable_file });
        try f.writeStreamingAll(tio, content);
        f.close(tio);
    }

    // Build argv: tar czf archive.tar.gz <names...>
    var argv = std.ArrayListUnmanaged([]const u8).empty;
    defer argv.deinit(std.testing.allocator);
    try argv.appendSlice(std.testing.allocator, &.{ "tar", "czf", "archive.tar.gz" });
    try argv.appendSlice(std.testing.allocator, names);

    var child = try std.process.spawn(tio, .{
        .argv = argv.items,
        .cwd = .{ .dir = tmp.dir },
    });
    _ = try child.wait(tio);

    // Remove source files so extraction starts clean
    for (names) |name| {
        tmp.dir.deleteFile(tio, name) catch {};
        if (std.fs.path.dirname(name)) |parent| {
            tmp.dir.deleteDir(tio, parent) catch {};
        }
    }

    return try tmp.dir.openFile(tio, "archive.tar.gz", .{});
}

test "extractTarGz extracts files with correct contents" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var file = try createTestTarGz(&tmp, &.{ "myapp/README.md", "myapp/myapp" }, &.{ "readme\n", "#!/bin/sh\necho hello\n" });
    defer file.close(std.testing.io);

    extractTarGz(std.testing.io, tmp.dir, &file) catch |err| return err;

    // Verify files exist
    try std.testing.expect((try tmp.dir.statFile(std.testing.io, "myapp/README.md", .{})).kind == .file);
    try std.testing.expect((try tmp.dir.statFile(std.testing.io, "myapp/myapp", .{})).kind == .file);

    // Verify contents
    const content = try tmp.dir.readFileAlloc(std.testing.io, "myapp/README.md", std.testing.allocator, Io.Limit.limited(256));
    defer std.testing.allocator.free(content);
    try std.testing.expectEqualStrings("readme\n", content);
}

test "extractTarGz handles single file archive" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var file = try createTestTarGz(&tmp, &.{"tool"}, &.{"binary"});
    defer file.close(std.testing.io);

    extractTarGz(std.testing.io, tmp.dir, &file) catch |err| return err;

    try std.testing.expect((try tmp.dir.statFile(std.testing.io, "tool", .{})).kind == .file);
}

fn createTestTarXz(tmp: *std.testing.TmpDir, names: []const []const u8, contents: []const []const u8) !File {
    const tio = std.testing.io;
    for (names, contents) |name, content| {
        if (std.fs.path.dirname(name)) |parent| {
            tmp.dir.createDirPath(tio, parent) catch {};
        }
        var f = try tmp.dir.createFile(tio, name, .{ .permissions = .executable_file });
        try f.writeStreamingAll(tio, content);
        f.close(tio);
    }

    var argv = std.ArrayListUnmanaged([]const u8).empty;
    defer argv.deinit(std.testing.allocator);
    try argv.appendSlice(std.testing.allocator, &.{ "tar", "cJf", "archive.tar.xz" });
    try argv.appendSlice(std.testing.allocator, names);

    var child = try std.process.spawn(tio, .{
        .argv = argv.items,
        .cwd = .{ .dir = tmp.dir },
    });
    _ = try child.wait(tio);

    for (names) |name| {
        tmp.dir.deleteFile(tio, name) catch {};
        if (std.fs.path.dirname(name)) |parent| {
            tmp.dir.deleteDir(tio, parent) catch {};
        }
    }

    return try tmp.dir.openFile(tio, "archive.tar.xz", .{});
}

test "extractTarXz extracts files with correct contents" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var file = try createTestTarXz(&tmp, &.{ "myapp/README.md", "myapp/myapp" }, &.{ "readme\n", "#!/bin/sh\necho hello\n" });
    defer file.close(std.testing.io);

    extractTarXz(std.testing.io, tmp.dir, &file) catch |err| return err;

    try std.testing.expect((try tmp.dir.statFile(std.testing.io, "myapp/README.md", .{})).kind == .file);
    try std.testing.expect((try tmp.dir.statFile(std.testing.io, "myapp/myapp", .{})).kind == .file);

    const content = try tmp.dir.readFileAlloc(std.testing.io, "myapp/README.md", std.testing.allocator, Io.Limit.limited(256));
    defer std.testing.allocator.free(content);
    try std.testing.expectEqualStrings("readme\n", content);
}

test "findExecutables discovers executable files" {
    var tmp = std.testing.tmpDir(.{});
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
    var tmp = std.testing.tmpDir(.{});
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
    var tmp = std.testing.tmpDir(.{});
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
    var tmp = std.testing.tmpDir(.{});
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
    var tmp = std.testing.tmpDir(.{});
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
    var tmp = std.testing.tmpDir(.{});
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

test "urlEncode handles special characters" {
    const allocator = std.testing.allocator;

    const plain = try urlEncode(allocator, "v1.0.0");
    defer allocator.free(plain);
    try std.testing.expectEqualStrings("v1.0.0", plain);

    const plus = try urlEncode(allocator, "v1.0.0+build");
    defer allocator.free(plus);
    try std.testing.expectEqualStrings("v1.0.0%2Bbuild", plus);

    const space = try urlEncode(allocator, "my tag");
    defer allocator.free(space);
    try std.testing.expectEqualStrings("my%20tag", space);

    const multi = try urlEncode(allocator, "a+b&c#d");
    defer allocator.free(multi);
    try std.testing.expectEqualStrings("a%2Bb%26c%23d", multi);

    const percent = try urlEncode(allocator, "100%done");
    defer allocator.free(percent);
    try std.testing.expectEqualStrings("100%25done", percent);
}

test "isTransientStatus" {
    try std.testing.expect(isTransientStatus(.bad_request));
    try std.testing.expect(isTransientStatus(.request_timeout));
    try std.testing.expect(isTransientStatus(.too_many_requests));
    try std.testing.expect(isTransientStatus(.internal_server_error));
    try std.testing.expect(isTransientStatus(.bad_gateway));
    try std.testing.expect(isTransientStatus(.service_unavailable));
    try std.testing.expect(isTransientStatus(.gateway_timeout));
    try std.testing.expect(!isTransientStatus(.ok));
    try std.testing.expect(!isTransientStatus(.not_found));
    try std.testing.expect(!isTransientStatus(.forbidden));
}

test "http_write_buffer_size accommodates GitHub CDN redirect URLs" {
    // GitHub release downloads redirect to CDN URLs with long signed query strings.
    // The HTTP write buffer must hold the full request line + headers for the redirect.
    // A typical redirect URL path+query is ~900 bytes. With request line overhead
    // ("GET " + " HTTP/1.1\r\n") and headers (Host, User-Agent, Accept-Encoding,
    // Connection), the total request can reach ~1100 bytes.
    const typical_cdn_path = "/github-production-release-asset/1234567890/" ++
        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" ++
        "?sp=r&sv=2018-11-09&sr=b&spr=https" ++
        "&se=2026-04-15T07%3A04%3A01Z" ++
        "&rscd=attachment%3B+filename%3Dzig-aarch64-macos-0.16.0.tar.xz" ++
        "&rsct=application%2Foctet-stream" ++
        "&skoid=96c2d410-5711-43a1-aedd-ab1947aa7ab0" ++
        "&sktid=398a6654-997b-47e9-b12b-9515b896b4de" ++
        "&skt=2026-04-15T06%3A03%3A53Z" ++
        "&ske=2026-04-15T07%3A04%3A01Z" ++
        "&sks=b&skv=2018-11-09" ++
        "&sig=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop%2Bqrstuv%3D" ++
        "&jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" ++
        ".eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmVsZWFzZS1hc3NldHMu" ++
        "Z2l0aHVidXNlcmNvbnRlbnQuY29tIiwia2V5Ijoia2V5MSIsImV4cCI6MT" ++
        "c3NjIzNTg1MiwibmJmIjoxNzc2MjM0MDUyLCJwYXRoIjoicmVsZWFzZW" ++
        "Fzc2V0cHJvZHVjdGlvbi5ibG9iLmNvcmUud2luZG93cy5uZXQifQ" ++
        ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0" ++
        "&response-content-disposition=attachment%3B%20filename%3Dzig-aarch64-macos-0.16.0.tar.xz" ++
        "&response-content-type=application%2Foctet-stream";

    // Simulate the HTTP request line + minimal headers
    const request_line_overhead = "GET ".len + " HTTP/1.1\r\n".len;
    const host_header = "Host: release-assets.githubusercontent.com\r\n";
    const user_agent_header = "User-Agent: ghr/" ++ version ++ "\r\n";
    const min_request_size = request_line_overhead + typical_cdn_path.len +
        host_header.len + user_agent_header.len + "\r\n".len;

    try std.testing.expect(http_write_buffer_size >= min_request_size);
    // Verify the default of 1024 would NOT be sufficient (this is the bug we fixed)
    try std.testing.expect(1024 < min_request_size);
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
    try writeMetadata(allocator, std.testing.io, tmp.dir, "v1.0.0", "tool-windows.zip", &bins, &apps);

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
    try std.testing.expectEqual(@as(usize, 2), parsed.value.bins.len);
    try std.testing.expectEqualStrings("sub\\dir\\tool.exe", parsed.value.bins[0]);
    try std.testing.expectEqualStrings("other.exe", parsed.value.bins[1]);
}

test "readMetadata returns null for missing file" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Get absolute path for the tmp dir
    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const tmp_path = tmp.dir.realpath(std.testing.io, ".", &path_buf) catch return;
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

test "ghAuthToken returns token when gh is available" {
    const allocator = std.testing.allocator;
    const token = ghAuthToken(allocator, std.testing.io);
    // gh may or may not be installed in the test environment;
    // just verify no crash and that if returned, it's non-empty
    if (token) |t| {
        defer allocator.free(t);
        try std.testing.expect(t.len > 0);
    }
}
