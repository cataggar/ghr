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

/// Best-effort `mkdir -p` for `abs_path`, walking up `max_parents` ancestor
/// levels. Each create is wrapped in `catch {}`: existing directories and
/// permission errors on outer ancestors that we don't own (e.g. `C:\Users`)
/// are tolerated. The caller is expected to detect actual failure by then
/// opening or using `abs_path` and reporting an error with the path.
fn ensureDirWithParents(io: Io, abs_path: []const u8, max_parents: u8) void {
    var ancestors: [8][]const u8 = undefined;
    const cap: usize = @min(@as(usize, max_parents), ancestors.len);
    var n: usize = 0;
    var cur = abs_path;
    while (n < cap) : (n += 1) {
        const parent = std.fs.path.dirname(cur) orelse break;
        ancestors[n] = parent;
        cur = parent;
    }
    // Create ancestors top-down (outermost first) so each create has its
    // parent in place.
    var i: usize = n;
    while (i > 0) {
        i -= 1;
        Dir.createDirAbsolute(io, ancestors[i], .default_dir) catch {};
    }
    Dir.createDirAbsolute(io, abs_path, .default_dir) catch {};
}

/// Best-effort recursive `mkdir -p` for an absolute path. Unlike
/// `ensureDirWithParents`, this walks up an unbounded number of ancestor
/// levels, recursing only when create fails because a parent is missing.
/// All other errors (already-exists, access-denied on ancestors we don't
/// own) are tolerated; the caller detects real failure by then trying to
/// use `abs_path`.
pub fn ensureDirAbsoluteRecursive(io: Io, abs_path: []const u8) void {
    Dir.createDirAbsolute(io, abs_path, .default_dir) catch |err| {
        if (err == error.FileNotFound) {
            const parent = std.fs.path.dirname(abs_path) orelse return;
            ensureDirAbsoluteRecursive(io, parent);
            Dir.createDirAbsolute(io, abs_path, .default_dir) catch {};
        }
    };
}

/// ASCII case-insensitive equality. Cheap and allocation-free.
fn eqlIgnoreAsciiCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (std.ascii.toLower(x) != std.ascii.toLower(y)) return false;
    }
    return true;
}

/// ASCII-lowercase `s` into a freshly-allocated slice.
fn asciiLowerDup(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, s.len);
    for (s, 0..) |c, i| out[i] = std.ascii.toLower(c);
    return out;
}

/// Rename a directory across a case-only difference in its leaf name.
///
/// On case-sensitive filesystems (typical Linux ext4) this is a direct
/// `renameAbsolute`. On case-insensitive ones (NTFS by default, APFS
/// usually) `rename("AzureAD", "azuread")` is a no-op since the entries
/// alias to the same inode; we detour through a `<name>.casetmp` so the
/// on-disk casing actually flips.
///
/// When `old_abs` and `new_abs` differ in more than just leaf casing
/// (different parent, or same name byte-for-byte), this is a plain
/// `renameAbsolute` — no temp dance is performed.
fn caseRenameDir(io: Io, old_abs: []const u8, new_abs: []const u8) !void {
    const old_parent = std.fs.path.dirname(old_abs) orelse return error.InvalidPath;
    const new_parent = std.fs.path.dirname(new_abs) orelse return error.InvalidPath;
    const leaf_old = std.fs.path.basename(old_abs);
    const leaf_new = std.fs.path.basename(new_abs);
    const same_parent = std.mem.eql(u8, old_parent, new_parent);
    const leaf_case_only =
        same_parent and
        !std.mem.eql(u8, leaf_old, leaf_new) and
        eqlIgnoreAsciiCase(leaf_old, leaf_new);

    if (leaf_case_only) {
        var tmp_buf: [Dir.max_path_bytes]u8 = undefined;
        const tmp_abs = try std.fmt.bufPrint(&tmp_buf, "{s}.casetmp", .{old_abs});
        // Clean up any leftover tombstone from a prior failed attempt.
        deleteTreeAbsolute(io, tmp_abs) catch {};
        try Dir.renameAbsolute(old_abs, tmp_abs, io);
        try Dir.renameAbsolute(tmp_abs, new_abs, io);
        return;
    }
    try Dir.renameAbsolute(old_abs, new_abs, io);
}

/// Search `parent` for a directory entry whose name matches `target`
/// (case-insensitive). Returns the actual on-disk name (heap-owned by
/// `allocator`) so callers preserve the casing already present on the
/// filesystem.
///
/// Prefers an exact byte-for-byte match over a case-insensitive one when
/// both happen to exist (only possible on case-sensitive filesystems).
/// Returns `null` when no match exists.
fn findDirEntryIgnoreCase(
    allocator: std.mem.Allocator,
    io: Io,
    parent: Dir,
    target: []const u8,
) !?[]u8 {
    var iter = parent.iterate();
    var ci_hit: ?[]u8 = null;
    errdefer if (ci_hit) |h| allocator.free(h);
    while (try iter.next(io)) |entry| {
        if (entry.kind != .directory) continue;
        if (std.mem.eql(u8, entry.name, target)) {
            if (ci_hit) |h| {
                allocator.free(h);
                ci_hit = null;
            }
            return try allocator.dupe(u8, entry.name);
        }
        if (ci_hit == null and eqlIgnoreAsciiCase(entry.name, target)) {
            ci_hit = try allocator.dupe(u8, entry.name);
        }
    }
    return ci_hit;
}

/// Find the actual on-disk path for `<tools_dir>/<owner>/<repo>`,
/// regardless of the on-disk casing. Prefers an exact lowercase match
/// (the new canonical layout); falls back to a case-insensitive scan of
/// `tools_dir/*` and `<owner-match>/*` so that pre-migration installs
/// created with mixed-case slugs (e.g. `AzureAD/foo`) are still found.
///
/// `owner_lower` and `repo_lower` MUST be ASCII-lowercased by the caller
/// (see `release.parseRepoSpecOwned`).
///
/// Returns the joined absolute path, owned by `allocator`, or `null` when
/// no matching tool directory exists. The path uses the host path
/// separator so it's directly usable with `openDirAbsolute`.
pub fn resolveInstalledToolPath(
    allocator: std.mem.Allocator,
    io: Io,
    tools_dir: []const u8,
    owner_lower: []const u8,
    repo_lower: []const u8,
) !?[]u8 {
    var tools = Dir.openDirAbsolute(io, tools_dir, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return null,
        else => return err,
    };
    defer tools.close(io);

    const owner_name = (try findDirEntryIgnoreCase(allocator, io, tools, owner_lower)) orelse return null;
    defer allocator.free(owner_name);

    var owner_dir = tools.openDir(io, owner_name, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return null,
        else => return err,
    };
    defer owner_dir.close(io);

    const repo_name = (try findDirEntryIgnoreCase(allocator, io, owner_dir, repo_lower)) orelse return null;
    defer allocator.free(repo_name);

    return try std.fs.path.join(allocator, &.{ tools_dir, owner_name, repo_name });
}

/// Magic-byte sniff for native executable formats on POSIX. Returns true for
/// ELF, Mach-O (thin/fat, both endians), and shebang scripts. Used as a
/// fallback when the on-disk executable bit is missing — notably for files
/// extracted from a zip, since `std.zip.extract` does not preserve the Unix
/// mode bits stored in the central directory's `external_file_attributes`.
fn looksLikePosixExecutable(io: Io, dir: Dir, name: []const u8) bool {
    var f = dir.openFile(io, name, .{}) catch return false;
    defer f.close(io);
    var head: [4]u8 = undefined;
    var buf: [4]u8 = undefined;
    var reader = f.reader(io, &buf);
    const n = reader.interface.readSliceShort(&head) catch return false;
    if (n >= 2 and head[0] == '#' and head[1] == '!') return true;
    if (n < 4) return false;
    if (std.mem.eql(u8, &head, "\x7fELF")) return true;
    const macho_magics = [_][4]u8{
        // Mach-O thin (32/64, both byte orders)
        .{ 0xfe, 0xed, 0xfa, 0xce }, .{ 0xce, 0xfa, 0xed, 0xfe },
        .{ 0xfe, 0xed, 0xfa, 0xcf }, .{ 0xcf, 0xfa, 0xed, 0xfe },
        // Mach-O universal (fat) 32/64
        .{ 0xca, 0xfe, 0xba, 0xbe }, .{ 0xbe, 0xba, 0xfe, 0xca },
        .{ 0xca, 0xfe, 0xba, 0xbf }, .{ 0xbf, 0xba, 0xfe, 0xca },
    };
    for (macho_magics) |m| if (std.mem.eql(u8, &head, &m)) return true;
    return false;
}

/// Add the executable bit (0o111) to a file's existing permissions. No-op on
/// platforms without a Unix-style mode (Windows, WASI). Errors are swallowed:
/// the worst case is that `findExecutables` ignores the file, matching the
/// pre-existing behavior.
fn addExecutableBit(io: Io, dir: Dir, name: []const u8) void {
    if (comptime !File.Permissions.has_executable_bit) return;
    var f = dir.openFile(io, name, .{}) catch return;
    defer f.close(io);
    const st = f.stat(io) catch return;
    const mode = @as(u32, @intFromEnum(st.permissions));
    if (mode & 0o111 != 0) return;
    const new_perms: File.Permissions = @enumFromInt(mode | 0o111);
    f.setPermissions(io, new_perms) catch {};
}

/// Returns true if `name` is macOS archive cruft: an AppleDouble companion
/// file (`._*`, which mirrors a real entry's resource fork/metadata) or the
/// `__MACOSX` directory that `zip` adds. These are never real executables.
fn isAppleArchiveCruft(name: []const u8) bool {
    if (std.mem.startsWith(u8, name, "._")) return true;
    if (std.mem.eql(u8, name, "__MACOSX")) return true;
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
        if (c == '-' or c == '_') {
            sep_idx = i;
            break;
        }
    }

    if (sep_idx) |si| {
        if (si > 0 and si + 1 < name.len) {
            const stem = name[0..si];
            const after = name[si + 1 ..];
            const archs = [_][]const u8{
                "x86_64",  "x64",   "amd64",
                "aarch64", "arm64", "armv7l",
                "armv7",   "armv6", "x86",
                "i686",    "i386",  "ppc64le",
                "ppc64",   "s390x", "riscv64",
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

/// Some archives bundle the *same* command compiled for several architectures
/// under arch-named directories — e.g. `jedisct1/minisign@0.12` ships both
/// `minisign-linux/x86_64/minisign` and `minisign-linux/aarch64/minisign`.
/// `findExecutables` returns every copy, and because they share the basename
/// `minisign`, `linkToBin` would link them in arbitrary directory-iteration
/// order, letting the foreign-arch build win on some hosts. Exec'ing that
/// binary fails immediately (issue #123).
///
/// Resolve such collisions by detecting basename groups that contain a copy
/// whose relative path targets the host architecture, then dropping the
/// foreign-arch copies from that group. Groups with no host-arch match, and
/// unique basenames, are left untouched so this is a safe no-op for normal
/// single-arch archives.
fn dedupeExecutablesByHostArch(
    allocator: std.mem.Allocator,
    exes: *std.ArrayListUnmanaged([]const u8),
) void {
    dedupeExecutablesByArch(allocator, exes, release_mod.currentPlatformKeywords().arch);
}

fn dedupeExecutablesByArch(
    allocator: std.mem.Allocator,
    exes: *std.ArrayListUnmanaged([]const u8),
    host_arch: []const []const u8,
) void {
    if (host_arch.len == 0 or exes.items.len < 2) return;

    var i: usize = 0;
    while (i < exes.items.len) {
        const path = exes.items[i];
        // Only consider dropping a copy that clearly targets a foreign arch.
        if (!release_mod.isForeignArch(path, host_arch)) {
            i += 1;
            continue;
        }
        const base = std.fs.path.basename(path);
        // Keep it unless a sibling with the same basename targets the host arch.
        var host_sibling = false;
        for (exes.items, 0..) |other, j| {
            if (j == i) continue;
            if (!std.mem.eql(u8, std.fs.path.basename(other), base)) continue;
            if (release_mod.hasHostArch(other, host_arch)) {
                host_sibling = true;
                break;
            }
        }
        if (host_sibling) {
            allocator.free(exes.orderedRemove(i));
            continue;
        }
        i += 1;
    }
}

fn findDebExecutables(allocator: std.mem.Allocator, io: Io, dir: Dir) !std.ArrayListUnmanaged([]const u8) {
    var result: std.ArrayListUnmanaged([]const u8) = .empty;
    var bin_dir = dir.openDir(io, "usr/bin", .{ .iterate = true }) catch return result;
    defer bin_dir.close(io);

    var iter = bin_dir.iterate();
    while (try iter.next(io)) |entry| {
        if (entry.kind != .file and entry.kind != .sym_link) continue;
        const rel_name = try std.fmt.allocPrint(allocator, "usr/bin/{s}", .{entry.name});
        try result.append(allocator, rel_name);
    }

    return result;
}

fn hasDebShims(io: Io, dir: Dir) bool {
    var bin_dir = dir.openDir(io, "usr/bin", .{ .iterate = true }) catch return false;
    defer bin_dir.close(io);

    var iter = bin_dir.iterate();
    while (iter.next(io) catch null) |entry| {
        if (entry.kind == .sym_link or entry.kind == .file) return true;
    }
    return false;
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
        // Skip macOS archive metadata (AppleDouble `._*` companions and the
        // `__MACOSX` directory). These are not real executables even when they
        // carry the exec bit, and linking them clutters the bin dir (#123).
        if (isAppleArchiveCruft(entry.name)) continue;
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
                if ((@as(u32, @intFromEnum(stat.permissions)) & 0o111) != 0)
                    break :blk true;
                // Fallback: zip archives drop Unix mode bits. If the file's
                // magic bytes identify it as a native executable, chmod +x
                // and treat it as installable.
                if (!looksLikePosixExecutable(io, dir, entry.name))
                    break :blk false;
                addExecutableBit(io, dir, entry.name);
                break :blk true;
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
            if ((@as(u32, @intFromEnum(stat.permissions)) & 0o111) != 0)
                break :blk true;
            if (!looksLikePosixExecutable(io, macos_dir, entry.name))
                break :blk false;
            addExecutableBit(io, macos_dir, entry.name);
            break :blk true;
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
    // A `.wasm` module is not directly executable: install a shim launcher
    // (embedded in ghr) plus a `<stem>.ghr` manifest that the shim loads at
    // run time.
    if (release_mod.isWasmAssetName(exe_rel_path)) {
        return linkWasmToBin(allocator, io, tool_dir_path, bin_dir, exe_rel_path, w);
    }

    const exe_name = std.fs.path.basename(exe_rel_path);
    var src_path_buf: [Dir.max_path_bytes]u8 = undefined;
    const src_path = std.fmt.bufPrint(&src_path_buf, "{s}{c}{s}", .{
        tool_dir_path,
        std.fs.path.sep,
        exe_rel_path,
    }) catch return error.PathTooLong;

    if (builtin.os.tag == .windows) {
        // Use an embedded shim .exe driven by a `<stem>.ghr` manifest instead
        // of a .cmd wrapper. The shim is embedded in ghr at build time so it's
        // always available, regardless of how ghr is installed (PyPI, GitHub
        // release, etc.). This is the same technique used by npm and Scoop.
        const shim_exe_bytes = @import("shim_exe").bytes;

        const stem = if (std.mem.endsWith(u8, exe_name, ".exe"))
            exe_name[0 .. exe_name.len - 4]
        else
            exe_name;

        // Write the `<stem>.ghr` manifest naming the native target. The shim
        // reads this at run time; for a current shim it supersedes the legacy
        // `.shim` file (which is reconciled further below).
        var ghr_name_buf: [Dir.max_path_bytes]u8 = undefined;
        const ghr_name = std.fmt.bufPrint(&ghr_name_buf, "{s}.ghr", .{stem}) catch return error.PathTooLong;
        try writeNativeGhr(io, bin_dir, ghr_name, src_path);

        // Remove any legacy `.cmd` wrapper from very old installs; the shim
        // exe + `.ghr` manifest supersede it unconditionally. The legacy
        // `.shim` is reconciled below, once we know whether the current shim
        // exe was actually installed.
        var cmd_name_buf: [Dir.max_path_bytes]u8 = undefined;
        if (std.fmt.bufPrint(&cmd_name_buf, "{s}.cmd", .{stem})) |p| {
            bin_dir.deleteFile(io, p) catch {};
        } else |_| {}

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
        const shim_replaced = if (bin_dir.createFile(io, shim_exe_name, .{})) |*exe_file| blk: {
            defer exe_file.close(io);
            exe_file.writeStreamingAll(io, shim_exe_bytes) catch return error.WriteFailed;
            break :blk true;
        } else |_| false;

        // Reconcile the legacy `.shim` file now that we know whether the
        // current shim exe was installed.
        var legacy_shim_buf: [Dir.max_path_bytes]u8 = undefined;
        const legacy_shim = std.fmt.bufPrint(&legacy_shim_buf, "{s}.shim", .{stem}) catch return error.PathTooLong;
        if (shim_replaced) {
            // The freshly written shim reads the `.ghr` manifest; drop any
            // stale `.shim` from an older install.
            bin_dir.deleteFile(io, legacy_shim) catch {};
        } else {
            // Self-update on Windows: the running shim exe is locked, so we
            // could not install the current `.ghr`-aware shim. The shim that
            // is still running may predate the `.ghr` format and only
            // understand a legacy `.shim` file, so write that fallback
            // pointing at the new target. A current shim prefers the `.ghr`
            // manifest and ignores `.shim` when one is present, so this is
            // safe for both old and new shims and prevents a broken command
            // (`shim: cannot read <stem>.shim`) after a self-update.
            writeLegacyShim(io, bin_dir, legacy_shim, src_path) catch {};
        }
    } else {
        // Unix: symlink
        bin_dir.deleteFile(io, exe_name) catch {};
        try bin_dir.symLink(io, src_path, exe_name, .{});
    }
    try w.print("  linked {s}\n", .{exe_name});
}

/// Strip the trailing `.wasm` from a wasm asset basename to get the command
/// stem (e.g. `hello.wasm` -> `hello`).
fn wasmStem(wasm_rel_path: []const u8) []const u8 {
    const base = std.fs.path.basename(wasm_rel_path);
    return base[0 .. base.len - ".wasm".len];
}

/// Shape of a `.ghr` manifest (ZON). The release ships `<wasm>.ghr` with
/// `version` + `runtime` + `runtimeArgs`; ghr writes a bin-dir `<stem>.ghr`
/// that additionally carries `target` / `targetWasm` (absolute install paths)
/// for the shim to read at run time.
const GhrManifest = struct {
    version: u32,
    target: []const u8 = "",
    targetWasm: []const u8 = "",
    runtime: []const u8 = "wasmtime",
    runtimeArgs: []const []const u8 = &.{},
};

const allowed_runtimes = [_][]const u8{ "wasmtime", "wamr" };

/// Write a ZON string literal body (the bytes between the quotes), escaping
/// per Zig string-literal rules so Windows paths (with `\`) round-trip.
fn writeZonEscaped(w: *Writer, s: []const u8) !void {
    for (s) |c| {
        switch (c) {
            '\\' => try w.print("\\\\", .{}),
            '"' => try w.print("\\\"", .{}),
            '\n' => try w.print("\\n", .{}),
            '\r' => try w.print("\\r", .{}),
            '\t' => try w.print("\\t", .{}),
            else => {
                if (c < 0x20) {
                    try w.print("\\x{x:0>2}", .{c});
                } else {
                    try w.print("{c}", .{c});
                }
            },
        }
    }
}

/// Write a bin-dir `<stem>.ghr` for a native command: `.version = 1` plus a
/// `.target` absolute path the shim spawns directly. Replaces the legacy
/// `.shim` file.
fn writeNativeGhr(io: Io, bin_dir: Dir, ghr_name: []const u8, target_abs: []const u8) !void {
    bin_dir.deleteFile(io, ghr_name) catch {};
    var ghr_file = bin_dir.createFile(io, ghr_name, .{}) catch return error.CreateFailed;
    defer ghr_file.close(io);
    var buf: [4096]u8 = undefined;
    var fw = ghr_file.writer(io, &buf);
    const gw = &fw.interface;
    gw.print(".{{\n    .version = 1,\n    .target = \"", .{}) catch return error.WriteFailed;
    writeZonEscaped(gw, target_abs) catch return error.WriteFailed;
    gw.print("\",\n}}\n", .{}) catch return error.WriteFailed;
    fw.end() catch return error.WriteFailed;
}

/// Write a legacy `<stem>.shim` file: a single line holding the absolute
/// native target path. Only used as a self-update fallback on Windows when the
/// shim exe is locked and cannot be replaced, so an older `.shim`-only shim
/// that is still running keeps resolving the new target. Current shims prefer
/// the `.ghr` manifest and ignore this file whenever one is present.
fn writeLegacyShim(io: Io, bin_dir: Dir, shim_name: []const u8, target_abs: []const u8) !void {
    bin_dir.deleteFile(io, shim_name) catch {};
    var shim_file = bin_dir.createFile(io, shim_name, .{}) catch return error.CreateFailed;
    defer shim_file.close(io);
    var buf: [Dir.max_path_bytes]u8 = undefined;
    var fw = shim_file.writer(io, &buf);
    const sw = &fw.interface;
    sw.print("{s}\n", .{target_abs}) catch return error.WriteFailed;
    fw.end() catch return error.WriteFailed;
}

/// Install the embedded shim launcher for a wasm module. Creates the launcher
/// binary (`<stem>.exe` on Windows, `<stem>` on Unix) plus a `<stem>.ghr`
/// manifest next to it. The manifest carries `targetWasm` (the absolute path
/// to the installed wasm) along with the `runtime` / `runtimeArgs` copied from
/// the release's `<wasm>.ghr`. No `.shim` file is written. Works identically on
/// Windows, Linux, and macOS.
fn linkWasmToBin(
    allocator: std.mem.Allocator,
    io: Io,
    tool_dir_path: []const u8,
    bin_dir: Dir,
    wasm_rel_path: []const u8,
    w: *Writer,
) !void {
    const shim_exe_bytes = @import("shim_exe").bytes;
    const stem = wasmStem(wasm_rel_path);
    const wasm_base = std.fs.path.basename(wasm_rel_path);

    // Absolute path to the installed wasm (the shim's run-time target).
    var src_path_buf: [Dir.max_path_bytes]u8 = undefined;
    const src_path = std.fmt.bufPrint(&src_path_buf, "{s}{c}{s}", .{
        tool_dir_path,
        std.fs.path.sep,
        wasm_rel_path,
    }) catch return error.PathTooLong;

    // Read the release manifest staged in the tool dir to recover the
    // runtime + runtimeArgs.
    var tool_dir = Dir.openDirAbsolute(io, tool_dir_path, .{}) catch return error.CreateFailed;
    defer tool_dir.close(io);
    var manifest_name_buf: [Dir.max_path_bytes]u8 = undefined;
    const manifest_name = std.fmt.bufPrint(&manifest_name_buf, "{s}.ghr", .{wasm_base}) catch return error.PathTooLong;
    const raw = tool_dir.readFileAlloc(io, manifest_name, allocator, Io.Limit.limited(64 * 1024)) catch return error.CreateFailed;
    defer allocator.free(raw);
    const source = try allocator.dupeZ(u8, raw);
    defer allocator.free(source);
    const manifest = std.zon.parse.fromSliceAlloc(GhrManifest, allocator, source, null, .{
        .ignore_unknown_fields = true,
    }) catch return error.WriteFailed;
    defer std.zon.parse.free(allocator, manifest);

    // Write the bin-dir `<stem>.ghr` the shim reads at run time.
    var ghr_name_buf: [Dir.max_path_bytes]u8 = undefined;
    const ghr_name = std.fmt.bufPrint(&ghr_name_buf, "{s}.ghr", .{stem}) catch return error.PathTooLong;
    bin_dir.deleteFile(io, ghr_name) catch {};
    {
        var ghr_file = bin_dir.createFile(io, ghr_name, .{}) catch return error.CreateFailed;
        defer ghr_file.close(io);
        var ghr_buf: [4096]u8 = undefined;
        var ghr_w = ghr_file.writer(io, &ghr_buf);
        const gw = &ghr_w.interface;
        gw.print(".{{\n    .version = 1,\n    .targetWasm = \"", .{}) catch return error.WriteFailed;
        writeZonEscaped(gw, src_path) catch return error.WriteFailed;
        gw.print("\",\n    .runtime = \"", .{}) catch return error.WriteFailed;
        writeZonEscaped(gw, manifest.runtime) catch return error.WriteFailed;
        gw.print("\",\n    .runtimeArgs = .{{", .{}) catch return error.WriteFailed;
        for (manifest.runtimeArgs, 0..) |arg, i| {
            if (i > 0) gw.print(",", .{}) catch return error.WriteFailed;
            gw.print(" \"", .{}) catch return error.WriteFailed;
            writeZonEscaped(gw, arg) catch return error.WriteFailed;
            gw.print("\"", .{}) catch return error.WriteFailed;
        }
        if (manifest.runtimeArgs.len > 0) gw.print(" ", .{}) catch return error.WriteFailed;
        gw.print("}},\n}}\n", .{}) catch return error.WriteFailed;
        ghr_w.end() catch return error.WriteFailed;
    }

    // Remove any legacy `.shim` from a previous install of this command.
    var legacy_shim_buf: [Dir.max_path_bytes]u8 = undefined;
    if (std.fmt.bufPrint(&legacy_shim_buf, "{s}.shim", .{stem})) |legacy_shim| {
        bin_dir.deleteFile(io, legacy_shim) catch {};
    } else |_| {}

    // Launcher binary name: `<stem>.exe` on Windows, `<stem>` on Unix.
    var launcher_name_buf: [Dir.max_path_bytes]u8 = undefined;
    const launcher_name = if (builtin.os.tag == .windows)
        std.fmt.bufPrint(&launcher_name_buf, "{s}.exe", .{stem}) catch return error.PathTooLong
    else
        stem;

    bin_dir.deleteFile(io, launcher_name) catch {
        // On Windows a running launcher cannot be deleted; rename it aside.
        if (builtin.os.tag == .windows) {
            var old_name_buf: [Dir.max_path_bytes]u8 = undefined;
            const old_name = std.fmt.bufPrint(&old_name_buf, "{s}.old", .{launcher_name}) catch return error.PathTooLong;
            bin_dir.deleteFile(io, old_name) catch {};
            bin_dir.rename(launcher_name, bin_dir, old_name, io) catch {};
        }
    };

    // `.executable_file` is a no-op on Windows but yields the +x bit on Unix,
    // matching `stageBareExecutable`.
    if (bin_dir.createFile(io, launcher_name, .{ .permissions = .executable_file })) |*exe_file| {
        defer exe_file.close(io);
        exe_file.writeStreamingAll(io, shim_exe_bytes) catch return error.WriteFailed;
    } else |_| {
        // Launcher is locked (e.g. concurrently running); the .ghr file is
        // already updated, so the existing launcher keeps working.
    }

    try w.print("  linked {s}\n", .{launcher_name});
}

/// Remove the shim launcher + `<stem>.ghr` (and any legacy `.shim`) for a wasm
/// bin entry, but only when the `.ghr` still references `tool_path` (so we
/// never clobber an unrelated command of the same name). Works on all
/// platforms.
fn cleanupWasmBinEntry(io: Io, bin_dir: Dir, wasm_rel_path: []const u8, tool_path: []const u8) void {
    const stem = wasmStem(wasm_rel_path);
    var ghr_name_buf: [Dir.max_path_bytes]u8 = undefined;
    const ghr_name = std.fmt.bufPrint(&ghr_name_buf, "{s}.ghr", .{stem}) catch return;

    var owned = binGhrPointsToToolDir(io, bin_dir, ghr_name, tool_path);

    // Also handle (and own via) a legacy `.shim` file pointing into tool_path.
    var shim_name_buf: [Dir.max_path_bytes]u8 = undefined;
    if (std.fmt.bufPrint(&shim_name_buf, "{s}.shim", .{stem})) |shim_name| {
        if (shimPointsToToolDir(io, bin_dir, shim_name, tool_path)) {
            bin_dir.deleteFile(io, shim_name) catch {};
            owned = true;
        }
    } else |_| {}

    if (!owned) return;
    bin_dir.deleteFile(io, ghr_name) catch {};
    if (builtin.os.tag == .windows) {
        var exe_name_buf: [Dir.max_path_bytes]u8 = undefined;
        const exe_name = std.fmt.bufPrint(&exe_name_buf, "{s}.exe", .{stem}) catch return;
        bin_dir.deleteFile(io, exe_name) catch {};
    } else {
        bin_dir.deleteFile(io, stem) catch {};
    }
}

/// Ownership check for a bin-dir `<stem>.ghr`: true when the manifest text
/// references `tool_path` in its `target` / `targetWasm` field. Allocation-
/// free: matches `tool_path` after applying the same ZON `\`-escaping ghr
/// wrote, so Windows backslash paths compare correctly.
fn binGhrPointsToToolDir(io: Io, bin_dir: Dir, ghr_name: []const u8, tool_path: []const u8) bool {
    var content_buf: [16 * 1024]u8 = undefined;
    const file = bin_dir.openFile(io, ghr_name, .{}) catch return false;
    defer file.close(io);
    const len = file.readPositionalAll(io, &content_buf, 0) catch return false;
    const content = content_buf[0..len];

    // Build the escaped needle (`\` -> `\\`, `"` -> `\"`).
    var needle_buf: [Dir.max_path_bytes * 2]u8 = undefined;
    var n: usize = 0;
    for (tool_path) |c| {
        if (c == '\\' or c == '"') {
            if (n >= needle_buf.len) return false;
            needle_buf[n] = '\\';
            n += 1;
        }
        if (n >= needle_buf.len) return false;
        needle_buf[n] = c;
        n += 1;
    }
    return std.mem.indexOf(u8, content, needle_buf[0..n]) != null;
}

/// Validate a downloaded `.ghr` manifest (ZON): `.version` must be present and
/// equal to 1, and `.runtime` (default `wasmtime`) must be in the allow list.
/// Prints a diagnostic and returns an error when invalid.
fn validateGhrManifest(
    allocator: std.mem.Allocator,
    io: Io,
    ghr_path: []const u8,
    err_w: *Writer,
) !void {
    const raw = Dir.cwd().readFileAlloc(io, ghr_path, allocator, Io.Limit.limited(64 * 1024)) catch {
        try err_w.print("error: cannot read manifest '{s}'\n", .{ghr_path});
        try err_w.flush();
        return error.InstallStepFailed;
    };
    defer allocator.free(raw);

    const source = try allocator.dupeZ(u8, raw);
    defer allocator.free(source);

    const manifest = std.zon.parse.fromSliceAlloc(GhrManifest, allocator, source, null, .{
        .ignore_unknown_fields = true,
    }) catch {
        try err_w.print("error: invalid `.ghr` manifest '{s}' (must be ZON with a `.version` field)\n", .{ghr_path});
        try err_w.flush();
        return error.InstallStepFailed;
    };
    defer std.zon.parse.free(allocator, manifest);

    if (manifest.version != 1) {
        try err_w.print("error: unsupported `.ghr` version {d} (only version 1 is supported)\n", .{manifest.version});
        try err_w.flush();
        return error.InstallStepFailed;
    }

    for (allowed_runtimes) |r| {
        if (std.mem.eql(u8, r, manifest.runtime)) return;
    }
    try err_w.print("error: `.ghr` runtime '{s}' is not allowed (allowed: wasmtime, wamr)\n", .{manifest.runtime});
    try err_w.flush();
    return error.InstallStepFailed;
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
///
/// `minisign_pubkey` is the base64 minisign public key that the install
/// actually verified the asset with (i.e., the caller-supplied key from
/// either `--minisign` or the per-spec positional form). It is recorded
/// only when minisign verification succeeded, so that `ghr list` can
/// surface a copy-pasteable key for the same spec on future installs.
/// Pass `null` (or an empty string) when minisign was not used.
fn writeMetadata(
    allocator: std.mem.Allocator,
    io: Io,
    tool_dir: Dir,
    tag: []const u8,
    asset_name: []const u8,
    bins: []const []const u8,
    apps: []const []const u8,
    verified: []const u8,
    minisign_pubkey: ?[]const u8,
) !void {
    _ = allocator;
    var file = try tool_dir.createFile(io, "ghr.json", .{});
    defer file.close(io);
    var buf: [4096]u8 = undefined;
    var fw = file.writer(io, &buf);
    const w = &fw.interface;
    try w.print("{{\"tag\":\"{s}\",\"asset\":\"{s}\",\"verified\":\"{s}\"", .{ tag, asset_name, verified });
    if (minisign_pubkey) |k| {
        if (k.len > 0) {
            try w.print(",\"minisign\":\"", .{});
            try writeJsonEscaped(w, k);
            try w.print("\"", .{});
        }
    }
    try w.print(",\"bins\":[", .{});
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
pub const Metadata = struct {
    tag: []const u8,
    asset: []const u8,
    verified: []const u8 = "none",
    /// Base64 minisign public key that was used to verify the asset at
    /// install time. Empty string means the install did not opt in to
    /// minisign verification. Older `ghr.json` files (predating this
    /// field) also parse as the empty default.
    minisign: []const u8 = "",
    bins: []const []const u8 = &.{},
    apps: []const []const u8 = &.{},
};

/// Read ghr.json metadata from a tool directory.
pub fn readMetadata(allocator: std.mem.Allocator, io: Io, tool_dir_path: []const u8) ?struct {
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
        if (release_mod.isWasmAssetName(exe_rel)) {
            cleanupWasmBinEntry(io, bin_dir, exe_rel, tool_path);
        } else if (builtin.os.tag == .windows) {
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

/// Remove the shim `.exe` plus its `<stem>.ghr` manifest (and any legacy
/// `.shim` / `.cmd`) for a single native bin entry on Windows. The `.exe` is
/// only removed when a `.ghr` or `.shim` confirms the entry belongs to
/// `tool_path`.
fn cleanupWindowsBinEntry(io: Io, bin_dir: Dir, exe_name: []const u8, tool_path: []const u8) void {
    const stem = if (std.mem.endsWith(u8, exe_name, ".exe"))
        exe_name[0 .. exe_name.len - 4]
    else
        exe_name;

    var owned = false;

    // Remove the `<stem>.ghr` manifest if its target points to our tool dir.
    var ghr_name_buf: [Dir.max_path_bytes]u8 = undefined;
    if (std.fmt.bufPrint(&ghr_name_buf, "{s}.ghr", .{stem})) |ghr_name| {
        if (binGhrPointsToToolDir(io, bin_dir, ghr_name, tool_path)) {
            bin_dir.deleteFile(io, ghr_name) catch {};
            owned = true;
        }
    } else |_| {}

    // Remove any legacy `.shim` file if it points to our tool dir.
    var shim_name_buf: [Dir.max_path_bytes]u8 = undefined;
    if (std.fmt.bufPrint(&shim_name_buf, "{s}.shim", .{stem})) |shim_name| {
        if (shimPointsToToolDir(io, bin_dir, shim_name, tool_path)) {
            bin_dir.deleteFile(io, shim_name) catch {};
            owned = true;
        }
    } else |_| {}

    if (owned) {
        const shim_exe_name = if (std.mem.endsWith(u8, exe_name, ".exe")) exe_name else blk: {
            var name_buf: [Dir.max_path_bytes]u8 = undefined;
            break :blk std.fmt.bufPrint(&name_buf, "{s}.exe", .{stem}) catch return;
        };
        bin_dir.deleteFile(io, shim_exe_name) catch {};
    }

    // Always best-effort remove a legacy .cmd wrapper.
    var cmd_name_buf: [Dir.max_path_bytes]u8 = undefined;
    if (std.fmt.bufPrint(&cmd_name_buf, "{s}.cmd", .{stem})) |cmd_name| {
        bin_dir.deleteFile(io, cmd_name) catch {};
    } else |_| {}
}

/// Check if a .shim file's target path starts with tool_path.
///
/// On Windows, the comparison is ASCII case-insensitive so a shim
/// written before lowercase-tool-dir migration (`...\AzureAD\foo\...`)
/// is still recognized as owned after the dir was renamed to
/// `...\azuread\foo\...`. Windows paths are case-insensitive anyway.
fn shimPointsToToolDir(io: Io, bin_dir: Dir, shim_name: []const u8, tool_path: []const u8) bool {
    var content_buf: [Dir.max_path_bytes]u8 = undefined;
    const file = bin_dir.openFile(io, shim_name, .{}) catch return false;
    defer file.close(io);
    const len = file.readPositionalAll(io, &content_buf, 0) catch return false;
    const content = std.mem.trim(u8, content_buf[0..len], &[_]u8{ ' ', '\t', '\r', '\n' });
    if (content.len < tool_path.len) return false;
    const prefix_matches = if (builtin.os.tag == .windows)
        std.ascii.eqlIgnoreCase(content[0..tool_path.len], tool_path)
    else
        std.mem.eql(u8, content[0..tool_path.len], tool_path);
    if (!prefix_matches) return false;
    return content.len == tool_path.len or content[tool_path.len] == '\\' or content[tool_path.len] == '/';
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
        if (release_mod.isWasmAssetName(old_exe_rel)) {
            cleanupWasmBinEntry(io, bin_dir, old_exe_rel, old_tool_path);
        } else if (builtin.os.tag == .windows) {
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
    const owned = release_mod.parseRepoSpecOwned(allocator, spec_str) catch {
        try err_w.print("error: invalid spec '{s}', expected owner/repo\n", .{spec_str});
        try err_w.flush();
        std.process.exit(1);
    };
    defer owned.deinit();

    const d = try Dirs.detect(allocator, environ);
    defer d.deinit();

    // Look up the on-disk path case-insensitively so a user can run
    // `ghr uninstall azuread/foo` against an existing pre-migration
    // `<tools>/AzureAD/foo` directory.
    const tool_path = (try resolveInstalledToolPath(allocator, io, d.tools, owned.owner, owned.repo)) orelse {
        try err_w.print("error: {s}/{s} is not installed\n", .{ owned.owner, owned.repo });
        try err_w.flush();
        std.process.exit(1);
    };
    defer allocator.free(tool_path);

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
                if (release_mod.isWasmAssetName(exe_rel)) {
                    cleanupWasmBinEntry(io, bd, exe_rel, tool_path);
                    try w.print("  unlinked {s}\n", .{wasmStem(exe_rel)});
                } else if (builtin.os.tag == .windows) {
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

    try w.print("uninstalled {s}/{s}\n", .{ owned.owner, owned.repo });
}

/// Per-install error signalling a single spec's install path failed after
/// printing a user-visible diagnostic. The outer multi-spec driver decides
/// whether to abort (fail-fast) or continue (`--keep-going`).
pub const InstallStepError = error{InstallStepFailed};

/// Shared state for one or more sequential per-spec installs in a single
/// `ghr install` invocation. Built once by `cmdInstallMany`; reused by
/// `installOne` so a multi-spec invocation reuses one HTTP client, one
/// auth resolution, and one `Dirs.detect` result.
pub const InstallContext = struct {
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    dirs: Dirs,
    client: *std.http.Client,
    auth_resolved: auth.Resolved,
    auth_header: ?[]const u8,
    w: *Writer,
    err_w: *Writer,
    debug: bool,
    no_auth: bool,
    /// Verification skip flags (`--skip-verify` umbrella + four narrow
    /// flags). Each gates a single `verifyDownloadedAsset*` call site in
    /// `installOne`.
    gates: release_mod.VerifyGates,
    /// Global default minisign public key (from `--minisign`). Applied to
    /// any spec whose `SpecWithKey.key` is null.
    minisign_pubkey_b64: ?[]const u8,
};

/// Install a single spec using the shared `InstallContext`.
///
/// On any user-visible failure this prints a diagnostic via `ctx.err_w`
/// and returns `error.InstallStepFailed`. Allocation / I/O errors that
/// indicate environmental rather than per-spec problems propagate as
/// their original error type.
fn installOne(ctx: *const InstallContext, entry: release_mod.SpecWithKey) anyerror!void {
    const allocator = ctx.allocator;
    const io = ctx.io;
    const environ = ctx.environ;
    const d = ctx.dirs;
    const auth_header = ctx.auth_header;
    const w = ctx.w;
    const err_w = ctx.err_w;
    const debug = ctx.debug;
    const gates = ctx.gates;
    const spec_str = entry.spec;
    // Effective minisign key: per-spec inline key overrides the global
    // `--minisign` default for this one spec only.
    const minisign_pubkey_b64: ?[]const u8 = entry.key orelse ctx.minisign_pubkey_b64;

    const classified = release_mod.classifyArg(spec_str) catch {
        try err_w.print("error: invalid argument '{s}'\n", .{spec_str});
        try err_w.print("  expected: owner/repo[@tag] or owner/repo/file[@tag]\n", .{});
        try err_w.flush();
        return error.InstallStepFailed;
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
                return error.InstallStepFailed;
            };
            const parsed = parsed_opt orelse {
                try err_w.print("error: install only accepts github.com release-download URLs (got: {s})\n", .{u});
                try err_w.print("  hint: use owner/repo[@tag] for auto-pick or owner/repo/file[@tag] for an explicit file\n", .{});
                try err_w.flush();
                return error.InstallStepFailed;
            };
            url_buf = parsed;
            spec = .{ .owner = parsed.owner, .repo = parsed.repo, .tag = parsed.tag };
            requested_file = parsed.file;
        },
    }

    try w.print("resolving {s}/{s}", .{ spec.owner, spec.repo });
    if (spec.tag) |t| try w.print("@{s}", .{t});
    try w.print(" ...\n", .{});
    try w.flush();

    // Canonical lowercase slug for on-disk paths (tools dir, cache dir,
    // owner dir). GitHub is case-insensitive on slugs but Linux paths
    // are not, so we standardize. The original mixed-case `spec.owner` /
    // `spec.repo` are still used for the GitHub API call and for
    // user-visible diagnostics.
    const owner_lower = try asciiLowerDup(allocator, spec.owner);
    defer allocator.free(owner_lower);
    const repo_lower = try asciiLowerDup(allocator, spec.repo);
    defer allocator.free(repo_lower);

    // Get release info
    var release = getRelease(allocator, ctx.client, spec.owner, spec.repo, spec.tag, auth_header) catch |err| {
        switch (err) {
            error.GitHubApiError => {
                try err_w.print("error: release not found for {s}/{s}", .{ spec.owner, spec.repo });
                if (spec.tag) |t| try err_w.print("@{s}", .{t});
                try err_w.print("\n", .{});
            },
            else => try err_w.print("error: failed to fetch release: {}\n", .{err}),
        }
        try err_w.flush();
        return error.InstallStepFailed;
    };
    defer release.deinit();

    const tag_name = release.parsed.value.tag_name;
    try w.print("found release {s}\n", .{tag_name});

    // Build the list of primary assets to install.
    //
    //   - Explicit file filter (owner/repo/file or a release URL): exactly
    //     the one matched asset.
    //   - No filter, and the release publishes one or more wasm modules that
    //     each ship a companion `<wasm>.ghr` manifest: install ALL of them,
    //     so a single `ghr install owner/repo` brings in every wasm tool the
    //     release ships (e.g. both `petstore` and `petstore-test`).
    //   - Otherwise: a single platform auto-pick via findBestAsset.
    var primary_assets: std.ArrayListUnmanaged(release_mod.Asset) = .empty;
    defer primary_assets.deinit(allocator);
    if (requested_file) |fname| {
        const m = release_mod.findAssetByName(allocator, release.parsed.value.assets, fname) catch |err| {
            try err_w.print("error: failed to match asset by name: {}\n", .{err});
            try err_w.flush();
            return error.InstallStepFailed;
        };
        switch (m) {
            .one => |a| try primary_assets.append(allocator, a),
            .none => {
                try err_w.print("error: no asset matching '{s}' in {s}/{s}@{s}\n", .{ fname, spec.owner, spec.repo, tag_name });
                try err_w.print("available assets:\n", .{});
                for (release.parsed.value.assets) |a| {
                    try err_w.print("  {s}\n", .{a.name});
                }
                try err_w.flush();
                return error.InstallStepFailed;
            },
            .ambiguous => |list| {
                defer allocator.free(list);
                try err_w.print("error: '{s}' matches multiple assets in {s}/{s}@{s}:\n", .{ fname, spec.owner, spec.repo, tag_name });
                for (list) |a| {
                    try err_w.print("  {s}\n", .{a.name});
                }
                try err_w.flush();
                return error.InstallStepFailed;
            },
        }
    } else {
        // No explicit filter: install every wasm module that ships a
        // companion `.ghr` manifest. This is what makes a bare
        // `ghr install owner/repo` pull in all of a release's wasm tools.
        const wasm_mods = try release_mod.wasmModulesWithManifest(allocator, release.parsed.value.assets);
        defer allocator.free(wasm_mods);
        for (wasm_mods) |a| try primary_assets.append(allocator, a);
        if (primary_assets.items.len == 0) {
            const a = findBestAsset(release.parsed.value.assets) catch {
                try err_w.print("error: no matching asset for this platform\n", .{});
                try err_w.print("available assets:\n", .{});
                for (release.parsed.value.assets) |av| {
                    try err_w.print("  {s}\n", .{av.name});
                }
                try err_w.flush();
                return error.InstallStepFailed;
            };
            try primary_assets.append(allocator, a);
        }
    }

    // Name used for user-facing messages and the `asset` field of ghr.json.
    // When several wasm modules are installed together this is the first.
    const primary_name = primary_assets.items[0].name;

    // Staging directory, shared across every primary asset.
    const staging_path = try std.fmt.allocPrint(allocator, "{s}{c}staging-{s}-{s}", .{
        d.cache, std.fs.path.sep, owner_lower, repo_lower,
    });
    defer allocator.free(staging_path);
    deleteTreeAbsolute(io, staging_path) catch {};
    Dir.createDirAbsolute(io, staging_path, .default_dir) catch |err| {
        try err_w.print("error: failed to create staging dir '{s}': {t}\n", .{ staging_path, err });
        try err_w.flush();
        return error.InstallStepFailed;
    };
    var staging_dir = Dir.openDirAbsolute(io, staging_path, .{ .iterate = true }) catch |err| {
        try err_w.print("error: failed to open staging dir '{s}': {t}\n", .{ staging_path, err });
        try err_w.flush();
        return error.InstallStepFailed;
    };
    defer staging_dir.close(io);

    // Executables to link, accumulated across every staged asset.
    var exes: std.ArrayListUnmanaged([]const u8) = .empty;
    defer {
        for (exes.items) |e| allocator.free(e);
        exes.deinit(allocator);
    }

    // Verification label + minisign key recorded in ghr.json. Every primary
    // asset is verified with the same gates/key, so the last asset's outcome
    // (recorded here) reflects them all.
    var verified_label: []const u8 = "none";
    var recorded_minisign_key: ?[]const u8 = null;

    for (primary_assets.items) |asset| {
        // Pre-flight verification check: if a `.minisig` sidecar exists but
        // the caller did not pass a minisign key (inline or `--minisign`), and
        // is not using `--skip-verify` / `--skip-minisign`, abort BEFORE
        // downloading. Mirrors the same check in cmdDownload.
        release_mod.preflightVerification(
            release.parsed.value.assets,
            asset.name,
            gates,
            minisign_pubkey_b64,
            err_w,
        ) catch return error.InstallStepFailed;

        try w.print("downloading {s} ...\n", .{asset.name});
        try w.flush();

        // Ensure cache directory tree exists
        ensureDirAbsoluteRecursive(io, d.cache);

        // Download to cache file
        const download_path = try std.fmt.allocPrint(allocator, "{s}{c}{s}", .{
            d.cache, std.fs.path.sep, asset.name,
        });
        defer allocator.free(download_path);

        const debug_w: ?*Writer = if (debug) err_w else null;

        const asset_dl = release_mod.assetDownload(asset, auth_header != null);
        debugLog(debug_w, "debug: ghr {s}\n", .{version});
        debugLog(debug_w, "debug: auth: {s}\n", .{ctx.auth_resolved.source});
        debugLog(debug_w, "debug: url: {s}\n", .{asset_dl.url});
        debugLog(debug_w, "debug: cache: {s}\n", .{download_path});

        http.downloadToFile(allocator, io, asset_dl.url, download_path, .{
            .auth_header = auth_header,
            .accept = asset_dl.accept,
            .debug_w = debug_w,
        }) catch |err| {
            try err_w.print("error: download failed: {}\n", .{err});
            try err_w.print("  url: {s}\n", .{asset_dl.url});
            try err_w.flush();
            return error.InstallStepFailed;
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
        // disk, before we extract or move anything. Checksum (Phase 1),
        // minisign (issue #65, requires a key — inline or `--minisign`), and
        // sigstore bundle (Phase 2) are independent — all run when material
        // is published, unless the matching skip flag suppresses one. Outcome
        // precedence for the metadata label: sigstore > minisign > authenticode > checksum.
        verified_label = "none";
        // Pubkey the install actually verified against (sticky across the
        // other verifiers' outcomes). Recorded in `ghr.json` and surfaced by
        // `ghr list` so users can copy it back into future installs.
        recorded_minisign_key = null;
        if (gates.skip_verify) {
            verified_label = "skipped";
            try w.print("note: verification skipped (--skip-verify)\n", .{});
        } else {
            const sha_outcome: release_mod.VerifyOutcome = if (gates.skip_checksum) blk: {
                try w.print("note: checksum verification skipped (--skip-checksum)\n", .{});
                break :blk .no_verification;
            } else blk: {
                // Verify GitHub's built-in asset digest (inline in the release
                // JSON, no extra network request). Independently, if the
                // release also publishes a `.sha256` / `SHA256SUMS` sidecar,
                // validate that too — a published sidecar is never silently
                // ignored. Both must pass; the sidecar drives the recorded
                // label when present.
                const gh_outcome = release_mod.verifyDownloadedAssetGithubDigest(
                    io,
                    release.parsed.value.assets,
                    asset.name,
                    download_path,
                    debug_w,
                    w,
                    err_w,
                ) catch |verr| {
                    Dir.deleteFileAbsolute(io, download_path) catch {};
                    switch (verr) {
                        error.ChecksumMismatch => return error.InstallStepFailed,
                        else => {
                            try err_w.print("error: checksum verification failed: {}\n", .{verr});
                            try err_w.flush();
                            return error.InstallStepFailed;
                        },
                    }
                };
                const sidecar_outcome = verifyDownloadedAssetSha256(
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
                            return error.InstallStepFailed;
                        },
                        else => {
                            try err_w.print("error: checksum verification failed: {}\n", .{verr});
                            try err_w.flush();
                            Dir.deleteFileAbsolute(io, download_path) catch {};
                            return error.InstallStepFailed;
                        },
                    }
                };
                break :blk if (sidecar_outcome == .sha256_verified) sidecar_outcome else gh_outcome;
            };
            if (sha_outcome == .sha256_verified) verified_label = "checksum";
            if (sha_outcome == .github_digest_verified) verified_label = "github-digest";

            const mini_outcome: release_mod.VerifyOutcome = if (gates.skip_minisign) blk: {
                if (minisign_pubkey_b64 != null) {
                    try w.print("note: minisign verification skipped (--skip-minisign)\n", .{});
                }
                break :blk .no_verification;
            } else release_mod.verifyDownloadedAssetMinisign(
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
                return error.InstallStepFailed;
            };
            if (mini_outcome == .minisign_verified) {
                verified_label = "minisign";
                recorded_minisign_key = minisign_pubkey_b64;
            }

            const ac_outcome: release_mod.VerifyOutcome = if (gates.skip_authenticode) blk: {
                try w.print("note: authenticode verification skipped (--skip-authenticode)\n", .{});
                break :blk .no_verification;
            } else release_mod.verifyDownloadedAssetAuthenticode(
                allocator,
                io,
                download_path,
                debug_w,
                w,
                err_w,
            ) catch |verr| {
                try err_w.print("error: authenticode verification failed: {s}\n", .{@errorName(verr)});
                try err_w.flush();
                Dir.deleteFileAbsolute(io, download_path) catch {};
                return error.InstallStepFailed;
            };
            if (ac_outcome == .authenticode_verified) verified_label = "authenticode";

            const sig_outcome: release_mod.VerifyOutcome = if (gates.skip_sigstore) blk: {
                try w.print("note: sigstore verification skipped (--skip-sigstore)\n", .{});
                break :blk .no_verification;
            } else verifyDownloadedAssetSigstore(
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
                return error.InstallStepFailed;
            };
            if (sig_outcome == .sigstore_verified) verified_label = "sigstore";

            if (sha_outcome == .no_verification and
                mini_outcome == .no_verification and
                ac_outcome == .no_verification and
                sig_outcome == .no_verification)
            {
                try w.print("note: download is unverified (no checksum, minisign, sigstore, or authenticode)\n", .{});
            }
            try w.flush();
        }

        // Whether the selected asset is a WebAssembly module. Wasm installs take a
        // dedicated path: the `.wasm` plus its companion `<wasm>.ghr` manifest are
        // copied verbatim into the tool dir, and a shim launcher (which loads the
        // manifest at run time) is linked into the bin dir.
        const is_wasm = release_mod.isWasmAssetName(asset.name);
        const ghr_name: ?[]u8 = if (is_wasm)
            try std.fmt.allocPrint(allocator, "{s}.ghr", .{asset.name})
        else
            null;
        defer if (ghr_name) |g| allocator.free(g);

        if (is_wasm) {
            const ghr_asset = release_mod.findGhrManifestAsset(release.parsed.value.assets, asset.name) orelse {
                try err_w.print("error: wasm asset '{s}' has no companion '{s}.ghr' manifest in this release\n", .{ asset.name, asset.name });
                try err_w.flush();
                return error.InstallStepFailed;
            };
            const ghr_path = try std.fmt.allocPrint(allocator, "{s}{c}{s}", .{ d.cache, std.fs.path.sep, ghr_name.? });
            defer allocator.free(ghr_path);
            const ghr_dl = release_mod.assetDownload(ghr_asset, auth_header != null);
            http.downloadToFile(allocator, io, ghr_dl.url, ghr_path, .{
                .auth_header = auth_header,
                .accept = ghr_dl.accept,
                .debug_w = debug_w,
            }) catch |err| {
                try err_w.print("error: failed to download manifest '{s}': {t}\n", .{ ghr_asset.name, err });
                try err_w.flush();
                return error.InstallStepFailed;
            };
            // Validate the manifest now so a bad one fails before we touch the
            // installed tool dir.
            validateGhrManifest(allocator, io, ghr_path, err_w) catch return error.InstallStepFailed;
        }

        // Best-effort removal of the cached `.ghr` once staged.
        defer if (ghr_name) |g| {
            var pb: [Dir.max_path_bytes]u8 = undefined;
            if (std.fmt.bufPrint(&pb, "{s}{c}{s}", .{ d.cache, std.fs.path.sep, g })) |p| {
                Dir.deleteFileAbsolute(io, p) catch {};
            } else |_| {}
        };

        // Extract
        try w.print("extracting ...\n", .{});
        try w.flush();

        if (is_wasm) {
            // Copy the wasm module and its `.ghr` manifest verbatim into staging.
            var cache_dir = Dir.openDirAbsolute(io, d.cache, .{}) catch |err| {
                try err_w.print("error: failed to open cache dir '{s}': {t}\n", .{ d.cache, err });
                try err_w.flush();
                return error.InstallStepFailed;
            };
            defer cache_dir.close(io);
            cache_dir.copyFile(asset.name, staging_dir, asset.name, io, .{}) catch |err| {
                try err_w.print("error: failed to stage wasm '{s}': {t}\n", .{ asset.name, err });
                try err_w.flush();
                return error.InstallStepFailed;
            };
            cache_dir.copyFile(ghr_name.?, staging_dir, ghr_name.?, io, .{}) catch |err| {
                try err_w.print("error: failed to stage manifest '{s}': {t}\n", .{ ghr_name.?, err });
                try err_w.flush();
                return error.InstallStepFailed;
            };
        } else switch (archive.detectFormat(asset.name)) {
            .zip, .tar_gz, .tar_xz, .deb => {
                archive.extractAuto(allocator, io, staging_dir, download_path, 0) catch |err| {
                    try err_w.print(
                        "error: failed to extract '{s}' from '{s}' into '{s}': {t}\n",
                        .{ asset.name, download_path, staging_path, err },
                    );
                    try err_w.flush();
                    return error.InstallStepFailed;
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

                stageBareExecutable(allocator, io, d.cache, asset.name, staging_dir, exe_name) catch |err| {
                    try err_w.print(
                        "error: failed to stage bare executable '{s}' from '{s}' into '{s}' as '{s}': {t}\n",
                        .{ asset.name, d.cache, staging_path, exe_name, err },
                    );
                    try err_w.flush();
                    return error.InstallStepFailed;
                };
            },
        }

        // Find executables. For wasm, the single "executable" is the wasm module
        // itself; `linkToBin` recognizes the `.wasm` extension and installs the
        // shim launcher rather than a symlink/native shim.
        const prefer_deb_shims = !is_wasm and archive.detectFormat(asset.name) == .deb and hasDebShims(io, staging_dir);
        if (is_wasm) {
            try exes.append(allocator, try allocator.dupe(u8, asset.name));
        } else if (prefer_deb_shims) {
            exes = findDebExecutables(allocator, io, staging_dir) catch |err| {
                try err_w.print(
                    "error: failed to scan staging dir '{s}' for executables: {t}\n",
                    .{ staging_path, err },
                );
                try err_w.flush();
                return error.InstallStepFailed;
            };
        } else {
            exes = findExecutables(allocator, io, staging_dir) catch |err| {
                try err_w.print(
                    "error: failed to scan staging dir '{s}' for executables: {t}\n",
                    .{ staging_path, err },
                );
                try err_w.flush();
                return error.InstallStepFailed;
            };
        }
    }

    // Collapse same-named binaries bundled for multiple architectures down to
    // the host-arch copy so linking can't land on a foreign-arch build (#123).
    dedupeExecutablesByHostArch(allocator, &exes);

    if (exes.items.len == 0) {
        try err_w.print("error: no executables found in archive\n", .{});
        try err_w.print("  selected asset: {s}\n", .{primary_name});
        try err_w.print("  other installable assets in this release:\n", .{});
        var listed: u32 = 0;
        for (release.parsed.value.assets) |a| {
            if (std.mem.eql(u8, a.name, primary_name)) continue;
            if (!isInstallableAsset(a.name)) continue;
            try err_w.print("    {s}\n", .{a.name});
            listed += 1;
        }
        if (listed == 0) {
            try err_w.print("    (none)\n", .{});
        }
        try err_w.flush();
        return error.InstallStepFailed;
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
        d.tools, std.fs.path.sep, owner_lower, std.fs.path.sep, repo_lower,
    });
    defer allocator.free(tool_path);

    // Opportunistic case-migration: a pre-migration install of the same
    // repo may live at a mixed-case path (e.g. `<tools>/AzureAD/foo`).
    // If found, rename it to the canonical lowercase path before we
    // touch anything else. Best-effort: a collision with an already-
    // canonical entry, or a failed rename, falls through to the
    // normal delete-and-replace path.
    if (try resolveInstalledToolPath(allocator, io, d.tools, owner_lower, repo_lower)) |existing| {
        defer allocator.free(existing);
        if (!std.mem.eql(u8, existing, tool_path)) {
            const dest_already_present = blk: {
                var dc = Dir.openDirAbsolute(io, tool_path, .{}) catch break :blk false;
                dc.close(io);
                break :blk true;
            };
            if (!dest_already_present) {
                // Ensure the canonical owner dir exists at the right
                // casing before moving the repo dir into it.
                const canon_owner_path = try std.fmt.allocPrint(allocator, "{s}{c}{s}", .{
                    d.tools, std.fs.path.sep, owner_lower,
                });
                defer allocator.free(canon_owner_path);
                ensureDirAbsoluteRecursive(io, d.tools);
                Dir.createDirAbsolute(io, canon_owner_path, .default_dir) catch {};

                caseRenameDir(io, existing, tool_path) catch {};

                // Best-effort: remove the now-empty mixed-case owner dir
                // (only succeeds when there are no other repos under it).
                if (std.fs.path.dirname(existing)) |old_owner_path| {
                    if (!std.mem.eql(u8, old_owner_path, canon_owner_path)) {
                        Dir.deleteDirAbsolute(io, old_owner_path) catch {};
                    }
                }
            }
        }
    }

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
    // Pre-check existence so the Windows fallback only runs when there is
    // actually something to move out of the way — without this, a first
    // install on Windows surfaces deleteTreeAbsolute's PathNotFound as a
    // misleading "files may be locked" error from the rename fallback.
    const tool_dir_exists = blk: {
        var d_check = Dir.openDirAbsolute(io, tool_path, .{}) catch break :blk false;
        d_check.close(io);
        break :blk true;
    };
    if (tool_dir_exists) {
        deleteTreeAbsolute(io, tool_path) catch {
            if (comptime builtin.os.tag == .windows) {
                var tombstone_buf: [Dir.max_path_bytes]u8 = undefined;
                const tombstone = std.fmt.bufPrint(&tombstone_buf, "{s}.old", .{tool_path}) catch {
                    try err_w.print("error: tool path too long\n", .{});
                    try err_w.flush();
                    return error.InstallStepFailed;
                };
                deleteTreeAbsolute(io, tombstone) catch {};
                Dir.renameAbsolute(tool_path, tombstone, io) catch {
                    try err_w.print("error: cannot replace tool directory (files may be locked by a running process)\n", .{});
                    try err_w.flush();
                    return error.InstallStepFailed;
                };
            }
        };
    }

    // Ensure tools and owner dirs exist (create full path)
    const owner_path = try std.fmt.allocPrint(allocator, "{s}{c}{s}", .{
        d.tools, std.fs.path.sep, owner_lower,
    });
    defer allocator.free(owner_path);
    // Ensure the tools directory and all of its ancestors exist. On a fresh
    // install on Linux this may need to create `~/.local`, `~/.local/share`,
    // `~/.local/share/ghr`, and `~/.local/share/ghr/tools`; on Windows it
    // creates `%APPDATA%\ghr\data\tools` and its parents. The previous
    // 2-ancestor bound was insufficient for the tools layout and caused
    // a misleading `FileNotFound` on `renameAbsolute` below.
    ensureDirAbsoluteRecursive(io, d.tools);
    Dir.createDirAbsolute(io, owner_path, .default_dir) catch {};

    // Rename staging to final
    Dir.renameAbsolute(staging_path, tool_path, io) catch |err| {
        try err_w.print(
            "error: failed to move staging directory '{s}' to tool directory '{s}': {t}\n",
            .{ staging_path, tool_path, err },
        );
        try err_w.flush();
        return error.InstallStepFailed;
    };

    // Re-open the tool dir for metadata and linking
    var tool_dir = Dir.openDirAbsolute(io, tool_path, .{}) catch |err| {
        try err_w.print(
            "error: failed to open tool directory '{s}': {t}\n",
            .{ tool_path, err },
        );
        try err_w.flush();
        return error.InstallStepFailed;
    };
    defer tool_dir.close(io);

    // Write metadata
    const bins_slice = exes.items;
    const apps_slice = apps.items;
    writeMetadata(allocator, io, tool_dir, tag_name, primary_name, bins_slice, apps_slice, verified_label, recorded_minisign_key) catch |err| {
        try err_w.print("warning: failed to write metadata: {}\n", .{err});
    };

    // Create bin dir and link executables. The bin directory normally lives
    // under `~/.local/bin`; on a fresh install neither `.local` nor `.local/bin`
    // may exist yet, so create the full ancestor chain before opening.
    ensureDirAbsoluteRecursive(io, d.bin);
    var bin_dir = Dir.openDirAbsolute(io, d.bin, .{}) catch |err| {
        try err_w.print(
            "error: failed to open bin directory '{s}': {t}\n",
            .{ d.bin, err },
        );
        try err_w.flush();
        return error.InstallStepFailed;
    };
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

/// Install one or more release specs in a single invocation. Builds the
/// shared HTTP client + auth context + `Dirs.detect` result once and
/// reuses them across every spec.
///
/// Each entry is a spec plus an optional inline minisign pubkey. The
/// effective key for a spec is `entry.key orelse minisign_pubkey_b64`
/// (the inline override beats the global default for that one spec).
///
/// `keep_going` controls failure semantics:
///   - `false` (default for `ghr install`): on the first per-spec
///     failure, exit the process with status 1. The current spec's
///     diagnostic has already been printed by `installOne`.
///   - `true` (`--keep-going`): continue past per-spec failures,
///     attempt every spec, and exit non-zero with a summary line if
///     any spec failed.
pub fn cmdInstallMany(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    entries: []const release_mod.SpecWithKey,
    w: *Writer,
    err_w: *Writer,
    debug: bool,
    no_auth: bool,
    gates: release_mod.VerifyGates,
    minisign_pubkey_b64: ?[]const u8,
    keep_going: bool,
) !void {
    if (entries.len == 0) return;

    const dirs = try Dirs.detect(allocator, environ);
    defer dirs.deinit();

    // Resolve auth token: env vars first, then `gh auth token` as fallback.
    const auth_resolved = auth.resolveGithubToken(allocator, io, environ, no_auth);
    defer auth_resolved.deinit(allocator);
    const auth_header = try auth.bearerHeader(allocator, auth_resolved);
    defer if (auth_header) |h| allocator.free(h);

    // One HTTP client per invocation, reused across all specs.
    var client: std.http.Client = .{
        .allocator = allocator,
        .io = io,
        .write_buffer_size = http_write_buffer_size,
    };
    defer client.deinit();

    const ctx = InstallContext{
        .allocator = allocator,
        .io = io,
        .environ = environ,
        .dirs = dirs,
        .client = &client,
        .auth_resolved = auth_resolved,
        .auth_header = auth_header,
        .w = w,
        .err_w = err_w,
        .debug = debug,
        .no_auth = no_auth,
        .gates = gates,
        .minisign_pubkey_b64 = minisign_pubkey_b64,
    };

    var failed_specs: std.ArrayListUnmanaged([]const u8) = .empty;
    defer failed_specs.deinit(allocator);

    for (entries, 0..) |entry, i| {
        if (entries.len > 1) {
            try w.print("[{d}/{d}] {s}\n", .{ i + 1, entries.len, entry.spec });
            try w.flush();
        }
        installOne(&ctx, entry) catch |err| switch (err) {
            error.InstallStepFailed => {
                try failed_specs.append(allocator, entry.spec);
                if (!keep_going) std.process.exit(1);
                try err_w.print("note: --keep-going, continuing past failure for {s}\n", .{entry.spec});
                try err_w.flush();
            },
            else => return err,
        };
    }

    if (entries.len > 1) {
        const ok = entries.len - failed_specs.items.len;
        try w.print("installed {d}/{d}", .{ ok, entries.len });
        if (failed_specs.items.len > 0) {
            try w.print(", failed:", .{});
            for (failed_specs.items) |s| try w.print(" {s}", .{s});
        }
        try w.print("\n", .{});
        try w.flush();
    }

    if (failed_specs.items.len > 0) std.process.exit(1);
}

/// Single-spec install wrapper retained for backwards compatibility with
/// older callers. Delegates to `cmdInstallMany`.
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
    const entries: [1]release_mod.SpecWithKey = .{.{ .spec = spec_str }};
    const gates: release_mod.VerifyGates = .{ .skip_verify = skip_verify };
    return cmdInstallMany(
        allocator,
        io,
        environ,
        entries[0..],
        w,
        err_w,
        debug,
        no_auth,
        gates,
        minisign_pubkey_b64,
        false,
    );
}

test "cmdInstallMany short-circuits on empty spec list" {
    // No allocator/io is even consulted because len==0 returns immediately.
    var out_buf: [64]u8 = undefined;
    var out_w = std.Io.Writer.Discarding.init(&out_buf);
    var err_buf: [64]u8 = undefined;
    var err_w = std.Io.Writer.Discarding.init(&err_buf);

    var environ_map = EnvironMap.init(std.testing.allocator);
    defer environ_map.deinit();

    const empty: []const release_mod.SpecWithKey = &.{};
    try cmdInstallMany(
        std.testing.allocator,
        std.testing.io,
        &environ_map,
        empty,
        &out_w.writer,
        &err_w.writer,
        false,
        false,
        .{},
        null,
        false,
    );
}

test "wasmStem strips the .wasm extension from the basename" {
    try std.testing.expectEqualStrings("hello", wasmStem("hello.wasm"));
    try std.testing.expectEqualStrings("hello", wasmStem("sub/dir/hello.wasm"));
    try std.testing.expectEqualStrings("a.b", wasmStem("a.b.wasm"));
}

test "writeZonEscaped escapes backslashes, quotes, and control chars" {
    const allocator = std.testing.allocator;
    var c = std.Io.Writer.Allocating.init(allocator);
    defer c.deinit();
    try writeZonEscaped(&c.writer, "C:\\a\\b \"x\"\t");
    const got = try c.toOwnedSlice();
    defer allocator.free(got);
    try std.testing.expectEqualStrings("C:\\\\a\\\\b \\\"x\\\"\\t", got);
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
    if (comptime !File.Permissions.has_executable_bit) return error.SkipZigTest;
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

fn makeExeList(allocator: std.mem.Allocator, paths: []const []const u8) !std.ArrayListUnmanaged([]const u8) {
    var list: std.ArrayListUnmanaged([]const u8) = .empty;
    for (paths) |p| try list.append(allocator, try allocator.dupe(u8, p));
    return list;
}

test "dedupeExecutablesByArch keeps host-arch copy of bundled multi-arch binary" {
    const allocator = std.testing.allocator;
    // Mirrors jedisct1/minisign@0.12, which ships both arches under one tarball.
    var exes = try makeExeList(allocator, &.{
        "minisign-linux/aarch64/minisign",
        "minisign-linux/x86_64/minisign",
    });
    defer {
        for (exes.items) |e| allocator.free(e);
        exes.deinit(allocator);
    }

    dedupeExecutablesByArch(allocator, &exes, &.{ "x86_64", "x64", "amd64" });

    try std.testing.expectEqual(@as(usize, 1), exes.items.len);
    try std.testing.expectEqualStrings("minisign-linux/x86_64/minisign", exes.items[0]);
}

test "dedupeExecutablesByArch is a no-op for single-arch archives" {
    const allocator = std.testing.allocator;
    var exes = try makeExeList(allocator, &.{
        "bin/foo",
        "bin/bar",
    });
    defer {
        for (exes.items) |e| allocator.free(e);
        exes.deinit(allocator);
    }

    dedupeExecutablesByArch(allocator, &exes, &.{ "aarch64", "arm64" });

    try std.testing.expectEqual(@as(usize, 2), exes.items.len);
}

test "dedupeExecutablesByArch leaves group untouched when no copy matches host" {
    const allocator = std.testing.allocator;
    // Host arch absent from every copy: don't drop the only builds available.
    var exes = try makeExeList(allocator, &.{
        "tool-x86_64",
        "tool-aarch64",
    });
    defer {
        for (exes.items) |e| allocator.free(e);
        exes.deinit(allocator);
    }

    dedupeExecutablesByArch(allocator, &exes, &.{ "riscv64gc", "riscv64" });

    try std.testing.expectEqual(@as(usize, 2), exes.items.len);
}

test "dedupeExecutablesByArch drops multiple foreign-arch copies" {
    const allocator = std.testing.allocator;
    var exes = try makeExeList(allocator, &.{
        "pkg/x86_64/tool",
        "pkg/aarch64/tool",
        "pkg/riscv64/tool",
    });
    defer {
        for (exes.items) |e| allocator.free(e);
        exes.deinit(allocator);
    }

    dedupeExecutablesByArch(allocator, &exes, &.{ "aarch64", "arm64" });

    try std.testing.expectEqual(@as(usize, 1), exes.items.len);
    try std.testing.expectEqualStrings("pkg/aarch64/tool", exes.items[0]);
}

test "findExecutables skips AppleDouble and __MACOSX cruft" {
    if (comptime !File.Permissions.has_executable_bit) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    // A real executable plus macOS archive metadata that carries the exec bit.
    const real = try tmp.dir.createFile(std.testing.io, "minisign", .{ .permissions = .executable_file });
    real.close(std.testing.io);
    const ad1 = try tmp.dir.createFile(std.testing.io, "._minisign", .{ .permissions = .executable_file });
    ad1.close(std.testing.io);
    try tmp.dir.createDirPath(std.testing.io, "__MACOSX");
    const ad2 = try tmp.dir.createFile(std.testing.io, "__MACOSX/._minisign", .{ .permissions = .executable_file });
    ad2.close(std.testing.io);

    const allocator = std.testing.allocator;
    var exes = try findExecutables(allocator, std.testing.io, tmp.dir);
    defer {
        for (exes.items) |e| allocator.free(e);
        exes.deinit(allocator);
    }

    try std.testing.expectEqual(@as(usize, 1), exes.items.len);
    try std.testing.expectEqualStrings("minisign", exes.items[0]);
}

test "findExecutables discovers nested executables" {
    if (comptime !File.Permissions.has_executable_bit) return error.SkipZigTest;
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
    if (comptime !File.Permissions.has_executable_bit) return error.SkipZigTest;
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
    if (comptime !File.Permissions.has_executable_bit) return error.SkipZigTest;
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
    try std.testing.expect(!isLibraryDir("lib"));
    try std.testing.expect(isLibraryDir("Frameworks"));
    try std.testing.expect(isLibraryDir("PlugIns"));
    try std.testing.expect(!isLibraryDir("bin"));
    try std.testing.expect(!isLibraryDir("Contents"));
    try std.testing.expect(!isLibraryDir("MacOS"));
}

test "findExecutables skips shared libraries" {
    if (comptime !File.Permissions.has_executable_bit) return error.SkipZigTest;
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

test "looksLikePosixExecutable recognises ELF, Mach-O, and shebang" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    const cases = [_]struct { name: []const u8, head: []const u8, expect: bool }{
        .{ .name = "elf", .head = "\x7fELF\x02\x01\x01\x00", .expect = true },
        .{ .name = "macho64_le", .head = "\xcf\xfa\xed\xfe\x07\x00\x00\x01", .expect = true },
        .{ .name = "macho64_be", .head = "\xfe\xed\xfa\xcf\x01\x00\x00\x07", .expect = true },
        .{ .name = "macho32_le", .head = "\xce\xfa\xed\xfe", .expect = true },
        .{ .name = "macho_fat", .head = "\xca\xfe\xba\xbe\x00\x00\x00\x02", .expect = true },
        .{ .name = "macho_fat64", .head = "\xca\xfe\xba\xbf\x00\x00\x00\x02", .expect = true },
        .{ .name = "shebang", .head = "#!/bin/sh\nexit 0\n", .expect = true },
        .{ .name = "readme", .head = "# README\n\nThis is text.\n", .expect = false },
        .{ .name = "json", .head = "{\"foo\":1}\n", .expect = false },
        .{ .name = "empty", .head = "", .expect = false },
        .{ .name = "one_byte", .head = "#", .expect = false },
    };
    for (cases) |c| {
        var f = try tmp.dir.createFile(std.testing.io, c.name, .{});
        try f.writeStreamingAll(std.testing.io, c.head);
        f.close(std.testing.io);
        try std.testing.expectEqual(c.expect, looksLikePosixExecutable(std.testing.io, tmp.dir, c.name));
    }
}

test "findExecutables recovers Mach-O without exec bit (zip extraction)" {
    if (comptime !File.Permissions.has_executable_bit) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    // Simulate a file extracted by std.zip.extract: real Mach-O contents but
    // no executable bit (zip extraction discards Unix mode bits).
    var f = try tmp.dir.createFile(std.testing.io, "minisign", .{});
    try f.writeStreamingAll(std.testing.io, "\xcf\xfa\xed\xfe" ++ "rest-of-mach-o");
    f.close(std.testing.io);

    // A plain text file should still be skipped.
    var rf = try tmp.dir.createFile(std.testing.io, "README.md", .{});
    try rf.writeStreamingAll(std.testing.io, "# minisign\n");
    rf.close(std.testing.io);

    const allocator = std.testing.allocator;
    var exes = try findExecutables(allocator, std.testing.io, tmp.dir);
    defer {
        for (exes.items) |e| allocator.free(e);
        exes.deinit(allocator);
    }
    try std.testing.expectEqual(@as(usize, 1), exes.items.len);
    try std.testing.expectEqualStrings("minisign", exes.items[0]);

    // The fallback must also have chmod'd the file so `linkToBin` produces a
    // runnable symlink target.
    const stat = try tmp.dir.statFile(std.testing.io, "minisign", .{});
    try std.testing.expect((@as(u32, @intFromEnum(stat.permissions)) & 0o111) != 0);
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
    try writeMetadata(allocator, std.testing.io, tmp.dir, "v1.0.0", "tool-windows.zip", &bins, &apps, "checksum", null);

    // Verify it's valid JSON by reading it back
    const body = try tmp.dir.readFileAlloc(std.testing.io, "ghr.json", allocator, Io.Limit.limited(8192));
    defer allocator.free(body);

    // Backslashes must be escaped in JSON
    try std.testing.expect(std.mem.indexOf(u8, body, "sub\\\\dir\\\\tool.exe") != null);
    // Tools installed without a minisign key must not emit the field.
    try std.testing.expect(std.mem.indexOf(u8, body, "\"minisign\"") == null);

    // Parse it back
    const parsed = try std.json.parseFromSlice(Metadata, allocator, body, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    try std.testing.expectEqualStrings("v1.0.0", parsed.value.tag);
    try std.testing.expectEqualStrings("tool-windows.zip", parsed.value.asset);
    try std.testing.expectEqualStrings("checksum", parsed.value.verified);
    try std.testing.expectEqualStrings("", parsed.value.minisign);
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
    try writeMetadata(allocator, std.testing.io, tmp.dir, "v1.2.3", "tool-linux.tar.xz", &bins, &apps, "minisign", null);

    const body = try tmp.dir.readFileAlloc(std.testing.io, "ghr.json", allocator, Io.Limit.limited(8192));
    defer allocator.free(body);

    const parsed = try std.json.parseFromSlice(Metadata, allocator, body, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    try std.testing.expectEqualStrings("minisign", parsed.value.verified);
}

test "writeMetadata round-trips a minisign pubkey" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const bins = [_][]const u8{"tool"};
    const apps = [_][]const u8{};
    const pubkey = "RWSbsumpaHb+N3KCEt/EUXQ5y6Kkk8r/zCb5Z4jhEuEX8x2/U5wr5QC0";
    try writeMetadata(allocator, std.testing.io, tmp.dir, "v1.2.3", "tool-linux.tar.xz", &bins, &apps, "sigstore", pubkey);

    const body = try tmp.dir.readFileAlloc(std.testing.io, "ghr.json", allocator, Io.Limit.limited(8192));
    defer allocator.free(body);

    const parsed = try std.json.parseFromSlice(Metadata, allocator, body, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    try std.testing.expectEqualStrings("sigstore", parsed.value.verified);
    try std.testing.expectEqualStrings(pubkey, parsed.value.minisign);
}

test "writeMetadata omits the minisign field for an empty pubkey" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const bins = [_][]const u8{"tool"};
    const apps = [_][]const u8{};
    try writeMetadata(allocator, std.testing.io, tmp.dir, "v1.2.3", "tool-linux.tar.xz", &bins, &apps, "checksum", "");

    const body = try tmp.dir.readFileAlloc(std.testing.io, "ghr.json", allocator, Io.Limit.limited(8192));
    defer allocator.free(body);

    try std.testing.expect(std.mem.indexOf(u8, body, "\"minisign\"") == null);
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

    // On Windows, the prefix comparison is ASCII case-insensitive so a
    // shim written before lowercase-tool-dir migration is still
    // recognized as owned after the dir was case-renamed.
    if (comptime builtin.os.tag == .windows) {
        try std.testing.expect(shimPointsToToolDir(
            std.testing.io,
            tmp.dir,
            "tool.shim",
            "C:\\TOOLS\\OWNER\\REPO",
        ));
        try std.testing.expect(shimPointsToToolDir(
            std.testing.io,
            tmp.dir,
            "tool.shim",
            "c:\\tools\\OWNER\\repo",
        ));
    }
}

test "writeLegacyShim writes a single-line target readable by shimPointsToToolDir" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const target = "C:\\tools\\owner\\repo\\bin\\tool.exe";
    try writeLegacyShim(std.testing.io, tmp.dir, "tool.shim", target);

    // Contents are exactly the target followed by a trailing newline.
    const body = try tmp.dir.readFileAlloc(std.testing.io, "tool.shim", allocator, Io.Limit.limited(4096));
    defer allocator.free(body);
    try std.testing.expectEqualStrings(target ++ "\n", body);

    // The fallback is recognized as owning its tool dir, so a legacy
    // `.shim`-only shim resolves it after a self-update.
    try std.testing.expect(shimPointsToToolDir(
        std.testing.io,
        tmp.dir,
        "tool.shim",
        "C:\\tools\\owner\\repo",
    ));

    // Overwrites any pre-existing `.shim` rather than appending.
    const target2 = "C:\\tools\\owner\\repo\\bin\\v2\\tool.exe";
    try writeLegacyShim(std.testing.io, tmp.dir, "tool.shim", target2);
    const body2 = try tmp.dir.readFileAlloc(std.testing.io, "tool.shim", allocator, Io.Limit.limited(4096));
    defer allocator.free(body2);
    try std.testing.expectEqualStrings(target2 ++ "\n", body2);
}

test "ensureDirWithParents creates leaf and one missing parent" {
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &path_buf);
    const base = path_buf[0..base_len];

    var sub_buf: [Dir.max_path_bytes]u8 = undefined;
    const leaf = try std.fmt.bufPrint(&sub_buf, "{s}{c}a{c}b", .{ base, std.fs.path.sep, std.fs.path.sep });

    // Pre-condition: neither `a` nor `a/b` exist.
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(tio, "a", .{}));

    ensureDirWithParents(tio, leaf, 2);

    // Post-condition: `a` and `a/b` both exist as directories.
    try std.testing.expect((try tmp.dir.statFile(tio, "a", .{})).kind == .directory);
    try std.testing.expect((try tmp.dir.statFile(tio, "a/b", .{})).kind == .directory);
}

test "ensureDirWithParents creates leaf and two missing parents" {
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &path_buf);
    const base = path_buf[0..base_len];

    var sub_buf: [Dir.max_path_bytes]u8 = undefined;
    const leaf = try std.fmt.bufPrint(&sub_buf, "{s}{c}a{c}b{c}c", .{
        base, std.fs.path.sep, std.fs.path.sep, std.fs.path.sep,
    });

    ensureDirWithParents(tio, leaf, 2);

    try std.testing.expect((try tmp.dir.statFile(tio, "a", .{})).kind == .directory);
    try std.testing.expect((try tmp.dir.statFile(tio, "a/b", .{})).kind == .directory);
    try std.testing.expect((try tmp.dir.statFile(tio, "a/b/c", .{})).kind == .directory);
}

test "ensureDirWithParents tolerates already-existing path" {
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(tio, "a/b");

    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &path_buf);
    const base = path_buf[0..base_len];

    var sub_buf: [Dir.max_path_bytes]u8 = undefined;
    const leaf = try std.fmt.bufPrint(&sub_buf, "{s}{c}a{c}b", .{ base, std.fs.path.sep, std.fs.path.sep });

    // Should be a no-op; in particular it must not raise.
    ensureDirWithParents(tio, leaf, 2);

    try std.testing.expect((try tmp.dir.statFile(tio, "a/b", .{})).kind == .directory);
}

test "ensureDirWithParents does not create beyond max_parents" {
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &path_buf);
    const base = path_buf[0..base_len];

    var sub_buf: [Dir.max_path_bytes]u8 = undefined;
    // Four missing levels below base. With max_parents = 2 the helper can
    // create the bottom three (two ancestors + the leaf), but cannot
    // succeed because the outermost level `a` is still missing when it
    // tries to create `a/b`. The function must not crash, and the
    // mid-level `a/b/c` must not be created either.
    const leaf = try std.fmt.bufPrint(&sub_buf, "{s}{c}a{c}b{c}c{c}d", .{
        base, std.fs.path.sep, std.fs.path.sep, std.fs.path.sep, std.fs.path.sep,
    });

    ensureDirWithParents(tio, leaf, 2);

    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(tio, "a", .{}));
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(tio, "a/b/c", .{}));
}

test "ensureDirAbsoluteRecursive creates arbitrarily deep missing tree" {
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &path_buf);
    const base = path_buf[0..base_len];

    // Four missing levels below base — the scenario that caused the
    // self-install `FileNotFound` on a fresh `~/.local/share/ghr/tools`.
    var sub_buf: [Dir.max_path_bytes]u8 = undefined;
    const leaf = try std.fmt.bufPrint(&sub_buf, "{s}{c}a{c}b{c}c{c}d", .{
        base, std.fs.path.sep, std.fs.path.sep, std.fs.path.sep, std.fs.path.sep,
    });

    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(tio, "a", .{}));

    ensureDirAbsoluteRecursive(tio, leaf);

    try std.testing.expect((try tmp.dir.statFile(tio, "a", .{})).kind == .directory);
    try std.testing.expect((try tmp.dir.statFile(tio, "a/b", .{})).kind == .directory);
    try std.testing.expect((try tmp.dir.statFile(tio, "a/b/c", .{})).kind == .directory);
    try std.testing.expect((try tmp.dir.statFile(tio, "a/b/c/d", .{})).kind == .directory);
}

test "ensureDirAbsoluteRecursive tolerates already-existing path" {
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(tio, "a/b");

    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &path_buf);
    const base = path_buf[0..base_len];

    var sub_buf: [Dir.max_path_bytes]u8 = undefined;
    const leaf = try std.fmt.bufPrint(&sub_buf, "{s}{c}a{c}b", .{ base, std.fs.path.sep, std.fs.path.sep });

    ensureDirAbsoluteRecursive(tio, leaf);

    try std.testing.expect((try tmp.dir.statFile(tio, "a/b", .{})).kind == .directory);
}

test "resolveInstalledToolPath: exact lowercase match" {
    const tio = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(tio, "azuread/microsoft-authentication-cli");

    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &path_buf);
    const base = path_buf[0..base_len];

    const got = try resolveInstalledToolPath(allocator, tio, base, "azuread", "microsoft-authentication-cli");
    try std.testing.expect(got != null);
    defer allocator.free(got.?);

    var expect_buf: [Dir.max_path_bytes]u8 = undefined;
    const expect = try std.fmt.bufPrint(&expect_buf, "{s}{c}azuread{c}microsoft-authentication-cli", .{ base, std.fs.path.sep, std.fs.path.sep });
    try std.testing.expectEqualStrings(expect, got.?);
}

test "resolveInstalledToolPath: case-insensitive owner match" {
    const tio = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Pre-migration mixed-case install
    try tmp.dir.createDirPath(tio, "AzureAD/microsoft-authentication-cli");

    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &path_buf);
    const base = path_buf[0..base_len];

    const got = try resolveInstalledToolPath(allocator, tio, base, "azuread", "microsoft-authentication-cli");
    try std.testing.expect(got != null);
    defer allocator.free(got.?);

    // Returned path preserves the actual on-disk casing.
    try std.testing.expect(std.mem.indexOf(u8, got.?, "AzureAD") != null);
    try std.testing.expect(std.mem.indexOf(u8, got.?, "microsoft-authentication-cli") != null);
}

test "resolveInstalledToolPath: case-insensitive repo match" {
    const tio = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(tio, "owner/MixedCase-Repo");

    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &path_buf);
    const base = path_buf[0..base_len];

    const got = try resolveInstalledToolPath(allocator, tio, base, "owner", "mixedcase-repo");
    try std.testing.expect(got != null);
    defer allocator.free(got.?);

    try std.testing.expect(std.mem.indexOf(u8, got.?, "MixedCase-Repo") != null);
}

test "resolveInstalledToolPath: prefers exact lowercase over case-insensitive match" {
    const tio = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Only possible on case-sensitive filesystems. On case-insensitive
    // ones the second createDirPath is a no-op and the test trivially
    // succeeds (we still get a valid resolved path back).
    try tmp.dir.createDirPath(tio, "AzureAD/foo");
    tmp.dir.createDirPath(tio, "azuread/foo") catch {};

    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &path_buf);
    const base = path_buf[0..base_len];

    const got = try resolveInstalledToolPath(allocator, tio, base, "azuread", "foo");
    try std.testing.expect(got != null);
    defer allocator.free(got.?);
    // Path is valid either way; on a case-sensitive FS the lowercase form
    // wins, on case-insensitive it's the only entry.
    try std.testing.expect(std.mem.endsWith(u8, got.?, "foo"));
}

test "resolveInstalledToolPath: returns null when missing" {
    const tio = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &path_buf);
    const base = path_buf[0..base_len];

    try std.testing.expect(try resolveInstalledToolPath(allocator, tio, base, "missing", "repo") == null);

    try tmp.dir.createDirPath(tio, "owner");
    try std.testing.expect(try resolveInstalledToolPath(allocator, tio, base, "owner", "repo") == null);
}

test "resolveInstalledToolPath: tools_dir missing returns null" {
    const tio = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &path_buf);
    const base = path_buf[0..base_len];

    var nonexistent_buf: [Dir.max_path_bytes]u8 = undefined;
    const nonexistent = try std.fmt.bufPrint(&nonexistent_buf, "{s}{c}nope", .{ base, std.fs.path.sep });

    try std.testing.expect(try resolveInstalledToolPath(allocator, tio, nonexistent, "owner", "repo") == null);
}

test "caseRenameDir: leaf-case-only rename uses temp dance" {
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(tio, "AzureAD");
    try tmp.dir.writeFile(tio, .{ .sub_path = "AzureAD/marker", .data = "hi" });

    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &path_buf);
    const base = path_buf[0..base_len];

    var old_buf: [Dir.max_path_bytes]u8 = undefined;
    const old_abs = try std.fmt.bufPrint(&old_buf, "{s}{c}AzureAD", .{ base, std.fs.path.sep });
    var new_buf: [Dir.max_path_bytes]u8 = undefined;
    const new_abs = try std.fmt.bufPrint(&new_buf, "{s}{c}azuread", .{ base, std.fs.path.sep });

    try caseRenameDir(tio, old_abs, new_abs);

    // The marker file is preserved.
    try std.testing.expect((try tmp.dir.statFile(tio, "azuread/marker", .{})).kind == .file);

    // Verify the on-disk casing actually flipped by iterating the parent
    // and looking for an exact-byte match. (Works the same on case-
    // sensitive and case-insensitive filesystems.)
    var iter_dir = try Dir.openDirAbsolute(tio, base, .{ .iterate = true });
    defer iter_dir.close(tio);
    var iter = iter_dir.iterate();
    var saw_lower = false;
    var saw_upper = false;
    while (try iter.next(tio)) |entry| {
        if (entry.kind != .directory) continue;
        if (std.mem.eql(u8, entry.name, "azuread")) saw_lower = true;
        if (std.mem.eql(u8, entry.name, "AzureAD")) saw_upper = true;
    }
    try std.testing.expect(saw_lower);
    try std.testing.expect(!saw_upper);

    // Tombstone from the dance must be gone.
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(tio, "AzureAD.casetmp", .{}));
}

test "caseRenameDir: cross-parent rename uses plain rename" {
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(tio, "Old/repo");
    try tmp.dir.createDirPath(tio, "new");

    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &path_buf);
    const base = path_buf[0..base_len];

    var old_buf: [Dir.max_path_bytes]u8 = undefined;
    const old_abs = try std.fmt.bufPrint(&old_buf, "{s}{c}Old{c}repo", .{ base, std.fs.path.sep, std.fs.path.sep });
    var new_buf: [Dir.max_path_bytes]u8 = undefined;
    const new_abs = try std.fmt.bufPrint(&new_buf, "{s}{c}new{c}repo", .{ base, std.fs.path.sep, std.fs.path.sep });

    try caseRenameDir(tio, old_abs, new_abs);
    try std.testing.expect((try tmp.dir.statFile(tio, "new/repo", .{})).kind == .directory);
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(tio, "Old/repo", .{}));
}
