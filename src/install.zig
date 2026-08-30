const std = @import("std");
const builtin = @import("builtin");
const Dirs = @import("dirs.zig").Dirs;
const http = @import("http.zig");
const archive = @import("archive.zig");
const auth = @import("auth.zig");
const release_mod = @import("release.zig");
const attestation = @import("attestation.zig");
const minisign = @import("minisign.zig");
const install_request = @import("install_request.zig");
const install_state = @import("install_state.zig");
const install_state_write = @import("install_state_write.zig");
const install_txn = @import("install_txn.zig");
const command_plan = @import("command_plan.zig");
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

const CreateDirAbsoluteFn = *const fn (Io, []const u8, File.Permissions) Dir.CreateDirError!void;

fn ensureDirAbsoluteRecursiveWith(
    io: Io,
    abs_path: []const u8,
    create_dir: CreateDirAbsoluteFn,
) Dir.CreateDirError!void {
    create_dir(io, abs_path, .default_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        error.FileNotFound => {
            const parent = std.fs.path.dirname(abs_path) orelse return err;
            try ensureDirAbsoluteRecursiveWith(io, parent, create_dir);
            create_dir(io, abs_path, .default_dir) catch |retry_err| switch (retry_err) {
                error.PathAlreadyExists => {},
                else => return retry_err,
            };
        },
        else => return err,
    };
}

/// Recursive `mkdir -p` for an absolute path. Missing ancestors are created
/// from the top down, while permission and other filesystem errors are
/// preserved for the caller to report.
pub fn ensureDirAbsoluteRecursive(io: Io, abs_path: []const u8) Dir.CreateDirError!void {
    try ensureDirAbsoluteRecursiveWith(io, abs_path, Dir.createDirAbsolute);
}

/// Build a hidden, deterministic staging path beside an install path.
fn stagingSiblingPath(allocator: std.mem.Allocator, parent: []const u8, leaf: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}{c}.{s}.staging", .{ parent, std.fs.path.sep, leaf });
}

/// Build the tombstone path used while replacing an install path.
fn backupSiblingPath(allocator: std.mem.Allocator, parent: []const u8, leaf: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}{c}.{s}.old", .{ parent, std.fs.path.sep, leaf });
}

/// Build the visible tombstone path used by ghr 0.6.8 and earlier.
fn legacyBackupPath(allocator: std.mem.Allocator, final_path: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}.old", .{final_path});
}

fn directoryExists(io: Io, abs_path: []const u8) !bool {
    var dir = Dir.openDirAbsolute(io, abs_path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        error.NotDir => return error.InstallPathNotDirectory,
        else => return err,
    };
    dir.close(io);
    return true;
}

fn deleteTreeIfExists(io: Io, abs_path: []const u8) !void {
    deleteTreeAbsolute(io, abs_path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
}

/// Prepare a destination-local staging directory. Its parent is created before
/// stale staging contents are removed, so a fresh tools hierarchy works even
/// when the cache and tools roots are on different filesystems.
fn prepareStagingDir(io: Io, staging_parent: []const u8, staging_path: []const u8) !void {
    try ensureDirAbsoluteRecursive(io, staging_parent);
    var parent = try Dir.openDirAbsolute(io, staging_parent, .{});
    defer parent.close(io);

    try deleteTreeIfExists(io, staging_path);
    try parent.createDir(io, std.fs.path.basename(staging_path), .default_dir);
}

fn reportStagingDirCreateError(err_w: *Writer, staging_path: []const u8, err: anyerror) !void {
    try err_w.print("error: failed to create staging dir '{s}': {t}\n", .{ staging_path, err });
    if (err == error.AccessDenied or err == error.PermissionDenied) {
        try err_w.print("  try sudo, or point GHR_TOOL_DIR somewhere writable\n", .{});
    }
    try err_w.flush();
}

/// A stale backup with no live directory means the previous transaction
/// stopped after moving the live installation aside. Restore it before
/// inspecting or preserving the live install. When both are present, the
/// backup belongs to an already committed transaction and can be removed.
fn recoverStaleBackup(io: Io, final_path: []const u8, backup_path: []const u8) !void {
    if (!try directoryExists(io, backup_path)) return;
    if (try directoryExists(io, final_path)) {
        try deleteTreeIfExists(io, backup_path);
    } else {
        try Dir.renameAbsolute(backup_path, final_path, io);
    }
}

/// Recover the current hidden backup first, then migrate or clean the legacy
/// visible backup. This makes a current interrupted transaction win if both
/// backup forms are present.
fn recoverInstallBackups(
    io: Io,
    final_path: []const u8,
    backup_path: []const u8,
    legacy_backup_path: []const u8,
) !void {
    try recoverStaleBackup(io, final_path, backup_path);
    try recoverStaleBackup(io, final_path, legacy_backup_path);
}

const RenameDirFn = *const fn (Io, []const u8, []const u8) anyerror!void;

fn renameDirectory(io: Io, old_path: []const u8, new_path: []const u8) anyerror!void {
    try Dir.renameAbsolute(old_path, new_path, io);
}

const ReplaceResult = union(enum) {
    committed,
    backup_retained: anyerror,
};

fn replaceStagedDirWithRename(
    io: Io,
    staging_path: []const u8,
    final_path: []const u8,
    backup_path: []const u8,
    rename_dir: RenameDirFn,
) !ReplaceResult {
    try recoverStaleBackup(io, final_path, backup_path);
    if (!try directoryExists(io, staging_path)) return error.StagingDirectoryNotFound;

    if (try directoryExists(io, final_path)) {
        try rename_dir(io, final_path, backup_path);
        rename_dir(io, staging_path, final_path) catch |err| {
            rename_dir(io, backup_path, final_path) catch return error.InstallRollbackFailed;
            return err;
        };
        deleteTreeIfExists(io, backup_path) catch |err| return .{ .backup_retained = err };
    } else {
        try rename_dir(io, staging_path, final_path);
    }
    return .committed;
}

/// Commit a completed staging tree without deleting the previous live tree
/// first. The two rename operations are always between siblings, avoiding
/// cross-device EXDEV failures and permitting rollback if the commit fails.
fn replaceStagedDir(
    io: Io,
    staging_path: []const u8,
    final_path: []const u8,
    backup_path: []const u8,
) !ReplaceResult {
    return replaceStagedDirWithRename(io, staging_path, final_path, backup_path, renameDirectory);
}

fn isInstallTransactionDir(name: []const u8) bool {
    return std.mem.endsWith(u8, name, ".old") or
        (std.mem.startsWith(u8, name, ".") and std.mem.endsWith(u8, name, ".staging"));
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

fn renameInstalledToolDir(
    allocator: std.mem.Allocator,
    io: Io,
    existing_path: []const u8,
    canonical_path: []const u8,
) !?[]u8 {
    const previous = try allocator.dupe(u8, existing_path);
    caseRenameDir(io, existing_path, canonical_path) catch {
        allocator.free(previous);
        return null;
    };
    return previous;
}

const ExistingToolPathAction = enum {
    none,
    rename,
    retain_alias,
    collision,
};

fn chooseExistingToolPathAction(
    spelling_differs: bool,
    canonical_exists: bool,
    same_directory: bool,
) ExistingToolPathAction {
    if (!spelling_differs) return .none;
    if (!canonical_exists) return .rename;
    return if (same_directory) .retain_alias else .collision;
}

fn directoriesHaveSameIdentity(io: Io, a_path: []const u8, b_path: []const u8) bool {
    var a = Dir.openDirAbsolute(io, a_path, .{}) catch return false;
    defer a.close(io);
    var b = Dir.openDirAbsolute(io, b_path, .{}) catch return false;
    defer b.close(io);

    var a_buf: [Dir.max_path_bytes]u8 = undefined;
    const a_len = a.realPath(io, &a_buf) catch return false;
    var b_buf: [Dir.max_path_bytes]u8 = undefined;
    const b_len = b.realPath(io, &b_buf) catch return false;
    if (a_len != b_len) return false;
    // `realPath` is reported from each opened handle. Exact equality is
    // deliberately required even on Windows: per-directory case sensitivity
    // can make paths that differ only by case identify distinct directories.
    // If the handles do not report the same final spelling, treat them as a
    // collision rather than guessing that they alias.
    return std.mem.eql(u8, a_buf[0..a_len], b_buf[0..b_len]);
}

fn existingToolPathAction(io: Io, existing_path: []const u8, canonical_path: []const u8) ExistingToolPathAction {
    if (std.mem.eql(u8, existing_path, canonical_path)) return .none;
    var canonical = Dir.openDirAbsolute(io, canonical_path, .{}) catch return .rename;
    canonical.close(io);
    return chooseExistingToolPathAction(
        true,
        true,
        directoriesHaveSameIdentity(io, existing_path, canonical_path),
    );
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

/// Returns the length of `tok` if `haystack` starts with it (case-insensitive)
/// and `tok` is immediately followed by a separator, a `.`, or the end of
/// the string (so `"arm"` doesn't spuriously match inside `"armv7"`).
fn matchLeadingToken(haystack: []const u8, tok: []const u8) ?usize {
    if (haystack.len < tok.len) return null;
    if (!std.ascii.eqlIgnoreCase(haystack[0..tok.len], tok)) return null;
    if (haystack.len > tok.len) {
        const nc = haystack[tok.len];
        if (nc != '-' and nc != '_' and nc != '.') return null;
    }
    return tok.len;
}

const bare_binary_archs = [_][]const u8{
    "x86_64",  "x64",   "amd64",
    "aarch64", "arm64", "armv7l",
    "armv7",   "armv6", "x86",
    "i686",    "i386",  "ppc64le",
    "ppc64",   "s390x", "riscv64",
};

fn hasWindowsExeSuffix(name: []const u8) bool {
    return name.len >= 4 and std.ascii.eqlIgnoreCase(name[name.len - 4 ..], ".exe");
}

fn windowsExeStem(name: []const u8) []const u8 {
    if (hasWindowsExeSuffix(name)) return name[0 .. name.len - 4];
    return name;
}

fn windowsShimExeName(buf: []u8, exe_name: []const u8) ![]const u8 {
    if (hasWindowsExeSuffix(exe_name)) return exe_name;
    return std.fmt.bufPrint(buf, "{s}.exe", .{exe_name});
}

/// For bare-binary assets whose name follows the `<name>-<arch>-<triple>...`
/// convention (e.g. `wash-aarch64-unknown-linux-musl`) or the
/// `<name>-<os>-<arch>` convention (e.g. `mer-macos-aarch64`,
/// `cosign-linux-amd64`), extract `<name>` so the resulting link in
/// `~/.ghr/bin/` is the natural command the user expects to run. Falls back
/// to `repo` if neither pattern matches.
fn deriveBareBinaryName(
    allocator: std.mem.Allocator,
    asset_name: []const u8,
    repo: []const u8,
    is_windows: bool,
) ![]u8 {
    var name = asset_name;
    if (hasWindowsExeSuffix(name)) name = name[0 .. name.len - 4];

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

            for (bare_binary_archs) |a| {
                if (matchLeadingToken(after, a) != null) {
                    if (is_windows) {
                        return std.fmt.allocPrint(allocator, "{s}.exe", .{stem});
                    }
                    return allocator.dupe(u8, stem);
                }
            }

            // Try the `<name>-<os>-<arch>` ordering: the token right after
            // the stem is an OS name, and an arch token follows it.
            const oses = [_][]const u8{
                "linux",   "darwin",  "macos",  "windows",
                "win",     "freebsd", "netbsd", "openbsd",
                "android", "ios",
            };
            for (oses) |o| {
                const os_len = matchLeadingToken(after, o) orelse continue;
                if (os_len >= after.len) continue; // nothing follows the OS token
                const rest = after[os_len + 1 ..];
                for (bare_binary_archs) |a| {
                    if (matchLeadingToken(rest, a) != null) {
                        if (is_windows) {
                            return std.fmt.allocPrint(allocator, "{s}.exe", .{stem});
                        }
                        return allocator.dupe(u8, stem);
                    }
                }
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

fn deinitPathList(
    allocator: std.mem.Allocator,
    paths: *std.ArrayListUnmanaged([]const u8),
) void {
    for (paths.items) |path| allocator.free(path);
    paths.deinit(allocator);
    paths.* = .empty;
}

/// Scan directories breadth-first and return executable files from the
/// shallowest level that contains any. Release archives commonly have one
/// wrapper directory around their commands; stopping at that wrapper's level
/// keeps executable-looking firmware and other data in deeper directories off
/// PATH while preserving nested-only archive layouts.
fn findExecutables(allocator: std.mem.Allocator, io: Io, dir: Dir) !std.ArrayListUnmanaged([]const u8) {
    return findExecutablesForPlatform(allocator, io, dir, builtin.os.tag == .windows);
}

fn findExecutablesForPlatform(
    allocator: std.mem.Allocator,
    io: Io,
    dir: Dir,
    windows: bool,
) !std.ArrayListUnmanaged([]const u8) {
    var result: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer deinitPathList(allocator, &result);

    var current: std.ArrayListUnmanaged([]const u8) = .empty;
    defer deinitPathList(allocator, &current);
    const root_path = try allocator.dupe(u8, "");
    current.append(allocator, root_path) catch |err| {
        allocator.free(root_path);
        return err;
    };

    while (current.items.len > 0) {
        var next: std.ArrayListUnmanaged([]const u8) = .empty;
        errdefer deinitPathList(allocator, &next);

        for (current.items) |prefix| {
            var opened: ?Dir = null;
            if (prefix.len > 0) {
                opened = dir.openDir(io, prefix, .{ .iterate = true }) catch continue;
            }
            defer if (opened) |*d| d.close(io);

            try scanExecutableLevel(
                allocator,
                io,
                opened orelse dir,
                &result,
                &next,
                prefix,
                windows,
            );
        }

        if (result.items.len > 0) {
            deinitPathList(allocator, &next);
            return result;
        }

        deinitPathList(allocator, &current);
        current = next;
    }

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

fn installedCommandName(exe_rel_path: []const u8, windows: bool) []const u8 {
    const base = std.fs.path.basename(exe_rel_path);
    if (windows) return windowsExeStem(base);
    return base;
}

fn commandNamesEqual(a: []const u8, b: []const u8, windows: bool) bool {
    return if (windows) std.ascii.eqlIgnoreCase(a, b) else std.mem.eql(u8, a, b);
}

fn executableMatchesFilter(exe_rel_path: []const u8, filter: []const u8, windows: bool) bool {
    return commandNamesEqual(installedCommandName(exe_rel_path, windows), filter, windows);
}

fn filterWasSeenEarlier(filters: []const []const u8, index: usize, windows: bool) bool {
    for (filters[0..index]) |earlier| {
        if (commandNamesEqual(earlier, filters[index], windows)) return true;
    }
    return false;
}

fn filterExecutables(
    allocator: std.mem.Allocator,
    exes: *std.ArrayListUnmanaged([]const u8),
    filters: []const []const u8,
    windows: bool,
    err_w: *Writer,
) !void {
    if (filters.len == 0) return;

    var unmatched: usize = 0;
    for (filters, 0..) |filter, filter_index| {
        if (filterWasSeenEarlier(filters, filter_index, windows)) continue;
        var matched = false;
        for (exes.items) |exe_rel_path| {
            if (executableMatchesFilter(exe_rel_path, filter, windows)) {
                matched = true;
                break;
            }
        }
        if (!matched) {
            if (unmatched == 0) {
                try err_w.print("error: requested --bin filter", .{});
            }
            try err_w.print("{s}'{s}'", .{ if (unmatched == 0) " " else ", ", filter });
            unmatched += 1;
        }
    }

    if (unmatched > 0) {
        try err_w.print(" did not match an available binary\n", .{});
        try err_w.print("available binaries:\n", .{});
        var listed: usize = 0;
        for (exes.items, 0..) |exe_rel_path, exe_index| {
            const name = installedCommandName(exe_rel_path, windows);
            var duplicate = false;
            for (exes.items[0..exe_index]) |earlier| {
                if (commandNamesEqual(installedCommandName(earlier, windows), name, windows)) {
                    duplicate = true;
                    break;
                }
            }
            if (duplicate) continue;
            try err_w.print("  {s}\n", .{name});
            listed += 1;
        }
        if (listed == 0) try err_w.print("  (none)\n", .{});
        try err_w.print("  hint: pass the installed command name shown above, not an archive path\n", .{});
        return error.UnmatchedBinFilter;
    }

    var i: usize = 0;
    while (i < exes.items.len) {
        var selected = false;
        for (filters) |filter| {
            if (executableMatchesFilter(exes.items[i], filter, windows)) {
                selected = true;
                break;
            }
        }
        if (selected) {
            i += 1;
        } else {
            allocator.free(exes.orderedRemove(i));
        }
    }
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

/// Scan one breadth-first level. Executable files and recognized app bundles
/// are collected in `result`; ordinary subdirectories are queued in `next`.
fn scanExecutableLevel(
    allocator: std.mem.Allocator,
    io: Io,
    dir: Dir,
    result: *std.ArrayListUnmanaged([]const u8),
    next: *std.ArrayListUnmanaged([]const u8),
    prefix: []const u8,
    windows: bool,
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
                // Treat the bundle as a candidate at this level while only
                // inspecting its Contents/MacOS directory for launchers.
                scanAppBundle(allocator, io, dir, entry.name, result, rel_name, windows) catch |err| {
                    allocator.free(rel_name);
                    return err;
                };
                allocator.free(rel_name);
            } else if (isLibraryDir(entry.name)) {
                // Skip directories that contain shared libraries, not executables
                allocator.free(rel_name);
            } else {
                next.append(allocator, rel_name) catch |err| {
                    allocator.free(rel_name);
                    return err;
                };
            }
        } else if (entry.kind == .file) {
            if (isSharedLibrary(entry.name)) {
                allocator.free(rel_name);
                continue;
            }
            const is_exe = if (windows)
                hasWindowsExeSuffix(entry.name)
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
                result.append(allocator, rel_name) catch |err| {
                    allocator.free(rel_name);
                    return err;
                };
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
    windows: bool,
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
        const is_exe = if (windows)
            hasWindowsExeSuffix(entry.name)
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
/// free: matches `tool_path` at the start of a generated target field after
/// applying the same ZON `\`-escaping ghr wrote, and requires a path-component
/// boundary so similarly prefixed repositories are not treated as owned.
fn binGhrPointsToToolDir(io: Io, bin_dir: Dir, ghr_name: []const u8, tool_path: []const u8) bool {
    return binGhrPointsToToolDirForPlatform(
        io,
        bin_dir,
        ghr_name,
        tool_path,
        builtin.os.tag == .windows,
    );
}

fn zonTargetValuePointsToToolDir(
    value: []const u8,
    escaped_tool_path: []const u8,
    windows: bool,
) bool {
    if (value.len < escaped_tool_path.len) return false;
    const prefix_matches = if (windows)
        std.ascii.eqlIgnoreCase(value[0..escaped_tool_path.len], escaped_tool_path)
    else
        std.mem.eql(u8, value[0..escaped_tool_path.len], escaped_tool_path);
    if (!prefix_matches) return false;
    if (value.len == escaped_tool_path.len) return true;
    return switch (value[escaped_tool_path.len]) {
        '"' => true,
        '/' => true,
        '\\' => windows and
            value.len > escaped_tool_path.len + 1 and
            value[escaped_tool_path.len + 1] == '\\',
        else => false,
    };
}

fn binGhrContentPointsToToolDir(
    content: []const u8,
    escaped_tool_path: []const u8,
    windows: bool,
) bool {
    const fields = [_][]const u8{
        ".target = \"",
        ".targetWasm = \"",
    };
    for (fields) |field| {
        const field_pos = std.mem.indexOf(u8, content, field) orelse continue;
        const value = content[field_pos + field.len ..];
        if (zonTargetValuePointsToToolDir(value, escaped_tool_path, windows)) return true;
    }
    return false;
}

fn binGhrPointsToToolDirForPlatform(
    io: Io,
    bin_dir: Dir,
    ghr_name: []const u8,
    tool_path: []const u8,
    windows: bool,
) bool {
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
    return binGhrContentPointsToToolDir(content, needle_buf[0..n], windows);
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
    previous_tool_dir_path: ?[]const u8,
    w: *Writer,
) !void {
    if (app_paths.len == 0) return;

    const home = environ.get("HOME") orelse return error.HomeNotFound;
    const apps_dir_path = try std.fmt.allocPrint(allocator, "{s}/Applications", .{home});
    defer allocator.free(apps_dir_path);
    Dir.createDirAbsolute(io, apps_dir_path, .default_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    var apps_dir = try Dir.openDirAbsolute(io, apps_dir_path, .{});
    defer apps_dir.close(io);

    for (app_paths) |rel_path| {
        const app_name = std.fs.path.basename(rel_path);
        const app_src = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ tool_dir_path, rel_path });
        defer allocator.free(app_src);

        // If an existing app is present, only replace it if we own it (has our marker or is a legacy symlink)
        const existing = apps_dir.statFile(io, app_name, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.FileNotFound => null,
            else => return err,
        };
        if (existing) |_| {
            const legacy_owned =
                isLegacyAppSymlink(allocator, io, apps_dir, app_name, tool_dir_path, rel_path) or
                (if (previous_tool_dir_path) |previous|
                    isLegacyAppSymlink(allocator, io, apps_dir, app_name, previous, rel_path)
                else
                    false);
            const marker_owned =
                isOwnedAppBundle(io, apps_dir, app_name, tool_dir_path) or
                (if (previous_tool_dir_path) |previous|
                    isOwnedAppBundle(io, apps_dir, app_name, previous)
                else
                    false);
            if (legacy_owned) {
                try apps_dir.deleteFile(io, app_name);
            } else if (marker_owned) {
                try apps_dir.deleteTree(io, app_name);
            } else {
                return error.AppOwnershipConflict;
            }
        }

        // Copy to a staging name, then rename for atomicity
        const staging_name = try std.fmt.allocPrint(allocator, ".ghr-staging-{s}", .{app_name});
        defer allocator.free(staging_name);
        apps_dir.deleteTree(io, staging_name) catch {};

        // Open source .app directory
        var src_dir = try Dir.openDirAbsolute(io, app_src, .{ .iterate = true });
        defer src_dir.close(io);

        // Create staging directory and copy
        try apps_dir.createDir(io, staging_name, .default_dir);
        var staging_dir = try apps_dir.openDir(io, staging_name, .{});
        defer staging_dir.close(io);

        copyDirRecursive(io, src_dir, staging_dir) catch |err| {
            apps_dir.deleteTree(io, staging_name) catch {};
            return err;
        };

        // Write ownership marker (remove first in case archive contained one as a symlink)
        staging_dir.deleteFile(io, ghr_marker) catch {};
        writeMarkerFile(io, staging_dir, tool_dir_path) catch |err| {
            apps_dir.deleteTree(io, staging_name) catch {};
            return err;
        };

        // Atomic rename into place
        apps_dir.rename(staging_name, apps_dir, app_name, io) catch |err| {
            apps_dir.deleteTree(io, staging_name) catch {};
            return err;
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
) !void {
    if (app_paths.len == 0) return;

    const home = environ.get("HOME") orelse return error.HomeNotFound;
    const apps_dir_path = try std.fmt.allocPrint(allocator, "{s}/Applications", .{home});
    defer allocator.free(apps_dir_path);

    var apps_dir = Dir.openDirAbsolute(io, apps_dir_path, .{}) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer apps_dir.close(io);

    for (app_paths) |rel_path| {
        const app_name = std.fs.path.basename(rel_path);

        // Handle legacy symlinks from older ghr versions
        if (isLegacyAppSymlink(allocator, io, apps_dir, app_name, tool_dir_path, rel_path)) {
            try apps_dir.deleteFile(io, app_name);
            try w.print("  uninstalled ~/Applications/{s}\n", .{app_name});
            continue;
        }

        if (!isOwnedAppBundle(io, apps_dir, app_name, tool_dir_path)) continue;

        try apps_dir.deleteTree(io, app_name);
        try w.print("  uninstalled ~/Applications/{s}\n", .{app_name});
    }
}

/// Check if an .app bundle in ~/Applications is owned by ghr for the given tool path.
fn isOwnedAppBundle(io: Io, apps_dir: Dir, app_name: []const u8, tool_dir_path: []const u8) bool {
    // Build path to marker: <app_name>/Contents/.ghr-source
    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const marker_path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ app_name, ghr_marker }) catch return false;

    // Verify marker is a regular file, not a symlink
    const stat = apps_dir.statFile(io, marker_path, .{ .follow_symlinks = false }) catch return false;
    if (stat.kind == .sym_link) return false;

    // Read and compare source path
    var content_buf: [Dir.max_path_bytes]u8 = undefined;
    const file = apps_dir.openFile(io, marker_path, .{ .follow_symlinks = false }) catch return false;
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
                try dest_dir.symLink(io, buf[0..len], entry.name, .{});
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
        uninstallAppBundles(allocator, io, environ, meta.parsed.value.apps, tool_path, w) catch {};
    }
}

/// Remove the shim `.exe` plus its `<stem>.ghr` manifest (and any legacy
/// `.shim` / `.cmd`) for a single native bin entry on Windows. The `.exe` is
/// only removed when a `.ghr` or `.shim` confirms the entry belongs to
/// `tool_path`.
fn cleanupWindowsBinEntry(io: Io, bin_dir: Dir, exe_name: []const u8, tool_path: []const u8) void {
    const stem = windowsExeStem(exe_name);

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
        var name_buf: [Dir.max_path_bytes]u8 = undefined;
        const shim_exe_name = windowsShimExeName(&name_buf, exe_name) catch return;
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

fn pathIsWithinTool(path: []const u8, tool_path: []const u8, windows: bool) bool {
    return std.mem.startsWith(u8, path, tool_path) and
        (path.len == tool_path.len or
            path[tool_path.len] == '/' or
            (windows and path[tool_path.len] == '\\'));
}

/// Per-install error signalling a single spec's install path failed after
/// printing a user-visible diagnostic. The outer multi-spec driver decides
/// whether to abort (fail-fast) or continue (`--keep-going`).
pub const InstallStepError = error{InstallStepFailed};
pub const InstallOptionsError = error{
    MissingInstallSpec,
    BinFilterRequiresSingleSpec,
};

pub fn validateInstallOptions(
    spec_count: usize,
    bin_filters: []const []const u8,
    err_w: *Writer,
) (InstallOptionsError || Writer.Error)!void {
    if (spec_count == 0) {
        try err_w.print("error: 'ghr install' requires <owner/repo[@tag]> or <owner/repo/file[@tag]>\n", .{});
        try err_w.flush();
        return error.MissingInstallSpec;
    }
    if (bin_filters.len > 0 and spec_count != 1) {
        try err_w.print("error: '--bin' can only be used when installing exactly one spec\n", .{});
        try err_w.print("  hint: run a separate 'ghr install <spec> --bin <name>' command for each spec\n", .{});
        try err_w.flush();
        return error.BinFilterRequiresSingleSpec;
    }
}

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
    /// Installed command names selected by repeatable `--bin` options.
    /// Validation guarantees this is non-empty only for a single-spec run.
    bin_filters: []const []const u8,
};

/// True when `abs_dir` is a directory containing a `ghr.json` — i.e. an
/// installed unit (a wasm module dir, or the repo dir of an archive install).
fn dirHasGhrJson(io: Io, abs_dir: []const u8) bool {
    var dir = Dir.openDirAbsolute(io, abs_dir, .{}) catch return false;
    defer dir.close(io);
    var f = dir.openFile(io, "ghr.json", .{}) catch return false;
    f.close(io);
    return true;
}

/// Result of `verifyDownloadedAsset`: the metadata label recorded in
/// `ghr.json` and the minisign key the install actually verified against.
const VerifyResult = struct {
    label: []const u8,
    minisign_key: ?[]const u8,
};

/// Run the full verification pipeline (checksum / minisign / authenticode /
/// sigstore) over an asset already downloaded to `download_path` and report
/// the strongest outcome. Shared by the archive and per-module wasm install
/// paths. On any verification failure the diagnostic is printed, the cached
/// download is removed, and `error.InstallStepFailed` is returned.
fn verifyDownloadedAsset(
    ctx: *const InstallContext,
    assets: []const release_mod.Asset,
    asset_name: []const u8,
    download_path: []const u8,
    minisign_pubkey_b64: ?[]const u8,
    repository: ?attestation.Repository,
    debug_w: ?*Writer,
) !VerifyResult {
    const allocator = ctx.allocator;
    const io = ctx.io;
    const d = ctx.dirs;
    const auth_header = ctx.auth_header;
    const gates = ctx.gates;
    const w = ctx.w;
    const err_w = ctx.err_w;

    // Verification (issue #50 + issue #65). Runs after the asset is on
    // disk, before we extract or move anything. Checksum (Phase 1),
    // minisign (issue #65, requires a key — inline or `--minisign`),
    // sigstore sidecar (Phase 2), and GitHub-native attestation
    // (issue #165) are independent — all run when material is published,
    // unless the matching skip flag suppresses one. The recorded label is
    // the strongest successful outcome, ranked by `release_mod`:
    // github-attestation > sigstore > minisign > authenticode > checksum.
    var verified_label: []const u8 = "none";
    // Pubkey the install actually verified against (sticky across the
    // other verifiers' outcomes). Recorded in `ghr.json` and surfaced by
    // `ghr list` so users can copy it back into future installs.
    var recorded_minisign_key: ?[]const u8 = null;
    if (gates.skip_verify) {
        verified_label = "skipped";
        try w.print("note: verification skipped (--skip-verify)\n", .{});
    } else {
        const sha_outcome: release_mod.VerifyOutcome = if (gates.shouldSkip(.checksum)) blk: {
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
                assets,
                asset_name,
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
                assets,
                asset_name,
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

        const mini_outcome: release_mod.VerifyOutcome = if (gates.skip_minisign) blk: {
            if (minisign_pubkey_b64 != null) {
                try w.print("note: minisign verification skipped (--skip-minisign)\n", .{});
            }
            break :blk .no_verification;
        } else release_mod.verifyDownloadedAssetMinisign(
            allocator,
            io,
            d.cache,
            assets,
            asset_name,
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
            recorded_minisign_key = minisign_pubkey_b64;
        }

        const ac_outcome: release_mod.VerifyOutcome = if (gates.shouldSkip(.authenticode)) blk: {
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

        const sig_outcome: release_mod.VerifyOutcome = if (gates.shouldSkip(.sigstore)) blk: {
            try w.print("note: sigstore verification skipped (--skip-sigstore)\n", .{});
            break :blk .no_verification;
        } else verifyDownloadedAssetSigstore(
            allocator,
            io,
            d.cache,
            assets,
            asset_name,
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

        // Runs even when the sidecar above succeeded: the two forms are
        // independent, and a release can publish both.
        const att_outcome: release_mod.VerifyOutcome = if (gates.shouldSkip(.attestation)) blk: {
            try w.print("note: github attestation verification skipped (--skip-attestation)\n", .{});
            break :blk .no_verification;
        } else release_mod.verifyDownloadedAssetAttestation(
            allocator,
            io,
            repository,
            download_path,
            debug_w,
            auth_header,
            w,
            err_w,
        ) catch {
            // Diagnostic and remediation hint already printed by the
            // verifier.
            Dir.deleteFileAbsolute(io, download_path) catch {};
            return error.InstallStepFailed;
        };

        const best = release_mod.strongestOutcome(&.{
            att_outcome,
            sig_outcome,
            mini_outcome,
            ac_outcome,
            sha_outcome,
        });
        if (release_mod.outcomeLabel(best)) |label| {
            verified_label = label;
        } else {
            try w.print("note: download is unverified (no checksum, minisign, sigstore, attestation, or authenticode)\n", .{});
        }
        try w.flush();
    }
    return .{ .label = verified_label, .minisign_key = recorded_minisign_key };
}

// ===========================================================================
// ID-based install pipeline (PR 5)
// ===========================================================================
//
// The pipeline has two strictly ordered halves:
//
//   1. RESOLUTION + STAGING. Every surviving request is resolved, downloaded,
//      verified, and extracted inside the reserved `_v2/txn` namespace on the
//      tools filesystem. A staging directory is transaction-private, never live
//      state, and is removed when anything fails before commit.
//   2. PLANNING + COMMIT. One `install_state.scan`, one
//      `command_plan.snapshotBinDir`, and one `command_plan.planWithDiagnostic`
//      cover the COMPLETE expanded invocation before the first live mutation.
//      Only then is each unit committed through its own local transaction.
//
// `--keep-going` affects half 1 only: a request that fails to resolve is
// reported and skipped. Plan rejection is global and commits nothing.

/// Inventory/plan/write platform for the local store. Named once so the
/// reader, planner, and writer cannot drift apart.
const host_platform: install_state.Platform = install_state.default_platform;
const host_is_windows = builtin.os.tag == .windows;

/// Command-level options for one `ghr install` invocation.
pub const InstallOptions = struct {
    debug: bool = false,
    no_auth: bool = false,
    gates: release_mod.VerifyGates = .{},
    /// Default minisign key applied to requests that carry no key of their own.
    minisign_pubkey_b64: ?[]const u8 = null,
    /// Repeatable `--bin` selection, applied before aliases. Requires exactly
    /// one request.
    bin_filters: []const []const u8 = &.{},
    keep_going: bool = false,
};

pub const InstallRunError = error{
    InvalidInstallRequest,
    InstallPlanRejected,
    InstallFailed,
};

/// One request resolved and staged inside the transaction namespace. Every
/// string it references lives in its own arena; the struct is heap-allocated so
/// that arena's address stays stable while units accumulate.
const StagedUnit = struct {
    gpa: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    id: []const u8 = "",
    /// Human label for progress and summary lines.
    display: []const u8 = "",
    paths: install_txn.Paths = undefined,
    commands: []command_plan.Command = &.{},
    aliases: []command_plan.Alias = &.{},
    apps: []const []const u8 = &.{},
    source: install_state_write.Source = .{ .kind = .github },
    config: install_state_write.Config = .{},
    resolved: install_state_write.Resolved = .{},
    verification: install_state_write.Verification = .{ .result = "none" },
    /// Serialized v2 metadata, built and validated after planning and before
    /// the first commit.
    metadata_body: []const u8 = "",

    fn create(gpa: std.mem.Allocator) !*StagedUnit {
        const self = try gpa.create(StagedUnit);
        self.* = .{ .gpa = gpa, .arena = std.heap.ArenaAllocator.init(gpa) };
        return self;
    }

    fn alloc(self: *StagedUnit) std.mem.Allocator {
        return self.arena.allocator();
    }

    fn destroy(self: *StagedUnit) void {
        self.arena.deinit();
        self.gpa.destroy(self);
    }
};

/// Convert a host-separator relative path into the portable form persisted in
/// metadata and consumed by the planner.
fn portableRel(allocator: std.mem.Allocator, raw: []const u8) ![]const u8 {
    return install_state_write.portableRelPath(allocator, raw);
}

/// Convert a portable relative path back into the host separator for building
/// absolute filesystem paths.
fn hostRelInto(buf: []u8, rel: []const u8) ![]const u8 {
    if (rel.len > buf.len) return error.PathTooLong;
    for (rel, 0..) |c, i| buf[i] = if (c == '/') std.fs.path.sep else c;
    return buf[0..rel.len];
}

fn commandKindFor(rel_target: []const u8) command_plan.Kind {
    return if (install_state.isWasmTarget(rel_target)) .wasm else .native;
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

/// Report a request-parse failure. Source tokens are echoed because they are
/// the user's own spec; query tokens and their values never are, because a
/// value may be minisign or other key-like material. Failing query fields are
/// identified by name and position only.
fn reportRequestParseError(
    err_w: *Writer,
    err: anyerror,
    diagnostic: install_request.Diagnostic,
    tokens: []const []const u8,
) !void {
    const position: ?usize = diagnostic.token_index;
    const field = diagnostic.fieldName();
    const echo_source = diagnostic.field == .source and position != null and
        position.? < tokens.len;

    try err_w.print("error: invalid install request", .{});
    if (position) |i| try err_w.print(" (argument {d})", .{i + 1});
    if (field) |name| {
        if (diagnostic.field != .source) try err_w.print(" field '{s}'", .{name});
    }
    if (diagnostic.pair_index) |pi| try err_w.print(" pair {d}", .{pi + 1});
    try err_w.print(": {t}\n", .{err});
    if (echo_source) try err_w.print("  argument: {s}\n", .{tokens[position.?]});

    switch (err) {
        error.GenericUrlRequiresExplicitId => try err_w.print(
            "  hint: a non-GitHub URL has no repository identity; add a quoted \"?id=<name>\"\n",
            .{},
        ),
        error.LoneQueryToken, error.DuplicateQueryToken, error.QueryAfterBareKey => try err_w.print(
            "  hint: quote the query token and place it directly after its source, e.g. \"?id=<id>&alias=<from>:<to>\"\n",
            .{},
        ),
        error.LoneBareKey, error.DoubleBareKey => try err_w.print(
            "  hint: a bare minisign key attaches to the preceding source only\n",
            .{},
        ),
        else => {},
    }
    try err_w.flush();
}

/// Report a rejected invocation plan. Nothing has been mutated at this point,
/// and nothing will be.
fn reportPlanError(
    err_w: *Writer,
    err: anyerror,
    diag: command_plan.Diagnostic,
    inventory: install_state.Inventory,
) !void {
    try err_w.print("error: refusing to install: {t}\n", .{err});
    if (diag.id.len > 0) try err_w.print("  id: {s}\n", .{diag.id.slice()});
    if (diag.name.len > 0) try err_w.print("  name: {s}\n", .{diag.name.slice()});
    if (diag.artifact.len > 0) try err_w.print("  bin entry: {s}\n", .{diag.artifact.slice()});
    if (diag.owner_id.len > 0) try err_w.print("  already owned by: {s}\n", .{diag.owner_id.slice()});
    if (diag.entry_kind) |k| try err_w.print("  entry kind: {t}\n", .{k});
    if (diag.record_index) |ri| {
        if (ri < inventory.records.len) {
            const rec = inventory.records[ri];
            try err_w.print("  install state: {s} ({t}/{t})\n", .{
                rec.path,
                rec.status,
                rec.reason,
            });
        }
    }
    switch (err) {
        error.InventoryNotOk,
        error.InventoryIdMissing,
        error.InventoryInvalidId,
        error.InventoryDuplicateId,
        error.InventoryInvalidCommand,
        error.InventoryUnknownKind,
        error.InventoryKindMismatch,
        error.InventoryAmbiguousArtifact,
        => try err_w.print(
            "  hint: install state must be healthy before ghr may change it; inspect with 'ghr list --json'\n",
            .{},
        ),
        error.UnmanagedArtifact => try err_w.print(
            "  hint: that bin entry is not managed by ghr; move it aside or choose another command name\n",
            .{},
        ),
        error.ArtifactOwnedByOtherId => try err_w.print(
            "  hint: uninstall the owning id, or publish this command under a different name with alias=\n",
            .{},
        ),
        else => {},
    }
    try err_w.print("  no install state was changed\n", .{});
    try err_w.flush();
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Install every request in one invocation.
pub fn cmdInstallRequests(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    tokens: []const []const u8,
    w: *Writer,
    err_w: *Writer,
    options: InstallOptions,
) !void {
    if (tokens.len == 0) {
        try validateInstallOptions(0, options.bin_filters, err_w);
        return error.MissingInstallSpec;
    }

    var diagnostic: install_request.Diagnostic = .{};
    var parsed = install_request.parseWithDiagnostic(allocator, tokens, &diagnostic) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            try reportRequestParseError(err_w, err, diagnostic, tokens);
            return error.InvalidInstallRequest;
        },
    };
    defer parsed.deinit();

    try validateInstallOptions(parsed.items.len, options.bin_filters, err_w);
    {
        var seen: std.StringHashMapUnmanaged(void) = .empty;
        defer seen.deinit(allocator);
        for (parsed.items, 0..) |request, i| {
            if ((try seen.getOrPut(allocator, request.id)).found_existing) {
                try err_w.print(
                    "error: install request {d} repeats id '{s}' in the same invocation\n",
                    .{ i + 1, request.id },
                );
                try err_w.print("  no install state was changed\n", .{});
                try err_w.flush();
                return error.InvalidInstallRequest;
            }
        }
    }

    const dirs = try Dirs.detect(allocator, environ);
    defer dirs.deinit();

    const auth_resolved = auth.resolveGithubToken(allocator, io, environ, options.no_auth);
    defer auth_resolved.deinit(allocator);
    const auth_header = try auth.bearerHeader(allocator, auth_resolved);
    defer if (auth_header) |h| allocator.free(h);

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
        .debug = options.debug,
        .no_auth = options.no_auth,
        .gates = options.gates,
        .minisign_pubkey_b64 = options.minisign_pubkey_b64,
        .bin_filters = options.bin_filters,
    };

    // Finish or roll back whatever a previous run left behind BEFORE any
    // command is touched, so recovery never races publication.
    recoverPendingTransactions(&ctx) catch |err| {
        try err_w.print("error: could not recover a pending install transaction: {t}\n", .{err});
        try err_w.print("  no install state was changed\n", .{});
        try err_w.flush();
        return error.InstallFailed;
    };

    var units: std.ArrayListUnmanaged(*StagedUnit) = .empty;
    defer {
        for (units.items) |u| u.destroy();
        units.deinit(allocator);
    }
    errdefer discardStaging(allocator, io, units.items);

    var failed: std.ArrayListUnmanaged([]const u8) = .empty;
    defer failed.deinit(allocator);

    for (parsed.items, 0..) |request, i| {
        const token = tokens[request.original_tokens.source];
        if (parsed.items.len > 1) {
            try w.print("[{d}/{d}] {s}\n", .{ i + 1, parsed.items.len, token });
            try w.flush();
        }
        stageRequest(&ctx, request, &units) catch |err| switch (err) {
            error.InstallStepFailed => {
                try failed.append(allocator, token);
                if (!options.keep_going) return error.InstallFailed;
                try err_w.print("note: --keep-going, continuing past failure for {s}\n", .{token});
                try err_w.flush();
            },
            else => return err,
        };
    }

    if (units.items.len > 0) try planAndCommit(&ctx, units.items);

    if (parsed.items.len > 1) {
        const ok = parsed.items.len - failed.items.len;
        try w.print("installed {d}/{d}", .{ ok, parsed.items.len });
        if (failed.items.len > 0) {
            try w.print(", failed:", .{});
            for (failed.items) |s| try w.print(" {s}", .{s});
        }
        try w.print("\n", .{});
        try w.flush();
    }

    if (failed.items.len > 0) return error.InstallFailed;
}

/// Drop the transactions of units that never reached live state.
///
/// A transaction whose journal has advanced past `staged` has already moved a
/// directory or published a command, and its journal and backup are the only
/// record of that. Those are left for recovery; only purely staged work is
/// reclaimed here. A committed unit has no journal left, so this is a no-op
/// for it.
fn discardStaging(allocator: std.mem.Allocator, io: Io, units: []const *StagedUnit) void {
    for (units) |u| discardStagedUnit(allocator, io, u);
}

/// Discard only a transaction proven not to have touched live state. Failure to
/// read its journal is a reason to preserve it, never permission to delete a
/// possible backup.
fn discardStagedUnit(allocator: std.mem.Allocator, io: Io, unit: *StagedUnit) void {
    var owned_opt = install_txn.readJournal(allocator, io, unit.paths.journal) catch return;
    if (owned_opt) |*owned| {
        defer owned.deinit();
        if (owned.journal.op == .uninstall or
            @intFromEnum(owned.journal.phase) >= @intFromEnum(install_txn.Phase.swapping))
            return;
    } else if (install_txn.directoryExists(io, unit.paths.backup) catch return) {
        return;
    }
    install_txn.discardTransaction(io, unit.paths) catch {};
}

// ---------------------------------------------------------------------------
// Resolution + staging
// ---------------------------------------------------------------------------

fn stageRequest(
    ctx: *const InstallContext,
    request: install_request.InstallRequest,
    out: *std.ArrayListUnmanaged(*StagedUnit),
) !void {
    const allocator = ctx.allocator;
    const w = ctx.w;
    const err_w = ctx.err_w;
    // A per-request key wins over the command-level default for this request
    // only; the parser already rejected two keys on one request.
    const minisign_pubkey_b64: ?[]const u8 = request.config.minisign orelse ctx.minisign_pubkey_b64;

    var url_buf: ?release_mod.ParsedReleaseUrl = null;
    defer if (url_buf) |*u| u.deinit(allocator);

    var spec: Spec = undefined;
    var requested_file: ?[]const u8 = null;

    switch (request.source) {
        .github_repo => |rs| spec = rs,
        .github_file => |fs| {
            spec = .{ .owner = fs.owner, .repo = fs.repo, .tag = fs.tag };
            requested_file = fs.file;
        },
        .github_release_url => |u| {
            const parsed_opt = release_mod.parseGitHubReleaseUrl(allocator, u) catch {
                try err_w.print("error: failed to parse URL '{s}'\n", .{u});
                try err_w.flush();
                return error.InstallStepFailed;
            };
            const parsed = parsed_opt orelse {
                try err_w.print("error: '{s}' is not a github.com release-download URL\n", .{u});
                try err_w.flush();
                return error.InstallStepFailed;
            };
            url_buf = parsed;
            spec = .{ .owner = parsed.owner, .repo = parsed.repo, .tag = parsed.tag };
            requested_file = parsed.file;
        },
        .generic_url => |u| return stageGenericUrlRequest(ctx, request, u, minisign_pubkey_b64, out),
    }

    try w.print("resolving {s}/{s}", .{ spec.owner, spec.repo });
    if (spec.tag) |t| try w.print("@{s}", .{t});
    try w.print(" ...\n", .{});
    try w.flush();

    var release = getRelease(allocator, ctx.client, spec.owner, spec.repo, spec.tag, ctx.auth_header) catch |err| {
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

    var primary_assets: std.ArrayListUnmanaged(release_mod.Asset) = .empty;
    defer primary_assets.deinit(allocator);
    try selectPrimaryAssets(ctx, spec, release.parsed.value, requested_file, tag_name, &primary_assets);

    const repository: attestation.Repository = release_mod.canonicalRepository(release.parsed.value) orelse
        .{ .owner = spec.owner, .repo = spec.repo };

    if (release_mod.isWasmAssetName(primary_assets.items[0].name)) {
        if (ctx.bin_filters.len > 0) {
            try err_w.print("error: '--bin' is not supported when installing wasm modules\n", .{});
            try err_w.print("  hint: omit --bin; each wasm module installs its manifest-defined command\n", .{});
            try err_w.flush();
            return error.InstallStepFailed;
        }
        for (primary_assets.items) |asset| {
            try stageWasmUnit(
                ctx,
                request,
                spec,
                tag_name,
                release.parsed.value.assets,
                asset,
                minisign_pubkey_b64,
                repository,
                out,
            );
        }
        return;
    }

    try stageArchiveUnit(
        ctx,
        request,
        spec,
        requested_file,
        tag_name,
        release.parsed.value.assets,
        primary_assets.items,
        minisign_pubkey_b64,
        repository,
        out,
    );
}

/// Build the list of assets one GitHub request installs, exactly as the
/// pre-ID installer did: an explicit file selector, else every wasm module that
/// ships a companion `.ghr` manifest, else one platform auto-pick.
fn selectPrimaryAssets(
    ctx: *const InstallContext,
    spec: Spec,
    release: release_mod.Release,
    requested_file: ?[]const u8,
    tag_name: []const u8,
    out: *std.ArrayListUnmanaged(release_mod.Asset),
) !void {
    const allocator = ctx.allocator;
    const err_w = ctx.err_w;

    if (requested_file) |fname| {
        const m = release_mod.findAssetByName(allocator, release.assets, fname) catch |err| {
            try err_w.print("error: failed to match asset by name: {}\n", .{err});
            try err_w.flush();
            return error.InstallStepFailed;
        };
        switch (m) {
            .one => |a| try out.append(allocator, a),
            .none => {
                try err_w.print("error: no asset matching '{s}' in {s}/{s}@{s}\n", .{
                    fname, spec.owner, spec.repo, tag_name,
                });
                try err_w.print("available assets:\n", .{});
                for (release.assets) |a| try err_w.print("  {s}\n", .{a.name});
                try err_w.flush();
                return error.InstallStepFailed;
            },
            .ambiguous => |list| {
                defer allocator.free(list);
                try err_w.print("error: '{s}' matches multiple assets in {s}/{s}@{s}:\n", .{
                    fname, spec.owner, spec.repo, tag_name,
                });
                for (list) |a| try err_w.print("  {s}\n", .{a.name});
                try err_w.flush();
                return error.InstallStepFailed;
            },
        }
        return;
    }

    const wasm_mods = try release_mod.wasmModulesWithManifest(allocator, release.assets);
    defer allocator.free(wasm_mods);
    for (wasm_mods) |a| try out.append(allocator, a);
    if (out.items.len > 0) return;

    const a = findBestAsset(release.assets) catch {
        try err_w.print("error: no matching asset for this platform\n", .{});
        try err_w.print("available assets:\n", .{});
        for (release.assets) |av| try err_w.print("  {s}\n", .{av.name});
        try err_w.flush();
        return error.InstallStepFailed;
    };
    try out.append(allocator, a);
}

/// Non-sensitive provenance for one resolved GitHub asset. A signed or
/// credential-bearing effective URL is never persisted; the asset is then
/// identified by repository/tag/name/`api_asset_id`/digest instead.
fn resolvedFromAsset(
    a: std.mem.Allocator,
    tag_name: []const u8,
    asset: release_mod.Asset,
) !install_state_write.Resolved {
    var resolved: install_state_write.Resolved = .{
        .tag = try a.dupe(u8, tag_name),
        .asset = try a.dupe(u8, asset.name),
        .api_asset_id = if (asset.id) |id| (if (id > 0) id else null) else null,
    };
    if (asset.browser_download_url.len > 0 and
        install_state_write.isPersistableUrl(asset.browser_download_url))
    {
        resolved.download_url = try a.dupe(u8, asset.browser_download_url);
    }
    if (asset.digest) |d| {
        if (std.mem.indexOfScalar(u8, d, ':')) |cut| {
            const algorithm = d[0..cut];
            const value = d[cut + 1 ..];
            if (algorithm.len > 0 and value.len > 0 and install_state.isBoundedMetaString(value)) {
                resolved.digest = .{
                    .algorithm = try a.dupe(u8, algorithm),
                    .value = try a.dupe(u8, value),
                };
            }
        }
    }
    return resolved;
}

fn policyFromGates(gates: release_mod.VerifyGates) install_state_write.VerificationPolicy {
    return .{
        .skip_verify = gates.skip_verify,
        .skip_checksum = gates.skip_checksum,
        .skip_minisign = gates.skip_minisign,
        .skip_sigstore = gates.skip_sigstore,
        .skip_attestation = gates.skip_attestation,
        .skip_authenticode = gates.skip_authenticode,
    };
}

/// Copy the request's durable configuration into the unit's arena.
fn fillConfig(
    unit: *StagedUnit,
    request: install_request.InstallRequest,
    minisign_pubkey_b64: ?[]const u8,
    gates: release_mod.VerifyGates,
    bin_filters: []const []const u8,
) !void {
    const a = unit.alloc();

    const aliases = try a.alloc(command_plan.Alias, request.config.aliases.len);
    const meta_aliases = try a.alloc(install_state_write.Alias, request.config.aliases.len);
    for (request.config.aliases, 0..) |alias, i| {
        const from = try a.dupe(u8, alias.source);
        const to = try a.dupe(u8, alias.published);
        aliases[i] = .{ .source = from, .published = to };
        meta_aliases[i] = .{ .from = from, .to = to };
    }
    unit.aliases = aliases;

    var selected: ?[]const []const u8 = null;
    if (bin_filters.len > 0) {
        const copy = try a.alloc([]const u8, bin_filters.len);
        for (bin_filters, 0..) |f, i| copy[i] = try a.dupe(u8, f);
        selected = copy;
    }

    unit.config = .{
        .aliases = meta_aliases,
        .selected_commands = selected,
        .minisign = if (minisign_pubkey_b64) |k| try a.dupe(u8, k) else null,
        .verification_policy = policyFromGates(gates),
    };
}

/// Create the transaction paths and an empty staging directory for `id`.
fn beginStaging(ctx: *const InstallContext, unit: *StagedUnit, id: []const u8) !void {
    const a = unit.alloc();
    unit.id = try a.dupe(u8, id);
    unit.paths = install_txn.paths(a, ctx.dirs.tools, unit.id, host_platform) catch |err| {
        try ctx.err_w.print("error: install id '{s}' cannot be stored: {t}\n", .{ id, err });
        try ctx.err_w.flush();
        return error.InstallStepFailed;
    };

    var pending = install_txn.readJournal(ctx.allocator, ctx.io, unit.paths.journal) catch |err| {
        try ctx.err_w.print("error: cannot inspect the pending transaction for '{s}': {t}\n", .{ id, err });
        try ctx.err_w.print("  no existing transaction was changed\n", .{});
        try ctx.err_w.flush();
        return error.InstallStepFailed;
    };
    if (pending) |*owned| {
        defer owned.deinit();
        try ctx.err_w.print("error: install id '{s}' has an unfinished transaction\n", .{id});
        try ctx.err_w.print("  run any ghr command to retry recovery before installing this id\n", .{});
        try ctx.err_w.flush();
        return error.InstallStepFailed;
    }
    if (install_txn.directoryExists(ctx.io, unit.paths.backup) catch |err| {
        try ctx.err_w.print("error: cannot inspect the pending backup for '{s}': {t}\n", .{ id, err });
        try ctx.err_w.flush();
        return error.InstallStepFailed;
    }) {
        try ctx.err_w.print("error: install id '{s}' has an unjournaled transaction backup\n", .{id});
        try ctx.err_w.print("  refusing to overwrite the only possible copy of the previous install\n", .{});
        try ctx.err_w.flush();
        return error.InstallStepFailed;
    }

    install_txn.prepareStage(ctx.io, unit.paths) catch |err| {
        try reportStagingDirCreateError(ctx.err_w, unit.paths.stage, err);
        return error.InstallStepFailed;
    };
    // Journal the staging directory immediately. Resolution can be interrupted
    // (a long download, a failed verification, a killed process), and a staged
    // tree with no journal would be litter nothing could safely reclaim. A
    // `prepared` journal names nothing live, so recovery simply discards it.
    install_txn.writeJournal(ctx.io, unit.paths, ctx.allocator, .{
        .op = .install,
        .id = unit.id,
        .unit_path = unit.paths.unit,
        .stage_path = unit.paths.stage,
        .backup_path = unit.paths.backup,
        .phase = .prepared,
    }) catch |err| {
        try ctx.err_w.print("error: failed to journal the install transaction: {t}\n", .{err});
        try ctx.err_w.flush();
        install_txn.discardTransaction(ctx.io, unit.paths) catch {};
        return error.InstallStepFailed;
    };
}

fn ensureInvocationIdAvailable(
    err_w: *Writer,
    staged: []const *StagedUnit,
    id: []const u8,
) !void {
    for (staged) |unit| {
        if (!std.mem.eql(u8, unit.id, id)) continue;
        try err_w.print("error: expanded install id '{s}' occurs more than once in this invocation\n", .{id});
        try err_w.print("  no install state was changed\n", .{});
        try err_w.flush();
        return error.InstallPlanRejected;
    }
}

/// Discover the commands and app bundles a staged tree publishes, apply the
/// `--bin` selection (which is pre-alias), and record them on the unit.
fn discoverStagedCommands(
    ctx: *const InstallContext,
    unit: *StagedUnit,
    stage_dir: Dir,
    prefer_deb_shims: bool,
    primary_name: []const u8,
    assets: []const release_mod.Asset,
) !void {
    const allocator = ctx.allocator;
    const a = unit.alloc();
    const err_w = ctx.err_w;

    var exes = (if (prefer_deb_shims)
        findDebExecutables(allocator, ctx.io, stage_dir)
    else
        findExecutables(allocator, ctx.io, stage_dir)) catch |err| {
        try err_w.print("error: failed to scan staging dir '{s}' for executables: {t}\n", .{
            unit.paths.stage, err,
        });
        try err_w.flush();
        return error.InstallStepFailed;
    };
    defer {
        for (exes.items) |e| allocator.free(e);
        exes.deinit(allocator);
    }

    dedupeExecutablesByHostArch(allocator, &exes);
    filterExecutables(allocator, &exes, ctx.bin_filters, host_is_windows, err_w) catch |err| switch (err) {
        error.UnmatchedBinFilter => {
            try err_w.flush();
            return error.InstallStepFailed;
        },
        else => return err,
    };

    if (exes.items.len == 0) {
        try err_w.print("error: no executables found in archive\n", .{});
        try err_w.print("  selected asset: {s}\n", .{primary_name});
        try err_w.print("  other installable assets in this release:\n", .{});
        var listed: u32 = 0;
        for (assets) |asset| {
            if (std.mem.eql(u8, asset.name, primary_name)) continue;
            if (!isInstallableAsset(asset.name)) continue;
            try err_w.print("    {s}\n", .{asset.name});
            listed += 1;
        }
        if (listed == 0) try err_w.print("    (none)\n", .{});
        try err_w.flush();
        return error.InstallStepFailed;
    }

    const commands = try a.alloc(command_plan.Command, exes.items.len);
    for (exes.items, 0..) |rel, i| {
        const portable = try portableRel(a, rel);
        commands[i] = .{ .relative_target = portable, .kind = commandKindFor(portable) };
    }
    unit.commands = commands;

    if (comptime builtin.os.tag.isDarwin()) {
        var apps = try findAppBundles(allocator, ctx.io, stage_dir);
        defer {
            for (apps.items) |app| allocator.free(app);
            apps.deinit(allocator);
        }
        const owned = try a.alloc([]const u8, apps.items.len);
        for (apps.items, 0..) |app, i| owned[i] = try portableRel(a, app);
        unit.apps = owned;
    }
}

fn stageArchiveUnit(
    ctx: *const InstallContext,
    request: install_request.InstallRequest,
    spec: Spec,
    requested_file: ?[]const u8,
    tag_name: []const u8,
    assets: []const release_mod.Asset,
    primary_assets: []const release_mod.Asset,
    minisign_pubkey_b64: ?[]const u8,
    repository: attestation.Repository,
    out: *std.ArrayListUnmanaged(*StagedUnit),
) !void {
    const allocator = ctx.allocator;
    const io = ctx.io;
    const d = ctx.dirs;
    const w = ctx.w;
    const err_w = ctx.err_w;
    const debug_w: ?*Writer = if (ctx.debug) err_w else null;

    const unit = try StagedUnit.create(allocator);
    var keep = false;
    defer if (!keep) unit.destroy();
    const a = unit.alloc();

    try ensureInvocationIdAvailable(err_w, out.items, request.id);
    try beginStaging(ctx, unit, request.id);
    errdefer discardStagedUnit(allocator, io, unit);

    var stage_dir = Dir.openDirAbsolute(io, unit.paths.stage, .{ .iterate = true }) catch |err| {
        try err_w.print("error: failed to open staging dir '{s}': {t}\n", .{ unit.paths.stage, err });
        try err_w.flush();
        return error.InstallStepFailed;
    };
    defer stage_dir.close(io);

    ensureDirAbsoluteRecursive(io, d.cache) catch {};

    var verified_label: []const u8 = "none";
    var recorded_minisign_key: ?[]const u8 = null;
    var prefer_deb_shims = false;

    for (primary_assets) |asset| {
        release_mod.preflightVerification(assets, asset.name, ctx.gates, minisign_pubkey_b64, err_w) catch
            return error.InstallStepFailed;

        try w.print("downloading {s} ...\n", .{asset.name});
        try w.flush();

        const download_path = try std.fmt.allocPrint(allocator, "{s}{c}{s}", .{
            d.cache, std.fs.path.sep, asset.name,
        });
        defer allocator.free(download_path);

        const asset_dl = release_mod.assetDownload(asset, ctx.auth_header != null);
        debugLog(debug_w, "debug: ghr {s}\n", .{version});
        debugLog(debug_w, "debug: auth: {s}\n", .{ctx.auth_resolved.source});
        debugLog(debug_w, "debug: url: {s}\n", .{asset_dl.url});
        debugLog(debug_w, "debug: cache: {s}\n", .{download_path});

        http.downloadToFile(allocator, io, asset_dl.url, download_path, .{
            .auth_header = ctx.auth_header,
            .accept = asset_dl.accept,
            .debug_w = debug_w,
        }) catch |err| {
            try err_w.print("error: download failed: {}\n", .{err});
            try err_w.print("  url: {s}\n", .{asset_dl.url});
            try err_w.flush();
            return error.InstallStepFailed;
        };
        defer Dir.deleteFileAbsolute(io, download_path) catch {};

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

        const vr = try verifyDownloadedAsset(
            ctx,
            assets,
            asset.name,
            download_path,
            minisign_pubkey_b64,
            repository,
            debug_w,
        );
        verified_label = vr.label;
        recorded_minisign_key = vr.minisign_key;

        try w.print("extracting ...\n", .{});
        try w.flush();

        switch (archive.detectFormat(asset.name)) {
            .zip, .tar_gz, .tar_xz, .deb => {
                archive.extractAuto(allocator, io, stage_dir, download_path, 0) catch |err| {
                    try err_w.print(
                        "error: failed to extract '{s}' from '{s}' into '{s}': {t}\n",
                        .{ asset.name, download_path, unit.paths.stage, err },
                    );
                    try err_w.flush();
                    return error.InstallStepFailed;
                };
            },
            .unknown => {
                const exe_name = try deriveBareBinaryName(allocator, asset.name, spec.repo, host_is_windows);
                defer allocator.free(exe_name);
                stageBareExecutable(allocator, io, d.cache, asset.name, stage_dir, exe_name) catch |err| {
                    try err_w.print(
                        "error: failed to stage bare executable '{s}' from '{s}' into '{s}' as '{s}': {t}\n",
                        .{ asset.name, d.cache, unit.paths.stage, exe_name, err },
                    );
                    try err_w.flush();
                    return error.InstallStepFailed;
                };
            },
        }
        prefer_deb_shims = archive.detectFormat(asset.name) == .deb and hasDebShims(io, stage_dir);
    }

    const primary_name = primary_assets[0].name;
    try discoverStagedCommands(ctx, unit, stage_dir, prefer_deb_shims, primary_name, assets);

    unit.source = .{
        .kind = .github,
        .owner = try a.dupe(u8, spec.owner),
        .repo = try a.dupe(u8, spec.repo),
        .tag = if (spec.tag) |t| try a.dupe(u8, t) else null,
        .asset_selector = if (requested_file) |f| try a.dupe(u8, f) else null,
    };
    try fillConfig(unit, request, minisign_pubkey_b64, ctx.gates, ctx.bin_filters);
    unit.resolved = try resolvedFromAsset(a, tag_name, primary_assets[0]);
    unit.verification = .{
        .result = try a.dupe(u8, verified_label),
        .minisign = if (recorded_minisign_key) |k| try a.dupe(u8, k) else null,
    };
    unit.display = try std.fmt.allocPrint(a, "{s}@{s}", .{ unit.id, tag_name });

    try out.append(allocator, unit);
    keep = true;
}

fn stageWasmUnit(
    ctx: *const InstallContext,
    request: install_request.InstallRequest,
    spec: Spec,
    tag_name: []const u8,
    assets: []const release_mod.Asset,
    asset: release_mod.Asset,
    minisign_pubkey_b64: ?[]const u8,
    repository: attestation.Repository,
    out: *std.ArrayListUnmanaged(*StagedUnit),
) !void {
    const allocator = ctx.allocator;
    const io = ctx.io;
    const d = ctx.dirs;
    const w = ctx.w;
    const err_w = ctx.err_w;
    const debug_w: ?*Writer = if (ctx.debug) err_w else null;

    const unit = try StagedUnit.create(allocator);
    var keep = false;
    defer if (!keep) unit.destroy();
    const a = unit.alloc();

    // Each wasm module is its own unit under the request's ID. The stem must be
    // a single canonical ID segment; anything else is rejected before staging.
    const stem = wasmStem(asset.name);
    const canonical_stem = install_request.canonicalizeId(a, stem) catch {
        try err_w.print("error: wasm module '{s}' has no usable install id segment\n", .{asset.name});
        try err_w.flush();
        return error.InstallStepFailed;
    };
    if (std.mem.indexOfScalar(u8, canonical_stem, '/') != null) {
        try err_w.print("error: wasm module '{s}' expands to an unsafe install id\n", .{asset.name});
        try err_w.flush();
        return error.InstallStepFailed;
    }
    const child_id = try std.fmt.allocPrint(a, "{s}/{s}", .{ request.id, canonical_stem });

    release_mod.preflightVerification(assets, asset.name, ctx.gates, minisign_pubkey_b64, err_w) catch
        return error.InstallStepFailed;

    try ensureInvocationIdAvailable(err_w, out.items, child_id);
    try beginStaging(ctx, unit, child_id);
    errdefer discardStagedUnit(allocator, io, unit);

    try w.print("downloading {s} ...\n", .{asset.name});
    try w.flush();

    ensureDirAbsoluteRecursive(io, d.cache) catch {};

    const download_path = try std.fmt.allocPrint(allocator, "{s}{c}{s}", .{
        d.cache, std.fs.path.sep, asset.name,
    });
    defer allocator.free(download_path);

    const asset_dl = release_mod.assetDownload(asset, ctx.auth_header != null);
    debugLog(debug_w, "debug: url: {s}\n", .{asset_dl.url});
    http.downloadToFile(allocator, io, asset_dl.url, download_path, .{
        .auth_header = ctx.auth_header,
        .accept = asset_dl.accept,
        .debug_w = debug_w,
    }) catch |err| {
        try err_w.print("error: download failed: {}\n", .{err});
        try err_w.print("  url: {s}\n", .{asset_dl.url});
        try err_w.flush();
        return error.InstallStepFailed;
    };
    defer Dir.deleteFileAbsolute(io, download_path) catch {};

    const vr = try verifyDownloadedAsset(
        ctx,
        assets,
        asset.name,
        download_path,
        minisign_pubkey_b64,
        repository,
        debug_w,
    );

    const ghr_name = try std.fmt.allocPrint(allocator, "{s}.ghr", .{asset.name});
    defer allocator.free(ghr_name);
    const ghr_asset = release_mod.findGhrManifestAsset(assets, asset.name) orelse {
        try err_w.print(
            "error: wasm asset '{s}' has no companion '{s}.ghr' manifest in this release\n",
            .{ asset.name, asset.name },
        );
        try err_w.flush();
        return error.InstallStepFailed;
    };
    const ghr_path = try std.fmt.allocPrint(allocator, "{s}{c}{s}", .{ d.cache, std.fs.path.sep, ghr_name });
    defer allocator.free(ghr_path);
    defer Dir.deleteFileAbsolute(io, ghr_path) catch {};
    const ghr_dl = release_mod.assetDownload(ghr_asset, ctx.auth_header != null);
    http.downloadToFile(allocator, io, ghr_dl.url, ghr_path, .{
        .auth_header = ctx.auth_header,
        .accept = ghr_dl.accept,
        .debug_w = debug_w,
    }) catch |err| {
        try err_w.print("error: failed to download manifest '{s}': {t}\n", .{ ghr_asset.name, err });
        try err_w.flush();
        return error.InstallStepFailed;
    };
    validateGhrManifest(allocator, io, ghr_path, err_w) catch return error.InstallStepFailed;

    {
        var stage_dir = Dir.openDirAbsolute(io, unit.paths.stage, .{ .iterate = true }) catch |err| {
            try err_w.print("error: failed to open staging dir '{s}': {t}\n", .{ unit.paths.stage, err });
            try err_w.flush();
            return error.InstallStepFailed;
        };
        defer stage_dir.close(io);
        var cache_dir = Dir.openDirAbsolute(io, d.cache, .{}) catch |err| {
            try err_w.print("error: failed to open cache dir '{s}': {t}\n", .{ d.cache, err });
            try err_w.flush();
            return error.InstallStepFailed;
        };
        defer cache_dir.close(io);
        cache_dir.copyFile(asset.name, stage_dir, asset.name, io, .{}) catch |err| {
            try err_w.print("error: failed to stage wasm '{s}': {t}\n", .{ asset.name, err });
            try err_w.flush();
            return error.InstallStepFailed;
        };
        cache_dir.copyFile(ghr_name, stage_dir, ghr_name, io, .{}) catch |err| {
            try err_w.print("error: failed to stage manifest '{s}': {t}\n", .{ ghr_name, err });
            try err_w.flush();
            return error.InstallStepFailed;
        };
    }

    const target = try a.dupe(u8, asset.name);
    const commands = try a.alloc(command_plan.Command, 1);
    commands[0] = .{ .relative_target = target, .kind = .wasm };
    unit.commands = commands;

    unit.source = .{
        .kind = .github,
        .owner = try a.dupe(u8, spec.owner),
        .repo = try a.dupe(u8, spec.repo),
        .tag = if (spec.tag) |t| try a.dupe(u8, t) else null,
        .asset_selector = try a.dupe(u8, asset.name),
    };
    try fillConfig(unit, request, minisign_pubkey_b64, ctx.gates, &.{});
    unit.resolved = try resolvedFromAsset(a, tag_name, asset);
    unit.verification = .{
        .result = try a.dupe(u8, vr.label),
        .minisign = if (vr.minisign_key) |k| try a.dupe(u8, k) else null,
    };
    unit.display = try std.fmt.allocPrint(a, "{s}@{s}", .{ unit.id, tag_name });

    try out.append(allocator, unit);
    keep = true;
}

// ---------------------------------------------------------------------------
// Generic (non-GitHub) URL sources
// ---------------------------------------------------------------------------

fn hexNibble(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

/// Derive the asset file name a generic URL downloads, from the LAST path
/// segment only. The segment is percent-decoded, then it must be a safe
/// portable file name: no separators, traversal, control bytes, or reserved
/// device names survive this.
fn genericUrlAssetName(a: std.mem.Allocator, url: []const u8) ![]const u8 {
    const scheme_end = std.mem.indexOf(u8, url, "://") orelse return error.InvalidGenericUrl;
    var rest = url[scheme_end + 3 ..];
    if (std.mem.indexOfAny(u8, rest, "?#")) |cut| rest = rest[0..cut];
    const slash = std.mem.indexOfScalar(u8, rest, '/') orelse return error.InvalidGenericUrl;
    const path = rest[slash + 1 ..];
    if (path.len == 0) return error.InvalidGenericUrl;
    const last = if (std.mem.lastIndexOfScalar(u8, path, '/')) |i| path[i + 1 ..] else path;
    if (last.len == 0 or last.len > 255) return error.InvalidGenericUrl;

    var decoded: std.ArrayListUnmanaged(u8) = .empty;
    var i: usize = 0;
    while (i < last.len) {
        if (last[i] == '%') {
            if (i + 2 >= last.len) return error.InvalidGenericUrl;
            const hi = hexNibble(last[i + 1]) orelse return error.InvalidGenericUrl;
            const lo = hexNibble(last[i + 2]) orelse return error.InvalidGenericUrl;
            try decoded.append(a, (hi << 4) | lo);
            i += 3;
        } else {
            try decoded.append(a, last[i]);
            i += 1;
        }
    }
    const name = try decoded.toOwnedSlice(a);
    if (!install_state.isSafePortableRelPath(name)) return error.InvalidGenericUrl;
    if (std.mem.indexOfScalar(u8, name, '/') != null) return error.InvalidGenericUrl;
    return name;
}

/// Verify a generic-URL download. ghr never claims a verification it did not
/// perform: a generic URL publishes no GitHub digest, no sigstore sidecar, and
/// no attestation, so those verifiers report that they cannot run instead of
/// contributing an outcome. A supplied minisign key MUST verify against the
/// sibling `<url>.minisig`, or the install fails.
fn verifyGenericUrlAsset(
    ctx: *const InstallContext,
    url: []const u8,
    asset_name: []const u8,
    download_path: []const u8,
    minisign_pubkey_b64: ?[]const u8,
    debug_w: ?*Writer,
) !VerifyResult {
    const allocator = ctx.allocator;
    const io = ctx.io;
    const w = ctx.w;
    const err_w = ctx.err_w;

    if (ctx.gates.skip_verify) {
        try w.print("note: verification skipped (--skip-verify)\n", .{});
        return .{ .label = "skipped", .minisign_key = null };
    }

    var outcomes: std.ArrayListUnmanaged(release_mod.VerifyOutcome) = .empty;
    defer outcomes.deinit(allocator);
    var recorded_key: ?[]const u8 = null;

    if (!ctx.gates.shouldSkip(.checksum)) {
        try w.print(
            "note: '{s}' is a direct URL; ghr has no published checksum to verify against\n",
            .{asset_name},
        );
    }

    if (minisign_pubkey_b64) |key_b64| {
        if (ctx.gates.skip_minisign) {
            try w.print("note: minisign verification skipped (--skip-minisign)\n", .{});
        } else {
            try verifyGenericUrlMinisign(ctx, url, asset_name, download_path, key_b64, debug_w);
            try outcomes.append(allocator, .minisign_verified);
            recorded_key = key_b64;
        }
    }

    if (!ctx.gates.shouldSkip(.authenticode)) {
        const ac = release_mod.verifyDownloadedAssetAuthenticode(
            allocator,
            io,
            download_path,
            debug_w,
            w,
            err_w,
        ) catch |err| {
            try err_w.print("error: authenticode verification failed: {s}\n", .{@errorName(err)});
            try err_w.flush();
            return error.InstallStepFailed;
        };
        try outcomes.append(allocator, ac);
    }

    if (!ctx.gates.shouldSkip(.sigstore)) {
        try w.print("note: sigstore sidecars are not resolvable for a direct URL\n", .{});
    }
    if (!ctx.gates.shouldSkip(.attestation)) {
        try w.print("note: GitHub attestations are not resolvable for a direct URL\n", .{});
    }

    const best = release_mod.strongestOutcome(outcomes.items);
    const label = release_mod.outcomeLabel(best) orelse blk: {
        try w.print("note: download is unverified (direct URL with no verifiable material)\n", .{});
        break :blk "none";
    };
    try w.flush();
    return .{ .label = label, .minisign_key = recorded_key };
}

/// Verify `download_path` against `<url>.minisig`. The sidecar location is the
/// deterministic sibling of the download URL; a URL carrying a query string has
/// no unambiguous sibling and is refused rather than guessed at.
fn verifyGenericUrlMinisign(
    ctx: *const InstallContext,
    url: []const u8,
    asset_name: []const u8,
    download_path: []const u8,
    key_b64: []const u8,
    debug_w: ?*Writer,
) !void {
    const allocator = ctx.allocator;
    const io = ctx.io;
    const w = ctx.w;
    const err_w = ctx.err_w;

    if (std.mem.indexOfAny(u8, url, "?#") != null) {
        try err_w.print(
            "error: cannot locate a minisign sidecar for a URL carrying a query string\n",
            .{},
        );
        try err_w.print("  hint: publish '<url>.minisig' beside a plain URL, or drop --minisign\n", .{});
        try err_w.flush();
        return error.InstallStepFailed;
    }

    const pk = minisign.parsePublicKey(key_b64) catch |err| {
        try err_w.print("error: minisign value is not a valid public key ({s})\n", .{@errorName(err)});
        try err_w.flush();
        return error.InstallStepFailed;
    };

    const sidecar_url = try std.fmt.allocPrint(allocator, "{s}.minisig", .{url});
    defer allocator.free(sidecar_url);
    const sidecar_path = try std.fmt.allocPrint(allocator, "{s}{c}{s}.minisig", .{
        ctx.dirs.cache, std.fs.path.sep, asset_name,
    });
    defer allocator.free(sidecar_path);
    defer Dir.deleteFileAbsolute(io, sidecar_path) catch {};

    // A direct URL is not a GitHub endpoint: never send the GitHub token.
    http.downloadToFile(allocator, io, sidecar_url, sidecar_path, .{
        .auth_header = null,
        .accept = null,
        .debug_w = debug_w,
    }) catch |err| {
        try err_w.print("error: failed to download minisign sidecar '{s}': {t}\n", .{ sidecar_url, err });
        try err_w.flush();
        return error.InstallStepFailed;
    };

    const sidecar_bytes = blk: {
        var dir = Dir.openDirAbsolute(io, ctx.dirs.cache, .{}) catch |err| {
            try err_w.print("error: failed to open cache dir: {t}\n", .{err});
            try err_w.flush();
            return error.InstallStepFailed;
        };
        defer dir.close(io);
        break :blk dir.readFileAlloc(
            io,
            std.fs.path.basename(sidecar_path),
            allocator,
            Io.Limit.limited(64 * 1024),
        ) catch |err| {
            try err_w.print("error: failed to read minisign sidecar: {t}\n", .{err});
            try err_w.flush();
            return error.InstallStepFailed;
        };
    };
    defer allocator.free(sidecar_bytes);

    const sig = minisign.parseSignature(sidecar_bytes) catch |err| {
        try err_w.print("error: failed to parse minisign sidecar: {s}\n", .{@errorName(err)});
        try err_w.flush();
        return error.InstallStepFailed;
    };
    minisign.verifyKeyId(pk, sig) catch {
        try err_w.print("error: minisign key id mismatch for '{s}'\n", .{asset_name});
        try err_w.flush();
        return error.InstallStepFailed;
    };
    var file = Dir.openFileAbsolute(io, download_path, .{}) catch |err| {
        try err_w.print("error: failed to open '{s}': {t}\n", .{ download_path, err });
        try err_w.flush();
        return error.InstallStepFailed;
    };
    defer file.close(io);
    minisign.verifyArtifact(io, file, pk, sig) catch |err| {
        try err_w.print(
            "error: minisign artifact signature does not verify for '{s}': {s}\n",
            .{ asset_name, @errorName(err) },
        );
        try err_w.flush();
        return error.InstallStepFailed;
    };
    minisign.verifyGlobal(pk, sig) catch |err| {
        try err_w.print(
            "error: minisign trusted-comment signature does not verify for '{s}': {s}\n",
            .{ asset_name, @errorName(err) },
        );
        try err_w.flush();
        return error.InstallStepFailed;
    };
    var key_hex: [16]u8 = undefined;
    minisign.keyIdToHex(pk.key_id, &key_hex);
    try w.print("verified minisign: key {s}\n", .{&key_hex});
    try w.flush();
}

fn stageGenericUrlRequest(
    ctx: *const InstallContext,
    request: install_request.InstallRequest,
    url: []const u8,
    minisign_pubkey_b64: ?[]const u8,
    out: *std.ArrayListUnmanaged(*StagedUnit),
) !void {
    const allocator = ctx.allocator;
    const io = ctx.io;
    const d = ctx.dirs;
    const w = ctx.w;
    const err_w = ctx.err_w;
    const debug_w: ?*Writer = if (ctx.debug) err_w else null;

    // Provenance for a direct URL IS the URL, so a URL that cannot be persisted
    // (userinfo, signed query parameters, expiry) is refused outright rather
    // than installed with invented provenance.
    if (!install_state_write.isPersistableUrl(url)) {
        try err_w.print("error: refusing to install from a URL that cannot be recorded as provenance\n", .{});
        try err_w.print(
            "  hint: the URL carries credentials, an expiry, or a signature; download it first and install the file\n",
            .{},
        );
        try err_w.flush();
        return error.InstallStepFailed;
    }

    const unit = try StagedUnit.create(allocator);
    var keep = false;
    defer if (!keep) unit.destroy();
    const a = unit.alloc();

    const asset_name = genericUrlAssetName(a, url) catch {
        try err_w.print("error: cannot derive a safe file name from '{s}'\n", .{url});
        try err_w.flush();
        return error.InstallStepFailed;
    };

    try ensureInvocationIdAvailable(err_w, out.items, request.id);
    try beginStaging(ctx, unit, request.id);
    errdefer discardStagedUnit(allocator, io, unit);

    var stage_dir = Dir.openDirAbsolute(io, unit.paths.stage, .{ .iterate = true }) catch |err| {
        try err_w.print("error: failed to open staging dir '{s}': {t}\n", .{ unit.paths.stage, err });
        try err_w.flush();
        return error.InstallStepFailed;
    };
    defer stage_dir.close(io);

    ensureDirAbsoluteRecursive(io, d.cache) catch {};
    const download_path = try std.fmt.allocPrint(allocator, "{s}{c}{s}", .{
        d.cache, std.fs.path.sep, asset_name,
    });
    defer allocator.free(download_path);

    try w.print("downloading {s} ...\n", .{url});
    try w.flush();
    // Never send GitHub credentials to a host ghr does not control.
    http.downloadToFile(allocator, io, url, download_path, .{
        .auth_header = null,
        .accept = null,
        .debug_w = debug_w,
    }) catch |err| {
        try err_w.print("error: download failed: {}\n", .{err});
        try err_w.print("  url: {s}\n", .{url});
        try err_w.flush();
        return error.InstallStepFailed;
    };
    defer Dir.deleteFileAbsolute(io, download_path) catch {};

    const vr = try verifyGenericUrlAsset(ctx, url, asset_name, download_path, minisign_pubkey_b64, debug_w);

    const digest = release_mod.computeFileSha256(io, download_path) catch |err| {
        try err_w.print("error: failed to digest '{s}': {t}\n", .{ download_path, err });
        try err_w.flush();
        return error.InstallStepFailed;
    };
    const digest_hex = try std.fmt.allocPrint(a, "{x}", .{&digest});

    try w.print("extracting ...\n", .{});
    try w.flush();
    switch (archive.detectFormat(asset_name)) {
        .zip, .tar_gz, .tar_xz, .deb => {
            archive.extractAuto(allocator, io, stage_dir, download_path, 0) catch |err| {
                try err_w.print("error: failed to extract '{s}': {t}\n", .{ asset_name, err });
                try err_w.flush();
                return error.InstallStepFailed;
            };
        },
        .unknown => {
            const exe_name = try deriveBareBinaryName(
                allocator,
                asset_name,
                std.fs.path.basename(unit.id),
                host_is_windows,
            );
            defer allocator.free(exe_name);
            stageBareExecutable(allocator, io, d.cache, asset_name, stage_dir, exe_name) catch |err| {
                try err_w.print("error: failed to stage bare executable '{s}': {t}\n", .{ asset_name, err });
                try err_w.flush();
                return error.InstallStepFailed;
            };
        },
    }

    const prefer_deb_shims = archive.detectFormat(asset_name) == .deb and hasDebShims(io, stage_dir);
    try discoverStagedCommands(ctx, unit, stage_dir, prefer_deb_shims, asset_name, &.{});

    unit.source = .{ .kind = .generic_url, .url = try a.dupe(u8, url) };
    try fillConfig(unit, request, minisign_pubkey_b64, ctx.gates, ctx.bin_filters);
    unit.resolved = .{
        .asset = try a.dupe(u8, asset_name),
        .download_url = try a.dupe(u8, url),
        .digest = .{ .algorithm = try a.dupe(u8, "sha256"), .value = digest_hex },
    };
    unit.verification = .{
        .result = try a.dupe(u8, vr.label),
        .minisign = if (vr.minisign_key) |k| try a.dupe(u8, k) else null,
    };
    unit.display = try a.dupe(u8, unit.id);

    try out.append(allocator, unit);
    keep = true;
}

// ---------------------------------------------------------------------------
// Planning
// ---------------------------------------------------------------------------

fn planAndCommit(ctx: *const InstallContext, units: []const *StagedUnit) !void {
    const allocator = ctx.allocator;
    const io = ctx.io;
    const d = ctx.dirs;
    const err_w = ctx.err_w;

    var inventory = install_state.scan(allocator, io, d.tools, .{ .platform = host_platform }) catch |err| {
        try err_w.print("error: failed to read install state under '{s}': {t}\n", .{ d.tools, err });
        try err_w.print("  no install state was changed\n", .{});
        try err_w.flush();
        return error.InstallFailed;
    };
    defer inventory.deinit(allocator);

    ensureDirAbsoluteRecursive(io, d.bin) catch {};
    var snapshot = command_plan.snapshotBinDir(allocator, io, d.bin) catch |err| {
        try err_w.print("error: failed to read the bin directory '{s}': {t}\n", .{ d.bin, err });
        try err_w.print("  no install state was changed\n", .{});
        try err_w.flush();
        return error.InstallFailed;
    };
    defer snapshot.deinit();

    const plan_units = try allocator.alloc(command_plan.Unit, units.len);
    defer allocator.free(plan_units);
    for (units, 0..) |u, i| {
        plan_units[i] = .{ .id = u.id, .commands = u.commands, .aliases = u.aliases };
    }

    var diag: command_plan.Diagnostic = .{};
    var plan = command_plan.planWithDiagnostic(
        allocator,
        plan_units,
        inventory,
        snapshot.entries,
        .{ .platform = host_platform },
        &diag,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            try reportPlanError(err_w, err, diag, inventory);
            return error.InstallPlanRejected;
        },
    };
    defer plan.deinit();

    if (comptime builtin.os.tag.isDarwin()) {
        preflightAppBundles(ctx, units, inventory) catch |err| {
            try err_w.print("error: .app bundle publication is not safe: {t}\n", .{err});
            try err_w.print("  no install state was changed\n", .{});
            try err_w.flush();
            return error.InstallPlanRejected;
        };
    }

    // Build and validate every record BEFORE the first live change, so a
    // metadata that the reader would reject can never leave a half-mutated
    // invocation behind.
    for (units) |u| buildUnitMetadata(ctx, u, plan) catch |err| switch (err) {
        error.InstallStepFailed => return error.InstallFailed,
        else => return err,
    };

    for (units) |u| {
        commitUnit(ctx, u, plan, inventory) catch |err| switch (err) {
            error.InstallStepFailed => return error.InstallFailed,
            else => return err,
        };
    }
}

fn preflightAppBundles(
    ctx: *const InstallContext,
    units: []const *StagedUnit,
    inventory: install_state.Inventory,
) !void {
    var arena_inst = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena_inst.deinit();
    const a = arena_inst.allocator();

    var claimed: std.StringHashMapUnmanaged(void) = .empty;
    const home = ctx.environ.get("HOME") orelse {
        for (units) |unit| if (unit.apps.len > 0) return error.HomeNotFound;
        return;
    };
    const apps_path = try std.fmt.allocPrint(a, "{s}/Applications", .{home});
    var apps_dir_opt: ?Dir = Dir.openDirAbsolute(ctx.io, apps_path, .{}) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    defer if (apps_dir_opt) |*dir| dir.close(ctx.io);

    for (units) |unit| {
        const previous = findRecord(inventory, unit.id);
        const previous_path = if (previous) |rec|
            try recordAbsPath(a, ctx.dirs.tools, rec.path)
        else
            null;

        for (unit.apps) |rel_path| {
            const app_name = std.fs.path.basename(rel_path);
            const key = try a.dupe(u8, app_name);
            for (key) |*c| c.* = std.ascii.toLower(c.*);
            if ((try claimed.getOrPut(a, key)).found_existing)
                return error.DuplicateAppBundle;

            const apps_dir = apps_dir_opt orelse continue;
            _ = apps_dir.statFile(ctx.io, app_name, .{ .follow_symlinks = false }) catch |err| switch (err) {
                error.FileNotFound => continue,
                else => return err,
            };

            const owner = previous_path orelse return error.AppOwnershipConflict;
            if (isLegacyAppSymlink(ctx.allocator, ctx.io, apps_dir, app_name, owner, rel_path))
                continue;
            if (isOwnedAppBundle(ctx.io, apps_dir, app_name, owner)) continue;
            return error.AppOwnershipConflict;
        }
    }
}

fn buildUnitMetadata(ctx: *const InstallContext, unit: *StagedUnit, plan: command_plan.Plan) !void {
    const a = unit.alloc();
    var cmds: std.ArrayListUnmanaged(install_state_write.Command) = .empty;
    for (plan.commands) |pc| {
        if (!std.mem.eql(u8, pc.id, unit.id)) continue;
        try cmds.append(a, .{
            .name = pc.final_name,
            .source_name = pc.source_name,
            .relative_target = pc.relative_target,
            .kind = switch (pc.kind) {
                .native => .native,
                .wasm => .wasm,
            },
        });
    }

    const meta: install_state_write.Metadata = .{
        .id = unit.id,
        .source = unit.source,
        .config = unit.config,
        .resolved = unit.resolved,
        .commands = cmds.items,
        .apps = unit.apps,
        .verification = unit.verification,
    };
    unit.metadata_body = install_state_write.stringify(a, meta, host_platform) catch |err| {
        try ctx.err_w.print("error: refusing to record install metadata for '{s}': {t}\n", .{ unit.id, err });
        try ctx.err_w.print("  no install state was changed\n", .{});
        try ctx.err_w.flush();
        return error.InstallStepFailed;
    };
}

// ---------------------------------------------------------------------------
// Commit
// ---------------------------------------------------------------------------

fn findRecord(inventory: install_state.Inventory, id: []const u8) ?install_state.InventoryRecord {
    for (inventory.records) |rec| {
        const rid = rec.id orelse continue;
        if (std.mem.eql(u8, rid, id)) return rec;
    }
    return null;
}

/// Absolute path of an inventory record, rebuilt from the tools-relative path
/// the reader recorded (never from user input).
fn recordAbsPath(a: std.mem.Allocator, tools_dir: []const u8, rel: []const u8) ![]const u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    try out.appendSlice(a, tools_dir);
    try out.append(a, std.fs.path.sep);
    for (rel) |c| try out.append(a, if (c == '/') std.fs.path.sep else c);
    return out.toOwnedSlice(a);
}

/// True when the previous definition of this ID already published the same
/// command name and kind. Only then may a locked Windows launcher be retained.
fn previousPublishedSame(previous: ?install_state.InventoryRecord, pc: command_plan.PlannedCommand) bool {
    const rec = previous orelse return false;
    for (rec.commands) |cmd| {
        const kind: command_plan.Kind = if (install_state.isWasmTarget(cmd.relative_target)) .wasm else .native;
        if (kind != pc.kind) continue;
        const equal = if (host_platform == .windows)
            std.ascii.eqlIgnoreCase(cmd.name, pc.final_name)
        else
            std.mem.eql(u8, cmd.name, pc.final_name);
        if (equal) return true;
    }
    return false;
}

fn commitUnit(
    ctx: *const InstallContext,
    unit: *StagedUnit,
    plan: command_plan.Plan,
    inventory: install_state.Inventory,
) !void {
    const allocator = ctx.allocator;
    const io = ctx.io;
    const w = ctx.w;
    const err_w = ctx.err_w;
    const a = unit.alloc();
    const p = unit.paths;

    const previous = findRecord(inventory, unit.id);
    const previous_path: ?[]const u8 = if (previous) |rec|
        try recordAbsPath(a, ctx.dirs.tools, rec.path)
    else
        null;
    const legacy: ?struct { path: []const u8, kind: install_txn.LegacyKind } = if (previous) |rec|
        switch (rec.kind) {
            .v1_repo => .{ .path = previous_path.?, .kind = .v1_repo },
            .v1_wasm => .{ .path = previous_path.?, .kind = .v1_wasm },
            else => null,
        }
    else
        null;

    // Journal exactly the artifacts this transaction may touch.
    var publish: std.ArrayListUnmanaged([]const u8) = .empty;
    var cleanup: std.ArrayListUnmanaged([]const u8) = .empty;
    for (plan.commands) |pc| {
        if (!std.mem.eql(u8, pc.id, unit.id)) continue;
        for (pc.publish) |name| try publish.append(a, name);
        for (pc.cleanup) |name| try cleanup.append(a, name);
    }
    var stale: std.ArrayListUnmanaged([]const u8) = .empty;
    for (plan.stale) |sc| {
        if (!std.mem.eql(u8, sc.id, unit.id)) continue;
        for (sc.remove) |name| try stale.append(a, name);
    }

    var journal: install_txn.Journal = .{
        .op = .install,
        .id = unit.id,
        .unit_path = p.unit,
        .stage_path = p.stage,
        .backup_path = p.backup,
        .publish = publish.items,
        .cleanup = cleanup.items,
        .stale = stale.items,
        .apps = unit.apps,
        .had_previous = previous != null,
        .legacy_path = if (legacy) |l| l.path else null,
        .legacy_kind = if (legacy) |l| l.kind else null,
        .phase = .staged,
    };

    // Metadata is written into transaction staging, never into live state.
    {
        var stage_dir = Dir.openDirAbsolute(io, p.stage, .{}) catch |err| {
            try err_w.print("error: failed to open staging dir '{s}': {t}\n", .{ p.stage, err });
            try err_w.flush();
            return error.InstallStepFailed;
        };
        defer stage_dir.close(io);
        var file = stage_dir.createFile(io, install_state.metadata_file, .{}) catch |err| {
            try err_w.print("error: failed to write install metadata: {t}\n", .{err});
            try err_w.flush();
            return error.InstallStepFailed;
        };
        defer file.close(io);
        file.writeStreamingAll(io, unit.metadata_body) catch |err| {
            try err_w.print("error: failed to write install metadata: {t}\n", .{err});
            try err_w.flush();
            return error.InstallStepFailed;
        };
        file.sync(io) catch {};
    }

    install_txn.writeJournal(io, p, allocator, journal) catch |err| {
        try err_w.print("error: failed to journal the install transaction: {t}\n", .{err});
        try err_w.flush();
        return error.InstallStepFailed;
    };

    journal.phase = .swapping;
    install_txn.writeJournal(io, p, allocator, journal) catch |err| {
        try err_w.print("error: failed to journal the install transaction: {t}\n", .{err});
        try err_w.flush();
        return error.InstallStepFailed;
    };
    install_txn.swapUnit(io, p, .{}) catch |err| {
        try err_w.print("error: failed to publish the unit directory '{s}': {t}\n", .{ p.unit, err });
        if (err == error.InstallRollbackFailed) {
            // The previous unit was moved aside and could not be put back. Its
            // only copy is the transaction backup, so the journal and backup
            // MUST survive for recovery to restore them.
            try err_w.print(
                "  the previous install is preserved at '{s}'; run any ghr command to retry recovery\n",
                .{p.backup},
            );
            try err_w.flush();
            return error.InstallStepFailed;
        }
        try err_w.flush();
        install_txn.discardTransaction(io, p) catch {};
        return error.InstallStepFailed;
    };

    // From here on a journal-write failure is tolerated: recovery combines the
    // recorded phase with the observed unit/stage/backup presence, and every
    // later phase classifies identically to `.swapping` once the unit is live,
    // so a stale phase still recovers correctly.
    journal.phase = .publishing;
    install_txn.writeJournal(io, p, allocator, journal) catch {};

    ensureDirAbsoluteRecursive(io, ctx.dirs.bin) catch {};
    var bin_dir = Dir.openDirAbsolute(io, ctx.dirs.bin, .{}) catch |err| {
        try err_w.print("error: failed to open bin directory '{s}': {t}\n", .{ ctx.dirs.bin, err });
        try err_w.flush();
        try rollbackCommit(ctx, unit, plan, previous, previous_path, journal);
        return error.InstallStepFailed;
    };
    defer bin_dir.close(io);

    try w.print("linking executables:\n", .{});
    publishUnitCommands(ctx, bin_dir, unit, plan, previous) catch |err| {
        try err_w.print("error: failed to publish commands for '{s}': {t}\n", .{ unit.id, err });
        try err_w.flush();
        try rollbackCommit(ctx, unit, plan, previous, previous_path, journal);
        return error.InstallStepFailed;
    };

    if (comptime builtin.os.tag.isDarwin()) {
        installAppBundles(allocator, io, ctx.environ, unit.apps, p.unit, previous_path, w) catch |err| {
            try err_w.print("error: failed to install .app bundle for '{s}': {t}\n", .{ unit.id, err });
            try err_w.flush();
            try rollbackCommit(ctx, unit, plan, previous, previous_path, journal);
            return error.InstallStepFailed;
        };
    }

    journal.phase = .retiring;
    install_txn.writeJournal(io, p, allocator, journal) catch {};

    removeStaleCommands(ctx, bin_dir, unit, plan, previous_path);
    if (legacy) |l| retireLegacyUnit(ctx, l.path, l.kind);

    journal.phase = .complete;
    install_txn.writeJournal(io, p, allocator, journal) catch {};
    install_txn.discardTransaction(io, p) catch {};

    try w.print("installed {s}\n", .{unit.display});
    try w.flush();
}

/// Restore the previous unit and its command set after a synchronous failure
/// during publication. Publication failures are never warnings.
fn rollbackCommit(
    ctx: *const InstallContext,
    unit: *StagedUnit,
    plan: command_plan.Plan,
    previous: ?install_state.InventoryRecord,
    previous_path: ?[]const u8,
    journal_in: install_txn.Journal,
) !void {
    const allocator = ctx.allocator;
    const io = ctx.io;
    const err_w = ctx.err_w;
    const p = unit.paths;

    // Make rollback intent durable before changing the live unit. Recovery of
    // this phase never applies the failed install's stale/legacy retirement.
    var journal = journal_in;
    journal.phase = .rolled_back;
    install_txn.writeJournal(io, p, allocator, journal) catch |err| {
        try err_w.print("error: failed to journal rollback for '{s}': {t}\n", .{ unit.id, err });
        try err_w.print("  run any ghr command to finish transaction recovery\n", .{});
        try err_w.flush();
        return;
    };

    // Remove exactly what this transaction wrote, and nothing else.
    if (Dir.openDirAbsolute(io, ctx.dirs.bin, .{})) |*bin_dir_| {
        var bin_dir = bin_dir_.*;
        defer bin_dir.close(io);
        for (plan.commands) |pc| {
            if (!std.mem.eql(u8, pc.id, unit.id)) continue;
            for (pc.publish) |name| bin_dir.deleteFile(io, name) catch {};
        }
    } else |_| {}

    if (comptime builtin.os.tag.isDarwin()) {
        try uninstallAppBundles(allocator, io, ctx.environ, unit.apps, p.unit, ctx.w);
    }

    const prev = previous orelse {
        // The ID had no previous unit, so remove the one this transaction
        // published rather than leaving it half-live.
        deleteTreeIfExists(io, p.unit) catch |err| {
            try err_w.print("error: rollback could not remove failed unit '{s}': {t}\n", .{ p.unit, err });
            try err_w.print("  run any ghr command to retry recovery\n", .{});
            try err_w.flush();
            return;
        };
        install_txn.discardTransaction(io, p) catch {};
        return;
    };

    if (prev.kind == .v2) {
        // The previous unit is in the transaction backup; it must be live again
        // BEFORE its commands are republished, or they would point at the
        // replacement that just failed.
        install_txn.restoreUnit(io, p, .{}) catch |err| {
            try err_w.print(
                "error: rollback failed: could not restore '{s}' from '{s}': {t}\n",
                .{ p.unit, p.backup, err },
            );
            try err_w.print("  run any ghr command to retry recovery\n", .{});
            try err_w.flush();
            return;
        };
        republishInBin(ctx, prev, p.unit);
        if (comptime builtin.os.tag.isDarwin()) {
            installAppBundles(allocator, io, ctx.environ, prev.apps, p.unit, null, ctx.w) catch {};
        }
    } else {
        // A legacy unit was never moved, so its content is still live; only its
        // commands may have been overwritten.
        republishInBin(ctx, prev, previous_path orelse p.unit);
        if (comptime builtin.os.tag.isDarwin()) {
            installAppBundles(
                allocator,
                io,
                ctx.environ,
                prev.apps,
                previous_path orelse p.unit,
                null,
                ctx.w,
            ) catch {};
        }
        deleteTreeIfExists(io, p.unit) catch |err| {
            try err_w.print("error: rollback could not remove failed unit '{s}': {t}\n", .{ p.unit, err });
            try err_w.print("  the legacy install remains live; run any ghr command to retry recovery\n", .{});
            try err_w.flush();
            return;
        };
    }
    install_txn.discardTransaction(io, p) catch {};
}

fn republishInBin(ctx: *const InstallContext, record: install_state.InventoryRecord, unit_path: []const u8) void {
    var bin_dir = Dir.openDirAbsolute(ctx.io, ctx.dirs.bin, .{}) catch return;
    defer bin_dir.close(ctx.io);
    republishRecordCommands(ctx, bin_dir, record, unit_path);
}

/// Explicit fault-injection seam for the commit path. Production never writes
/// to it; tests set it to reproduce a publication failure at a chosen point so
/// rollback is exercised by real code rather than by a mock.
const CommitFaults = struct {
    /// Fail after this many commands have been published.
    fail_publish_after: ?usize = null,
};
var commit_faults: CommitFaults = .{};

fn publishUnitCommands(
    ctx: *const InstallContext,
    bin_dir: Dir,
    unit: *StagedUnit,
    plan: command_plan.Plan,
    previous: ?install_state.InventoryRecord,
) !void {
    var published: usize = 0;
    for (plan.commands) |pc| {
        if (!std.mem.eql(u8, pc.id, unit.id)) continue;
        if (builtin.is_test) {
            if (commit_faults.fail_publish_after) |limit| {
                if (published == limit) return error.InjectedPublishFailure;
            }
        }
        published += 1;
        try publishCommand(
            ctx.allocator,
            ctx.io,
            unit.paths.unit,
            bin_dir,
            pc.final_name,
            pc.relative_target,
            pc.kind,
            previousPublishedSame(previous, pc),
        );
        try ctx.w.print("  linked {s}\n", .{pc.final_name});
    }
    try ctx.w.flush();
}

/// Re-publish a record's commands from its own metadata. Used by rollback and
/// by crash recovery; both need to make the live bin directory agree with the
/// unit that is actually installed.
fn republishRecordCommands(
    ctx: *const InstallContext,
    bin_dir: Dir,
    record: install_state.InventoryRecord,
    unit_path: []const u8,
) void {
    for (record.commands) |cmd| {
        const kind: command_plan.Kind = if (install_state.isWasmTarget(cmd.relative_target)) .wasm else .native;
        publishCommand(
            ctx.allocator,
            ctx.io,
            unit_path,
            bin_dir,
            cmd.name,
            cmd.relative_target,
            kind,
            true,
        ) catch {};
    }
}

/// Remove the same-ID artifacts a previous definition owned and the new one
/// does not. `command_plan` produces intent only: each entry's live symlink or
/// manifest must still prove this ID owns it before anything is unlinked.
fn removeStaleCommands(
    ctx: *const InstallContext,
    bin_dir: Dir,
    unit: *StagedUnit,
    plan: command_plan.Plan,
    previous_path: ?[]const u8,
) void {
    const io = ctx.io;
    for (plan.stale) |sc| {
        if (!std.mem.eql(u8, sc.id, unit.id)) continue;
        var owned = commandArtifactIsOwned(io, bin_dir, sc.name, sc.kind, unit.paths.unit);
        if (!owned) {
            if (previous_path) |prev| {
                owned = commandArtifactIsOwned(io, bin_dir, sc.name, sc.kind, prev);
            }
        }
        if (!owned) continue;
        for (sc.remove) |name| bin_dir.deleteFile(io, name) catch {};
    }
}

/// Revalidate that a live bin entry really belongs to `unit_path` before it is
/// removed. A symlink must resolve inside the unit; a shim must be described by
/// a `.ghr` or legacy `.shim` that points inside it. Anything else -- another
/// ID's artifact, a user's own file, a modified link -- is left alone.
fn commandArtifactIsOwned(
    io: Io,
    bin_dir: Dir,
    name: []const u8,
    kind: command_plan.Kind,
    unit_path: []const u8,
) bool {
    if (kind == .native and !host_is_windows) {
        var link_buf: [Dir.max_path_bytes]u8 = undefined;
        const len = bin_dir.readLink(io, name, &link_buf) catch return false;
        return pathIsWithinTool(link_buf[0..len], unit_path, false);
    }

    const stem = if (host_is_windows and kind == .native) windowsExeStem(name) else name;
    var ghr_buf: [Dir.max_path_bytes]u8 = undefined;
    if (std.fmt.bufPrint(&ghr_buf, "{s}.ghr", .{stem})) |ghr_name| {
        if (binGhrPointsToToolDir(io, bin_dir, ghr_name, unit_path)) return true;
    } else |_| {}
    var shim_buf: [Dir.max_path_bytes]u8 = undefined;
    if (std.fmt.bufPrint(&shim_buf, "{s}.shim", .{stem})) |shim_name| {
        if (shimPointsToToolDir(io, bin_dir, shim_name, unit_path)) return true;
    } else |_| {}
    return false;
}

/// Retire a legacy v1 unit AFTER the v2 unit and its commands are durable.
/// Independently installed nested wasm units are preserved: only repo-level
/// content is removed, and the repo directory itself survives while it still
/// holds a child unit.
fn retireLegacyUnit(ctx: *const InstallContext, legacy_path: []const u8, kind: install_txn.LegacyKind) void {
    const allocator = ctx.allocator;
    const io = ctx.io;

    switch (kind) {
        .v1_wasm => {
            deleteTreeAbsolute(io, legacy_path) catch {};
            if (std.fs.path.dirname(legacy_path)) |parent| Dir.deleteDirAbsolute(io, parent) catch {};
        },
        .v1_repo => {
            var rd = Dir.openDirAbsolute(io, legacy_path, .{ .iterate = true }) catch return;
            var entries: std.ArrayListUnmanaged(struct { name: []u8, is_dir: bool }) = .empty;
            defer {
                for (entries.items) |e| allocator.free(e.name);
                entries.deinit(allocator);
            }
            {
                defer rd.close(io);
                var it = rd.iterate();
                while (it.next(io) catch null) |entry| {
                    const is_dir = entry.kind == .directory;
                    if (is_dir and !isInstallTransactionDir(entry.name)) {
                        const child = std.fmt.allocPrint(allocator, "{s}{c}{s}", .{
                            legacy_path, std.fs.path.sep, entry.name,
                        }) catch continue;
                        defer allocator.free(child);
                        // A child unit is an independent install; never remove it.
                        if (dirHasGhrJson(io, child)) continue;
                    }
                    const dup = allocator.dupe(u8, entry.name) catch continue;
                    entries.append(allocator, .{ .name = dup, .is_dir = is_dir }) catch {
                        allocator.free(dup);
                        continue;
                    };
                }
            }
            for (entries.items) |e| {
                var pb: [Dir.max_path_bytes]u8 = undefined;
                const child = std.fmt.bufPrint(&pb, "{s}{c}{s}", .{
                    legacy_path, std.fs.path.sep, e.name,
                }) catch continue;
                if (e.is_dir) {
                    deleteTreeAbsolute(io, child) catch {};
                } else {
                    Dir.deleteFileAbsolute(io, child) catch {};
                }
            }
            // Only succeeds when no preserved child unit remains.
            Dir.deleteDirAbsolute(io, legacy_path) catch {};
        },
    }
}

// ---------------------------------------------------------------------------
// Crash recovery
// ---------------------------------------------------------------------------

/// Finish or roll back every transaction a previous run left behind. Runs
/// before any command is touched. Every step revalidates identity and
/// ownership: a journal that does not describe the transaction directory it
/// sits in is reported and left alone rather than acted on.
fn recoverPendingTransactions(ctx: *const InstallContext) !void {
    const allocator = ctx.allocator;
    const io = ctx.io;
    const err_w = ctx.err_w;

    var pending = install_txn.scanPending(allocator, io, ctx.dirs.tools, host_platform) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer pending.deinit();

    for (pending.items) |entry| {
        if (entry.id.len == 0) {
            try err_w.print(
                "warning: ignoring an unrecognizable install transaction at '{s}'\n",
                .{entry.root},
            );
            try err_w.flush();
            continue;
        }
        recoverOneTransaction(ctx, entry.id) catch |err| {
            try err_w.print(
                "warning: could not recover the install transaction for '{s}': {t}\n",
                .{ entry.id, err },
            );
            try err_w.flush();
        };
    }
}

/// A journal's `legacy_path` drives a recursive delete, so it is the one field
/// that must be proven to name this transaction's own legacy unit before
/// recovery acts on it. The path must live directly under the tools directory,
/// have exactly the depth its kind implies, and lowercase to the journal's
/// canonical ID -- which permits a pre-migration mixed-case directory such as
/// `AzureAD/foo` while rejecting anything else.
fn legacyPathMatchesId(
    tools_dir: []const u8,
    legacy_path: []const u8,
    kind: install_txn.LegacyKind,
    id: []const u8,
) bool {
    if (legacy_path.len <= tools_dir.len + 1) return false;
    if (!std.mem.startsWith(u8, legacy_path, tools_dir)) return false;
    const sep = legacy_path[tools_dir.len];
    if (sep != std.fs.path.sep and sep != '/') return false;
    const rest = legacy_path[tools_dir.len + 1 ..];

    const want_segments: usize = switch (kind) {
        .v1_repo => 2,
        .v1_wasm => 3,
    };

    var lowered: [install_state.max_id_bytes]u8 = undefined;
    if (rest.len > lowered.len) return false;
    var segments: usize = 1;
    for (rest, 0..) |c, i| {
        if (c == std.fs.path.sep or c == '/') {
            segments += 1;
            lowered[i] = '/';
        } else {
            lowered[i] = std.ascii.toLower(c);
        }
    }
    if (segments != want_segments) return false;
    return std.mem.eql(u8, lowered[0..rest.len], id);
}

fn recoverOneTransaction(ctx: *const InstallContext, id: []const u8) !void {
    const allocator = ctx.allocator;
    const io = ctx.io;

    var p = try install_txn.paths(allocator, ctx.dirs.tools, id, host_platform);
    defer p.deinit();

    var owned = (try install_txn.readJournal(allocator, io, p.journal)) orelse return;
    defer owned.deinit();
    const journal = owned.journal;
    try install_txn.validateAgainstPaths(journal, p);
    if (journal.legacy_path) |legacy_path| {
        const kind = journal.legacy_kind orelse return error.JournalMalformed;
        if (!legacyPathMatchesId(ctx.dirs.tools, legacy_path, kind, journal.id))
            return error.JournalInvalidPath;
    }

    const present = try install_txn.presence(io, p);
    switch (install_txn.classifyRecovery(journal.op, journal.phase, present)) {
        .rollback => {
            try install_txn.discardTransaction(io, p);
        },
        .restore_backup => {
            try install_txn.restoreUnit(io, p, .{});
            try republishFromUnit(ctx, p, journal);
            try install_txn.discardTransaction(io, p);
        },
        .finish_swap => {
            try install_txn.finishSwap(io, p, .{});
            try republishFromUnit(ctx, p, journal);
            try finishRetirement(ctx, p, journal);
            try install_txn.discardTransaction(io, p);
        },
        .republish => {
            try republishFromUnit(ctx, p, journal);
            try finishRetirement(ctx, p, journal);
            try install_txn.discardTransaction(io, p);
        },
        .finish_removal => {
            try finishRemoval(ctx, p, journal);
            try install_txn.discardTransaction(io, p);
        },
        .finish_rollback => {
            try finishRollback(ctx, p, journal);
            try install_txn.discardTransaction(io, p);
        },
    }
}

/// Re-publish commands from the metadata that is actually live. The unit is
/// addressed by the journal's canonical ID through the same reversible
/// encoding the writer used, so recovery can never publish another unit's
/// commands -- and a mid-flight migration, where the legacy unit and its v2
/// replacement deliberately share one ID, does not make the unit unreadable.
///
/// This fails CLOSED. If the unit is missing or not a healthy v2 record, the
/// caller must not go on to retire a legacy unit or drop the journal.
fn republishFromUnit(ctx: *const InstallContext, p: install_txn.Paths, journal: install_txn.Journal) !void {
    const allocator = ctx.allocator;
    const io = ctx.io;

    var record = (try install_state.readUnitById(
        allocator,
        io,
        ctx.dirs.tools,
        journal.id,
        .{ .platform = host_platform },
    )) orelse return error.RecoveryUnitMissing;
    defer record.deinit(allocator);
    if (record.kind != .v2 or record.status != .ok) return error.RecoveryUnitUnusable;

    ensureDirAbsoluteRecursive(io, ctx.dirs.bin) catch {};
    var bin_dir = try Dir.openDirAbsolute(io, ctx.dirs.bin, .{});
    defer bin_dir.close(io);
    republishRecordCommands(ctx, bin_dir, record, p.unit);
    if (comptime builtin.os.tag.isDarwin()) {
        try installAppBundles(
            allocator,
            io,
            ctx.environ,
            record.apps,
            p.unit,
            journal.legacy_path,
            ctx.w,
        );
    }
}

/// Complete the parts of a commit that follow publication: stale artifacts the
/// journal recorded, and the legacy unit a migration was retiring.
fn finishRetirement(ctx: *const InstallContext, p: install_txn.Paths, journal: install_txn.Journal) !void {
    const io = ctx.io;
    if (journal.stale.len > 0) {
        if (Dir.openDirAbsolute(io, ctx.dirs.bin, .{})) |*bin_dir_| {
            var bin_dir = bin_dir_.*;
            defer bin_dir.close(io);
            for (journal.stale) |name| {
                if (artifactBelongsToUnit(io, bin_dir, name, p.unit, journal.legacy_path)) {
                    bin_dir.deleteFile(io, name) catch {};
                }
            }
        } else |_| {}
    }
    if (journal.legacy_path) |legacy_path| {
        if (journal.legacy_kind) |kind| retireLegacyUnit(ctx, legacy_path, kind);
    }
}

/// Finish an interrupted uninstall exactly as the journal recorded it.
fn finishRemoval(ctx: *const InstallContext, p: install_txn.Paths, journal: install_txn.Journal) !void {
    const io = ctx.io;
    if (Dir.openDirAbsolute(io, ctx.dirs.bin, .{})) |*bin_dir_| {
        var bin_dir = bin_dir_.*;
        defer bin_dir.close(io);
        for (journal.stale) |name| {
            if (artifactBelongsToUnit(io, bin_dir, name, p.unit, journal.legacy_path)) {
                bin_dir.deleteFile(io, name) catch {};
            }
        }
    } else |_| {}
    if (comptime builtin.os.tag.isDarwin()) {
        try uninstallAppBundles(
            ctx.allocator,
            io,
            ctx.environ,
            journal.apps,
            journal.legacy_path orelse p.unit,
            ctx.w,
        );
    }
    if (journal.legacy_path) |legacy_path| {
        if (journal.legacy_kind) |kind| retireLegacyUnit(ctx, legacy_path, kind);
    } else {
        try deleteTreeIfExists(io, p.unit);
        pruneEncodedParents(io, ctx.dirs.tools, p.unit);
    }
}

/// Complete a rollback whose intent was made durable before the live unit was
/// restored. This path never consumes the failed install's stale or legacy
/// retirement lists.
fn finishRollback(ctx: *const InstallContext, p: install_txn.Paths, journal: install_txn.Journal) !void {
    const io = ctx.io;
    if (Dir.openDirAbsolute(io, ctx.dirs.bin, .{})) |*bin_dir_| {
        var bin_dir = bin_dir_.*;
        defer bin_dir.close(io);
        for (journal.publish) |name| {
            if (artifactBelongsToUnit(io, bin_dir, name, p.unit, null))
                bin_dir.deleteFile(io, name) catch {};
        }
        for (journal.cleanup) |name| {
            if (artifactBelongsToUnit(io, bin_dir, name, p.unit, null))
                bin_dir.deleteFile(io, name) catch {};
        }
    } else |_| {}
    if (comptime builtin.os.tag.isDarwin()) {
        try uninstallAppBundles(ctx.allocator, io, ctx.environ, journal.apps, p.unit, ctx.w);
    }

    if (!journal.had_previous) {
        try deleteTreeIfExists(io, p.unit);
        return;
    }

    if (journal.legacy_path) |legacy_path| {
        // The v1 unit was never moved. Remove the failed v2 unit, then recover
        // the legacy record after the duplicate-ID conflict has disappeared.
        try deleteTreeIfExists(io, p.unit);
        try republishLegacyUnit(ctx, journal, legacy_path);
        return;
    }

    if (try install_txn.directoryExists(io, p.backup)) {
        try install_txn.restoreUnit(io, p, .{});
    }
    try republishFromUnit(ctx, p, journal);
}

fn republishLegacyUnit(
    ctx: *const InstallContext,
    journal: install_txn.Journal,
    legacy_path: []const u8,
) !void {
    var inventory = try install_state.scan(
        ctx.allocator,
        ctx.io,
        ctx.dirs.tools,
        .{ .platform = host_platform },
    );
    defer inventory.deinit(ctx.allocator);

    const record = findRecord(inventory, journal.id) orelse return error.RecoveryUnitMissing;
    if (record.status != .ok) return error.RecoveryUnitUnusable;
    const expected_kind: install_state.UnitKind = switch (journal.legacy_kind orelse
        return error.JournalMalformed) {
        .v1_repo => .v1_repo,
        .v1_wasm => .v1_wasm,
    };
    if (record.kind != expected_kind) return error.RecoveryUnitUnusable;

    const actual_path = try recordAbsPath(ctx.allocator, ctx.dirs.tools, record.path);
    defer ctx.allocator.free(actual_path);
    if (!std.mem.eql(u8, actual_path, legacy_path)) return error.JournalInvalidPath;

    ensureDirAbsoluteRecursive(ctx.io, ctx.dirs.bin) catch {};
    var bin_dir = try Dir.openDirAbsolute(ctx.io, ctx.dirs.bin, .{});
    defer bin_dir.close(ctx.io);
    republishRecordCommands(ctx, bin_dir, record, legacy_path);
    if (comptime builtin.os.tag.isDarwin()) {
        try installAppBundles(
            ctx.allocator,
            ctx.io,
            ctx.environ,
            record.apps,
            legacy_path,
            null,
            ctx.w,
        );
    }
}

/// Recovery-time ownership check for a bare artifact name. A `.ghr`/`.shim`
/// companion or a symlink must still point inside one of this ID's own unit
/// paths; a plain companion file (`.cmd`, `.old`) is removed only when a
/// sibling proves ownership.
fn artifactBelongsToUnit(
    io: Io,
    bin_dir: Dir,
    name: []const u8,
    unit_path: []const u8,
    legacy_path: ?[]const u8,
) bool {
    var link_buf: [Dir.max_path_bytes]u8 = undefined;
    if (bin_dir.readLink(io, name, &link_buf)) |len| {
        const target = link_buf[0..len];
        if (pathIsWithinTool(target, unit_path, host_is_windows)) return true;
        if (legacy_path) |legacy| return pathIsWithinTool(target, legacy, host_is_windows);
        return false;
    } else |_| {}

    const stem = stripKnownArtifactSuffix(name);
    var buf: [Dir.max_path_bytes]u8 = undefined;
    if (std.fmt.bufPrint(&buf, "{s}.ghr", .{stem})) |ghr_name| {
        if (binGhrPointsToToolDir(io, bin_dir, ghr_name, unit_path)) return true;
        if (legacy_path) |legacy| {
            if (binGhrPointsToToolDir(io, bin_dir, ghr_name, legacy)) return true;
        }
    } else |_| {}
    var shim_buf: [Dir.max_path_bytes]u8 = undefined;
    if (std.fmt.bufPrint(&shim_buf, "{s}.shim", .{stem})) |shim_name| {
        if (shimPointsToToolDir(io, bin_dir, shim_name, unit_path)) return true;
        if (legacy_path) |legacy| {
            if (shimPointsToToolDir(io, bin_dir, shim_name, legacy)) return true;
        }
    } else |_| {}
    return false;
}

fn stripKnownArtifactSuffix(name: []const u8) []const u8 {
    const suffixes = [_][]const u8{ ".exe.old", ".exe", ".ghr", ".cmd", ".shim", ".old" };
    for (suffixes) |suffix| {
        if (name.len > suffix.len and std.ascii.endsWithIgnoreCase(name, suffix))
            return name[0 .. name.len - suffix.len];
    }
    return name;
}

/// Remove the now-empty encoded directories above a deleted unit, stopping at
/// the units root. `deleteDir` only succeeds on an empty directory, so a parent
/// that still holds a sibling or child unit is never touched.
fn pruneEncodedParents(io: Io, tools_dir: []const u8, unit_path: []const u8) void {
    var units_root_buf: [Dir.max_path_bytes]u8 = undefined;
    const units_root = std.fmt.bufPrint(&units_root_buf, "{s}{c}{s}{c}{s}", .{
        tools_dir,
        std.fs.path.sep,
        install_state.v2_namespace,
        std.fs.path.sep,
        install_state.v2_units_dir,
    }) catch return;
    install_txn.pruneEmptyParents(io, units_root, unit_path);
}

/// Publish one planned command into the bin directory under its EXACT final
/// name. The final name comes from the invocation plan (an alias when one
/// applied) and is never re-derived here.
///
/// `allow_locked_launcher` is true only for a same-ID replacement whose
/// previous definition already published this command. On Windows a running
/// shim exe cannot be replaced; in that one case the compatible launcher is
/// retained while its `.ghr` (and legacy `.shim`) target is updated. For a new
/// or renamed command a launcher that cannot be written is a failure, not a
/// warning.
fn publishCommand(
    allocator: std.mem.Allocator,
    io: Io,
    unit_path: []const u8,
    bin_dir: Dir,
    final_name: []const u8,
    relative_target: []const u8,
    kind: command_plan.Kind,
    allow_locked_launcher: bool,
) !void {
    var host_rel_buf: [Dir.max_path_bytes]u8 = undefined;
    const host_rel = try hostRelInto(&host_rel_buf, relative_target);

    var src_path_buf: [Dir.max_path_bytes]u8 = undefined;
    const src_path = std.fmt.bufPrint(&src_path_buf, "{s}{c}{s}", .{
        unit_path,
        std.fs.path.sep,
        host_rel,
    }) catch return error.PathTooLong;

    return switch (kind) {
        .wasm => publishWasmCommand(
            allocator,
            io,
            unit_path,
            bin_dir,
            final_name,
            host_rel,
            src_path,
            allow_locked_launcher,
        ),
        .native => publishNativeCommand(io, bin_dir, final_name, src_path, allow_locked_launcher),
    };
}

fn publishNativeCommand(
    io: Io,
    bin_dir: Dir,
    final_name: []const u8,
    src_path: []const u8,
    allow_locked_launcher: bool,
) !void {
    if (builtin.os.tag != .windows) {
        bin_dir.deleteFile(io, final_name) catch {};
        try bin_dir.symLink(io, src_path, final_name, .{});
        return;
    }

    // Windows: an embedded shim exe plus a `<stem>.ghr` manifest naming the
    // native target, exactly as `command_plan.artifactsFor` describes.
    const shim_exe_bytes = @import("shim_exe").bytes;
    const stem = windowsExeStem(final_name);

    var ghr_name_buf: [Dir.max_path_bytes]u8 = undefined;
    const ghr_name = std.fmt.bufPrint(&ghr_name_buf, "{s}.ghr", .{stem}) catch return error.PathTooLong;
    try writeNativeGhr(io, bin_dir, ghr_name, src_path);

    var cmd_name_buf: [Dir.max_path_bytes]u8 = undefined;
    if (std.fmt.bufPrint(&cmd_name_buf, "{s}.cmd", .{stem})) |p| {
        bin_dir.deleteFile(io, p) catch {};
    } else |_| {}

    var name_buf: [Dir.max_path_bytes]u8 = undefined;
    const shim_exe_name = windowsShimExeName(&name_buf, final_name) catch return error.PathTooLong;
    bin_dir.deleteFile(io, shim_exe_name) catch {
        // A running shim exe cannot be deleted; rename it out of the way.
        var old_name_buf: [Dir.max_path_bytes]u8 = undefined;
        const old_name = std.fmt.bufPrint(&old_name_buf, "{s}.old", .{shim_exe_name}) catch
            return error.PathTooLong;
        bin_dir.deleteFile(io, old_name) catch {};
        bin_dir.rename(shim_exe_name, bin_dir, old_name, io) catch {};
    };
    const shim_replaced = if (bin_dir.createFile(io, shim_exe_name, .{})) |*exe_file| blk: {
        defer exe_file.close(io);
        exe_file.writeStreamingAll(io, shim_exe_bytes) catch return error.WriteFailed;
        break :blk true;
    } else |_| false;

    var legacy_shim_buf: [Dir.max_path_bytes]u8 = undefined;
    const legacy_shim = std.fmt.bufPrint(&legacy_shim_buf, "{s}.shim", .{stem}) catch
        return error.PathTooLong;
    if (shim_replaced) {
        bin_dir.deleteFile(io, legacy_shim) catch {};
        return;
    }
    if (!allow_locked_launcher) return error.CommandLauncherLocked;
    // Self-update: the still-running shim may predate the `.ghr` format, so
    // write the legacy `.shim` fallback pointing at the new target. A current
    // shim prefers `.ghr` and ignores this file.
    writeLegacyShim(io, bin_dir, legacy_shim, src_path) catch {};
}

fn publishWasmCommand(
    allocator: std.mem.Allocator,
    io: Io,
    unit_path: []const u8,
    bin_dir: Dir,
    final_name: []const u8,
    host_rel: []const u8,
    src_path: []const u8,
    allow_locked_launcher: bool,
) !void {
    const shim_exe_bytes = @import("shim_exe").bytes;

    // The release ships `<wasm>.ghr` beside the module; it carries the runtime
    // and its arguments.
    var tool_dir = Dir.openDirAbsolute(io, unit_path, .{}) catch return error.CreateFailed;
    defer tool_dir.close(io);
    var manifest_name_buf: [Dir.max_path_bytes]u8 = undefined;
    const manifest_name = std.fmt.bufPrint(&manifest_name_buf, "{s}.ghr", .{host_rel}) catch
        return error.PathTooLong;
    const raw = tool_dir.readFileAlloc(io, manifest_name, allocator, Io.Limit.limited(64 * 1024)) catch
        return error.CreateFailed;
    defer allocator.free(raw);
    const source = try allocator.dupeZ(u8, raw);
    defer allocator.free(source);
    const manifest = std.zon.parse.fromSliceAlloc(GhrManifest, allocator, source, null, .{
        .ignore_unknown_fields = true,
    }) catch return error.WriteFailed;
    defer std.zon.parse.free(allocator, manifest);

    var ghr_name_buf: [Dir.max_path_bytes]u8 = undefined;
    const ghr_name = std.fmt.bufPrint(&ghr_name_buf, "{s}.ghr", .{final_name}) catch
        return error.PathTooLong;
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

    var legacy_shim_buf: [Dir.max_path_bytes]u8 = undefined;
    if (std.fmt.bufPrint(&legacy_shim_buf, "{s}.shim", .{final_name})) |legacy_shim| {
        bin_dir.deleteFile(io, legacy_shim) catch {};
    } else |_| {}

    var launcher_name_buf: [Dir.max_path_bytes]u8 = undefined;
    const launcher_name = if (builtin.os.tag == .windows)
        std.fmt.bufPrint(&launcher_name_buf, "{s}.exe", .{final_name}) catch return error.PathTooLong
    else
        final_name;

    bin_dir.deleteFile(io, launcher_name) catch {
        if (builtin.os.tag == .windows) {
            var old_name_buf: [Dir.max_path_bytes]u8 = undefined;
            const old_name = std.fmt.bufPrint(&old_name_buf, "{s}.old", .{launcher_name}) catch
                return error.PathTooLong;
            bin_dir.deleteFile(io, old_name) catch {};
            bin_dir.rename(launcher_name, bin_dir, old_name, io) catch {};
        }
    };

    // `.executable_file` is a no-op on Windows but yields the +x bit on Unix.
    if (bin_dir.createFile(io, launcher_name, .{ .permissions = .executable_file })) |*exe_file| {
        defer exe_file.close(io);
        exe_file.writeStreamingAll(io, shim_exe_bytes) catch return error.WriteFailed;
    } else |_| {
        if (!allow_locked_launcher) return error.CommandLauncherLocked;
        // The existing launcher is locked but compatible; its `.ghr` above now
        // names the new target, so the command keeps working.
    }
}

// ---------------------------------------------------------------------------
// Uninstall by canonical ID
// ---------------------------------------------------------------------------

pub const UninstallError = error{
    UninstallTargetNotFound,
    UninstallStateUnusable,
    UninstallFailed,
};

/// Remove exactly one canonical install ID.
///
/// The ID is resolved ONLY through the inventory: no deletion target is ever
/// constructed from the argument. Prefixes are not recursive -- removing
/// `owner/repo` never touches `owner/repo/module`. Old `owner/repo[/stem]`
/// arguments keep working because they canonicalize to the same legacy IDs.
pub fn cmdUninstall(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    spec_str: []const u8,
    w: *Writer,
    err_w: *Writer,
) !void {
    const d = try Dirs.detect(allocator, environ);
    defer d.deinit();

    const ctx = InstallContext{
        .allocator = allocator,
        .io = io,
        .environ = environ,
        .dirs = d,
        .client = undefined,
        .auth_resolved = .{ .token = null, .owns_token = false, .source = "none" },
        .auth_header = null,
        .w = w,
        .err_w = err_w,
        .debug = false,
        .no_auth = true,
        .gates = .{},
        .minisign_pubkey_b64 = null,
        .bin_filters = &.{},
    };
    return uninstallUnit(&ctx, spec_str);
}

/// Uninstall against an already-resolved context. Split out so the transaction
/// can be driven against a test store without going through directory
/// detection.
fn uninstallUnit(ctx: *const InstallContext, spec_str: []const u8) !void {
    const allocator = ctx.allocator;
    const io = ctx.io;
    const d = ctx.dirs;
    const w = ctx.w;
    const err_w = ctx.err_w;

    const canonical = install_request.canonicalizeId(allocator, spec_str) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            try err_w.print("error: '{s}' is not a valid install id ({t})\n", .{ spec_str, err });
            try err_w.print("  hint: ids are lowercase, slash-separated, e.g. owner/repo or a custom id\n", .{});
            try err_w.print("  hint: list installed ids with 'ghr list --ids'\n", .{});
            try err_w.flush();
            return error.UninstallTargetNotFound;
        },
    };
    defer allocator.free(canonical);

    recoverPendingTransactions(ctx) catch |err| {
        try err_w.print("error: could not recover a pending install transaction: {t}\n", .{err});
        try err_w.flush();
        return error.UninstallFailed;
    };

    var inventory = install_state.scan(allocator, io, d.tools, .{ .platform = host_platform }) catch |err| {
        try err_w.print("error: failed to read install state under '{s}': {t}\n", .{ d.tools, err });
        try err_w.flush();
        return error.UninstallStateUnusable;
    };
    defer inventory.deinit(allocator);

    // Ownership must be knowable globally before anything is removed: a
    // damaged record anywhere can claim commands, so a damaged inventory fails
    // closed instead of guessing.
    var target: ?install_state.InventoryRecord = null;
    for (inventory.records) |rec| {
        if (rec.status != .ok) {
            const id_text = rec.id orelse "<unknown id>";
            try err_w.print("error: install state is not healthy; refusing to change it\n", .{});
            try err_w.print("  {s}: {s} ({t}/{t})\n", .{ id_text, rec.path, rec.status, rec.reason });
            try err_w.print("  hint: inspect with 'ghr list --json'\n", .{});
            try err_w.flush();
            return error.UninstallStateUnusable;
        }
        const rid = rec.id orelse continue;
        if (std.mem.eql(u8, rid, canonical)) target = rec;
    }

    const record = target orelse {
        try err_w.print("error: '{s}' is not installed\n", .{canonical});
        try err_w.print("  hint: list installed ids with 'ghr list --ids'\n", .{});
        try err_w.flush();
        return error.UninstallTargetNotFound;
    };

    var arena_inst = std.heap.ArenaAllocator.init(allocator);
    defer arena_inst.deinit();
    const a = arena_inst.allocator();

    const p = install_txn.paths(a, d.tools, canonical, host_platform) catch |err| {
        try err_w.print("error: cannot address install id '{s}': {t}\n", .{ canonical, err });
        try err_w.flush();
        return error.UninstallFailed;
    };
    const unit_path = try recordAbsPath(a, d.tools, record.path);

    // Every artifact this unit's commands own, expanded exactly as the planner
    // would. Removal still revalidates each one against live state.
    var artifacts: std.ArrayListUnmanaged([]const u8) = .empty;
    for (record.commands) |cmd| {
        const kind: command_plan.Kind = if (install_state.isWasmTarget(cmd.relative_target)) .wasm else .native;
        const family = try command_plan.artifactsFor(a, cmd.name, kind, host_platform);
        for (family) |name| try artifacts.append(a, name);
    }

    const legacy_kind: ?install_txn.LegacyKind = switch (record.kind) {
        .v1_repo => .v1_repo,
        .v1_wasm => .v1_wasm,
        else => null,
    };

    install_txn.ensureDirAbsolute(io, p.root) catch |err| {
        try err_w.print("error: failed to prepare the uninstall transaction: {t}\n", .{err});
        try err_w.flush();
        return error.UninstallFailed;
    };
    const journal: install_txn.Journal = .{
        .op = .uninstall,
        .id = canonical,
        .unit_path = p.unit,
        .stage_path = p.stage,
        .backup_path = p.backup,
        .stale = artifacts.items,
        .apps = record.apps,
        .had_previous = true,
        .legacy_path = if (legacy_kind != null) unit_path else null,
        .legacy_kind = legacy_kind,
        .phase = .retiring,
    };
    install_txn.writeJournal(io, p, allocator, journal) catch |err| {
        try err_w.print("error: failed to journal the uninstall transaction: {t}\n", .{err});
        try err_w.flush();
        install_txn.discardTransaction(io, p) catch {};
        return error.UninstallFailed;
    };

    if (Dir.openDirAbsolute(io, d.bin, .{})) |*bin_dir_| {
        var bin_dir = bin_dir_.*;
        defer bin_dir.close(io);
        for (record.commands) |cmd| {
            const kind: command_plan.Kind = if (install_state.isWasmTarget(cmd.relative_target)) .wasm else .native;
            if (!commandArtifactIsOwned(io, bin_dir, cmd.name, kind, unit_path)) continue;
            const family = try command_plan.artifactsFor(a, cmd.name, kind, host_platform);
            for (family) |name| bin_dir.deleteFile(io, name) catch {};
            try w.print("  unlinked {s}\n", .{cmd.name});
        }
    } else |_| {}

    if (comptime builtin.os.tag.isDarwin()) {
        try uninstallAppBundles(allocator, io, ctx.environ, record.apps, unit_path, w);
    }

    if (legacy_kind) |kind| {
        retireLegacyUnit(ctx, unit_path, kind);
    } else {
        deleteTreeIfExists(io, unit_path) catch |err| {
            try err_w.print("error: failed to remove '{s}': {t}\n", .{ unit_path, err });
            try err_w.flush();
            return error.UninstallFailed;
        };
        pruneEncodedParents(io, d.tools, unit_path);
    }

    install_txn.discardTransaction(io, p) catch {};
    try w.print("uninstalled {s}\n", .{canonical});
    try w.flush();
}

// ===========================================================================
// Activation tests: staging, planning, commit, recovery, migration, uninstall
// ===========================================================================
//
// These exercise the real commit path. Resolution/download is the only part
// stubbed out: a unit is staged on disk exactly as a download would leave it,
// then planning and commit run unmodified.

const t_alloc = std.testing.allocator;

/// A throwaway tools/bin/cache tree plus captured output, so every test drives
/// the same code the CLI does.
const TestStore = struct {
    tmp: std.testing.TmpDir,
    base: []u8,
    dirs: Dirs,
    out: Io.Writer.Allocating,
    err: Io.Writer.Allocating,
    environ: std.process.Environ.Map,
    client: std.http.Client,

    fn init() !TestStore {
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();
        var buf: [Dir.max_path_bytes]u8 = undefined;
        const len = try tmp.dir.realPath(std.testing.io, &buf);
        const base = try t_alloc.dupe(u8, buf[0..len]);
        errdefer t_alloc.free(base);

        const bin = try std.fmt.allocPrint(t_alloc, "{s}{c}bin", .{ base, std.fs.path.sep });
        errdefer t_alloc.free(bin);
        const tools = try std.fmt.allocPrint(t_alloc, "{s}{c}tools", .{ base, std.fs.path.sep });
        errdefer t_alloc.free(tools);
        const cache = try std.fmt.allocPrint(t_alloc, "{s}{c}cache", .{ base, std.fs.path.sep });
        errdefer t_alloc.free(cache);
        try ensureDirAbsoluteRecursive(std.testing.io, bin);
        try ensureDirAbsoluteRecursive(std.testing.io, tools);
        try ensureDirAbsoluteRecursive(std.testing.io, cache);

        return .{
            .tmp = tmp,
            .base = base,
            .dirs = .{ .bin = bin, .tools = tools, .cache = cache, .allocator = t_alloc },
            .out = .init(t_alloc),
            .err = .init(t_alloc),
            .environ = try std.testing.environ.createMap(t_alloc),
            .client = .{ .allocator = t_alloc, .io = std.testing.io },
        };
    }

    fn deinit(self: *TestStore) void {
        self.environ.deinit();
        self.out.deinit();
        self.err.deinit();
        self.dirs.deinit();
        t_alloc.free(self.base);
        self.tmp.cleanup();
    }

    fn ctx(self: *TestStore) InstallContext {
        return .{
            .allocator = t_alloc,
            .io = std.testing.io,
            .environ = &self.environ,
            .dirs = self.dirs,
            .client = &self.client,
            .auth_resolved = .{ .token = null, .owns_token = false, .source = "none" },
            .auth_header = null,
            .w = &self.out.writer,
            .err_w = &self.err.writer,
            .debug = false,
            .no_auth = true,
            .gates = .{},
            .minisign_pubkey_b64 = null,
            .bin_filters = &.{},
        };
    }

    fn errText(self: *TestStore) []const u8 {
        return self.err.writer.buffered();
    }

    fn binPath(self: *TestStore, a: std.mem.Allocator, name: []const u8) ![]u8 {
        return std.fmt.allocPrint(a, "{s}{c}{s}", .{ self.dirs.bin, std.fs.path.sep, name });
    }

    fn toolsPath(self: *TestStore, a: std.mem.Allocator, rel: []const u8) ![]u8 {
        var out: std.ArrayListUnmanaged(u8) = .empty;
        try out.appendSlice(a, self.dirs.tools);
        try out.append(a, std.fs.path.sep);
        for (rel) |c| try out.append(a, if (c == '/') std.fs.path.sep else c);
        return out.toOwnedSlice(a);
    }

    fn binEntryExists(self: *TestStore, name: []const u8) bool {
        var d = Dir.openDirAbsolute(std.testing.io, self.dirs.bin, .{}) catch return false;
        defer d.close(std.testing.io);
        _ = d.statFile(std.testing.io, name, .{ .follow_symlinks = false }) catch return false;
        return true;
    }
};

/// Stage a unit exactly as a completed download+extract would leave it: an
/// executable per requested command inside the transaction staging directory.
fn tStageUnit(
    ctx: *const InstallContext,
    id: []const u8,
    targets: []const []const u8,
    aliases: []const command_plan.Alias,
) !*StagedUnit {
    const unit = try StagedUnit.create(t_alloc);
    errdefer unit.destroy();
    const a = unit.alloc();
    try beginStaging(ctx, unit, id);

    var stage_dir = try Dir.openDirAbsolute(ctx.io, unit.paths.stage, .{ .iterate = true });
    defer stage_dir.close(ctx.io);

    const commands = try a.alloc(command_plan.Command, targets.len);
    for (targets, 0..) |target, i| {
        if (std.fs.path.dirname(target)) |parent| try stage_dir.createDirPath(ctx.io, parent);
        var f = try stage_dir.createFile(ctx.io, target, .{ .permissions = .executable_file });
        defer f.close(ctx.io);
        try f.writeStreamingAll(ctx.io, "#!/bin/sh\nexit 0\n");
        commands[i] = .{
            .relative_target = try a.dupe(u8, target),
            .kind = commandKindFor(target),
        };
    }
    unit.commands = commands;

    const owned_aliases = try a.alloc(command_plan.Alias, aliases.len);
    const meta_aliases = try a.alloc(install_state_write.Alias, aliases.len);
    for (aliases, 0..) |alias, i| {
        const from = try a.dupe(u8, alias.source);
        const to = try a.dupe(u8, alias.published);
        owned_aliases[i] = .{ .source = from, .published = to };
        meta_aliases[i] = .{ .from = from, .to = to };
    }
    unit.aliases = owned_aliases;

    unit.source = .{
        .kind = .github,
        .owner = try a.dupe(u8, "example"),
        .repo = try a.dupe(u8, "tool"),
        .tag = try a.dupe(u8, "v1"),
    };
    unit.config = .{ .aliases = meta_aliases, .verification_policy = .{} };
    unit.resolved = .{
        .tag = try a.dupe(u8, "v1"),
        .asset = try a.dupe(u8, "tool.tar.gz"),
        .api_asset_id = 1234,
    };
    unit.verification = .{ .result = try a.dupe(u8, "none") };
    unit.display = try a.dupe(u8, id);
    return unit;
}

fn tCommit(ctx: *const InstallContext, units: []const *StagedUnit) !void {
    return planAndCommit(ctx, units);
}

fn tWriteLegacyUnit(
    ctx: *const InstallContext,
    rel_dir: []const u8,
    bins: []const []const u8,
) !void {
    var arena_inst = std.heap.ArenaAllocator.init(t_alloc);
    defer arena_inst.deinit();
    const a = arena_inst.allocator();

    var out: std.ArrayListUnmanaged(u8) = .empty;
    try out.appendSlice(a, ctx.dirs.tools);
    try out.append(a, std.fs.path.sep);
    for (rel_dir) |c| try out.append(a, if (c == '/') std.fs.path.sep else c);
    const dir_path = out.items;
    try ensureDirAbsoluteRecursive(ctx.io, dir_path);

    var dir = try Dir.openDirAbsolute(ctx.io, dir_path, .{});
    defer dir.close(ctx.io);
    for (bins) |bin| {
        if (std.fs.path.dirname(bin)) |parent| try dir.createDirPath(ctx.io, parent);
        var f = try dir.createFile(ctx.io, bin, .{ .permissions = .executable_file });
        defer f.close(ctx.io);
        try f.writeStreamingAll(ctx.io, "#!/bin/sh\nexit 0\n");
    }
    try writeMetadata(t_alloc, ctx.io, dir, "v0", "legacy.tar.gz", bins, &.{}, "none", null);
}

fn tScan(ctx: *const InstallContext) !install_state.Inventory {
    return install_state.scan(t_alloc, ctx.io, ctx.dirs.tools, .{ .platform = host_platform });
}

fn tFindRecord(inv: install_state.Inventory, id: []const u8) ?install_state.InventoryRecord {
    return findRecord(inv, id);
}

test "app publication adopts a legacy marker and records the v2 unit" {
    var store = try TestStore.init();
    defer store.deinit();
    try store.environ.put("HOME", store.base);
    const ctx = store.ctx();

    var arena_inst = std.heap.ArenaAllocator.init(t_alloc);
    defer arena_inst.deinit();
    const a = arena_inst.allocator();
    var p = try install_txn.paths(a, ctx.dirs.tools, "example/tool", host_platform);
    defer p.deinit();
    const legacy = try store.toolsPath(a, "example/tool");

    const source_contents = try std.fmt.allocPrint(a, "{s}/Foo.app/Contents", .{p.unit});
    try ensureDirAbsoluteRecursive(ctx.io, source_contents);
    const source_file = try std.fmt.allocPrint(a, "{s}/payload", .{source_contents});
    var payload = try Dir.createFileAbsolute(ctx.io, source_file, .{});
    payload.close(ctx.io);

    const installed_contents = try std.fmt.allocPrint(a, "{s}/Applications/Foo.app/Contents", .{store.base});
    try ensureDirAbsoluteRecursive(ctx.io, installed_contents);
    const old_marker = try std.fmt.allocPrint(a, "{s}/.ghr-source", .{installed_contents});
    var marker = try Dir.createFileAbsolute(ctx.io, old_marker, .{});
    try marker.writeStreamingAll(ctx.io, legacy);
    marker.close(ctx.io);

    try installAppBundles(
        t_alloc,
        ctx.io,
        ctx.environ,
        &.{"Foo.app"},
        p.unit,
        legacy,
        ctx.w,
    );

    var apps_dir = try Dir.openDirAbsolute(ctx.io, store.base, .{});
    defer apps_dir.close(ctx.io);
    const adopted = try apps_dir.readFileAlloc(
        ctx.io,
        "Applications/Foo.app/Contents/.ghr-source",
        a,
        Io.Limit.limited(Dir.max_path_bytes),
    );
    try std.testing.expectEqualStrings(p.unit, adopted);
}

test "fresh install commits a v2 unit, its metadata, and its commands" {
    if (host_is_windows) return error.SkipZigTest;
    var store = try TestStore.init();
    defer store.deinit();
    const ctx = store.ctx();

    const unit = try tStageUnit(&ctx, "example/tool", &.{"bin/tool"}, &.{});
    defer unit.destroy();
    try tCommit(&ctx, &.{unit});

    var inv = try tScan(&ctx);
    defer inv.deinit(t_alloc);
    try std.testing.expectEqual(@as(usize, 1), inv.records.len);
    const rec = inv.records[0];
    try std.testing.expectEqual(install_state.Status.ok, rec.status);
    try std.testing.expectEqual(install_state.UnitKind.v2, rec.kind);
    try std.testing.expectEqualStrings("example/tool", rec.id.?);
    try std.testing.expectEqualStrings("tool", rec.commands[0].name);
    try std.testing.expect(store.binEntryExists("tool"));

    // The transaction namespace is fully cleaned up after a commit.
    var arena_inst = std.heap.ArenaAllocator.init(t_alloc);
    defer arena_inst.deinit();
    const txn = try store.toolsPath(arena_inst.allocator(), "_v2/txn/u-example");
    try std.testing.expect(!(try install_txn.directoryExists(ctx.io, txn)));
}

test "an alias publishes the exact requested name and never renames by id" {
    if (host_is_windows) return error.SkipZigTest;
    var store = try TestStore.init();
    defer store.deinit();
    const ctx = store.ctx();

    const unit = try tStageUnit(&ctx, "zigb", &.{"bin/zig"}, &.{.{ .source = "zig", .published = "zigb" }});
    defer unit.destroy();
    try tCommit(&ctx, &.{unit});

    try std.testing.expect(store.binEntryExists("zigb"));
    try std.testing.expect(!store.binEntryExists("zig"));

    var inv = try tScan(&ctx);
    defer inv.deinit(t_alloc);
    const rec = tFindRecord(inv, "zigb").?;
    try std.testing.expectEqualStrings("zigb", rec.commands[0].name);
    try std.testing.expectEqualStrings("zig", rec.commands[0].source_name.?);
    try std.testing.expectEqualStrings("bin/zig", rec.commands[0].relative_target);
}

test "two ids from one repository coexist" {
    if (host_is_windows) return error.SkipZigTest;
    var store = try TestStore.init();
    defer store.deinit();
    const ctx = store.ctx();

    const a = try tStageUnit(&ctx, "ziga", &.{"bin/zig"}, &.{.{ .source = "zig", .published = "ziga" }});
    defer a.destroy();
    const b = try tStageUnit(&ctx, "zigb", &.{"bin/zig"}, &.{.{ .source = "zig", .published = "zigb" }});
    defer b.destroy();
    try tCommit(&ctx, &.{ a, b });

    try std.testing.expect(store.binEntryExists("ziga"));
    try std.testing.expect(store.binEntryExists("zigb"));

    var inv = try tScan(&ctx);
    defer inv.deinit(t_alloc);
    try std.testing.expectEqual(@as(usize, 2), inv.records.len);
    try std.testing.expect(tFindRecord(inv, "ziga") != null);
    try std.testing.expect(tFindRecord(inv, "zigb") != null);
}

test "a duplicate command inside one invocation is rejected without mutation" {
    if (host_is_windows) return error.SkipZigTest;
    var store = try TestStore.init();
    defer store.deinit();
    const ctx = store.ctx();

    const a = try tStageUnit(&ctx, "one", &.{"bin/tool"}, &.{});
    defer a.destroy();
    const b = try tStageUnit(&ctx, "two", &.{"bin/tool"}, &.{});
    defer b.destroy();
    try std.testing.expectError(error.InstallPlanRejected, tCommit(&ctx, &.{ a, b }));

    var inv = try tScan(&ctx);
    defer inv.deinit(t_alloc);
    try std.testing.expectEqual(@as(usize, 0), inv.records.len);
    try std.testing.expect(!store.binEntryExists("tool"));
    try std.testing.expect(std.mem.indexOf(u8, store.errText(), "no install state was changed") != null);
}

test "a command owned by another id blocks the whole invocation" {
    if (host_is_windows) return error.SkipZigTest;
    var store = try TestStore.init();
    defer store.deinit();
    const ctx = store.ctx();

    const first = try tStageUnit(&ctx, "one", &.{"bin/tool"}, &.{});
    defer first.destroy();
    try tCommit(&ctx, &.{first});

    const second = try tStageUnit(&ctx, "two", &.{"bin/tool"}, &.{});
    defer second.destroy();
    const third = try tStageUnit(&ctx, "three", &.{"bin/other"}, &.{});
    defer third.destroy();
    try std.testing.expectError(error.InstallPlanRejected, tCommit(&ctx, &.{ second, third }));

    var inv = try tScan(&ctx);
    defer inv.deinit(t_alloc);
    try std.testing.expectEqual(@as(usize, 1), inv.records.len);
    // The unrelated unit in the same invocation is not committed either.
    try std.testing.expect(!store.binEntryExists("other"));
}

test "an unmanaged bin entry blocks installation" {
    if (host_is_windows) return error.SkipZigTest;
    var store = try TestStore.init();
    defer store.deinit();
    const ctx = store.ctx();

    var arena_inst = std.heap.ArenaAllocator.init(t_alloc);
    defer arena_inst.deinit();
    const foreign = try store.binPath(arena_inst.allocator(), "tool");
    (try Dir.createFileAbsolute(ctx.io, foreign, .{})).close(ctx.io);

    const unit = try tStageUnit(&ctx, "example/tool", &.{"bin/tool"}, &.{});
    defer unit.destroy();
    try std.testing.expectError(error.InstallPlanRejected, tCommit(&ctx, &.{unit}));
    try std.testing.expect(std.mem.indexOf(u8, store.errText(), "UnmanagedArtifact") != null);
}

test "same-id replacement retires stale commands and keeps the new set" {
    if (host_is_windows) return error.SkipZigTest;
    var store = try TestStore.init();
    defer store.deinit();
    const ctx = store.ctx();

    const first = try tStageUnit(&ctx, "example/tool", &.{ "bin/tool", "bin/extra" }, &.{});
    defer first.destroy();
    try tCommit(&ctx, &.{first});
    try std.testing.expect(store.binEntryExists("tool"));
    try std.testing.expect(store.binEntryExists("extra"));

    const second = try tStageUnit(&ctx, "example/tool", &.{"bin/tool"}, &.{});
    defer second.destroy();
    try tCommit(&ctx, &.{second});

    try std.testing.expect(store.binEntryExists("tool"));
    try std.testing.expect(!store.binEntryExists("extra"));

    var inv = try tScan(&ctx);
    defer inv.deinit(t_alloc);
    try std.testing.expectEqual(@as(usize, 1), inv.records.len);
    try std.testing.expectEqual(@as(usize, 1), inv.records[0].commands.len);
}

test "stale removal leaves an entry that no longer belongs to the id" {
    if (host_is_windows) return error.SkipZigTest;
    var store = try TestStore.init();
    defer store.deinit();
    const ctx = store.ctx();

    const first = try tStageUnit(&ctx, "example/tool", &.{ "bin/tool", "bin/extra" }, &.{});
    defer first.destroy();
    try tCommit(&ctx, &.{first});

    // Someone replaced the published command with their own file. The plan
    // still wants to retire it, but revalidation must refuse.
    var arena_inst = std.heap.ArenaAllocator.init(t_alloc);
    defer arena_inst.deinit();
    const extra = try store.binPath(arena_inst.allocator(), "extra");
    try Dir.deleteFileAbsolute(ctx.io, extra);
    (try Dir.createFileAbsolute(ctx.io, extra, .{})).close(ctx.io);

    const second = try tStageUnit(&ctx, "example/tool", &.{"bin/tool"}, &.{});
    defer second.destroy();
    try tCommit(&ctx, &.{second});
    try std.testing.expect(store.binEntryExists("extra"));
}

test "a publication failure restores the previous unit and its commands" {
    if (host_is_windows) return error.SkipZigTest;
    var store = try TestStore.init();
    defer store.deinit();
    const ctx = store.ctx();

    const first = try tStageUnit(&ctx, "example/tool", &.{"bin/tool"}, &.{});
    defer first.destroy();
    try tCommit(&ctx, &.{first});

    var arena_inst = std.heap.ArenaAllocator.init(t_alloc);
    defer arena_inst.deinit();
    const marker = try store.toolsPath(
        arena_inst.allocator(),
        "_v2/units/u-example/u-tool/_unit/first-generation",
    );
    (try Dir.createFileAbsolute(ctx.io, marker, .{})).close(ctx.io);

    const second = try tStageUnit(&ctx, "example/tool", &.{"bin/tool"}, &.{});
    defer second.destroy();
    commit_faults = .{ .fail_publish_after = 0 };
    defer commit_faults = .{};
    try std.testing.expectError(error.InstallFailed, tCommit(&ctx, &.{second}));

    // The previous unit is live again, with its content and its command.
    var f = try Dir.openFileAbsolute(ctx.io, marker, .{});
    f.close(ctx.io);
    try std.testing.expect(store.binEntryExists("tool"));

    var inv = try tScan(&ctx);
    defer inv.deinit(t_alloc);
    try std.testing.expectEqual(@as(usize, 1), inv.records.len);
    try std.testing.expectEqual(install_state.Status.ok, inv.records[0].status);
}

test "a publication failure on a fresh install leaves no unit behind" {
    if (host_is_windows) return error.SkipZigTest;
    var store = try TestStore.init();
    defer store.deinit();
    const ctx = store.ctx();

    const unit = try tStageUnit(&ctx, "example/tool", &.{"bin/tool"}, &.{});
    defer unit.destroy();
    commit_faults = .{ .fail_publish_after = 0 };
    defer commit_faults = .{};
    try std.testing.expectError(error.InstallFailed, tCommit(&ctx, &.{unit}));

    var inv = try tScan(&ctx);
    defer inv.deinit(t_alloc);
    try std.testing.expectEqual(@as(usize, 0), inv.records.len);
    try std.testing.expect(!store.binEntryExists("tool"));
}

test "rolled-back recovery never retires the restored unit's commands" {
    if (host_is_windows) return error.SkipZigTest;
    var store = try TestStore.init();
    defer store.deinit();
    const ctx = store.ctx();

    const unit = try tStageUnit(&ctx, "example/tool", &.{ "bin/tool", "bin/extra" }, &.{});
    defer unit.destroy();
    try tCommit(&ctx, &.{unit});

    const p = unit.paths;
    try install_txn.ensureDirAbsolute(ctx.io, p.root);
    try install_txn.writeJournal(ctx.io, p, t_alloc, .{
        .op = .install,
        .id = p.id,
        .unit_path = p.unit,
        .stage_path = p.stage,
        .backup_path = p.backup,
        .stale = &.{"extra"},
        .had_previous = true,
        .phase = .rolled_back,
    });

    try recoverPendingTransactions(&ctx);
    try std.testing.expect(store.binEntryExists("tool"));
    try std.testing.expect(store.binEntryExists("extra"));
    try std.testing.expect(!(try install_txn.directoryExists(ctx.io, p.root)));
}

test "rolled-back recovery removes a failed fresh unit" {
    if (host_is_windows) return error.SkipZigTest;
    var store = try TestStore.init();
    defer store.deinit();
    const ctx = store.ctx();

    const unit = try tStageUnit(&ctx, "example/tool", &.{"bin/tool"}, &.{});
    defer unit.destroy();
    try tCommit(&ctx, &.{unit});

    const p = unit.paths;
    try install_txn.ensureDirAbsolute(ctx.io, p.root);
    try install_txn.writeJournal(ctx.io, p, t_alloc, .{
        .op = .install,
        .id = p.id,
        .unit_path = p.unit,
        .stage_path = p.stage,
        .backup_path = p.backup,
        .publish = &.{"tool"},
        .had_previous = false,
        .phase = .rolled_back,
    });

    try recoverPendingTransactions(&ctx);
    try std.testing.expect(!(try install_txn.directoryExists(ctx.io, p.unit)));
    try std.testing.expect(!(try install_txn.directoryExists(ctx.io, p.root)));
    try std.testing.expect(!store.binEntryExists("tool"));
}

test "staging never overwrites an unfinished transaction or its backup" {
    if (host_is_windows) return error.SkipZigTest;
    var store = try TestStore.init();
    defer store.deinit();
    const ctx = store.ctx();

    var existing = try install_txn.paths(t_alloc, ctx.dirs.tools, "example/tool", host_platform);
    defer existing.deinit();
    try install_txn.ensureDirAbsolute(ctx.io, existing.backup);
    try install_txn.writeJournal(ctx.io, existing, t_alloc, .{
        .op = .install,
        .id = existing.id,
        .unit_path = existing.unit,
        .stage_path = existing.stage,
        .backup_path = existing.backup,
        .had_previous = true,
        .phase = .publishing,
    });

    const unit = try StagedUnit.create(t_alloc);
    defer unit.destroy();
    try std.testing.expectError(error.InstallStepFailed, beginStaging(&ctx, unit, "example/tool"));
    try std.testing.expect(try install_txn.directoryExists(ctx.io, existing.backup));

    var owned = (try install_txn.readJournal(t_alloc, ctx.io, existing.journal)).?;
    defer owned.deinit();
    try std.testing.expectEqual(install_txn.Phase.publishing, owned.journal.phase);

    // Generic error cleanup uses the same fail-closed guard.
    discardStagedUnit(t_alloc, ctx.io, unit);
    try std.testing.expect(try install_txn.directoryExists(ctx.io, existing.backup));
    var preserved = (try install_txn.readJournal(t_alloc, ctx.io, existing.journal)).?;
    defer preserved.deinit();
}

test "an interrupted commit before the swap is rolled back" {
    if (host_is_windows) return error.SkipZigTest;
    var store = try TestStore.init();
    defer store.deinit();
    const ctx = store.ctx();

    const unit = try tStageUnit(&ctx, "example/tool", &.{"bin/tool"}, &.{});
    defer unit.destroy();
    const p = unit.paths;
    try install_txn.writeJournal(ctx.io, p, t_alloc, .{
        .op = .install,
        .id = p.id,
        .unit_path = p.unit,
        .stage_path = p.stage,
        .backup_path = p.backup,
        .publish = &.{"tool"},
        .phase = .staged,
    });

    try recoverPendingTransactions(&ctx);
    try std.testing.expect(!(try install_txn.directoryExists(ctx.io, p.stage)));
    try std.testing.expect(!(try install_txn.directoryExists(ctx.io, p.unit)));
    try std.testing.expect(!store.binEntryExists("tool"));
}

test "an interrupted commit between the two renames is completed" {
    if (host_is_windows) return error.SkipZigTest;
    var store = try TestStore.init();
    defer store.deinit();
    const ctx = store.ctx();

    const unit = try tStageUnit(&ctx, "example/tool", &.{"bin/tool"}, &.{});
    defer unit.destroy();
    const p = unit.paths;

    // Write the metadata the interrupted commit would already have staged.
    {
        var stage_dir = try Dir.openDirAbsolute(ctx.io, p.stage, .{});
        defer stage_dir.close(ctx.io);
        try install_state_write.writeUnitMetadata(t_alloc, ctx.io, stage_dir, .{
            .id = p.id,
            .source = .{ .kind = .github, .owner = "example", .repo = "tool", .tag = "v1" },
            .resolved = .{ .tag = "v1", .asset = "tool.tar.gz" },
            .commands = &.{.{ .name = "tool", .relative_target = "bin/tool", .kind = .native }},
            .verification = .{ .result = "none" },
        }, host_platform);
    }
    try install_txn.writeJournal(ctx.io, p, t_alloc, .{
        .op = .install,
        .id = p.id,
        .unit_path = p.unit,
        .stage_path = p.stage,
        .backup_path = p.backup,
        .publish = &.{"tool"},
        .phase = .swapping,
    });

    try recoverPendingTransactions(&ctx);
    try std.testing.expect(try install_txn.directoryExists(ctx.io, p.unit));
    try std.testing.expect(store.binEntryExists("tool"));

    var inv = try tScan(&ctx);
    defer inv.deinit(t_alloc);
    try std.testing.expectEqual(@as(usize, 1), inv.records.len);
    try std.testing.expectEqual(install_state.Status.ok, inv.records[0].status);
}

test "an interrupted commit after the swap republishes missing commands" {
    if (host_is_windows) return error.SkipZigTest;
    var store = try TestStore.init();
    defer store.deinit();
    const ctx = store.ctx();

    const unit = try tStageUnit(&ctx, "example/tool", &.{"bin/tool"}, &.{});
    defer unit.destroy();
    try tCommit(&ctx, &.{unit});

    // Simulate a crash after the unit went live but before publication
    // finished: remove the command and replay the journal.
    var arena_inst = std.heap.ArenaAllocator.init(t_alloc);
    defer arena_inst.deinit();
    const link_path = try store.binPath(arena_inst.allocator(), "tool");
    try Dir.deleteFileAbsolute(ctx.io, link_path);

    const p = unit.paths;
    try install_txn.ensureDirAbsolute(ctx.io, p.root);
    try install_txn.writeJournal(ctx.io, p, t_alloc, .{
        .op = .install,
        .id = p.id,
        .unit_path = p.unit,
        .stage_path = p.stage,
        .backup_path = p.backup,
        .publish = &.{"tool"},
        .phase = .publishing,
    });

    try recoverPendingTransactions(&ctx);
    try std.testing.expect(store.binEntryExists("tool"));
    try std.testing.expect(!(try install_txn.directoryExists(ctx.io, p.root)));
}

test "recovery refuses a journal that does not describe its own directory" {
    if (host_is_windows) return error.SkipZigTest;
    var store = try TestStore.init();
    defer store.deinit();
    const ctx = store.ctx();

    const unit = try tStageUnit(&ctx, "example/tool", &.{"bin/tool"}, &.{});
    defer unit.destroy();
    try tCommit(&ctx, &.{unit});

    var p = try install_txn.paths(t_alloc, ctx.dirs.tools, "example/tool", host_platform);
    defer p.deinit();
    try install_txn.ensureDirAbsolute(ctx.io, p.root);
    // A journal claiming another id must never make recovery touch this unit.
    try install_txn.writeJournal(ctx.io, p, t_alloc, .{
        .op = .uninstall,
        .id = "someone/else",
        .unit_path = p.unit,
        .stage_path = p.stage,
        .backup_path = p.backup,
        .stale = &.{"tool"},
        .phase = .retiring,
    });

    try recoverPendingTransactions(&ctx);
    try std.testing.expect(store.binEntryExists("tool"));
    try std.testing.expect(try install_txn.directoryExists(ctx.io, p.unit));
    try std.testing.expect(std.mem.indexOf(u8, store.errText(), "could not recover") != null);
}

test "installing over one healthy legacy unit migrates it and keeps nested wasm siblings" {
    if (host_is_windows) return error.SkipZigTest;
    var store = try TestStore.init();
    defer store.deinit();
    const ctx = store.ctx();

    try tWriteLegacyUnit(&ctx, "example/tool", &.{"legacy-tool"});
    try tWriteLegacyUnit(&ctx, "example/tool/mod", &.{"mod.wasm"});

    var arena_inst = std.heap.ArenaAllocator.init(t_alloc);
    defer arena_inst.deinit();
    const a = arena_inst.allocator();
    const legacy_target = try store.toolsPath(a, "example/tool/legacy-tool");
    const legacy_link = try store.binPath(a, "legacy-tool");
    {
        var bin = try Dir.openDirAbsolute(ctx.io, ctx.dirs.bin, .{});
        defer bin.close(ctx.io);
        try bin.symLink(ctx.io, legacy_target, "legacy-tool", .{});
    }
    try std.testing.expect(store.binEntryExists("legacy-tool"));

    const unit = try tStageUnit(&ctx, "example/tool", &.{"bin/tool"}, &.{});
    defer unit.destroy();
    try tCommit(&ctx, &.{unit});

    var inv = try tScan(&ctx);
    defer inv.deinit(t_alloc);
    const migrated = tFindRecord(inv, "example/tool").?;
    try std.testing.expectEqual(install_state.UnitKind.v2, migrated.kind);
    // The independently installed nested wasm unit survives the migration.
    const child = tFindRecord(inv, "example/tool/mod").?;
    try std.testing.expectEqual(install_state.UnitKind.v1_wasm, child.kind);

    // The legacy repo-level content is gone, its command retired, and the new
    // command is live.
    try std.testing.expect(!fileExistsAbsolute(ctx.io, legacy_target));
    try std.testing.expect(!store.binEntryExists("legacy-tool"));
    _ = legacy_link;
    try std.testing.expect(store.binEntryExists("tool"));
}

test "a legacy unit and a v2 unit sharing an id refuse mutation" {
    if (host_is_windows) return error.SkipZigTest;
    var store = try TestStore.init();
    defer store.deinit();
    const ctx = store.ctx();

    const unit = try tStageUnit(&ctx, "example/tool", &.{"bin/tool"}, &.{});
    defer unit.destroy();
    try tCommit(&ctx, &.{unit});
    try tWriteLegacyUnit(&ctx, "example/tool", &.{"legacy-tool"});

    const again = try tStageUnit(&ctx, "example/tool", &.{"bin/tool"}, &.{});
    defer again.destroy();
    try std.testing.expectError(error.InstallPlanRejected, tCommit(&ctx, &.{again}));
    try std.testing.expect(std.mem.indexOf(u8, store.errText(), "Inventory") != null);
}

test "corrupt metadata anywhere blocks install and uninstall" {
    if (host_is_windows) return error.SkipZigTest;
    var store = try TestStore.init();
    defer store.deinit();
    const ctx = store.ctx();

    const unit = try tStageUnit(&ctx, "example/tool", &.{"bin/tool"}, &.{});
    defer unit.destroy();
    try tCommit(&ctx, &.{unit});

    var arena_inst = std.heap.ArenaAllocator.init(t_alloc);
    defer arena_inst.deinit();
    const a = arena_inst.allocator();
    const other = try store.toolsPath(a, "_v2/units/u-broken/_unit");
    try ensureDirAbsoluteRecursive(ctx.io, other);
    const meta = try std.fmt.allocPrint(a, "{s}{c}ghr.json", .{ other, std.fs.path.sep });
    {
        var f = try Dir.createFileAbsolute(ctx.io, meta, .{});
        defer f.close(ctx.io);
        try f.writeStreamingAll(ctx.io, "{ not json");
    }

    const again = try tStageUnit(&ctx, "example/two", &.{"bin/two"}, &.{});
    defer again.destroy();
    try std.testing.expectError(error.InstallPlanRejected, tCommit(&ctx, &.{again}));

    try std.testing.expectError(
        error.UninstallStateUnusable,
        uninstallUnit(&ctx, "example/tool"),
    );
    // Nothing was removed while state was unusable.
    try std.testing.expect(store.binEntryExists("tool"));
}

fn fileExistsAbsolute(io: Io, path: []const u8) bool {
    var f = Dir.openFileAbsolute(io, path, .{}) catch return false;
    f.close(io);
    return true;
}

test "uninstall removes exactly one id and is not recursive over prefixes" {
    if (host_is_windows) return error.SkipZigTest;
    var store = try TestStore.init();
    defer store.deinit();
    var ctx = store.ctx();

    const parent = try tStageUnit(&ctx, "example/tool", &.{"bin/tool"}, &.{});
    defer parent.destroy();
    const child = try tStageUnit(&ctx, "example/tool/mod", &.{"bin/mod"}, &.{});
    defer child.destroy();
    try tCommit(&ctx, &.{ parent, child });

    try uninstallUnit(&ctx, "example/tool");

    var inv = try tScan(&ctx);
    defer inv.deinit(t_alloc);
    try std.testing.expectEqual(@as(usize, 1), inv.records.len);
    try std.testing.expectEqualStrings("example/tool/mod", inv.records[0].id.?);
    try std.testing.expect(!store.binEntryExists("tool"));
    try std.testing.expect(store.binEntryExists("mod"));
}

test "uninstall accepts a mixed-case argument that canonicalizes to the id" {
    if (host_is_windows) return error.SkipZigTest;
    var store = try TestStore.init();
    defer store.deinit();
    const ctx = store.ctx();

    const unit = try tStageUnit(&ctx, "example/tool", &.{"bin/tool"}, &.{});
    defer unit.destroy();
    try tCommit(&ctx, &.{unit});

    try uninstallUnit(&ctx, "Example/Tool");
    var inv = try tScan(&ctx);
    defer inv.deinit(t_alloc);
    try std.testing.expectEqual(@as(usize, 0), inv.records.len);
}

test "uninstall fails closed when two records claim one command" {
    if (host_is_windows) return error.SkipZigTest;
    var store = try TestStore.init();
    defer store.deinit();
    const ctx = store.ctx();

    const keeper = try tStageUnit(&ctx, "keeper", &.{"bin/shared"}, &.{});
    defer keeper.destroy();
    const other = try tStageUnit(&ctx, "other", &.{"bin/other"}, &.{});
    defer other.destroy();
    try tCommit(&ctx, &.{ keeper, other });

    // Tamper with one record so two ids claim `shared`. Ownership is no longer
    // decidable, so no mutation may happen at all.
    var arena_inst = std.heap.ArenaAllocator.init(t_alloc);
    defer arena_inst.deinit();
    const other_unit = try store.toolsPath(arena_inst.allocator(), "_v2/units/u-other/_unit");
    {
        var dir = try Dir.openDirAbsolute(ctx.io, other_unit, .{});
        defer dir.close(ctx.io);
        try install_state_write.writeUnitMetadata(t_alloc, ctx.io, dir, .{
            .id = "other",
            .source = .{ .kind = .github, .owner = "example", .repo = "tool", .tag = "v1" },
            .resolved = .{ .tag = "v1", .asset = "tool.tar.gz" },
            .commands = &.{.{ .name = "shared", .relative_target = "bin/other", .kind = .native }},
            .verification = .{ .result = "none" },
        }, host_platform);
    }

    try std.testing.expectError(error.UninstallStateUnusable, uninstallUnit(&ctx, "other"));
    try std.testing.expect(store.binEntryExists("shared"));
    try std.testing.expect(store.binEntryExists("other"));
}

test "uninstall leaves a command entry that no longer points into the unit" {
    if (host_is_windows) return error.SkipZigTest;
    var store = try TestStore.init();
    defer store.deinit();
    const ctx = store.ctx();

    const unit = try tStageUnit(&ctx, "example/tool", &.{"bin/tool"}, &.{});
    defer unit.destroy();
    try tCommit(&ctx, &.{unit});

    // The user repointed the published command at something of their own.
    var arena_inst = std.heap.ArenaAllocator.init(t_alloc);
    defer arena_inst.deinit();
    const link = try store.binPath(arena_inst.allocator(), "tool");
    try Dir.deleteFileAbsolute(ctx.io, link);
    {
        var bin = try Dir.openDirAbsolute(ctx.io, ctx.dirs.bin, .{});
        defer bin.close(ctx.io);
        try bin.symLink(ctx.io, "/usr/bin/true", "tool", .{});
    }

    try uninstallUnit(&ctx, "example/tool");
    var inv = try tScan(&ctx);
    defer inv.deinit(t_alloc);
    try std.testing.expectEqual(@as(usize, 0), inv.records.len);
    // The modified entry is not ghr's to remove.
    try std.testing.expect(store.binEntryExists("tool"));
}

test "uninstalling a legacy repo unit preserves its nested wasm units" {
    if (host_is_windows) return error.SkipZigTest;
    var store = try TestStore.init();
    defer store.deinit();
    const ctx = store.ctx();

    try tWriteLegacyUnit(&ctx, "example/tool", &.{"legacy-tool"});
    try tWriteLegacyUnit(&ctx, "example/tool/mod", &.{"mod.wasm"});

    try uninstallUnit(&ctx, "example/tool");

    var inv = try tScan(&ctx);
    defer inv.deinit(t_alloc);
    try std.testing.expectEqual(@as(usize, 1), inv.records.len);
    try std.testing.expectEqualStrings("example/tool/mod", inv.records[0].id.?);
}

test "uninstall reports a missing id without touching anything" {
    if (host_is_windows) return error.SkipZigTest;
    var store = try TestStore.init();
    defer store.deinit();
    const ctx = store.ctx();

    const unit = try tStageUnit(&ctx, "example/tool", &.{"bin/tool"}, &.{});
    defer unit.destroy();
    try tCommit(&ctx, &.{unit});

    try std.testing.expectError(
        error.UninstallTargetNotFound,
        uninstallUnit(&ctx, "example/absent"),
    );
    try std.testing.expect(store.binEntryExists("tool"));
}

test "uninstall rejects an argument that is not a valid id" {
    if (host_is_windows) return error.SkipZigTest;
    var store = try TestStore.init();
    defer store.deinit();

    try std.testing.expectError(
        error.UninstallTargetNotFound,
        uninstallUnit(&store.ctx(), "../escape"),
    );
    try std.testing.expect(std.mem.indexOf(u8, store.errText(), "is not a valid install id") != null);
}

test "an interrupted uninstall is finished, never resurrected" {
    if (host_is_windows) return error.SkipZigTest;
    var store = try TestStore.init();
    defer store.deinit();
    const ctx = store.ctx();

    const unit = try tStageUnit(&ctx, "example/tool", &.{"bin/tool"}, &.{});
    defer unit.destroy();
    try tCommit(&ctx, &.{unit});

    const p = unit.paths;
    try install_txn.ensureDirAbsolute(ctx.io, p.root);
    try install_txn.writeJournal(ctx.io, p, t_alloc, .{
        .op = .uninstall,
        .id = p.id,
        .unit_path = p.unit,
        .stage_path = p.stage,
        .backup_path = p.backup,
        .stale = &.{"tool"},
        .phase = .retiring,
    });

    try recoverPendingTransactions(&ctx);
    try std.testing.expect(!store.binEntryExists("tool"));
    try std.testing.expect(!(try install_txn.directoryExists(ctx.io, p.unit)));
}

/// Stage a wasm module unit the way a release does: the module plus the
/// companion `<module>.ghr` manifest that carries its runtime.
fn tStageWasmUnit(ctx: *const InstallContext, id: []const u8, module: []const u8) !*StagedUnit {
    const unit = try StagedUnit.create(t_alloc);
    errdefer unit.destroy();
    const a = unit.alloc();
    try beginStaging(ctx, unit, id);

    var stage_dir = try Dir.openDirAbsolute(ctx.io, unit.paths.stage, .{ .iterate = true });
    defer stage_dir.close(ctx.io);
    {
        var f = try stage_dir.createFile(ctx.io, module, .{});
        defer f.close(ctx.io);
        try f.writeStreamingAll(ctx.io, "\x00asm");
    }
    {
        const manifest_name = try std.fmt.allocPrint(a, "{s}.ghr", .{module});
        var f = try stage_dir.createFile(ctx.io, manifest_name, .{});
        defer f.close(ctx.io);
        try f.writeStreamingAll(ctx.io,
            \\.{
            \\    .version = 1,
            \\    .runtime = "wasmtime",
            \\    .runtimeArgs = .{ "--dir=." },
            \\}
        );
    }

    const commands = try a.alloc(command_plan.Command, 1);
    commands[0] = .{ .relative_target = try a.dupe(u8, module), .kind = .wasm };
    unit.commands = commands;
    unit.source = .{
        .kind = .github,
        .owner = try a.dupe(u8, "example"),
        .repo = try a.dupe(u8, "tools"),
        .tag = try a.dupe(u8, "v1"),
        .asset_selector = try a.dupe(u8, module),
    };
    unit.config = .{ .verification_policy = .{} };
    unit.resolved = .{ .tag = try a.dupe(u8, "v1"), .asset = try a.dupe(u8, module) };
    unit.verification = .{ .result = try a.dupe(u8, "none") };
    unit.display = try a.dupe(u8, id);
    return unit;
}

test "a wasm module publishes a launcher plus its runtime manifest" {
    if (host_is_windows) return error.SkipZigTest;
    var store = try TestStore.init();
    defer store.deinit();
    const ctx = store.ctx();

    const unit = try tStageWasmUnit(&ctx, "example/tools/parser", "parser.wasm");
    defer unit.destroy();
    try tCommit(&ctx, &.{unit});

    try std.testing.expect(store.binEntryExists("parser"));
    try std.testing.expect(store.binEntryExists("parser.ghr"));

    var arena_inst = std.heap.ArenaAllocator.init(t_alloc);
    defer arena_inst.deinit();
    const a = arena_inst.allocator();
    var bin = try Dir.openDirAbsolute(ctx.io, ctx.dirs.bin, .{});
    defer bin.close(ctx.io);
    const manifest = try bin.readFileAlloc(ctx.io, "parser.ghr", a, Io.Limit.limited(4096));
    try std.testing.expect(std.mem.indexOf(u8, manifest, "targetWasm") != null);
    try std.testing.expect(std.mem.indexOf(u8, manifest, "wasmtime") != null);
    try std.testing.expect(std.mem.indexOf(u8, manifest, "u-parser") != null);

    var inv = try tScan(&ctx);
    defer inv.deinit(t_alloc);
    const rec = tFindRecord(inv, "example/tools/parser").?;
    try std.testing.expectEqualStrings("wasm", rec.commands[0].kind.?);
    try std.testing.expectEqualStrings("parser.wasm", rec.commands[0].relative_target);
}

test "an archive id and its wasm child ids are independent units" {
    if (host_is_windows) return error.SkipZigTest;
    var store = try TestStore.init();
    defer store.deinit();
    const ctx = store.ctx();

    const archive_unit = try tStageUnit(&ctx, "example/tools", &.{"bin/tools"}, &.{});
    defer archive_unit.destroy();
    const module = try tStageWasmUnit(&ctx, "example/tools/parser", "parser.wasm");
    defer module.destroy();
    try tCommit(&ctx, &.{ archive_unit, module });

    // Replacing the archive must not disturb the module.
    const replacement = try tStageUnit(&ctx, "example/tools", &.{"bin/tools"}, &.{});
    defer replacement.destroy();
    try tCommit(&ctx, &.{replacement});

    var inv = try tScan(&ctx);
    defer inv.deinit(t_alloc);
    try std.testing.expectEqual(@as(usize, 2), inv.records.len);
    try std.testing.expect(tFindRecord(inv, "example/tools") != null);
    try std.testing.expect(tFindRecord(inv, "example/tools/parser") != null);
    try std.testing.expect(store.binEntryExists("tools"));
    try std.testing.expect(store.binEntryExists("parser"));
    try std.testing.expect(store.binEntryExists("parser.ghr"));

    // Removing one wasm child touches neither the archive nor its siblings.
    try uninstallUnit(&ctx, "example/tools/parser");
    try std.testing.expect(!store.binEntryExists("parser"));
    try std.testing.expect(!store.binEntryExists("parser.ghr"));
    try std.testing.expect(store.binEntryExists("tools"));

    var inv2 = try tScan(&ctx);
    defer inv2.deinit(t_alloc);
    try std.testing.expectEqual(@as(usize, 1), inv2.records.len);
    try std.testing.expectEqualStrings("example/tools", inv2.records[0].id.?);
}

test "an interrupted migration republishes before the legacy unit is retired" {
    if (host_is_windows) return error.SkipZigTest;
    var store = try TestStore.init();
    defer store.deinit();
    const ctx = store.ctx();

    // A legacy unit and its in-flight v2 replacement deliberately share one
    // canonical id. A whole-store scan sees that as a duplicate-id conflict, so
    // recovery must address the v2 unit directly instead.
    try tWriteLegacyUnit(&ctx, "example/tool", &.{"legacy-tool"});

    const unit = try tStageUnit(&ctx, "example/tool", &.{"bin/tool"}, &.{});
    defer unit.destroy();
    const p = unit.paths;
    {
        var stage_dir = try Dir.openDirAbsolute(ctx.io, p.stage, .{});
        defer stage_dir.close(ctx.io);
        try install_state_write.writeUnitMetadata(t_alloc, ctx.io, stage_dir, .{
            .id = p.id,
            .source = .{ .kind = .github, .owner = "example", .repo = "tool", .tag = "v1" },
            .resolved = .{ .tag = "v1", .asset = "tool.tar.gz" },
            .commands = &.{.{ .name = "tool", .relative_target = "bin/tool", .kind = .native }},
            .verification = .{ .result = "none" },
        }, host_platform);
    }
    try install_txn.swapUnit(ctx.io, p, .{});

    var arena_inst = std.heap.ArenaAllocator.init(t_alloc);
    defer arena_inst.deinit();
    const legacy_dir = try store.toolsPath(arena_inst.allocator(), "example/tool");
    try install_txn.writeJournal(ctx.io, p, t_alloc, .{
        .op = .install,
        .id = p.id,
        .unit_path = p.unit,
        .stage_path = p.stage,
        .backup_path = p.backup,
        .publish = &.{"tool"},
        .legacy_path = legacy_dir,
        .legacy_kind = .v1_repo,
        .phase = .publishing,
    });

    try recoverPendingTransactions(&ctx);

    // The command is published AND the legacy unit is retired -- never one
    // without the other.
    try std.testing.expect(store.binEntryExists("tool"));
    const legacy_meta = try store.toolsPath(arena_inst.allocator(), "example/tool/ghr.json");
    try std.testing.expect(!fileExistsAbsolute(ctx.io, legacy_meta));

    var inv = try tScan(&ctx);
    defer inv.deinit(t_alloc);
    try std.testing.expectEqual(@as(usize, 1), inv.records.len);
    try std.testing.expectEqual(install_state.UnitKind.v2, inv.records[0].kind);
}

test "recovery keeps a legacy unit when the replacement unit is unreadable" {
    if (host_is_windows) return error.SkipZigTest;
    var store = try TestStore.init();
    defer store.deinit();
    const ctx = store.ctx();

    try tWriteLegacyUnit(&ctx, "example/tool", &.{"legacy-tool"});

    const unit = try tStageUnit(&ctx, "example/tool", &.{"bin/tool"}, &.{});
    defer unit.destroy();
    const p = unit.paths;
    // The staged unit never received its metadata, so the v2 record cannot be
    // read back. Retiring the legacy unit here would destroy the only install.
    try install_txn.swapUnit(ctx.io, p, .{});

    var arena_inst = std.heap.ArenaAllocator.init(t_alloc);
    defer arena_inst.deinit();
    const legacy_dir = try store.toolsPath(arena_inst.allocator(), "example/tool");
    try install_txn.writeJournal(ctx.io, p, t_alloc, .{
        .op = .install,
        .id = p.id,
        .unit_path = p.unit,
        .stage_path = p.stage,
        .backup_path = p.backup,
        .publish = &.{"tool"},
        .legacy_path = legacy_dir,
        .legacy_kind = .v1_repo,
        .phase = .publishing,
    });

    try recoverPendingTransactions(&ctx);

    const legacy_meta = try store.toolsPath(arena_inst.allocator(), "example/tool/ghr.json");
    try std.testing.expect(fileExistsAbsolute(ctx.io, legacy_meta));
    try std.testing.expect(std.mem.indexOf(u8, store.errText(), "could not recover") != null);
}

test "recovery refuses a journal whose legacy path is not this id's legacy unit" {
    if (host_is_windows) return error.SkipZigTest;
    var store = try TestStore.init();
    defer store.deinit();
    const ctx = store.ctx();

    const unit = try tStageUnit(&ctx, "example/tool", &.{"bin/tool"}, &.{});
    defer unit.destroy();
    try tCommit(&ctx, &.{unit});

    var arena_inst = std.heap.ArenaAllocator.init(t_alloc);
    defer arena_inst.deinit();
    const a = arena_inst.allocator();
    const outsider = try std.fmt.allocPrint(a, "{s}{c}outsider", .{ store.base, std.fs.path.sep });
    try ensureDirAbsoluteRecursive(ctx.io, outsider);
    const canary = try std.fmt.allocPrint(a, "{s}{c}keep-me", .{ outsider, std.fs.path.sep });
    (try Dir.createFileAbsolute(ctx.io, canary, .{})).close(ctx.io);

    const p = unit.paths;
    try install_txn.ensureDirAbsolute(ctx.io, p.root);
    try install_txn.writeJournal(ctx.io, p, t_alloc, .{
        .op = .uninstall,
        .id = p.id,
        .unit_path = p.unit,
        .stage_path = p.stage,
        .backup_path = p.backup,
        .legacy_path = outsider,
        .legacy_kind = .v1_wasm,
        .phase = .retiring,
    });

    try recoverPendingTransactions(&ctx);
    // A path outside this id's legacy layout is never deleted.
    try std.testing.expect(fileExistsAbsolute(ctx.io, canary));
    try std.testing.expect(std.mem.indexOf(u8, store.errText(), "could not recover") != null);
}

test "legacy path validation accepts a pre-migration mixed-case directory" {
    try std.testing.expect(legacyPathMatchesId("/tools", "/tools/AzureAD/Foo", .v1_repo, "azuread/foo"));
    try std.testing.expect(legacyPathMatchesId("/tools", "/tools/o/r/mod", .v1_wasm, "o/r/mod"));
    // Wrong depth for the kind.
    try std.testing.expect(!legacyPathMatchesId("/tools", "/tools/o/r", .v1_wasm, "o/r"));
    try std.testing.expect(!legacyPathMatchesId("/tools", "/tools/o/r/mod", .v1_repo, "o/r/mod"));
    // A different id, an escape, and a path outside the tool store.
    try std.testing.expect(!legacyPathMatchesId("/tools", "/tools/o/other", .v1_repo, "o/r"));
    try std.testing.expect(!legacyPathMatchesId("/tools", "/etc/passwd", .v1_repo, "o/r"));
    try std.testing.expect(!legacyPathMatchesId("/tools", "/tools", .v1_repo, "o/r"));
    try std.testing.expect(!legacyPathMatchesId("/tools", "/toolsx/o/r", .v1_repo, "o/r"));
}

test "a failed invocation keeps the transaction that still holds live state" {
    if (host_is_windows) return error.SkipZigTest;
    var store = try TestStore.init();
    defer store.deinit();
    const ctx = store.ctx();

    const first = try tStageUnit(&ctx, "example/tool", &.{"bin/tool"}, &.{});
    defer first.destroy();
    try tCommit(&ctx, &.{first});

    // Simulate a transaction that already swapped the unit and could not roll
    // back: its journal and backup are the only copy of the previous install.
    const p = first.paths;
    try install_txn.ensureDirAbsolute(ctx.io, p.backup);
    var arena_inst = std.heap.ArenaAllocator.init(t_alloc);
    defer arena_inst.deinit();
    const backup_marker = try std.fmt.allocPrint(
        arena_inst.allocator(),
        "{s}{c}previous",
        .{ p.backup, std.fs.path.sep },
    );
    (try Dir.createFileAbsolute(ctx.io, backup_marker, .{})).close(ctx.io);
    try install_txn.writeJournal(ctx.io, p, t_alloc, .{
        .op = .install,
        .id = p.id,
        .unit_path = p.unit,
        .stage_path = p.stage,
        .backup_path = p.backup,
        .publish = &.{"tool"},
        .phase = .publishing,
    });

    discardStaging(t_alloc, ctx.io, &.{first});
    try std.testing.expect(fileExistsAbsolute(ctx.io, backup_marker));
    try std.testing.expect(fileExistsAbsolute(ctx.io, p.journal));

    // A purely staged transaction is still reclaimed.
    const second = try tStageUnit(&ctx, "example/other", &.{"bin/other"}, &.{});
    defer second.destroy();
    discardStaging(t_alloc, ctx.io, &.{second});
    try std.testing.expect(!(try install_txn.directoryExists(ctx.io, second.paths.root)));
}

test "invalid recorded configuration fails the install as a typed install error" {
    if (host_is_windows) return error.SkipZigTest;
    var store = try TestStore.init();
    defer store.deinit();
    const ctx = store.ctx();

    const unit = try tStageUnit(&ctx, "example/tool", &.{"bin/tool"}, &.{});
    defer unit.destroy();
    // A key-shaped value that the metadata validator rejects must surface as a
    // handled install failure, not as an unmapped error out of main.
    unit.config.minisign = "not-a-minisign-key";

    try std.testing.expectError(error.InstallFailed, tCommit(&ctx, &.{unit}));
    var inv = try tScan(&ctx);
    defer inv.deinit(t_alloc);
    try std.testing.expectEqual(@as(usize, 0), inv.records.len);
    try std.testing.expect(!store.binEntryExists("tool"));
}

test "generic url asset names are derived safely" {
    var arena_inst = std.heap.ArenaAllocator.init(t_alloc);
    defer arena_inst.deinit();
    const a = arena_inst.allocator();

    try std.testing.expectEqualStrings(
        "tool.tar.gz",
        try genericUrlAssetName(a, "https://example.com/dl/tool.tar.gz"),
    );
    try std.testing.expectEqualStrings(
        "tool.tar.gz",
        try genericUrlAssetName(a, "https://example.com/dl/tool.tar.gz?v=2"),
    );
    try std.testing.expectEqualStrings(
        "a b.zip",
        try genericUrlAssetName(a, "https://example.com/a%20b.zip"),
    );
    try std.testing.expectError(
        error.InvalidGenericUrl,
        genericUrlAssetName(a, "https://example.com/dl/"),
    );
    try std.testing.expectError(
        error.InvalidGenericUrl,
        genericUrlAssetName(a, "https://example.com/%2e%2e%2fetc%2fpasswd"),
    );
    try std.testing.expectError(
        error.InvalidGenericUrl,
        genericUrlAssetName(a, "https://example.com/x/%2e%2e"),
    );
    try std.testing.expectError(error.InvalidGenericUrl, genericUrlAssetName(a, "https://example.com"));
}

test "resolved provenance omits a url that cannot be persisted" {
    var arena_inst = std.heap.ArenaAllocator.init(t_alloc);
    defer arena_inst.deinit();
    const a = arena_inst.allocator();

    const signed = try resolvedFromAsset(a, "v1", .{
        .name = "tool.tgz",
        .browser_download_url = "https://objects.example.com/tool.tgz?X-Amz-Signature=deadbeef",
        .id = 99,
        .digest = "sha256:abc123",
    });
    try std.testing.expect(signed.download_url == null);
    try std.testing.expectEqual(@as(i64, 99), signed.api_asset_id.?);
    try std.testing.expectEqualStrings("sha256", signed.digest.?.algorithm);
    try std.testing.expectEqualStrings("abc123", signed.digest.?.value);

    const stable = try resolvedFromAsset(a, "v1", .{
        .name = "tool.tgz",
        .browser_download_url = "https://github.com/o/r/releases/download/v1/tool.tgz",
    });
    try std.testing.expectEqualStrings(
        "https://github.com/o/r/releases/download/v1/tool.tgz",
        stable.download_url.?,
    );
    try std.testing.expect(stable.api_asset_id == null);
}

test "a request without its own key inherits the command-level minisign default" {
    var parsed = try install_request.parse(t_alloc, &.{ "owner/repo", "example/other" });
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 2), parsed.items.len);
    try std.testing.expect(parsed.items[0].config.minisign == null);

    const default_key = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";
    const effective = parsed.items[0].config.minisign orelse default_key;
    try std.testing.expectEqualStrings(default_key, effective);
}

test "every legacy positional install form still parses" {
    const key = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";
    var parsed = try install_request.parse(t_alloc, &.{
        "owner/repo",
        "owner/repo@v1",
        "owner/repo/file.tar.gz@v1",
        "https://github.com/owner/repo/releases/download/v1/file.tar.gz",
        "jedisct1/minisign@0.12",
        key,
    });
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 5), parsed.items.len);
    try std.testing.expectEqualStrings("owner/repo", parsed.items[0].id);
    try std.testing.expectEqualStrings("owner/repo", parsed.items[2].id);
    try std.testing.expectEqualStrings("owner/repo", parsed.items[3].id);
    try std.testing.expectEqualStrings("jedisct1/minisign", parsed.items[4].id);
    try std.testing.expectEqualStrings(key, parsed.items[4].config.minisign.?);
}

test "staged relative targets are recorded portably" {
    var arena_inst = std.heap.ArenaAllocator.init(t_alloc);
    defer arena_inst.deinit();
    const a = arena_inst.allocator();
    const portable = try portableRel(a, "bin\\sub\\tool.exe");
    try std.testing.expectEqualStrings("bin/sub/tool.exe", portable);

    var buf: [64]u8 = undefined;
    const host = try hostRelInto(&buf, "bin/sub/tool");
    if (host_is_windows) {
        try std.testing.expectEqualStrings("bin\\sub\\tool", host);
    } else {
        try std.testing.expectEqualStrings("bin/sub/tool", host);
    }
}

test "windows locked-launcher fallback is only allowed for a same-id replacement" {
    var record_commands = [_]install_state.OwnedCommand{
        .{ .name = "tool", .relative_target = "bin/tool", .kind = "native" },
    };
    const record: install_state.InventoryRecord = .{
        .kind = .v2,
        .status = .ok,
        .reason = .none,
        .path = "_v2/units/u-x/_unit",
        .id = "x",
        .commands = &record_commands,
    };
    try std.testing.expect(previousPublishedSame(record, .{
        .id = "x",
        .source_name = "tool",
        .final_name = "tool",
        .relative_target = "bin/tool",
        .kind = .native,
        .publish = &.{},
        .cleanup = &.{},
    }));
    // A renamed command is a NEW command: its launcher must be writable.
    try std.testing.expect(!previousPublishedSame(record, .{
        .id = "x",
        .source_name = "tool",
        .final_name = "tool2",
        .relative_target = "bin/tool",
        .kind = .native,
        .publish = &.{},
        .cleanup = &.{},
    }));
    // A kind change is also a new artifact family.
    try std.testing.expect(!previousPublishedSame(record, .{
        .id = "x",
        .source_name = "tool",
        .final_name = "tool",
        .relative_target = "tool.wasm",
        .kind = .wasm,
        .publish = &.{},
        .cleanup = &.{},
    }));
    try std.testing.expect(!previousPublishedSame(null, .{
        .id = "x",
        .source_name = "tool",
        .final_name = "tool",
        .relative_target = "bin/tool",
        .kind = .native,
        .publish = &.{},
        .cleanup = &.{},
    }));
}

test "recovery artifact ownership never matches an unrelated entry" {
    if (host_is_windows) return error.SkipZigTest;
    var store = try TestStore.init();
    defer store.deinit();
    const ctx = store.ctx();

    const unit = try tStageUnit(&ctx, "example/tool", &.{"bin/tool"}, &.{});
    defer unit.destroy();
    try tCommit(&ctx, &.{unit});

    var bin_dir = try Dir.openDirAbsolute(ctx.io, ctx.dirs.bin, .{});
    defer bin_dir.close(ctx.io);
    try std.testing.expect(artifactBelongsToUnit(ctx.io, bin_dir, "tool", unit.paths.unit, null));
    try std.testing.expect(!artifactBelongsToUnit(ctx.io, bin_dir, "tool", "/somewhere/else", null));
    try std.testing.expect(!artifactBelongsToUnit(ctx.io, bin_dir, "absent", unit.paths.unit, null));
}

test "install refuses a lone query token before any work happens" {
    if (host_is_windows) return error.SkipZigTest;
    var store = try TestStore.init();
    defer store.deinit();

    try std.testing.expectError(error.InvalidInstallRequest, cmdInstallRequests(
        t_alloc,
        std.testing.io,
        &store.environ,
        &.{"?id=x"},
        &store.out.writer,
        &store.err.writer,
        .{},
    ));
    try std.testing.expect(std.mem.indexOf(u8, store.errText(), "LoneQueryToken") != null);
    // The failing value is never echoed.
    try std.testing.expect(std.mem.indexOf(u8, store.errText(), "?id=x") == null);
}

test "install rejects --bin with more than one source before staging" {
    if (host_is_windows) return error.SkipZigTest;
    var store = try TestStore.init();
    defer store.deinit();

    try std.testing.expectError(error.BinFilterRequiresSingleSpec, cmdInstallRequests(
        t_alloc,
        std.testing.io,
        &store.environ,
        &.{ "owner/repo", "owner/other" },
        &store.out.writer,
        &store.err.writer,
        .{ .bin_filters = &.{"tool"} },
    ));
}

test "install with no source reports the missing spec" {
    var store = try TestStore.init();
    defer store.deinit();

    try std.testing.expectError(error.MissingInstallSpec, cmdInstallRequests(
        t_alloc,
        std.testing.io,
        &store.environ,
        &.{},
        &store.out.writer,
        &store.err.writer,
        .{},
    ));
}

test "committed metadata records the selection and aliases durably" {
    if (host_is_windows) return error.SkipZigTest;
    var store = try TestStore.init();
    defer store.deinit();
    const ctx = store.ctx();

    const unit = try tStageUnit(&ctx, "example/tool", &.{"bin/tool"}, &.{.{ .source = "tool", .published = "t2" }});
    defer unit.destroy();
    const a = unit.alloc();
    const selection = try a.alloc([]const u8, 1);
    selection[0] = try a.dupe(u8, "tool");
    unit.config.selected_commands = selection;
    try tCommit(&ctx, &.{unit});

    var inv = try tScan(&ctx);
    defer inv.deinit(t_alloc);
    const rec = tFindRecord(inv, "example/tool").?;
    try std.testing.expectEqualStrings("t2", rec.commands[0].name);
    try std.testing.expectEqualStrings("tool", rec.config.?.selected_commands.?[0]);
    try std.testing.expectEqualStrings("tool", rec.config.?.aliases[0].from);
    try std.testing.expectEqualStrings("t2", rec.config.?.aliases[0].to);
}

test "commit survives allocation failure without leaving live state behind" {
    if (host_is_windows) return error.SkipZigTest;
    var store = try TestStore.init();
    defer store.deinit();
    const ctx = store.ctx();

    const unit = try tStageUnit(&ctx, "example/tool", &.{"bin/tool"}, &.{});
    defer unit.destroy();

    // A failing allocator during planning must abort before any mutation.
    var failing = std.testing.FailingAllocator.init(t_alloc, .{ .fail_index = 0 });
    var oom_ctx = ctx;
    oom_ctx.allocator = failing.allocator();
    const result = planAndCommit(&oom_ctx, &.{unit});
    try std.testing.expectError(error.OutOfMemory, result);

    var inv = try tScan(&ctx);
    defer inv.deinit(t_alloc);
    try std.testing.expectEqual(@as(usize, 0), inv.records.len);
    try std.testing.expect(!store.binEntryExists("tool"));
}

test "wasmStem strips the .wasm extension from the basename" {
    try std.testing.expectEqualStrings("hello", wasmStem("hello.wasm"));
    try std.testing.expectEqualStrings("hello", wasmStem("sub/dir/hello.wasm"));
    try std.testing.expectEqualStrings("a.b", wasmStem("a.b.wasm"));
}

test "validateInstallOptions requires one spec when bin filters are present" {
    const allocator = std.testing.allocator;
    var err_output = std.Io.Writer.Allocating.init(allocator);
    defer err_output.deinit();

    try validateInstallOptions(1, &.{"tool"}, &err_output.writer);
    try std.testing.expectError(
        error.BinFilterRequiresSingleSpec,
        validateInstallOptions(2, &.{"tool"}, &err_output.writer),
    );
    const message = try err_output.toOwnedSlice();
    defer allocator.free(message);
    try std.testing.expect(std.mem.indexOf(u8, message, "exactly one spec") != null);
    try std.testing.expect(std.mem.indexOf(u8, message, "separate 'ghr install") != null);
}

test "validateInstallOptions rejects a missing spec before setup" {
    const allocator = std.testing.allocator;
    var err_output = std.Io.Writer.Allocating.init(allocator);
    defer err_output.deinit();

    try std.testing.expectError(
        error.MissingInstallSpec,
        validateInstallOptions(0, &.{}, &err_output.writer),
    );
    const message = try err_output.toOwnedSlice();
    defer allocator.free(message);
    try std.testing.expect(std.mem.indexOf(u8, message, "requires <owner/repo") != null);
}

test "filterExecutables selects each requested command once and metadata records only selections" {
    const allocator = std.testing.allocator;
    var exes: std.ArrayListUnmanaged([]const u8) = .empty;
    defer deinitPathList(allocator, &exes);
    try exes.append(allocator, try allocator.dupe(u8, "nested/alpha"));
    try exes.append(allocator, try allocator.dupe(u8, "nested/beta"));
    try exes.append(allocator, try allocator.dupe(u8, "nested/gamma"));

    var err_output = std.Io.Writer.Allocating.init(allocator);
    defer err_output.deinit();
    try filterExecutables(allocator, &exes, &.{ "beta", "beta" }, false, &err_output.writer);
    try std.testing.expectEqual(@as(usize, 1), exes.items.len);
    try std.testing.expectEqualStrings("nested/beta", exes.items[0]);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeMetadata(allocator, std.testing.io, tmp.dir, "v1", "tool.tar.gz", exes.items, &.{}, "checksum", null);
    const body = try tmp.dir.readFileAlloc(std.testing.io, "ghr.json", allocator, Io.Limit.limited(8192));
    defer allocator.free(body);
    const parsed = try std.json.parseFromSlice(Metadata, allocator, body, .{});
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 1), parsed.value.bins.len);
    try std.testing.expectEqualStrings("nested/beta", parsed.value.bins[0]);
}

test "Windows executable discovery and filtering accept uppercase exe suffixes" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    for ([_][]const u8{ "AzureAuth.EXE", "Other.exe", "README.txt" }) |name| {
        var file = try tmp.dir.createFile(std.testing.io, name, .{});
        try file.writeStreamingAll(std.testing.io, "content");
        file.close(std.testing.io);
    }

    var scan_dir = try tmp.dir.openDir(std.testing.io, ".", .{ .iterate = true });
    defer scan_dir.close(std.testing.io);
    var exes = try findExecutablesForPlatform(allocator, std.testing.io, scan_dir, true);
    defer deinitPathList(allocator, &exes);
    try std.testing.expectEqual(@as(usize, 2), exes.items.len);

    var err_output = std.Io.Writer.Allocating.init(allocator);
    defer err_output.deinit();
    try filterExecutables(allocator, &exes, &.{"azureauth"}, true, &err_output.writer);
    try std.testing.expectEqual(@as(usize, 1), exes.items.len);
    try std.testing.expectEqualStrings("AzureAuth.EXE", exes.items[0]);
}

test "Windows shim and cleanup names strip exe suffix case-insensitively" {
    try std.testing.expectEqualStrings("AzureAuth", windowsExeStem("AzureAuth.EXE"));
    try std.testing.expectEqualStrings("AzureAuth", windowsExeStem("AzureAuth.ExE"));
    try std.testing.expectEqualStrings("AzureAuth", windowsExeStem("AzureAuth"));

    var name_buf: [Dir.max_path_bytes]u8 = undefined;
    try std.testing.expectEqualStrings("AzureAuth.EXE", try windowsShimExeName(&name_buf, "AzureAuth.EXE"));
    try std.testing.expectEqualStrings("AzureAuth.exe", try windowsShimExeName(&name_buf, "AzureAuth"));
}

test "filterExecutables preserves native command-name case sensitivity" {
    const allocator = std.testing.allocator;
    var exes: std.ArrayListUnmanaged([]const u8) = .empty;
    defer deinitPathList(allocator, &exes);
    try exes.append(allocator, try allocator.dupe(u8, "bin/AzureAuth"));

    var err_output = std.Io.Writer.Allocating.init(allocator);
    defer err_output.deinit();
    try std.testing.expectError(
        error.UnmatchedBinFilter,
        filterExecutables(allocator, &exes, &.{"azureauth"}, false, &err_output.writer),
    );
}

test "filterExecutables reports every unmatched filter and available command name" {
    const allocator = std.testing.allocator;
    var exes: std.ArrayListUnmanaged([]const u8) = .empty;
    defer deinitPathList(allocator, &exes);
    try exes.append(allocator, try allocator.dupe(u8, "bin/alpha"));
    try exes.append(allocator, try allocator.dupe(u8, "other/beta"));

    var err_output = std.Io.Writer.Allocating.init(allocator);
    defer err_output.deinit();
    try std.testing.expectError(
        error.UnmatchedBinFilter,
        filterExecutables(allocator, &exes, &.{ "missing", "also-missing", "missing" }, false, &err_output.writer),
    );
    try std.testing.expectEqual(@as(usize, 2), exes.items.len);
    const message = try err_output.toOwnedSlice();
    defer allocator.free(message);
    try std.testing.expectEqualStrings(
        "error: requested --bin filter 'missing', 'also-missing' did not match an available binary\n" ++
            "available binaries:\n" ++
            "  alpha\n" ++
            "  beta\n" ++
            "  hint: pass the installed command name shown above, not an archive path\n",
        message,
    );
}

test "existing tool path action retains aliases but rejects collisions" {
    try std.testing.expectEqual(
        ExistingToolPathAction.none,
        chooseExistingToolPathAction(false, true, true),
    );
    try std.testing.expectEqual(
        ExistingToolPathAction.rename,
        chooseExistingToolPathAction(true, false, false),
    );
    try std.testing.expectEqual(
        ExistingToolPathAction.retain_alias,
        chooseExistingToolPathAction(true, true, true),
    );
    try std.testing.expectEqual(
        ExistingToolPathAction.collision,
        chooseExistingToolPathAction(true, true, false),
    );
}

test "existing tool path action detects distinct case-sensitive collisions" {
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(tio, "tools/AzureAD/repo");
    try tmp.dir.createDirPath(tio, "tools/azuread/repo");

    var root_buf: [Dir.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(tio, &root_buf);
    const root = root_buf[0..root_len];
    var existing_buf: [Dir.max_path_bytes]u8 = undefined;
    const existing = try std.fmt.bufPrint(&existing_buf, "{s}{c}tools{c}AzureAD{c}repo", .{
        root,
        std.fs.path.sep,
        std.fs.path.sep,
        std.fs.path.sep,
    });
    var canonical_buf: [Dir.max_path_bytes]u8 = undefined;
    const canonical = try std.fmt.bufPrint(&canonical_buf, "{s}{c}tools{c}azuread{c}repo", .{
        root,
        std.fs.path.sep,
        std.fs.path.sep,
        std.fs.path.sep,
    });

    if (directoriesHaveSameIdentity(tio, existing, canonical)) return error.SkipZigTest;
    try std.testing.expectEqual(
        ExistingToolPathAction.collision,
        existingToolPathAction(tio, existing, canonical),
    );
}

test "existing tool path action retains case-insensitive aliases when available" {
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(tio, "tools/AzureAD/repo");

    var root_buf: [Dir.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(tio, &root_buf);
    const root = root_buf[0..root_len];
    var existing_buf: [Dir.max_path_bytes]u8 = undefined;
    const existing = try std.fmt.bufPrint(&existing_buf, "{s}{c}tools{c}AzureAD{c}repo", .{
        root,
        std.fs.path.sep,
        std.fs.path.sep,
        std.fs.path.sep,
    });
    var canonical_buf: [Dir.max_path_bytes]u8 = undefined;
    const canonical = try std.fmt.bufPrint(&canonical_buf, "{s}{c}tools{c}azuread{c}repo", .{
        root,
        std.fs.path.sep,
        std.fs.path.sep,
        std.fs.path.sep,
    });

    var alias = Dir.openDirAbsolute(tio, canonical, .{}) catch return error.SkipZigTest;
    alias.close(tio);
    try std.testing.expectEqual(
        ExistingToolPathAction.retain_alias,
        existingToolPathAction(tio, existing, canonical),
    );
}

test "directory identity requires identical final handle paths" {
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(tio, "tools/repo");
    try tmp.dir.createDirPath(tio, "tools/other");

    var root_buf: [Dir.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(tio, &root_buf);
    const root = root_buf[0..root_len];
    var repo_buf: [Dir.max_path_bytes]u8 = undefined;
    const repo = try std.fmt.bufPrint(&repo_buf, "{s}{c}tools{c}repo", .{
        root,
        std.fs.path.sep,
        std.fs.path.sep,
    });
    var other_buf: [Dir.max_path_bytes]u8 = undefined;
    const other = try std.fmt.bufPrint(&other_buf, "{s}{c}tools{c}other", .{
        root,
        std.fs.path.sep,
        std.fs.path.sep,
    });

    try std.testing.expect(directoriesHaveSameIdentity(tio, repo, repo));
    try std.testing.expect(!directoriesHaveSameIdentity(tio, repo, other));
}

test "tool path boundaries use platform separators" {
    try std.testing.expect(pathIsWithinTool(
        "/tools/owner/repo/bin/tool",
        "/tools/owner/repo",
        false,
    ));
    try std.testing.expect(!pathIsWithinTool(
        "/tools/owner/repo\\other/bin/tool",
        "/tools/owner/repo",
        false,
    ));
    try std.testing.expect(pathIsWithinTool(
        "C:\\tools\\owner\\repo\\bin\\tool.exe",
        "C:\\tools\\owner\\repo",
        true,
    ));
    try std.testing.expect(!pathIsWithinTool(
        "C:\\tools\\owner\\repo-cli\\bin\\tool.exe",
        "C:\\tools\\owner\\repo",
        true,
    ));
}

test "zon target boundaries reject POSIX backslashes" {
    try std.testing.expect(!zonTargetValuePointsToToolDir(
        "/tools/owner/repo\\other/bin/tool\"",
        "/tools/owner/repo",
        false,
    ));
    try std.testing.expect(zonTargetValuePointsToToolDir(
        "C:\\\\tools\\\\owner\\\\repo\\\\bin\\\\tool.exe\"",
        "C:\\\\tools\\\\owner\\\\repo",
        true,
    ));
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
        // `<name>-<os>-<arch>` ordering, stem happens to equal repo.
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
        // `<name>-<os>-<arch>` ordering where stem differs from repo
        // (e.g. justrach/merjs ships a binary literally named `mer`).
        const n = try deriveBareBinaryName(a, "mer-macos-aarch64", "merjs", false);
        defer a.free(n);
        try std.testing.expectEqualStrings("mer", n);
    }
    {
        const n = try deriveBareBinaryName(a, "mer-windows-x86_64.exe", "merjs", true);
        defer a.free(n);
        try std.testing.expectEqualStrings("mer.exe", n);
    }
    {
        // Underscore separator.
        const n = try deriveBareBinaryName(a, "foo_aarch64-unknown-linux-gnu", "repo", false);
        defer a.free(n);
        try std.testing.expectEqualStrings("foo", n);
    }
    {
        // Neither pattern matches -> fall back to repo.
        const n = try deriveBareBinaryName(a, "foo-bar-baz", "repo", false);
        defer a.free(n);
        try std.testing.expectEqualStrings("repo", n);
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

test "findExecutables stops at shallowest executable level" {
    if (comptime !File.Permissions.has_executable_bit) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    try tmp.dir.createDirPath(std.testing.io, "qemu-linux-arm64/share");

    const command = try tmp.dir.createFile(
        std.testing.io,
        "qemu-linux-arm64/qemu-img",
        .{ .permissions = .executable_file },
    );
    command.close(std.testing.io);

    // QEMU firmware can be a valid foreign-architecture ELF image without an
    // executable bit, which makes the ZIP mode-recovery heuristic match it.
    var elf_firmware = try tmp.dir.createFile(
        std.testing.io,
        "qemu-linux-arm64/share/openbios-ppc",
        .{},
    );
    try elf_firmware.writeStreamingAll(std.testing.io, "\x7fELFfirmware");
    elf_firmware.close(std.testing.io);

    // A few upstream firmware blobs also incorrectly carry executable mode.
    const mode_firmware = try tmp.dir.createFile(
        std.testing.io,
        "qemu-linux-arm64/share/qboot.rom",
        .{ .permissions = .executable_file },
    );
    mode_firmware.close(std.testing.io);

    const allocator = std.testing.allocator;
    var exes = try findExecutables(allocator, std.testing.io, tmp.dir);
    defer deinitPathList(allocator, &exes);

    try std.testing.expectEqual(@as(usize, 1), exes.items.len);
    try std.testing.expectEqualStrings("qemu-linux-arm64/qemu-img", exes.items[0]);

    // Deeper executable-looking data was never considered or chmod'd.
    const stat = try tmp.dir.statFile(std.testing.io, "qemu-linux-arm64/share/openbios-ppc", .{});
    try std.testing.expectEqual(
        @as(u32, 0),
        @as(u32, @intFromEnum(stat.permissions)) & 0o111,
    );
}

test "findExecutables keeps all candidates at the shallowest level" {
    if (comptime !File.Permissions.has_executable_bit) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    try tmp.dir.createDirPath(std.testing.io, "minisign-linux/aarch64");
    try tmp.dir.createDirPath(std.testing.io, "minisign-linux/x86_64");
    const arm = try tmp.dir.createFile(
        std.testing.io,
        "minisign-linux/aarch64/minisign",
        .{ .permissions = .executable_file },
    );
    arm.close(std.testing.io);
    const x86 = try tmp.dir.createFile(
        std.testing.io,
        "minisign-linux/x86_64/minisign",
        .{ .permissions = .executable_file },
    );
    x86.close(std.testing.io);

    const allocator = std.testing.allocator;
    var exes = try findExecutables(allocator, std.testing.io, tmp.dir);
    defer deinitPathList(allocator, &exes);

    try std.testing.expectEqual(@as(usize, 2), exes.items.len);
    dedupeExecutablesByArch(allocator, &exes, &.{ "aarch64", "arm64" });
    try std.testing.expectEqual(@as(usize, 1), exes.items.len);
    try std.testing.expectEqualStrings("minisign-linux/aarch64/minisign", exes.items[0]);
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

test "bin ghr ownership uses escaped field values and Windows path semantics" {
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try writeNativeGhr(
        tio,
        tmp.dir,
        "tool.ghr",
        "C:\\Tools\\Owner\\Repo\\bin\\AzureAuth.EXE",
    );
    try std.testing.expect(binGhrPointsToToolDirForPlatform(
        tio,
        tmp.dir,
        "tool.ghr",
        "C:\\Tools\\Owner\\Repo",
        true,
    ));
    try std.testing.expect(binGhrPointsToToolDirForPlatform(
        tio,
        tmp.dir,
        "tool.ghr",
        "c:\\tools\\owner\\repo",
        true,
    ));
    try std.testing.expect(!binGhrPointsToToolDirForPlatform(
        tio,
        tmp.dir,
        "tool.ghr",
        "C:\\Tools\\Owner\\Rep",
        true,
    ));

    try writeNativeGhr(
        tio,
        tmp.dir,
        "tool.ghr",
        "C:\\Tools\\Owner\\Repo-Cli\\bin\\tool.exe",
    );
    try std.testing.expect(!binGhrPointsToToolDirForPlatform(
        tio,
        tmp.dir,
        "tool.ghr",
        "c:\\tools\\owner\\repo",
        true,
    ));
}

test "Windows cleanup preserves prefix-collision ghr shims" {
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try writeNativeGhr(
        tio,
        tmp.dir,
        "tool.ghr",
        "C:\\tools\\owner\\repo-cli\\bin\\tool.exe",
    );
    var shim = try tmp.dir.createFile(tio, "tool.EXE", .{});
    shim.close(tio);

    cleanupWindowsBinEntry(
        tio,
        tmp.dir,
        "tool.EXE",
        "C:\\tools\\owner\\repo",
    );

    try std.testing.expect((try tmp.dir.statFile(tio, "tool.ghr", .{})).kind == .file);
    try std.testing.expect((try tmp.dir.statFile(tio, "tool.EXE", .{})).kind == .file);
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

    try ensureDirAbsoluteRecursive(tio, leaf);

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

    try ensureDirAbsoluteRecursive(tio, leaf);

    try std.testing.expect((try tmp.dir.statFile(tio, "a/b", .{})).kind == .directory);
}

test "ensureDirAbsoluteRecursive preserves permission errors from missing ancestors" {
    const TestCreateDir = struct {
        var calls: usize = 0;

        fn run(_: Io, _: []const u8, _: File.Permissions) Dir.CreateDirError!void {
            calls += 1;
            if (calls == 1) return error.FileNotFound;
            return error.AccessDenied;
        }
    };
    TestCreateDir.calls = 0;

    const path = if (builtin.os.tag == .windows)
        "C:\\tools\\owner"
    else
        "/tools/owner";
    try std.testing.expectError(
        error.AccessDenied,
        ensureDirAbsoluteRecursiveWith(std.testing.io, path, TestCreateDir.run),
    );
    try std.testing.expectEqual(@as(usize, 2), TestCreateDir.calls);
}

test "staging permission errors include a writable-directory hint" {
    const allocator = std.testing.allocator;
    var collected = std.Io.Writer.Allocating.init(allocator);
    defer collected.deinit();

    try reportStagingDirCreateError(&collected.writer, "/opt/ghr/tools/owner/.repo.staging", error.AccessDenied);
    const message = try collected.toOwnedSlice();
    defer allocator.free(message);

    try std.testing.expectEqualStrings(
        "error: failed to create staging dir '/opt/ghr/tools/owner/.repo.staging': AccessDenied\n" ++
            "  try sudo, or point GHR_TOOL_DIR somewhere writable\n",
        message,
    );
}

test "ensureDirAbsoluteRecursive restores a missing download cache hierarchy" {
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &path_buf);
    const base = path_buf[0..base_len];
    var cache_buf: [Dir.max_path_bytes]u8 = undefined;
    const cache_path = try std.fmt.bufPrint(&cache_buf, "{s}{c}cache{c}ghr", .{
        base,
        std.fs.path.sep,
        std.fs.path.sep,
    });

    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(tio, "cache", .{}));
    try ensureDirAbsoluteRecursive(tio, cache_path);
    try std.testing.expect((try tmp.dir.statFile(tio, "cache/ghr", .{})).kind == .directory);
}

test "prepareStagingDir uses the destination parent instead of cache" {
    const tio = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &path_buf);
    const base = path_buf[0..base_len];

    var cache_buf: [Dir.max_path_bytes]u8 = undefined;
    const cache_path = try std.fmt.bufPrint(&cache_buf, "{s}{c}cache{c}ghr", .{
        base, std.fs.path.sep, std.fs.path.sep,
    });
    var owner_buf: [Dir.max_path_bytes]u8 = undefined;
    const owner_path = try std.fmt.bufPrint(&owner_buf, "{s}{c}tools{c}owner", .{
        base, std.fs.path.sep, std.fs.path.sep,
    });
    const staging_path = try stagingSiblingPath(allocator, owner_path, "repo");
    defer allocator.free(staging_path);

    try prepareStagingDir(tio, owner_path, staging_path);

    try std.testing.expect((try tmp.dir.statFile(tio, "tools/owner/.repo.staging", .{})).kind == .directory);
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(tio, "cache", .{}));
    try std.testing.expect(std.mem.startsWith(u8, staging_path, owner_path));
    try std.testing.expect(!std.mem.startsWith(u8, staging_path, cache_path));
}

test "replaceStagedDir installs a fresh staging tree" {
    const tio = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(tio, "owner/.repo.staging");
    try tmp.dir.writeFile(tio, .{ .sub_path = "owner/.repo.staging/marker", .data = "new" });

    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &path_buf);
    const base = path_buf[0..base_len];
    const owner_path = try std.fmt.allocPrint(allocator, "{s}{c}owner", .{ base, std.fs.path.sep });
    defer allocator.free(owner_path);
    const final_path = try std.fmt.allocPrint(allocator, "{s}{c}repo", .{ owner_path, std.fs.path.sep });
    defer allocator.free(final_path);
    const staging_path = try stagingSiblingPath(allocator, owner_path, "repo");
    defer allocator.free(staging_path);
    const backup_path = try backupSiblingPath(allocator, owner_path, "repo");
    defer allocator.free(backup_path);

    _ = try replaceStagedDir(tio, staging_path, final_path, backup_path);

    const marker = try tmp.dir.readFileAlloc(tio, "owner/repo/marker", allocator, Io.Limit.limited(16));
    defer allocator.free(marker);
    try std.testing.expectEqualStrings("new", marker);
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(tio, "owner/.repo.staging", .{}));
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(tio, "owner/.repo.old", .{}));
}

test "replaceStagedDir removes backup after replacing an existing install" {
    const tio = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(tio, "owner/repo");
    try tmp.dir.writeFile(tio, .{ .sub_path = "owner/repo/marker", .data = "old" });
    try tmp.dir.createDirPath(tio, "owner/.repo.staging");
    try tmp.dir.writeFile(tio, .{ .sub_path = "owner/.repo.staging/marker", .data = "new" });

    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &path_buf);
    const base = path_buf[0..base_len];
    const owner_path = try std.fmt.allocPrint(allocator, "{s}{c}owner", .{ base, std.fs.path.sep });
    defer allocator.free(owner_path);
    const final_path = try std.fmt.allocPrint(allocator, "{s}{c}repo", .{ owner_path, std.fs.path.sep });
    defer allocator.free(final_path);
    const staging_path = try stagingSiblingPath(allocator, owner_path, "repo");
    defer allocator.free(staging_path);
    const backup_path = try backupSiblingPath(allocator, owner_path, "repo");
    defer allocator.free(backup_path);

    _ = try replaceStagedDir(tio, staging_path, final_path, backup_path);

    const marker = try tmp.dir.readFileAlloc(tio, "owner/repo/marker", allocator, Io.Limit.limited(16));
    defer allocator.free(marker);
    try std.testing.expectEqualStrings("new", marker);
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(tio, "owner/.repo.old", .{}));
}

test "recoverStaleBackup restores a missing live install" {
    const tio = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(tio, "owner/.repo.old");
    try tmp.dir.writeFile(tio, .{ .sub_path = "owner/.repo.old/marker", .data = "old" });

    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &path_buf);
    const base = path_buf[0..base_len];
    const owner_path = try std.fmt.allocPrint(allocator, "{s}{c}owner", .{ base, std.fs.path.sep });
    defer allocator.free(owner_path);
    const final_path = try std.fmt.allocPrint(allocator, "{s}{c}repo", .{ owner_path, std.fs.path.sep });
    defer allocator.free(final_path);
    const backup_path = try backupSiblingPath(allocator, owner_path, "repo");
    defer allocator.free(backup_path);

    try recoverStaleBackup(tio, final_path, backup_path);

    const marker = try tmp.dir.readFileAlloc(tio, "owner/repo/marker", allocator, Io.Limit.limited(16));
    defer allocator.free(marker);
    try std.testing.expectEqualStrings("old", marker);
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(tio, "owner/.repo.old", .{}));
}

test "recoverInstallBackups restores a legacy wasm module tombstone" {
    const tio = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(tio, "owner/repo/stem.old");
    try tmp.dir.writeFile(tio, .{ .sub_path = "owner/repo/stem.old/marker", .data = "legacy" });

    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &path_buf);
    const base = path_buf[0..base_len];
    const repo_path = try std.fmt.allocPrint(allocator, "{s}{c}owner{c}repo", .{
        base,
        std.fs.path.sep,
        std.fs.path.sep,
    });
    defer allocator.free(repo_path);
    const module_path = try std.fmt.allocPrint(allocator, "{s}{c}stem", .{ repo_path, std.fs.path.sep });
    defer allocator.free(module_path);
    const backup_path = try backupSiblingPath(allocator, repo_path, "stem");
    defer allocator.free(backup_path);
    const legacy_backup_path = try legacyBackupPath(allocator, module_path);
    defer allocator.free(legacy_backup_path);

    try recoverInstallBackups(tio, module_path, backup_path, legacy_backup_path);

    const marker = try tmp.dir.readFileAlloc(tio, "owner/repo/stem/marker", allocator, Io.Limit.limited(16));
    defer allocator.free(marker);
    try std.testing.expectEqualStrings("legacy", marker);
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(tio, "owner/repo/stem.old", .{}));
}

test "recoverInstallBackups removes a stale legacy archive tombstone" {
    const tio = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(tio, "owner/repo");
    try tmp.dir.writeFile(tio, .{ .sub_path = "owner/repo/marker", .data = "live" });
    try tmp.dir.createDirPath(tio, "owner/repo.old");
    try tmp.dir.writeFile(tio, .{ .sub_path = "owner/repo.old/marker", .data = "legacy" });

    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &path_buf);
    const base = path_buf[0..base_len];
    const owner_path = try std.fmt.allocPrint(allocator, "{s}{c}owner", .{ base, std.fs.path.sep });
    defer allocator.free(owner_path);
    const tool_path = try std.fmt.allocPrint(allocator, "{s}{c}repo", .{ owner_path, std.fs.path.sep });
    defer allocator.free(tool_path);
    const backup_path = try backupSiblingPath(allocator, owner_path, "repo");
    defer allocator.free(backup_path);
    const legacy_backup_path = try legacyBackupPath(allocator, tool_path);
    defer allocator.free(legacy_backup_path);

    try recoverInstallBackups(tio, tool_path, backup_path, legacy_backup_path);

    const marker = try tmp.dir.readFileAlloc(tio, "owner/repo/marker", allocator, Io.Limit.limited(16));
    defer allocator.free(marker);
    try std.testing.expectEqualStrings("live", marker);
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(tio, "owner/repo.old", .{}));
}

test "replaceStagedDir restores the live install when committing staging fails" {
    const tio = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(tio, "owner/repo");
    try tmp.dir.writeFile(tio, .{ .sub_path = "owner/repo/marker", .data = "old" });
    try tmp.dir.createDirPath(tio, "owner/.repo.staging");
    try tmp.dir.writeFile(tio, .{ .sub_path = "owner/.repo.staging/marker", .data = "new" });

    const TestRename = struct {
        var calls: usize = 0;

        fn run(io: Io, old_path: []const u8, new_path: []const u8) anyerror!void {
            calls += 1;
            if (calls == 2) return error.TestRenameFailure;
            try Dir.renameAbsolute(old_path, new_path, io);
        }
    };
    TestRename.calls = 0;

    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &path_buf);
    const base = path_buf[0..base_len];
    const owner_path = try std.fmt.allocPrint(allocator, "{s}{c}owner", .{ base, std.fs.path.sep });
    defer allocator.free(owner_path);
    const final_path = try std.fmt.allocPrint(allocator, "{s}{c}repo", .{ owner_path, std.fs.path.sep });
    defer allocator.free(final_path);
    const staging_path = try stagingSiblingPath(allocator, owner_path, "repo");
    defer allocator.free(staging_path);
    const backup_path = try backupSiblingPath(allocator, owner_path, "repo");
    defer allocator.free(backup_path);

    try std.testing.expectError(
        error.TestRenameFailure,
        replaceStagedDirWithRename(tio, staging_path, final_path, backup_path, TestRename.run),
    );

    const marker = try tmp.dir.readFileAlloc(tio, "owner/repo/marker", allocator, Io.Limit.limited(16));
    defer allocator.free(marker);
    try std.testing.expectEqualStrings("old", marker);
    try std.testing.expect((try tmp.dir.statFile(tio, "owner/.repo.staging", .{})).kind == .directory);
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(tio, "owner/.repo.old", .{}));
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

test "writeMetadata round-trips the github-attestation outcome" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const bins = [_][]const u8{"tool"};
    const apps = [_][]const u8{};
    // The label must survive a write/read cycle unchanged, since `ghr list`
    // and upgrade decisions read it back verbatim.
    const label = release_mod.outcomeLabel(.github_attestation_verified).?;
    try writeMetadata(allocator, std.testing.io, tmp.dir, "v1.2.3", "tool-linux.tar.xz", &bins, &apps, label, "");

    const body = try tmp.dir.readFileAlloc(std.testing.io, "ghr.json", allocator, Io.Limit.limited(8192));
    defer allocator.free(body);

    const parsed = try std.json.parseFromSlice(Metadata, allocator, body, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    try std.testing.expectEqualStrings("github-attestation", parsed.value.verified);
}

test "an attestation outranks every other verifier in recorded metadata" {
    // Both pipelines share one ranking, so an install that also verified a
    // checksum or a sidecar still records the strongest result.
    try std.testing.expectEqualStrings(
        "github-attestation",
        release_mod.outcomeLabel(release_mod.strongestOutcome(&.{
            .sha256_verified,
            .github_attestation_verified,
        })).?,
    );
    try std.testing.expectEqualStrings(
        "github-attestation",
        release_mod.outcomeLabel(release_mod.strongestOutcome(&.{
            .github_attestation_verified,
            .sigstore_verified,
            .authenticode_verified,
        })).?,
    );
}
