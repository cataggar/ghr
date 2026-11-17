//! WSL-side `ghr link` / `ghr unlink`.
//!
//! These commands let an install ID on the Windows side run from inside WSL by
//! creating Linux symlinks in ghr's bin directory that point at the original
//! Windows-side executable. Exact unit paths and command ownership come from
//! the shared install inventory, including v2 encoded paths and aliases.
//!
//! The link target is the real executable, NOT the shim — the shim lives
//! in the Windows bin dir, not under `tools/`, and going through it adds
//! a useless process hop. A raw `C:\…` symlink target would not work;
//! WSL interop requires a `/mnt/<drive>/…` path.

const std = @import("std");
const builtin = @import("builtin");
const Dirs = @import("dirs.zig").Dirs;
const install = @import("install.zig");
const install_request = @import("install_request.zig");
const install_state = @import("install_state.zig");
const install_state_write = @import("install_state_write.zig");

const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;
const Writer = Io.Writer;
const EnvironMap = std.process.Environ.Map;

// ---------------------------------------------------------------------------
// Bin path normalization.
//
// Windows-side `ghr.json` stores `bins[]` entries with the host path
// separator at install time, so a nested bin extracted on Windows lands
// in the JSON as `bin\\foo.exe`. When `ghr link` reads that JSON from
// WSL it has to flip the separator to `/` before computing basenames or
// joining onto the `/mnt/c/...` source path — `std.fs.path.basename`
// running on Linux treats `\` as a literal name character.
// ---------------------------------------------------------------------------

/// In-place normalize a `bins[]` entry: ASCII-replace `\` with `/`.
/// The slice is mutated rather than re-allocated; callers that need
/// to preserve the original should copy first.
pub fn normalizeBinPathInPlace(s: []u8) void {
    for (s) |*c| if (c.* == '\\') {
        c.* = '/';
    };
}

/// Lowercase rejection check for a relative bin path read from
/// Windows-side `ghr.json`: must be relative (no leading `/` or drive
/// letter) and contain no `..` segments.
pub fn isSafeRelativeBinPath(rel: []const u8) bool {
    if (rel.len == 0) return false;
    if (rel[0] == '/') return false;
    if (rel.len >= 2 and rel[1] == ':') return false; // drive letter
    var it = std.mem.tokenizeScalar(u8, rel, '/');
    while (it.next()) |seg| {
        if (std.mem.eql(u8, seg, "..")) return false;
        if (std.mem.eql(u8, seg, ".")) return false;
    }
    return true;
}

/// Derive the Linux link name for a bin entry: basename with a
/// trailing `.exe` stripped (ASCII case-insensitive). Pass the
/// already-normalized (`/`-separated) relative path.
pub fn linkNameForBin(rel_normalized: []const u8) []const u8 {
    const base = std.fs.path.basenamePosix(rel_normalized);
    if (base.len > 4) {
        const tail = base[base.len - 4 ..];
        if (std.ascii.eqlIgnoreCase(tail, ".exe")) return base[0 .. base.len - 4];
    }
    return base;
}

// ---------------------------------------------------------------------------
// Link manifest.
//
// `Manifest` is the common read shape for legacy owner/repo manifests, v2
// ID-keyed manifests, and the separate bare-PATH kind. ID writers require
// schema/layout/id/unit_path; legacy fields remain optional only so old state
// can be validated and migrated lazily.
// ---------------------------------------------------------------------------

pub const LinkEntry = struct {
    name: []const u8,
    target: []const u8,
    /// How the bin-dir entry was created. `"symlink"` (default) means
    /// `target` is the absolute path the symlink points at. `"script"`
    /// means we wrote a bash wrapper file at this name and `target` is
    /// the literal Windows path the wrapper exec's via cmd.exe.
    ///
    /// Optional in the JSON so existing manifests (owner/repo flow,
    /// pre-existing bare-exec entries) keep parsing as `"symlink"`.
    target_kind: []const u8 = "symlink",
    /// Lowercase 64-character SHA-256 hex digest of the exact wrapper bytes
    /// written for `"script"` entries in v2 ID manifests (`wsl-id`). Null for
    /// `"symlink"` entries and bare-PATH manifests.
    wrapper_sha256: ?[]const u8 = null,
};

pub const Manifest = struct {
    schema: ?i64 = null,
    layout_generation: ?i64 = null,
    kind: []const u8 = "wsl",
    id: ?[]const u8 = null,
    unit_path: ?[]const u8 = null,
    /// Windows-side tool dir at link time, e.g.
    /// `/mnt/c/Users/x/AppData/Roaming/ghr/data/tools/azuread/foo`.
    source: []const u8,
    links: []LinkEntry,
};

const id_manifest_schema: i64 = 2;
const id_manifest_layout: i64 = 2;
const id_manifest_kind = "wsl-id";
const id_manifest_root = "by-id";
const id_manifest_file = "_manifest.json";
const max_manifest_bytes: usize = 16 * 1024 * 1024;

/// Compose the manifest directory path: `<XDG_DATA_HOME-or-equiv>/ghr/links/<owner>`.
/// Owned by caller.
pub fn manifestDir(allocator: std.mem.Allocator, environ: *const EnvironMap, owner_lower: []const u8) ![]u8 {
    const base = try linksRoot(allocator, environ);
    defer allocator.free(base);
    return std.fs.path.join(allocator, &.{ base, owner_lower });
}

/// `<XDG_DATA_HOME-or-equiv>/ghr/links`. Owned by caller.
pub fn linksRoot(allocator: std.mem.Allocator, environ: *const EnvironMap) ![]u8 {
    if (environ.get("XDG_DATA_HOME")) |xdg| {
        return std.fs.path.join(allocator, &.{ xdg, "ghr", "links" });
    }
    const home = environ.get("HOME") orelse return error.HomeNotFound;
    return std.fs.path.join(allocator, &.{ home, ".local", "share", "ghr", "links" });
}

/// Full path of `<owner>/<repo>.json` under the manifest root.
/// Owned by caller.
pub fn manifestPath(
    allocator: std.mem.Allocator,
    environ: *const EnvironMap,
    owner_lower: []const u8,
    repo_lower: []const u8,
) ![]u8 {
    const dir = try manifestDir(allocator, environ, owner_lower);
    defer allocator.free(dir);
    var fname_buf: [256]u8 = undefined;
    const fname = try std.fmt.bufPrint(&fname_buf, "{s}.json", .{repo_lower});
    return std.fs.path.join(allocator, &.{ dir, fname });
}

/// Directory containing the manifest for a canonical install ID. Each ID
/// segment receives the same `u-` prefix used by install-state encoding, and
/// the terminal manifest filename permits prefix IDs such as `a` and `a/b`.
pub fn idManifestDir(
    allocator: std.mem.Allocator,
    environ: *const EnvironMap,
    id: []const u8,
) ![]u8 {
    if (!try install_state.isCanonicalId(allocator, id)) return error.InvalidId;

    const root = try linksRoot(allocator, environ);
    defer allocator.free(root);

    var out = std.Io.Writer.Allocating.init(allocator);
    errdefer out.deinit();
    try out.writer.writeAll(root);
    try out.writer.print("{c}{s}", .{ std.fs.path.sep, id_manifest_root });
    var segments = std.mem.splitScalar(u8, id, '/');
    while (segments.next()) |segment| {
        try out.writer.print("{c}{s}{s}", .{
            std.fs.path.sep,
            install_state.segment_prefix,
            segment,
        });
    }
    return out.toOwnedSlice();
}

pub fn idManifestPath(
    allocator: std.mem.Allocator,
    environ: *const EnvironMap,
    id: []const u8,
) ![]u8 {
    const dir = try idManifestDir(allocator, environ, id);
    defer allocator.free(dir);
    return std.fs.path.join(allocator, &.{ dir, id_manifest_file });
}

/// Read a manifest from disk. Returns `null` when missing (a first
/// `ghr link` for the repo). On parse failure returns `error.InvalidManifest`.
pub fn readManifest(
    allocator: std.mem.Allocator,
    io: Io,
    abs_path: []const u8,
) !?std.json.Parsed(Manifest) {
    const f = Dir.openFileAbsolute(io, abs_path, .{
        .follow_symlinks = false,
        .allow_directory = false,
    }) catch |err| switch (err) {
        error.FileNotFound => return null,
        error.SymLinkLoop, error.IsDir, error.NotDir => return error.InvalidManifest,
        else => return err,
    };
    defer f.close(io);
    const stat = try f.stat(io);
    if (stat.kind != .file) return error.InvalidManifest;
    var read_buf: [4096]u8 = undefined;
    var reader = f.reader(io, &read_buf);
    const body = reader.interface.allocRemaining(allocator, Io.Limit.limited(max_manifest_bytes)) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.StreamTooLong => return error.InvalidManifest,
        error.ReadFailed => return reader.err orelse error.ReadFailed,
    };
    defer allocator.free(body);
    return std.json.parseFromSlice(Manifest, allocator, body, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch return error.InvalidManifest;
}

fn isSafeManifestTarget(target: []const u8) bool {
    if (target.len == 0 or target[0] != '/') return false;
    for (target) |c| if (c < 0x20 or c == 0x7f) return false;
    return true;
}

pub fn isSafeScriptManifestTarget(target: []const u8) bool {
    if (!looksLikeWindowsPath(target)) return false;
    for (target) |c| {
        if (c < 0x20 or c == 0x7f or c == '%' or c == '"') return false;
    }
    return true;
}

pub fn sha256Hex(bytes: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

fn isValidSha256Hex(s: []const u8) bool {
    if (s.len != 64) return false;
    for (s) |c| {
        if (!std.ascii.isDigit(c) and !(c >= 'a' and c <= 'f')) return false;
    }
    return true;
}

fn validLinkEntries(links: []const LinkEntry) bool {
    for (links, 0..) |entry, i| {
        if (!install_state.isSafeV2CommandName(entry.name)) return false;
        if (std.mem.eql(u8, entry.target_kind, "symlink")) {
            if (!isSafeManifestTarget(entry.target)) return false;
            if (entry.wrapper_sha256 != null) return false;
        } else if (std.mem.eql(u8, entry.target_kind, "script")) {
            if (!isSafeScriptManifestTarget(entry.target)) return false;
            const digest = entry.wrapper_sha256 orelse return false;
            if (!isValidSha256Hex(digest)) return false;
        } else {
            return false;
        }
        for (links[0..i]) |prior| {
            if (std.ascii.eqlIgnoreCase(prior.name, entry.name)) return false;
        }
    }
    return true;
}

/// Read and strictly validate one v2 manifest for `expected_id`. The ID in the
/// payload must match the ID encoded by the caller-selected path.
pub fn readIdManifest(
    allocator: std.mem.Allocator,
    io: Io,
    abs_path: []const u8,
    expected_id: []const u8,
) !?std.json.Parsed(Manifest) {
    var parsed = (try readManifest(allocator, io, abs_path)) orelse return null;
    errdefer parsed.deinit();
    const manifest = parsed.value;
    if (manifest.schema == null or manifest.schema.? != id_manifest_schema or
        manifest.layout_generation == null or manifest.layout_generation.? != id_manifest_layout or
        !std.mem.eql(u8, manifest.kind, id_manifest_kind) or
        manifest.id == null or !std.mem.eql(u8, manifest.id.?, expected_id) or
        manifest.unit_path == null or !install_state.isSafePortableRelPath(manifest.unit_path.?) or
        !isSafeManifestTarget(manifest.source) or
        !validLinkEntries(manifest.links))
    {
        return error.InvalidManifest;
    }
    return parsed;
}

fn stringifyIdManifest(
    allocator: std.mem.Allocator,
    id: []const u8,
    unit_path: []const u8,
    source: []const u8,
    links: []const LinkEntry,
) ![]u8 {
    if (!try install_state.isCanonicalId(allocator, id) or
        !install_state.isSafePortableRelPath(unit_path) or
        !isSafeManifestTarget(source) or
        !validLinkEntries(links))
    {
        return error.InvalidManifest;
    }

    var body = std.Io.Writer.Allocating.init(allocator);
    errdefer body.deinit();
    const w = &body.writer;
    try w.print(
        "{{\"schema\":{d},\"layout_generation\":{d},\"kind\":\"{s}\",\"id\":\"",
        .{ id_manifest_schema, id_manifest_layout, id_manifest_kind },
    );
    try writeJsonEscaped(w, id);
    try w.writeAll("\",\"unit_path\":\"");
    try writeJsonEscaped(w, unit_path);
    try w.writeAll("\",\"source\":\"");
    try writeJsonEscaped(w, source);
    try w.writeAll("\",\"links\":[");
    for (links, 0..) |entry, i| {
        if (i > 0) try w.writeByte(',');
        try w.writeAll("{\"name\":\"");
        try writeJsonEscaped(w, entry.name);
        try w.writeAll("\",\"target\":\"");
        try writeJsonEscaped(w, entry.target);
        try w.writeAll("\",\"target_kind\":\"");
        try writeJsonEscaped(w, entry.target_kind);
        if (entry.wrapper_sha256) |digest| {
            try w.writeAll("\",\"wrapper_sha256\":\"");
            try writeJsonEscaped(w, digest);
        }
        try w.writeAll("\"}");
    }
    try w.writeAll("]}\n");
    if (body.written().len > max_manifest_bytes) return error.ManifestTooLarge;
    return body.toOwnedSlice();
}

fn persistIdManifestBody(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    id: []const u8,
    body: []const u8,
) !void {
    if (body.len > max_manifest_bytes) return error.ManifestTooLarge;
    const manifest_dir = try idManifestDir(allocator, environ, id);
    defer allocator.free(manifest_dir);
    try install.ensureDirAbsoluteRecursive(io, manifest_dir);

    const final_path = try idManifestPath(allocator, environ, id);
    defer allocator.free(final_path);
    const tmp_path = try allocator.print("{s}.tmp", .{final_path});
    defer allocator.free(tmp_path);
    Dir.deleteFileAbsolute(io, tmp_path) catch {};

    {
        var file = try Dir.createFileAbsolute(io, tmp_path, .{});
        defer file.close(io);
        try file.writeStreamingAll(io, body);
    }

    Dir.renameAbsolute(tmp_path, final_path, io) catch |err| {
        Dir.deleteFileAbsolute(io, tmp_path) catch {};
        return err;
    };
}

pub fn writeIdManifest(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    id: []const u8,
    unit_path: []const u8,
    source: []const u8,
    links: []const LinkEntry,
) !void {
    const body = try stringifyIdManifest(allocator, id, unit_path, source, links);
    defer allocator.free(body);
    try persistIdManifestBody(allocator, io, environ, id, body);
}

pub fn deleteIdManifest(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    id: []const u8,
) !void {
    const final_path = try idManifestPath(allocator, environ, id);
    defer allocator.free(final_path);
    Dir.deleteFileAbsolute(io, final_path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
}

/// Atomically write a manifest to `<owner>/<repo>.json` under the links
/// root. Creates the owner subdir on demand.
pub fn writeManifest(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    owner_lower: []const u8,
    repo_lower: []const u8,
    manifest: Manifest,
) !void {
    var body_writer = std.Io.Writer.Allocating.init(allocator);
    defer body_writer.deinit();
    const body_w = &body_writer.writer;
    try body_w.print("{{\"kind\":\"", .{});
    try writeJsonEscaped(body_w, manifest.kind);
    try body_w.print("\",\"source\":\"", .{});
    try writeJsonEscaped(body_w, manifest.source);
    try body_w.print("\",\"links\":[", .{});
    for (manifest.links, 0..) |entry, i| {
        if (i > 0) try body_w.print(",", .{});
        try body_w.print("{{\"name\":\"", .{});
        try writeJsonEscaped(body_w, entry.name);
        try body_w.print("\",\"target\":\"", .{});
        try writeJsonEscaped(body_w, entry.target);
        try body_w.print("\"}}", .{});
    }
    try body_w.print("]}}\n", .{});
    if (body_writer.written().len > max_manifest_bytes) return error.ManifestTooLarge;

    const owner_dir = try manifestDir(allocator, environ, owner_lower);
    defer allocator.free(owner_dir);
    install.ensureDirAbsoluteRecursive(io, owner_dir) catch {};

    const final_path = try manifestPath(allocator, environ, owner_lower, repo_lower);
    defer allocator.free(final_path);
    const tmp_path = try allocator.print("{s}.tmp", .{final_path});
    defer allocator.free(tmp_path);

    // Truncate any leftover tombstone.
    Dir.deleteFileAbsolute(io, tmp_path) catch {};

    {
        var f = try Dir.createFileAbsolute(io, tmp_path, .{});
        defer f.close(io);
        try f.writeStreamingAll(io, body_writer.written());
    }

    Dir.renameAbsolute(tmp_path, final_path, io) catch |err| {
        // Best-effort cleanup of the temp on failure.
        Dir.deleteFileAbsolute(io, tmp_path) catch {};
        return err;
    };
}

/// Delete the manifest file (and the owner subdir if it's now empty).
pub fn deleteManifest(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    owner_lower: []const u8,
    repo_lower: []const u8,
) !void {
    const final_path = try manifestPath(allocator, environ, owner_lower, repo_lower);
    defer allocator.free(final_path);
    Dir.deleteFileAbsolute(io, final_path) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };

    // Best-effort: remove the now-empty owner subdir.
    const owner_dir = try manifestDir(allocator, environ, owner_lower);
    defer allocator.free(owner_dir);
    Dir.deleteDirAbsolute(io, owner_dir) catch {};
}

fn writeJsonEscaped(w: *Writer, s: []const u8) !void {
    for (s) |c| {
        switch (c) {
            '\\' => try w.print("\\\\", .{}),
            '"' => try w.print("\\\"", .{}),
            '\n' => try w.print("\\n", .{}),
            '\r' => try w.print("\\r", .{}),
            '\t' => try w.print("\\t", .{}),
            0x08 => try w.print("\\b", .{}),
            0x0c => try w.print("\\f", .{}),
            else => {
                if (c < 0x20) {
                    try w.print("\\u{x:0>4}", .{c});
                } else {
                    try w.print("{c}", .{c});
                }
            },
        }
    }
}

// ---------------------------------------------------------------------------
// WSL guard + Windows-tools-dir discovery.
// ---------------------------------------------------------------------------

pub const WslError = error{NotInWsl};

/// Verify the caller is running in WSL with interop enabled. We gate
/// on a single env var — `WSL_INTEROP` — since interop is exactly
/// what we need (to spawn `cmd.exe` for discovery and to actually
/// execute the linked `.exe` later).
pub fn requireWsl(environ: *const EnvironMap, err_w: *Writer, cmd_name: []const u8) !void {
    if (environ.get("WSL_INTEROP") == null) {
        try err_w.print(
            "error: 'ghr {s}' is only supported inside WSL with interop enabled\n",
            .{cmd_name},
        );
        try err_w.print("       (WSL_INTEROP is not set)\n", .{});
        try err_w.flush();
        return error.NotInWsl;
    }
}

/// Discover the Windows-side `<tools>` dir from inside WSL, as a path
/// the WSL kernel can read (i.e. `/mnt/<drive>/...`). Resolution order:
///
///   1. `GHR_WIN_TOOLS_DIR` env override. Accepts either a WSL path
///      (`/mnt/c/...`) or a Windows path (`C:\...`); the latter is
///      converted with `wslpath -u`.
///   2. Spawn `cmd.exe /c echo %APPDATA%`, trim CRLF, then `wslpath -u`
///      the result and append `/ghr/data/tools`. This is the canonical
///      lookup — it handles non-default usernames, redirected APPDATA,
///      and roaming profiles.
///   3. Fallback `/mnt/c/Users/$USER/AppData/Roaming/ghr/data/tools`.
///      Logs a warning to `err_w` since this only works when the
///      Windows username matches `$USER`.
///
/// Returned path is owned by `allocator`. Caller is responsible for
/// verifying it actually exists; this function does not stat.
const WindowsToolsDiscovery = enum {
    allow_username_fallback,
    strict,
};

fn discoverWindowsToolsDirFromWsl(
    allocator: std.mem.Allocator,
    environ: *const EnvironMap,
    io: Io,
    err_w: *Writer,
    mode: WindowsToolsDiscovery,
) ![]u8 {
    if (environ.get("GHR_WIN_TOOLS_DIR")) |v| {
        if (looksLikeWindowsPath(v)) {
            if (wslpathToUnix(allocator, io, v)) |p| return p else |err| {
                if (mode == .strict) return err;
                try err_w.print(
                    "warning: GHR_WIN_TOOLS_DIR='{s}' looked like a Windows path but wslpath conversion failed; using verbatim\n",
                    .{v},
                );
            }
        }
        return allocator.dupe(u8, v);
    }

    const appdata_unix = queryAppDataViaCmd(allocator, io) catch |err| {
        if (mode == .strict) return err;
        const user = environ.get("USER") orelse environ.get("LOGNAME") orelse {
            try err_w.print("error: cannot resolve Windows tools dir: USER is not set and cmd.exe lookup failed\n", .{});
            try err_w.print("       hint: set GHR_WIN_TOOLS_DIR to the WSL path of the Windows tools dir\n", .{});
            try err_w.flush();
            return error.NoWindowsToolsDir;
        };
        try err_w.print(
            "warning: cmd.exe lookup of %APPDATA% failed; assuming /mnt/c/Users/{s}/AppData/Roaming\n",
            .{user},
        );
        try err_w.print("         set GHR_WIN_TOOLS_DIR to override\n", .{});
        return allocator.print("/mnt/c/Users/{s}/AppData/Roaming/ghr/data/tools", .{user});
    };
    defer allocator.free(appdata_unix);
    return std.fs.path.join(allocator, &.{ appdata_unix, "ghr", "data", "tools" });
}

pub fn windowsToolsDirFromWsl(
    allocator: std.mem.Allocator,
    environ: *const EnvironMap,
    io: Io,
    err_w: *Writer,
) ![]u8 {
    return discoverWindowsToolsDirFromWsl(
        allocator,
        environ,
        io,
        err_w,
        .allow_username_fallback,
    );
}

fn looksLikeWindowsPath(s: []const u8) bool {
    // Drive-letter form (`C:\...` or `c:/...`).
    return s.len >= 3 and std.ascii.isAlphabetic(s[0]) and s[1] == ':' and (s[2] == '\\' or s[2] == '/');
}

fn queryAppDataViaCmd(allocator: std.mem.Allocator, io: Io) ![]u8 {
    const r = try std.process.run(allocator, io, .{
        .argv = &.{ "cmd.exe", "/c", "echo %APPDATA%" },
        .stdout_limit = Io.Limit.limited(4096),
        .stderr_limit = Io.Limit.limited(4096),
    });
    defer allocator.free(r.stderr);
    defer allocator.free(r.stdout);
    if (r.term != .exited or r.term.exited != 0) return error.CmdFailed;
    const trimmed = std.mem.trim(u8, r.stdout, &[_]u8{ ' ', '\t', '\r', '\n' });
    if (trimmed.len == 0) return error.CmdFailed;
    // Defensively reject the literal unexpanded form if cmd.exe couldn't
    // resolve APPDATA for some reason.
    if (std.mem.indexOf(u8, trimmed, "%APPDATA%") != null) return error.CmdFailed;
    return wslpathToUnix(allocator, io, trimmed);
}

/// Resolve `wslpath` against `environ.get("PATH")` when present so callers (and
/// isolated test `EnvironMap`s) do not depend on `Io.Threaded`'s ambient parent
/// process `PATH` for `argv[0]` lookup.
fn resolveWslpathArgv0(
    allocator: std.mem.Allocator,
    io: Io,
    environ: ?*const EnvironMap,
) ![]u8 {
    if (environ) |env| {
        if (env.get("PATH")) |path_env| {
            var it = std.mem.splitScalar(u8, path_env, std.fs.path.delimiter);
            while (it.next()) |dir_entry| {
                if (dir_entry.len == 0 or !std.fs.path.isAbsolute(dir_entry)) continue;
                const candidate = try std.fs.path.join(allocator, &.{ dir_entry, "wslpath" });
                if (Dir.openFileAbsolute(io, candidate, .{ .allow_directory = false })) |f| {
                    f.close(io);
                    return candidate;
                } else |_| {
                    allocator.free(candidate);
                }
            }
            return error.FileNotFound;
        }
    }
    return allocator.dupe(u8, "wslpath");
}

fn wslpathToUnix(allocator: std.mem.Allocator, io: Io, win_path: []const u8) ![]u8 {
    return wslpathToUnixWithEnv(allocator, io, null, win_path);
}

fn wslpathToUnixWithEnv(
    allocator: std.mem.Allocator,
    io: Io,
    environ: ?*const EnvironMap,
    win_path: []const u8,
) ![]u8 {
    const exe = try resolveWslpathArgv0(allocator, io, environ);
    defer allocator.free(exe);
    const r = try std.process.run(allocator, io, .{
        .argv = &.{ exe, "-u", win_path },
        .environ_map = environ,
        .stdout_limit = Io.Limit.limited(4096),
        .stderr_limit = Io.Limit.limited(4096),
    });
    defer allocator.free(r.stderr);
    defer allocator.free(r.stdout);
    if (r.term != .exited or r.term.exited != 0) return error.WslpathFailed;
    const trimmed = std.mem.trim(u8, r.stdout, &[_]u8{ ' ', '\t', '\r', '\n' });
    if (trimmed.len == 0) return error.WslpathFailed;
    return allocator.dupe(u8, trimmed);
}

/// Convert a WSL `/mnt/<drive>/...` path back to the Windows form
/// (`C:\...`) via `wslpath -w`. Used when composing wrapper scripts
/// that hand the path to `cmd.exe /c`.
fn wslpathToWindows(
    allocator: std.mem.Allocator,
    io: Io,
    environ: ?*const EnvironMap,
    wsl_path: []const u8,
) ![]u8 {
    const exe = try resolveWslpathArgv0(allocator, io, environ);
    defer allocator.free(exe);
    const r = try std.process.run(allocator, io, .{
        .argv = &.{ exe, "-w", wsl_path },
        .environ_map = environ,
        .stdout_limit = Io.Limit.limited(4096),
        .stderr_limit = Io.Limit.limited(4096),
    });
    defer allocator.free(r.stderr);
    defer allocator.free(r.stdout);
    if (r.term != .exited or r.term.exited != 0) return error.WslpathFailed;
    const trimmed = std.mem.trim(u8, r.stdout, &[_]u8{ ' ', '\t', '\r', '\n' });
    if (trimmed.len == 0) return error.WslpathFailed;
    return allocator.dupe(u8, trimmed);
}

/// Pure fallback conversion from a canonical `/mnt/<letter>/...` drvfs path to
/// `<LETTER>:\...` when `wslpath` is unavailable.
pub fn drvfsToWindowsPath(allocator: std.mem.Allocator, wsl_path: []const u8) !?[]u8 {
    if (!looksLikeMntDrvfsPath(wsl_path)) return null;
    const prefix = "/mnt/";
    const drive = std.ascii.toUpper(wsl_path[prefix.len]);
    const rest = wsl_path[prefix.len + 2 ..];
    var out = try allocator.alloc(u8, 3 + rest.len);
    out[0] = drive;
    out[1] = ':';
    out[2] = '\\';
    for (rest, 0..) |c, idx| {
        out[3 + idx] = if (c == '/') '\\' else c;
    }
    return out;
}

const default_wsl_cmd_exe = "/mnt/c/Windows/System32/cmd.exe";

fn resolveWslCmdExePath(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
) error{OutOfMemory}![]const u8 {
    const converted = wslpathToUnixWithEnv(
        allocator,
        io,
        environ,
        "C:\\Windows\\System32\\cmd.exe",
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return default_wsl_cmd_exe,
    };
    if (!isSafeManifestTarget(converted)) {
        allocator.free(converted);
        return default_wsl_cmd_exe;
    }
    return converted;
}

fn resolveWindowsScriptTarget(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    wsl_path: []const u8,
) ![]u8 {
    const converted = wslpathToWindows(allocator, io, environ, wsl_path) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.FileNotFound => (try drvfsToWindowsPath(allocator, wsl_path)) orelse return error.WslpathFailed,
        else => return error.WslpathFailed,
    };
    errdefer allocator.free(converted);
    if (!isSafeScriptManifestTarget(converted)) return error.UnsafeScriptTarget;
    return converted;
}

// ---------------------------------------------------------------------------
// Desired-link computation (pure, testable).
// ---------------------------------------------------------------------------

pub const DesiredLinkKind = enum {
    symlink,
    script,

    pub fn manifestKind(self: DesiredLinkKind) []const u8 {
        return switch (self) {
            .symlink => "symlink",
            .script => "script",
        };
    }
};

pub const DesiredLink = struct {
    /// Linux-side link name (basename, with trailing `.exe`/`.cmd` stripped).
    /// Owned by the arena attached to `ComputedLinks`.
    name: []const u8,
    /// Absolute WSL path — `<win_tools_root>/<unit>/<bin>` with `/` separators.
    /// For `.symlink` entries this is also the persisted manifest target.
    /// Owned by the arena.
    target: []const u8,
    /// Link mechanism: direct WSL interop symlink for `.exe`, or bash `cmd.exe`
    /// wrapper script for `.cmd`.
    kind: DesiredLinkKind = .symlink,
    /// Resolved Windows drive path (`C:\...`) for `.script` entries; persisted
    /// as `LinkEntry.target`. Null until prepared by `cmdLink` (or for `.symlink`).
    win_target: ?[]const u8 = null,
    /// Rendered bash wrapper contents for `.script` entries.
    script_bytes: ?[]const u8 = null,
    /// 64-char lowercase SHA-256 hex of `script_bytes` for `.script` entries.
    wrapper_sha256: ?[]const u8 = null,

    pub fn manifestTarget(self: DesiredLink) []const u8 {
        return switch (self.kind) {
            .symlink => self.target,
            .script => self.win_target.?,
        };
    }
};

pub const ComputedLinks = struct {
    arena: std.heap.ArenaAllocator,
    links: []DesiredLink,
    /// `--bin` filters that did not match any bin entry. Caller error-
    /// reports these (and exits non-zero if any are listed).
    unmatched_filters: [][]const u8,
    /// All available link names (after normalization + dedup detection),
    /// used to build user-facing diagnostics. Sorted ASCII-ascending.
    available_names: [][]const u8,

    pub fn deinit(self: *ComputedLinks) void {
        self.arena.deinit();
    }
};

pub const DesiredError = error{
    DuplicateLinkName,
    NoBinsInMetadata,
    NoValidBinsAfterNormalize,
    UnsupportedCommandKind,
    OutOfMemory,
};

/// Pure computation: given the bins from a Windows-side `ghr.json` and
/// optional `--bin` filters, build the desired set of `(link_name,
/// absolute_target)` pairs.
///
/// `tool_dir_abs` is the WSL-readable absolute path of the Windows tool
/// dir (e.g. `/mnt/c/Users/x/AppData/Roaming/ghr/data/tools/azuread/foo`).
/// Bins are appended onto this with a `/` separator.
///
/// Validation:
///   - Each bin entry is normalized (`\` -> `/`) and `isSafeRelativeBinPath`
///     is enforced; unsafe entries are silently dropped. If ALL entries
///     are unsafe (or otherwise reduce to empty link names), returns
///     `error.NoValidBinsAfterNormalize` so the caller treats the
///     metadata as corrupt and refuses to reconcile.
///   - Multiple bin entries that collapse to the same link name produce
///     `error.DuplicateLinkName`; the caller surfaces the offending names.
///   - Filters: each `--bin` filter must match at least one entry
///     (post-normalization). Unmatched filters are returned in the
///     `unmatched_filters` slice for the caller to surface.
pub fn computeDesiredLinks(
    parent_allocator: std.mem.Allocator,
    raw_bins: []const []const u8,
    tool_dir_abs: []const u8,
    bin_filters: []const []const u8,
) DesiredError!ComputedLinks {
    var arena = std.heap.ArenaAllocator.init(parent_allocator);
    errdefer arena.deinit();
    const aa = arena.allocator();

    if (raw_bins.len == 0) return DesiredError.NoBinsInMetadata;

    var all_links = std.ArrayListUnmanaged(DesiredLink).empty;
    var available = std.ArrayListUnmanaged([]const u8).empty;

    for (raw_bins) |raw| {
        const normalized = try aa.dupe(u8, raw);
        normalizeBinPathInPlace(normalized);
        if (!isSafeRelativeBinPath(normalized)) continue;
        const name = try aa.dupe(u8, linkNameForBin(normalized));
        if (name.len == 0) continue;
        // Detect a collision against an already-seen link name.
        for (all_links.items) |existing| {
            if (std.ascii.eqlIgnoreCase(existing.name, name)) {
                return DesiredError.DuplicateLinkName;
            }
        }
        const target = try aa.print("{s}/{s}", .{ tool_dir_abs, normalized });
        try all_links.append(aa, .{ .name = name, .target = target });
        try available.append(aa, name);
    }

    // Refuse to reconcile when the metadata had bins but they all
    // dropped out. This protects against a corrupted `ghr.json` (all
    // absolute / all `..`) silently nuking a working manifest.
    if (all_links.items.len == 0) return DesiredError.NoValidBinsAfterNormalize;

    std.mem.sort([]const u8, available.items, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lt);

    var matched: std.ArrayListUnmanaged(DesiredLink) = .empty;
    var unmatched_filters: std.ArrayListUnmanaged([]const u8) = .empty;

    if (bin_filters.len == 0) {
        try matched.appendSlice(aa, all_links.items);
    } else {
        for (bin_filters) |filter| {
            const f_owned = try aa.dupe(u8, filter);
            var any = false;
            for (all_links.items) |link| {
                if (std.ascii.eqlIgnoreCase(link.name, filter)) {
                    // Avoid duplicates if the user passed the same filter twice.
                    var seen = false;
                    for (matched.items) |m| {
                        if (std.mem.eql(u8, m.name, link.name)) {
                            seen = true;
                            break;
                        }
                    }
                    if (!seen) try matched.append(aa, link);
                    any = true;
                }
            }
            if (!any) try unmatched_filters.append(aa, f_owned);
        }
    }

    return .{
        .arena = arena,
        .links = try matched.toOwnedSlice(aa),
        .unmatched_filters = try unmatched_filters.toOwnedSlice(aa),
        .available_names = try available.toOwnedSlice(aa),
    };
}

/// Compute WSL links from an inventory record's explicit command ownership.
/// Unlike the legacy `bins` form, command names are already final persisted
/// names and must never be re-derived from their target paths.
pub fn computeDesiredCommandLinks(
    parent_allocator: std.mem.Allocator,
    commands: []const install_state.OwnedCommand,
    tool_dir_abs: []const u8,
    bin_filters: []const []const u8,
) DesiredError!ComputedLinks {
    var arena = std.heap.ArenaAllocator.init(parent_allocator);
    errdefer arena.deinit();
    const aa = arena.allocator();

    if (commands.len == 0) return DesiredError.NoBinsInMetadata;

    var all_links: std.ArrayListUnmanaged(DesiredLink) = .empty;
    var available: std.ArrayListUnmanaged([]const u8) = .empty;

    for (commands) |command| {
        if ((command.kind != null and std.mem.eql(u8, command.kind.?, "wasm")) or
            install_state.isWasmTarget(command.relative_target))
        {
            return DesiredError.UnsupportedCommandKind;
        }
        const normalized_target = try aa.dupe(u8, command.relative_target);
        normalizeBinPathInPlace(normalized_target);
        if (!isSafeRelativeBinPath(normalized_target)) continue;
        const name = try aa.dupe(u8, command.name);
        for (all_links.items) |existing| {
            if (std.ascii.eqlIgnoreCase(existing.name, name))
                return DesiredError.DuplicateLinkName;
        }
        const target = try aa.print("{s}/{s}", .{ tool_dir_abs, normalized_target });
        const is_cmd = normalized_target.len > 4 and std.ascii.endsWithIgnoreCase(normalized_target, ".cmd");
        try all_links.append(aa, .{
            .name = name,
            .target = target,
            .kind = if (is_cmd) .script else .symlink,
        });
        try available.append(aa, name);
    }

    if (all_links.items.len == 0) return DesiredError.NoValidBinsAfterNormalize;

    std.mem.sort([]const u8, available.items, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lt);

    var matched: std.ArrayListUnmanaged(DesiredLink) = .empty;
    var unmatched_filters: std.ArrayListUnmanaged([]const u8) = .empty;
    if (bin_filters.len == 0) {
        try matched.appendSlice(aa, all_links.items);
    } else {
        for (bin_filters) |filter| {
            const filter_owned = try aa.dupe(u8, filter);
            var any = false;
            for (all_links.items) |link_entry| {
                if (!std.ascii.eqlIgnoreCase(link_entry.name, filter)) continue;
                any = true;
                var seen = false;
                for (matched.items) |existing| {
                    if (std.mem.eql(u8, existing.name, link_entry.name)) {
                        seen = true;
                        break;
                    }
                }
                if (!seen) try matched.append(aa, link_entry);
            }
            if (!any) try unmatched_filters.append(aa, filter_owned);
        }
    }

    return .{
        .arena = arena,
        .links = try matched.toOwnedSlice(aa),
        .unmatched_filters = try unmatched_filters.toOwnedSlice(aa),
        .available_names = try available.toOwnedSlice(aa),
    };
}

// ---------------------------------------------------------------------------
// `ghr link` and `ghr unlink` commands.
// ---------------------------------------------------------------------------

pub const LinkCmdError = error{LinkStepFailed};

fn idManifestEntryExists(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    id: []const u8,
) !bool {
    const path = try idManifestPath(allocator, environ, id);
    defer allocator.free(path);
    var file = Dir.openFileAbsolute(io, path, .{
        .follow_symlinks = false,
        .allow_directory = false,
    }) catch |err| switch (err) {
        error.FileNotFound => return false,
        error.NotDir, error.IsDir, error.SymLinkLoop => return true,
        else => return err,
    };
    file.close(io);
    return true;
}

/// Resolve the one-segment syntax shared by install IDs and Windows PATH
/// executable names. Existing ID state wins; otherwise the historical bare
/// executable shorthand remains available. `--path` bypasses this lookup.
fn isKnownOneSegmentId(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    spec: []const u8,
    err_w: *Writer,
) !bool {
    const id = install_request.canonicalizeId(allocator, spec) catch return false;
    defer allocator.free(id);
    if (std.mem.indexOfScalar(u8, id, '/') != null) return true;
    if (try idManifestEntryExists(allocator, io, environ, id)) return true;

    const win_tools = discoverWindowsToolsDirFromWsl(
        allocator,
        environ,
        io,
        err_w,
        .strict,
    ) catch |err| {
        try err_w.print(
            "error: cannot disambiguate '{s}' as an install ID because Windows tools discovery failed: {t}\n",
            .{ spec, err },
        );
        try err_w.print("       use --path only when Windows PATH mode is intended\n", .{});
        try err_w.flush();
        return LinkCmdError.LinkStepFailed;
    };
    defer allocator.free(win_tools);
    var inventory = install_state.scan(allocator, io, win_tools, .{ .platform = .windows }) catch |err| {
        try err_w.print(
            "error: cannot disambiguate '{s}' as an install ID because Windows inventory failed: {t}\n",
            .{ spec, err },
        );
        try err_w.print("       use --path only when Windows PATH mode is intended\n", .{});
        try err_w.flush();
        return LinkCmdError.LinkStepFailed;
    };
    defer inventory.deinit(allocator);
    return inventoryRecordById(&inventory, id) != null;
}

pub fn cmdLinkAuto(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    spec: []const u8,
    bin_filters: []const []const u8,
    force_path: bool,
    force_id: bool,
    w: *Writer,
    err_w: *Writer,
) !void {
    requireWsl(environ, err_w, "link") catch return LinkCmdError.LinkStepFailed;
    const id_mode = force_id or (!force_path and
        (std.mem.indexOfScalar(u8, spec, '/') != null or
            try isKnownOneSegmentId(allocator, io, environ, spec, err_w)));
    if (id_mode)
        return cmdLink(allocator, io, environ, spec, bin_filters, w, err_w);
    return cmdLinkBareExe(allocator, io, environ, spec, bin_filters, w, err_w);
}

pub fn cmdUnlinkAuto(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    spec: []const u8,
    bin_filters: []const []const u8,
    force_path: bool,
    force_id: bool,
    w: *Writer,
    err_w: *Writer,
) !void {
    requireWsl(environ, err_w, "unlink") catch return LinkCmdError.LinkStepFailed;
    const id_mode = force_id or (!force_path and
        (std.mem.indexOfScalar(u8, spec, '/') != null or
            try isKnownOneSegmentId(allocator, io, environ, spec, err_w)));
    if (id_mode)
        return cmdUnlink(allocator, io, environ, spec, bin_filters, w, err_w);
    return cmdUnlinkBareExe(allocator, io, environ, spec, bin_filters, w, err_w);
}

fn inventoryRecordById(
    inventory: *const install_state.Inventory,
    id: []const u8,
) ?*const install_state.InventoryRecord {
    var match: ?*const install_state.InventoryRecord = null;
    for (inventory.records) |*record| {
        const record_id = record.id orelse continue;
        if (!std.mem.eql(u8, record_id, id)) continue;
        if (match != null) return record;
        match = record;
    }
    return match;
}

fn writeIdNotInstalledError(
    err_w: *Writer,
    win_tools: []const u8,
    id: []const u8,
    inventory: *const install_state.Inventory,
) !void {
    try err_w.print("error: install id '{s}' is not installed on the Windows side\n", .{id});
    var any = false;
    for (inventory.records) |record| {
        if (record.id == null) continue;
        if (!any) {
            try err_w.print("       installed ids under {s}:\n", .{win_tools});
            any = true;
        }
        try err_w.print("         {s}", .{record.id.?});
        if (record.status != .ok)
            try err_w.print(" ({s}: {s})", .{ @tagName(record.status), @tagName(record.reason) });
        try err_w.writeByte('\n');
    }
    if (!any) try err_w.print("       no install records found under {s}\n", .{win_tools});
    try err_w.flush();
}

const LegacyManifestCandidate = struct {
    path: []u8,
    parsed: std.json.Parsed(Manifest),

    fn deinit(self: *LegacyManifestCandidate, allocator: std.mem.Allocator) void {
        self.parsed.deinit();
        allocator.free(self.path);
    }
};

fn splitDefaultGithubId(
    record: *const install_state.InventoryRecord,
    id: []const u8,
) ?struct { owner: []const u8, repo: []const u8 } {
    const slash = std.mem.indexOfScalar(u8, id, '/') orelse return null;
    if (std.mem.indexOfScalar(u8, id[slash + 1 ..], '/') != null) return null;
    const owner = id[0..slash];
    const repo = id[slash + 1 ..];
    switch (record.kind) {
        .v1_repo => {},
        .v2 => {
            const source = record.source orelse return null;
            if (source.kind != .github or source.owner == null or source.repo == null) return null;
            if (!std.ascii.eqlIgnoreCase(source.owner.?, owner) or
                !std.ascii.eqlIgnoreCase(source.repo.?, repo)) return null;
        },
        else => return null,
    }
    return .{ .owner = owner, .repo = repo };
}

fn hasPathPrefix(path: []const u8, prefix: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, path, prefix) or path.len <= prefix.len or path[prefix.len] != '/')
        return null;
    return path[prefix.len + 1 ..];
}

fn validateLegacyManifest(
    manifest: Manifest,
    win_tools: []const u8,
    owner: []const u8,
    repo: []const u8,
) bool {
    if (manifest.schema != null or manifest.layout_generation != null or
        !std.mem.eql(u8, manifest.kind, "wsl") or manifest.id != null or
        manifest.unit_path != null or !isSafeManifestTarget(manifest.source) or
        !validLinkEntries(manifest.links))
    {
        return false;
    }

    const tools_root = std.mem.trimEnd(u8, win_tools, "/");
    if (tools_root.len == 0) return false;
    const source_relative = hasPathPrefix(manifest.source, tools_root) orelse return false;
    var source_parts = std.mem.splitScalar(u8, source_relative, '/');
    const actual_owner = source_parts.next() orelse return false;
    const actual_repo = source_parts.next() orelse return false;
    if (source_parts.next() != null or
        !std.ascii.eqlIgnoreCase(actual_owner, owner) or
        !std.ascii.eqlIgnoreCase(actual_repo, repo))
    {
        return false;
    }

    for (manifest.links) |entry| {
        if (!std.mem.eql(u8, entry.target_kind, "symlink")) return false;
        const relative = hasPathPrefix(entry.target, manifest.source) orelse return false;
        if (!isSafeRelativeBinPath(relative)) return false;
        if (!std.mem.eql(u8, linkNameForBin(relative), entry.name)) return false;
    }
    return true;
}

fn splitLegacyManifestId(id: []const u8) ?struct { owner: []const u8, repo: []const u8 } {
    const slash = std.mem.indexOfScalar(u8, id, '/') orelse return null;
    if (std.mem.indexOfScalar(u8, id[slash + 1 ..], '/') != null) return null;
    return .{ .owner = id[0..slash], .repo = id[slash + 1 ..] };
}

fn readLegacyManifestForId(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    win_tools: []const u8,
    id: []const u8,
) !?LegacyManifestCandidate {
    const parts = splitLegacyManifestId(id) orelse return null;
    const path = try manifestPath(allocator, environ, parts.owner, parts.repo);
    errdefer allocator.free(path);
    var parsed = (readManifest(allocator, io, path) catch |err| switch (err) {
        error.InvalidManifest => return error.InvalidLegacyManifest,
        else => return err,
    }) orelse {
        allocator.free(path);
        return null;
    };
    errdefer parsed.deinit();

    if (!validateLegacyManifest(parsed.value, win_tools, parts.owner, parts.repo))
        return error.InvalidLegacyManifest;
    return .{ .path = path, .parsed = parsed };
}

/// Find the owner/repo manifest that can belong to this exact inferred ID.
/// Custom IDs never claim a legacy manifest merely because their source points
/// at the same GitHub repository.
fn readLegacyManifestCandidate(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    win_tools: []const u8,
    record: *const install_state.InventoryRecord,
    id: []const u8,
) !?LegacyManifestCandidate {
    _ = splitDefaultGithubId(record, id) orelse return null;
    return readLegacyManifestForId(allocator, io, environ, win_tools, id);
}

test "legacy manifest validation preserves source casing within tools root" {
    var links = [_]LinkEntry{.{
        .name = "zig",
        .target = "/mnt/c/ghr/tools/Cataggar/Zig/zig.exe",
    }};
    const manifest: Manifest = .{
        .source = "/mnt/c/ghr/tools/Cataggar/Zig",
        .links = &links,
    };
    try std.testing.expect(validateLegacyManifest(
        manifest,
        "/mnt/c/ghr/tools",
        "cataggar",
        "zig",
    ));

    var escaped = manifest;
    escaped.source = "/mnt/c/other/Cataggar/Zig";
    try std.testing.expect(!validateLegacyManifest(
        escaped,
        "/mnt/c/ghr/tools",
        "cataggar",
        "zig",
    ));
}

pub fn cmdLink(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    spec_str: []const u8,
    bin_filters: []const []const u8,
    w: *Writer,
    err_w: *Writer,
) !void {
    requireWsl(environ, err_w, "link") catch return LinkCmdError.LinkStepFailed;

    const id = install_request.canonicalizeId(allocator, spec_str) catch {
        try err_w.print("error: invalid install id '{s}'\n", .{spec_str});
        try err_w.flush();
        return LinkCmdError.LinkStepFailed;
    };
    defer allocator.free(id);

    const win_tools = windowsToolsDirFromWsl(allocator, environ, io, err_w) catch return LinkCmdError.LinkStepFailed;
    defer allocator.free(win_tools);

    var inventory = install_state.scan(allocator, io, win_tools, .{ .platform = .windows }) catch |err| {
        try err_w.print("error: failed to read Windows install state under '{s}': {t}\n", .{ win_tools, err });
        try err_w.flush();
        return LinkCmdError.LinkStepFailed;
    };
    defer inventory.deinit(allocator);

    const record = inventoryRecordById(&inventory, id) orelse {
        try writeIdNotInstalledError(err_w, win_tools, id, &inventory);
        return LinkCmdError.LinkStepFailed;
    };
    if (record.status != .ok) {
        try err_w.print(
            "error: install id '{s}' is {s} ({s}); refusing to link\n",
            .{ id, @tagName(record.status), @tagName(record.reason) },
        );
        try err_w.flush();
        return LinkCmdError.LinkStepFailed;
    }

    const tool_path = try std.fs.path.join(allocator, &.{ win_tools, record.path });
    defer allocator.free(tool_path);

    var computed = computeDesiredCommandLinks(allocator, record.commands, tool_path, bin_filters) catch |err| switch (err) {
        DesiredError.DuplicateLinkName => {
            try err_w.print(
                "error: install id '{s}' owns duplicate Windows command names\n",
                .{id},
            );
            try err_w.print("       refusing to link to avoid clobbering one with the other\n", .{});
            try err_w.flush();
            return LinkCmdError.LinkStepFailed;
        },
        DesiredError.NoBinsInMetadata => {
            try err_w.print("error: install id '{s}' owns no commands\n", .{id});
            try err_w.flush();
            return LinkCmdError.LinkStepFailed;
        },
        DesiredError.NoValidBinsAfterNormalize => {
            try err_w.print(
                "error: every command target for install id '{s}' is unsafe\n",
                .{id},
            );
            try err_w.print("       refusing to reconcile to avoid removing existing valid links\n", .{});
            try err_w.flush();
            return LinkCmdError.LinkStepFailed;
        },
        DesiredError.UnsupportedCommandKind => {
            try err_w.print(
                "error: install id '{s}' owns a wasm command that cannot be executed through a direct WSL link\n",
                .{id},
            );
            try err_w.print("       refusing to link the raw wasm module\n", .{});
            try err_w.flush();
            return LinkCmdError.LinkStepFailed;
        },
        else => |e| return e,
    };
    defer computed.deinit();

    if (computed.unmatched_filters.len > 0) {
        try err_w.print("error: --bin filter(s) did not match any installed bin:\n", .{});
        for (computed.unmatched_filters) |f| try err_w.print("  - {s}\n", .{f});
        try err_w.print("  available: ", .{});
        for (computed.available_names, 0..) |n, i| {
            if (i > 0) try err_w.print(", ", .{});
            try err_w.print("{s}", .{n});
        }
        try err_w.print("\n", .{});
        try err_w.flush();
        return LinkCmdError.LinkStepFailed;
    }

    const d = try Dirs.detect(allocator, environ);
    defer d.deinit();
    install.ensureDirAbsoluteRecursive(io, d.bin) catch {};
    var bin_dir = Dir.openDirAbsolute(io, d.bin, .{}) catch |err| {
        try err_w.print("error: failed to open bin directory '{s}': {t}\n", .{ d.bin, err });
        try err_w.flush();
        return LinkCmdError.LinkStepFailed;
    };
    defer bin_dir.close(io);

    // Prefer an ID-keyed manifest. A legacy owner/repo manifest can seed
    // ownership only for the exact inferred repository ID.
    const manifest_abs = try idManifestPath(allocator, environ, id);
    defer allocator.free(manifest_abs);
    var prior_parsed = readIdManifest(allocator, io, manifest_abs, id) catch |err| switch (err) {
        error.InvalidManifest => {
            try err_w.print("error: invalid ID manifest at {s}; refusing to reconcile\n", .{manifest_abs});
            try err_w.flush();
            return LinkCmdError.LinkStepFailed;
        },
        else => return err,
    };
    defer if (prior_parsed) |*p| p.deinit();

    var legacy_candidate: ?LegacyManifestCandidate = null;
    defer if (legacy_candidate) |*candidate| candidate.deinit(allocator);
    if (prior_parsed == null) {
        legacy_candidate = readLegacyManifestCandidate(
            allocator,
            io,
            environ,
            win_tools,
            record,
            id,
        ) catch |err| switch (err) {
            error.InvalidLegacyManifest => {
                try err_w.print(
                    "error: legacy link manifest for '{s}' does not match its install paths; refusing to import it\n",
                    .{id},
                );
                try err_w.flush();
                return LinkCmdError.LinkStepFailed;
            },
            else => return err,
        };
        if (legacy_candidate != null and bin_filters.len > 0) {
            try err_w.print(
                "error: legacy link manifest for '{s}' requires an unfiltered reconciliation before --bin can be used\n",
                .{id},
            );
            try err_w.flush();
            return LinkCmdError.LinkStepFailed;
        }
    }
    const prior_links: []const LinkEntry = if (prior_parsed) |p|
        p.value.links
    else if (legacy_candidate) |candidate|
        candidate.parsed.value.links
    else
        &.{};

    var has_script_links = false;
    for (computed.links) |desired| {
        if (desired.kind == .script) {
            has_script_links = true;
            break;
        }
    }
    if (has_script_links) {
        const aa = computed.arena.allocator();
        const cmd_exe_wsl = try resolveWslCmdExePath(aa, io, environ);
        for (computed.links) |*desired| {
            if (desired.kind != .script) continue;
            const win_path = resolveWindowsScriptTarget(aa, io, environ, desired.target) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => {
                    try err_w.print(
                        "error: failed to convert '{s}' to a safe Windows drive path for cmd.exe wrapper\n",
                        .{desired.target},
                    );
                    try err_w.flush();
                    return LinkCmdError.LinkStepFailed;
                },
            };
            const script_bytes = try buildIdWrapperScript(aa, id, desired.name, cmd_exe_wsl, win_path);
            const digest = sha256Hex(script_bytes);
            desired.win_target = win_path;
            desired.script_bytes = script_bytes;
            desired.wrapper_sha256 = try aa.dupe(u8, &digest);
        }
    }

    var planned_links = std.ArrayListUnmanaged(LinkEntry).empty;
    defer planned_links.deinit(allocator);
    try planned_links.ensureTotalCapacity(allocator, computed.links.len + prior_links.len);
    for (computed.links) |desired| {
        planned_links.appendAssumeCapacity(.{
            .name = desired.name,
            .target = desired.manifestTarget(),
            .target_kind = desired.kind.manifestKind(),
            .wrapper_sha256 = desired.wrapper_sha256,
        });
    }
    if (bin_filters.len > 0) {
        for (prior_links) |old| {
            var touched = false;
            for (computed.links) |desired| {
                if (std.mem.eql(u8, desired.name, old.name)) {
                    touched = true;
                    break;
                }
            }
            if (!touched) planned_links.appendAssumeCapacity(old);
        }
    }
    const manifest_body = try stringifyIdManifest(
        allocator,
        id,
        record.path,
        tool_path,
        planned_links.items,
    );
    defer allocator.free(manifest_body);

    if (try preflightLinkReconciliation(
        io,
        bin_dir,
        computed.links,
        prior_links,
        bin_filters.len == 0,
    )) |conflict| {
        switch (conflict.kind) {
            .unmanaged => try err_w.print(
                "error: {s}/{s} is not owned by install id '{s}'; refusing to overwrite it\n",
                .{ d.bin, conflict.name, id },
            ),
            .modified => try err_w.print(
                "error: {s}/{s} differs from the target recorded for install id '{s}'; refusing destructive reconciliation\n",
                .{ d.bin, conflict.name, id },
            ),
        }
        try err_w.flush();
        return LinkCmdError.LinkStepFailed;
    }

    // Apply the desired set: add / no-op / replace / record conflicts.
    var applied = std.ArrayListUnmanaged(AppliedLink).empty;
    defer deinitAppliedLinks(allocator, &applied);
    try applied.ensureTotalCapacity(allocator, computed.links.len + prior_links.len);
    var manifest_committed = false;
    errdefer if (!manifest_committed) rollbackAppliedLinks(io, bin_dir, applied.items);
    var action_log = std.Io.Writer.Allocating.init(allocator);
    defer action_log.deinit();
    const action_w = &action_log.writer;

    for (computed.links) |desired| {
        const suffix: []const u8 = if (desired.kind == .script) " (via cmd.exe)" else "";
        const outcome = applyOneLink(allocator, io, bin_dir, desired, prior_links) catch |err| {
            try err_w.print("error: failed to link {s}: {t}\n", .{ desired.name, err });
            try err_w.flush();
            return LinkCmdError.LinkStepFailed;
        };
        switch (outcome) {
            .created => {
                applied.appendAssumeCapacity(.{ .created = desired });
                try action_w.print("  linked   {s} -> {s}{s}\n", .{ desired.name, desired.target, suffix });
            },
            .replaced => |prior_script_bytes| {
                applied.appendAssumeCapacity(.{ .replaced = .{
                    .desired = desired,
                    .prior = findPriorLink(prior_links, desired.name).?,
                    .prior_script_bytes = prior_script_bytes,
                } });
                try action_w.print("  updated  {s} -> {s}{s}\n", .{ desired.name, desired.target, suffix });
            },
            .unchanged => try action_w.print("  ok       {s} -> {s}{s}\n", .{ desired.name, desired.target, suffix }),
            .conflict => {
                try err_w.print(
                    "error: ownership of {s}/{s} changed during reconciliation; refusing to continue\n",
                    .{ d.bin, desired.name },
                );
                try err_w.flush();
                return LinkCmdError.LinkStepFailed;
            },
        }
    }

    // Reconcile removals only when the user did not pass --bin filters.
    // With filters, prior entries outside the requested set are explicitly
    // out of scope for this invocation.
    if (bin_filters.len == 0) {
        for (prior_links) |old| {
            var still_desired = false;
            for (computed.links) |desired| {
                if (std.mem.eql(u8, desired.name, old.name)) {
                    still_desired = true;
                    break;
                }
            }
            if (still_desired) continue;
            const outcome = removeOwnedIdEntry(allocator, io, bin_dir, old) catch |err| {
                try err_w.print("error: failed to remove stale link {s}: {t}\n", .{ old.name, err });
                try err_w.flush();
                return LinkCmdError.LinkStepFailed;
            };
            switch (outcome) {
                .removed => |prior_script_bytes| {
                    applied.appendAssumeCapacity(.{ .removed = .{
                        .entry = old,
                        .prior_script_bytes = prior_script_bytes,
                    } });
                    try action_w.print("  removed  {s} (no longer owned by {s})\n", .{ old.name, id });
                },
                .missing => {}, // already gone, no message
                .target_mismatch => {
                    try err_w.print(
                        "error: ownership of {s}/{s} changed during reconciliation; refusing to continue\n",
                        .{ d.bin, old.name },
                    );
                    try err_w.flush();
                    return LinkCmdError.LinkStepFailed;
                },
            }
        }
    }

    try persistIdManifestBody(allocator, io, environ, id, manifest_body);
    manifest_committed = true;
    if (legacy_candidate) |candidate| {
        Dir.deleteFileAbsolute(io, candidate.path) catch |err| {
            try err_w.print(
                "warning: imported '{s}' but could not remove legacy manifest {s}: {t}\n",
                .{ id, candidate.path, err },
            );
        };
    }
    try w.writeAll(action_log.written());
}

const LinkConflictKind = enum { unmanaged, modified };

const LinkConflict = struct {
    name: []const u8,
    kind: LinkConflictKind,
};

fn findPriorLink(prior_links: []const LinkEntry, name: []const u8) ?LinkEntry {
    for (prior_links) |entry| {
        if (std.mem.eql(u8, entry.name, name)) return entry;
    }
    return null;
}

const max_id_wrapper_bytes: u64 = 64 * 1024;

const LiveBinEntry = union(enum) {
    missing,
    symlink: usize,
    regular_sha256: [64]u8,
    other,
};

fn inspectLiveBinEntry(
    io: Io,
    bin_dir: Dir,
    name: []const u8,
    link_buf: *[Dir.max_path_bytes]u8,
) !LiveBinEntry {
    if (bin_dir.readLink(io, name, link_buf)) |n| {
        return .{ .symlink = n };
    } else |err| switch (err) {
        error.FileNotFound, error.NotLink => {
            const stat = bin_dir.statFile(io, name, .{ .follow_symlinks = false }) catch |stat_err| switch (stat_err) {
                error.FileNotFound => return .missing,
                else => return stat_err,
            };
            if (stat.kind != .file or stat.size > max_id_wrapper_bytes) return .other;
        },
        else => return err,
    }

    var file = bin_dir.openFile(io, name, .{
        .follow_symlinks = false,
        .allow_directory = false,
    }) catch |err| switch (err) {
        error.FileNotFound => return .missing,
        error.IsDir, error.SymLinkLoop => return .other,
        else => return err,
    };
    defer file.close(io);

    const fstat = try file.stat(io);
    if (fstat.kind != .file or fstat.size > max_id_wrapper_bytes) return .other;

    var read_buf: [4096]u8 = undefined;
    var reader = file.reader(io, &read_buf);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var chunk: [4096]u8 = undefined;
    var total: u64 = 0;
    while (true) {
        const n = try reader.interface.readSliceShort(&chunk);
        if (n == 0) break;
        total += n;
        if (total > max_id_wrapper_bytes) return .other;
        hasher.update(chunk[0..n]);
        if (n < chunk.len) break;
    }
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return .{ .regular_sha256 = std.fmt.bytesToHex(digest, .lower) };
}

fn liveEntryMatchesPrior(
    live: LiveBinEntry,
    link_buf: *const [Dir.max_path_bytes]u8,
    prior: LinkEntry,
) bool {
    if (std.mem.eql(u8, prior.target_kind, "symlink")) {
        return switch (live) {
            .symlink => |n| std.mem.eql(u8, link_buf[0..n], prior.target),
            else => false,
        };
    }
    if (std.mem.eql(u8, prior.target_kind, "script")) {
        const expected = prior.wrapper_sha256 orelse return false;
        return switch (live) {
            .regular_sha256 => |actual| std.mem.eql(u8, &actual, expected),
            else => false,
        };
    }
    return false;
}

fn liveEntryMatchesDesired(
    live: LiveBinEntry,
    link_buf: *const [Dir.max_path_bytes]u8,
    desired: DesiredLink,
) bool {
    return switch (desired.kind) {
        .symlink => switch (live) {
            .symlink => |n| std.mem.eql(u8, link_buf[0..n], desired.target),
            else => false,
        },
        .script => blk: {
            const expected = desired.wrapper_sha256 orelse break :blk false;
            break :blk switch (live) {
                .regular_sha256 => |actual| std.mem.eql(u8, &actual, expected),
                else => false,
            };
        },
    };
}

const VerifiedScriptRead = union(enum) {
    missing,
    mismatch,
    matched: []u8,
};

/// Read an existing regular wrapper file and verify its SHA-256 against
/// `expected_sha256` on the exact captured buffer so rollback snapshots and
/// ownership checks share a single race-free read.
fn readVerifiedPriorScriptBytes(
    allocator: std.mem.Allocator,
    io: Io,
    bin_dir: Dir,
    name: []const u8,
    expected_sha256: []const u8,
) !VerifiedScriptRead {
    var link_buf: [Dir.max_path_bytes]u8 = undefined;
    if (bin_dir.readLink(io, name, &link_buf)) |_| {
        return .mismatch;
    } else |err| switch (err) {
        error.FileNotFound, error.NotLink => {},
        else => return err,
    }

    var file = bin_dir.openFile(io, name, .{
        .follow_symlinks = false,
        .allow_directory = false,
    }) catch |err| switch (err) {
        error.FileNotFound => return .missing,
        error.IsDir, error.SymLinkLoop => return .mismatch,
        else => return err,
    };
    defer file.close(io);

    const fstat = try file.stat(io);
    if (fstat.kind != .file or fstat.size > max_id_wrapper_bytes) return .mismatch;

    var read_buf: [4096]u8 = undefined;
    var reader = file.reader(io, &read_buf);
    var aw = std.Io.Writer.Allocating.init(allocator);
    defer aw.deinit();
    var chunk: [4096]u8 = undefined;
    var total: u64 = 0;
    while (true) {
        const n = try reader.interface.readSliceShort(&chunk);
        if (n == 0) break;
        total += n;
        if (total > max_id_wrapper_bytes) return .mismatch;
        try aw.writer.writeAll(chunk[0..n]);
        if (n < chunk.len) break;
    }

    const actual = sha256Hex(aw.written());
    if (!std.mem.eql(u8, &actual, expected_sha256)) return .mismatch;
    return .{ .matched = try aw.toOwnedSlice() };
}

fn writeIdWrapperFile(io: Io, bin_dir: Dir, name: []const u8, bytes: []const u8) !void {
    var tmp_buf: [Dir.max_path_bytes]u8 = undefined;
    const tmp_name = std.fmt.bufPrint(&tmp_buf, ".ghr-link-tmp.{s}", .{name}) catch return error.PathTooLong;
    bin_dir.deleteFile(io, tmp_name) catch {};
    {
        var f = try bin_dir.createFile(io, tmp_name, .{
            .exclusive = true,
            .permissions = .executable_file,
        });
        defer f.close(io);
        try f.writeStreamingAll(io, bytes);
    }
    bin_dir.rename(tmp_name, bin_dir, name, io) catch |err| {
        bin_dir.deleteFile(io, tmp_name) catch {};
        return err;
    };
}

/// Validate every live entry that reconciliation may replace or remove before
/// the first mutation. A manifest proves ownership only while the live target
/// (or wrapper SHA-256) still equals the recorded entry.
fn preflightLinkReconciliation(
    io: Io,
    bin_dir: Dir,
    desired_links: []const DesiredLink,
    prior_links: []const LinkEntry,
    reconcile_stale: bool,
) !?LinkConflict {
    var link_buf: [Dir.max_path_bytes]u8 = undefined;
    for (desired_links) |desired| {
        const live = try inspectLiveBinEntry(io, bin_dir, desired.name, &link_buf);
        if (live == .missing) continue;
        const prior = findPriorLink(prior_links, desired.name) orelse
            return .{ .name = desired.name, .kind = .unmanaged };
        if (!liveEntryMatchesPrior(live, &link_buf, prior))
            return .{ .name = desired.name, .kind = .modified };
    }

    if (!reconcile_stale) return null;
    for (prior_links) |prior| {
        var desired = false;
        for (desired_links) |entry| {
            if (std.mem.eql(u8, entry.name, prior.name)) {
                desired = true;
                break;
            }
        }
        if (desired) continue;
        const live = try inspectLiveBinEntry(io, bin_dir, prior.name, &link_buf);
        if (live == .missing) continue;
        if (!liveEntryMatchesPrior(live, &link_buf, prior))
            return .{ .name = prior.name, .kind = .modified };
    }
    return null;
}

const LinkOutcome = union(enum) {
    created,
    /// Carries the captured prior wrapper bytes when `prior.target_kind` was
    /// `"script"` so zero-allocation rollback can restore it faithfully.
    replaced: ?[]u8,
    unchanged,
    conflict,
};

const AppliedLink = union(enum) {
    created: DesiredLink,
    replaced: struct {
        desired: DesiredLink,
        prior: LinkEntry,
        prior_script_bytes: ?[]u8 = null,
    },
    removed: struct {
        entry: LinkEntry,
        prior_script_bytes: ?[]u8 = null,
    },
};

fn deinitAppliedLinks(
    allocator: std.mem.Allocator,
    applied: *std.ArrayListUnmanaged(AppliedLink),
) void {
    for (applied.items) |item| {
        switch (item) {
            .created => {},
            .replaced => |r| if (r.prior_script_bytes) |b| allocator.free(b),
            .removed => |r| if (r.prior_script_bytes) |b| allocator.free(b),
        }
    }
    applied.deinit(allocator);
}

fn restorePriorLinkEntry(
    io: Io,
    bin_dir: Dir,
    prior: LinkEntry,
    prior_script_bytes: ?[]const u8,
) void {
    if (std.mem.eql(u8, prior.target_kind, "symlink")) {
        bin_dir.symLink(io, prior.target, prior.name, .{}) catch {};
    } else if (std.mem.eql(u8, prior.target_kind, "script")) {
        if (prior_script_bytes) |bytes| {
            writeIdWrapperFile(io, bin_dir, prior.name, bytes) catch {};
        }
    }
}

fn rollbackAppliedLinks(io: Io, bin_dir: Dir, applied: []const AppliedLink) void {
    var link_buf: [Dir.max_path_bytes]u8 = undefined;
    var i = applied.len;
    while (i > 0) {
        i -= 1;
        switch (applied[i]) {
            .created => |desired| {
                const live = inspectLiveBinEntry(io, bin_dir, desired.name, &link_buf) catch continue;
                if (liveEntryMatchesDesired(live, &link_buf, desired))
                    bin_dir.deleteFile(io, desired.name) catch {};
            },
            .replaced => |replacement| {
                const live = inspectLiveBinEntry(io, bin_dir, replacement.desired.name, &link_buf) catch continue;
                if (!liveEntryMatchesDesired(live, &link_buf, replacement.desired)) continue;
                if (std.mem.eql(u8, replacement.prior.target_kind, "script")) {
                    restorePriorLinkEntry(io, bin_dir, replacement.prior, replacement.prior_script_bytes);
                } else {
                    bin_dir.deleteFile(io, replacement.desired.name) catch continue;
                    restorePriorLinkEntry(io, bin_dir, replacement.prior, null);
                }
            },
            .removed => |removed| {
                const live = inspectLiveBinEntry(io, bin_dir, removed.entry.name, &link_buf) catch continue;
                if (live == .missing) {
                    restorePriorLinkEntry(io, bin_dir, removed.entry, removed.prior_script_bytes);
                }
            },
        }
    }
}

fn createDesiredEntry(io: Io, bin_dir: Dir, desired: DesiredLink) !void {
    switch (desired.kind) {
        .symlink => try bin_dir.symLink(io, desired.target, desired.name, .{}),
        .script => try writeIdWrapperFile(io, bin_dir, desired.name, desired.script_bytes.?),
    }
}

/// Apply one desired link or wrapper in `bin_dir`. Considers an existing entry
/// ghr-owned only if a prior manifest records its name and its live symlink
/// target or wrapper SHA-256 still matches. A changed entry is user-owned and
/// must never be replaced.
fn applyOneLink(
    allocator: std.mem.Allocator,
    io: Io,
    bin_dir: Dir,
    desired: DesiredLink,
    prior_links: []const LinkEntry,
) !LinkOutcome {
    var link_buf: [Dir.max_path_bytes]u8 = undefined;
    if (bin_dir.readLink(io, desired.name, &link_buf)) |n| {
        const current = link_buf[0..n];
        const prior = findPriorLink(prior_links, desired.name) orelse return .conflict;
        if (!std.mem.eql(u8, prior.target_kind, "symlink")) return .conflict;
        if (!std.mem.eql(u8, current, prior.target)) return .conflict;
        if (desired.kind == .symlink and std.mem.eql(u8, current, desired.target))
            return .unchanged;
        switch (desired.kind) {
            .script => {
                // POSIX rename atomically replaces the existing symlink.
                try writeIdWrapperFile(io, bin_dir, desired.name, desired.script_bytes.?);
            },
            .symlink => {
                try bin_dir.deleteFile(io, desired.name);
                bin_dir.symLink(io, desired.target, desired.name, .{}) catch |err| {
                    bin_dir.symLink(io, prior.target, prior.name, .{}) catch {};
                    return err;
                };
            },
        }
        return .{ .replaced = null };
    } else |err| switch (err) {
        error.FileNotFound => {
            _ = bin_dir.statFile(io, desired.name, .{ .follow_symlinks = false }) catch |stat_err| switch (stat_err) {
                error.FileNotFound => {
                    try createDesiredEntry(io, bin_dir, desired);
                    return .created;
                },
                else => return stat_err,
            };
        },
        error.NotLink => {},
        else => return err,
    }

    // Existing non-symlink entry on disk: owned only if `prior` is a `"script"`
    // entry whose recorded SHA-256 matches the live file contents.
    const prior = findPriorLink(prior_links, desired.name) orelse return .conflict;
    if (!std.mem.eql(u8, prior.target_kind, "script")) return .conflict;
    const expected_sha = prior.wrapper_sha256 orelse return .conflict;
    const prior_bytes = switch (try readVerifiedPriorScriptBytes(allocator, io, bin_dir, desired.name, expected_sha)) {
        .missing => {
            try createDesiredEntry(io, bin_dir, desired);
            return .created;
        },
        .mismatch => return .conflict,
        .matched => |bytes| bytes,
    };
    errdefer allocator.free(prior_bytes);

    if (desired.kind == .script and std.mem.eql(u8, prior_bytes, desired.script_bytes.?)) {
        allocator.free(prior_bytes);
        return .unchanged;
    }

    switch (desired.kind) {
        .script => {
            try writeIdWrapperFile(io, bin_dir, desired.name, desired.script_bytes.?);
        },
        .symlink => {
            try bin_dir.deleteFile(io, desired.name);
            bin_dir.symLink(io, desired.target, desired.name, .{}) catch |err| {
                writeIdWrapperFile(io, bin_dir, prior.name, prior_bytes) catch {};
                return err;
            };
        },
    }
    return .{ .replaced = prior_bytes };
}

/// Outcome of attempting to remove a previously-linked symlink (bare-PATH mode).
const RemoveOutcome = enum {
    removed,
    missing,
    target_mismatch,
};

fn removeOwnedLink(io: Io, bin_dir: Dir, entry: LinkEntry) !RemoveOutcome {
    var link_buf: [Dir.max_path_bytes]u8 = undefined;
    const n = bin_dir.readLink(io, entry.name, &link_buf) catch |err| switch (err) {
        error.FileNotFound => return .missing,
        else => return err,
    };
    if (!std.mem.eql(u8, link_buf[0..n], entry.target)) return .target_mismatch;
    try bin_dir.deleteFile(io, entry.name);
    return .removed;
}

/// Outcome of attempting to remove an ID-owned symlink or wrapper script.
const IdRemoveOutcome = union(enum) {
    removed: ?[]u8,
    missing,
    target_mismatch,
};

fn linkWasRequested(entry: LinkEntry, filters: []const []const u8) bool {
    if (filters.len == 0) return true;
    for (filters) |filter| {
        if (std.ascii.eqlIgnoreCase(filter, entry.name)) return true;
    }
    return false;
}

fn preflightUnlink(
    io: Io,
    bin_dir: Dir,
    links: []const LinkEntry,
    filters: []const []const u8,
) !?[]const u8 {
    var link_buf: [Dir.max_path_bytes]u8 = undefined;
    for (links) |entry| {
        if (!linkWasRequested(entry, filters)) continue;
        const live = try inspectLiveBinEntry(io, bin_dir, entry.name, &link_buf);
        if (live == .missing) continue;
        if (!liveEntryMatchesPrior(live, &link_buf, entry)) return entry.name;
    }
    return null;
}

/// Remove a manifested symlink or wrapper script, but only when its live
/// target or SHA-256 still matches what was recorded.
fn removeOwnedIdEntry(
    allocator: std.mem.Allocator,
    io: Io,
    bin_dir: Dir,
    entry: LinkEntry,
) !IdRemoveOutcome {
    if (std.mem.eql(u8, entry.target_kind, "symlink")) {
        var link_buf: [Dir.max_path_bytes]u8 = undefined;
        const n = bin_dir.readLink(io, entry.name, &link_buf) catch |err| switch (err) {
            error.FileNotFound => {
                _ = bin_dir.statFile(io, entry.name, .{ .follow_symlinks = false }) catch |stat_err| switch (stat_err) {
                    error.FileNotFound => return .missing,
                    else => return stat_err,
                };
                return .target_mismatch;
            },
            error.NotLink => return .target_mismatch,
            else => return err,
        };
        if (!std.mem.eql(u8, link_buf[0..n], entry.target)) return .target_mismatch;
        try bin_dir.deleteFile(io, entry.name);
        return .{ .removed = null };
    }
    if (std.mem.eql(u8, entry.target_kind, "script")) {
        const expected_sha = entry.wrapper_sha256 orelse return .target_mismatch;
        const prior_bytes = switch (try readVerifiedPriorScriptBytes(allocator, io, bin_dir, entry.name, expected_sha)) {
            .missing => return .missing,
            .mismatch => return .target_mismatch,
            .matched => |bytes| bytes,
        };
        errdefer allocator.free(prior_bytes);
        try bin_dir.deleteFile(io, entry.name);
        return .{ .removed = prior_bytes };
    }
    return .target_mismatch;
}

pub fn cmdUnlink(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    spec_str: []const u8,
    bin_filters: []const []const u8,
    w: *Writer,
    err_w: *Writer,
) !void {
    requireWsl(environ, err_w, "unlink") catch return LinkCmdError.LinkStepFailed;

    const id = install_request.canonicalizeId(allocator, spec_str) catch {
        try err_w.print("error: invalid install id '{s}'\n", .{spec_str});
        try err_w.flush();
        return LinkCmdError.LinkStepFailed;
    };
    defer allocator.free(id);

    const manifest_abs = try idManifestPath(allocator, environ, id);
    defer allocator.free(manifest_abs);
    var parsed = readIdManifest(allocator, io, manifest_abs, id) catch |err| switch (err) {
        error.InvalidManifest => {
            try err_w.print("error: invalid ID manifest at {s}; refusing to unlink\n", .{manifest_abs});
            try err_w.flush();
            return LinkCmdError.LinkStepFailed;
        },
        else => return err,
    };
    defer if (parsed) |*p| p.deinit();

    var legacy_candidate: ?LegacyManifestCandidate = null;
    defer if (legacy_candidate) |*candidate| candidate.deinit(allocator);

    if (parsed == null) {
        const win_tools = windowsToolsDirFromWsl(allocator, environ, io, err_w) catch
            return LinkCmdError.LinkStepFailed;
        defer allocator.free(win_tools);
        var inventory = install_state.scan(allocator, io, win_tools, .{ .platform = .windows }) catch |err| {
            try err_w.print("error: failed to read Windows install state under '{s}': {t}\n", .{ win_tools, err });
            try err_w.flush();
            return LinkCmdError.LinkStepFailed;
        };
        defer inventory.deinit(allocator);
        const candidate_result = if (inventoryRecordById(&inventory, id)) |record| blk: {
            if (record.status != .ok) {
                try err_w.print(
                    "error: install id '{s}' is {s} ({s}); refusing legacy manifest reconciliation\n",
                    .{ id, @tagName(record.status), @tagName(record.reason) },
                );
                try err_w.flush();
                return LinkCmdError.LinkStepFailed;
            }
            break :blk readLegacyManifestCandidate(
                allocator,
                io,
                environ,
                win_tools,
                record,
                id,
            );
        } else readLegacyManifestForId(
            // A strict owner/repo manifest carries enough exact target state
            // for safe teardown even after its Windows install was removed.
            allocator,
            io,
            environ,
            win_tools,
            id,
        );
        legacy_candidate = candidate_result catch |err| switch (err) {
            error.InvalidLegacyManifest => {
                try err_w.print(
                    "error: legacy link manifest for '{s}' does not match its install paths; refusing to unlink\n",
                    .{id},
                );
                try err_w.flush();
                return LinkCmdError.LinkStepFailed;
            },
            else => return err,
        };
        if (legacy_candidate == null) {
            try err_w.print("error: no link manifest for install id '{s}'\n", .{id});
            try err_w.print("       (looked at {s})\n", .{manifest_abs});
            try err_w.flush();
            return LinkCmdError.LinkStepFailed;
        }
        if (bin_filters.len > 0) {
            try err_w.print(
                "error: legacy link manifest for '{s}' requires an unfiltered unlink before --bin can be used\n",
                .{id},
            );
            try err_w.flush();
            return LinkCmdError.LinkStepFailed;
        }
    }

    const active_manifest: Manifest = if (parsed) |p|
        p.value
    else
        legacy_candidate.?.parsed.value;

    // Pre-validate: every explicitly-requested filter must match a
    // manifest entry. Bail out before touching the filesystem so a
    // typo in one --bin doesn't half-unlink the rest.
    if (bin_filters.len > 0) {
        var any_unmatched = false;
        for (bin_filters) |f| {
            var matched = false;
            for (active_manifest.links) |entry| {
                if (std.ascii.eqlIgnoreCase(f, entry.name)) {
                    matched = true;
                    break;
                }
            }
            if (!matched) {
                try err_w.print("error: --bin '{s}' is not in the link manifest\n", .{f});
                any_unmatched = true;
            }
        }
        if (any_unmatched) {
            try err_w.print("       available: ", .{});
            for (active_manifest.links, 0..) |entry, i| {
                if (i > 0) try err_w.print(", ", .{});
                try err_w.print("{s}", .{entry.name});
            }
            try err_w.print("\n", .{});
            try err_w.flush();
            return LinkCmdError.LinkStepFailed;
        }
    }

    const d = try Dirs.detect(allocator, environ);
    defer d.deinit();
    var bin_dir = Dir.openDirAbsolute(io, d.bin, .{}) catch |err| {
        try err_w.print("error: failed to open bin directory '{s}': {t}\n", .{ d.bin, err });
        try err_w.flush();
        return LinkCmdError.LinkStepFailed;
    };
    defer bin_dir.close(io);

    if (try preflightUnlink(io, bin_dir, active_manifest.links, bin_filters)) |name| {
        try err_w.print(
            "error: {s}/{s} differs from the recorded target for install id '{s}'; refusing destructive unlink\n",
            .{ d.bin, name, id },
        );
        try err_w.flush();
        return LinkCmdError.LinkStepFailed;
    }

    var kept = std.ArrayListUnmanaged(LinkEntry).empty;
    defer kept.deinit(allocator);
    try kept.ensureTotalCapacity(allocator, active_manifest.links.len);
    for (active_manifest.links) |entry| {
        if (!linkWasRequested(entry, bin_filters)) kept.appendAssumeCapacity(entry);
    }
    const next_manifest_body: ?[]u8 = if (parsed != null and kept.items.len > 0)
        try stringifyIdManifest(
            allocator,
            id,
            parsed.?.value.unit_path.?,
            parsed.?.value.source,
            kept.items,
        )
    else
        null;
    defer if (next_manifest_body) |body| allocator.free(body);

    var applied = std.ArrayListUnmanaged(AppliedLink).empty;
    defer deinitAppliedLinks(allocator, &applied);
    try applied.ensureTotalCapacity(allocator, active_manifest.links.len);
    var manifest_committed = false;
    errdefer if (!manifest_committed) rollbackAppliedLinks(io, bin_dir, applied.items);
    var action_log = std.Io.Writer.Allocating.init(allocator);
    defer action_log.deinit();
    const action_w = &action_log.writer;

    for (active_manifest.links) |entry| {
        if (!linkWasRequested(entry, bin_filters)) continue;

        const outcome = removeOwnedIdEntry(allocator, io, bin_dir, entry) catch |err| {
            try err_w.print("error: failed to unlink {s}: {t}\n", .{ entry.name, err });
            try err_w.flush();
            return LinkCmdError.LinkStepFailed;
        };
        switch (outcome) {
            .removed => |prior_script_bytes| {
                applied.appendAssumeCapacity(.{ .removed = .{
                    .entry = entry,
                    .prior_script_bytes = prior_script_bytes,
                } });
                try action_w.print("  unlinked {s}\n", .{entry.name});
            },
            .missing => try action_w.print("  ok       {s} (already absent)\n", .{entry.name}),
            .target_mismatch => {
                try err_w.print(
                    "error: ownership of {s}/{s} changed during unlink; refusing to continue\n",
                    .{ d.bin, entry.name },
                );
                try err_w.flush();
                return LinkCmdError.LinkStepFailed;
            },
        }
    }

    if (legacy_candidate) |candidate| {
        try Dir.deleteFileAbsolute(io, candidate.path);
    } else if (kept.items.len == 0) {
        try deleteIdManifest(allocator, io, environ, id);
    } else {
        try persistIdManifestBody(
            allocator,
            io,
            environ,
            id,
            next_manifest_body.?,
        );
    }
    manifest_committed = true;
    try w.writeAll(action_log.written());
}

// ---------------------------------------------------------------------------
// Bare-executable mode: `ghr link <name>` / `ghr unlink <name>`.
//
// When the spec has no `/`, the user is asking ghr to link an executable
// that already exists on the Windows `%PATH%`, not a Windows-side ghr
// install. We resolve the path via `where.exe <name>.exe`, convert to
// `/mnt/<drive>/...` with `wslpath -u`, and create a symlink in ghr's
//   bin dir independently of install-ID linking.
//
// Bookkeeping lives in a separate manifest tree so the namespaces can't
// collide with any real GitHub owner/repo:
//
//   ~/.local/share/ghr/links/by-path/<name>.json
//
// The `kind` field is `"wsl-path"` so future readers can tell the two
// classes of manifest apart.
// ---------------------------------------------------------------------------

/// Validate a bare executable name supplied as the spec. Accepts a
/// short ASCII identifier optionally suffixed with `.exe` (any case).
/// Rejects any character that could be misread as a path, redirection,
/// flag, shell metacharacter, or `where.exe` query operator.
pub fn isValidBareExeName(name: []const u8) bool {
    if (name.len == 0 or name.len > 64) return false;
    if (name[0] == '-' or name[0] == '.') return false;
    for (name) |c| {
        switch (c) {
            'a'...'z', 'A'...'Z', '0'...'9', '_', '-', '.', '+' => {},
            else => return false,
        }
    }
    // Reject patterns like `..` or `.` even though `.` alone is caught above.
    if (std.mem.eql(u8, name, "..")) return false;
    if (std.mem.indexOf(u8, name, "..") != null) return false;
    return true;
}

/// Recognised resolvable extension for `ghr link <name>`. `.exe` is
/// linked via a symlink (WSL interop direct-executes the PE image).
/// `.cmd` and `.bat` require a bash wrapper that routes through
/// `cmd.exe`, because neither WSL interop nor `CreateProcessW` can
/// execute them directly. `.com` is treated like `.exe` (it's a PE).
const TargetKind = enum { exe, script };

/// Classify a resolved Windows-PATH path by its file extension.
/// Returns `null` for extensions we will not handle.
fn classifyTarget(path: []const u8) ?TargetKind {
    if (std.ascii.endsWithIgnoreCase(path, ".exe")) return .exe;
    if (std.ascii.endsWithIgnoreCase(path, ".com")) return .exe;
    if (std.ascii.endsWithIgnoreCase(path, ".cmd")) return .script;
    if (std.ascii.endsWithIgnoreCase(path, ".bat")) return .script;
    return null;
}

/// Drop a trailing executable extension recognised by `classifyTarget`.
/// `.exe`, `.com`, `.cmd`, `.bat` are all stripped (case-insensitive).
/// Returns the original slice when no recognised extension is present.
/// Borrows from the input.
fn stripExecutableExtension(name: []const u8) []const u8 {
    const exts = [_][]const u8{ ".exe", ".com", ".cmd", ".bat" };
    for (exts) |ext| {
        if (name.len > ext.len) {
            const tail = name[name.len - ext.len ..];
            if (std.ascii.eqlIgnoreCase(tail, ext)) return name[0 .. name.len - ext.len];
        }
    }
    return name;
}

/// Extract the first non-blank line from `where.exe` stdout. `where.exe`
/// emits one path per line in CRLF form, ordered by PATH precedence.
/// Returns `null` when there is no usable line.
pub fn parseFirstWherePath(stdout: []const u8) ?[]const u8 {
    var it = std.mem.tokenizeAny(u8, stdout, "\r\n");
    while (it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, &[_]u8{ ' ', '\t' });
        if (trimmed.len == 0) continue;
        return trimmed;
    }
    return null;
}

/// Pick the most appropriate path from `where.exe` output.
///
/// `where.exe <name>` lists every match in the current directory and on
/// `%PATH%`, including extensionless siblings of dispatchable files
/// (e.g. `wbin/az` is listed alongside `wbin/az.cmd`). cmd.exe itself
/// would dispatch via `PATHEXT` order, so `az` typed at a prompt runs
/// `az.cmd`. We mirror that by preferring matches whose extension is
/// in our supported set, ranked `.com > .exe > .cmd > .bat`. Within
/// the same rank, the earlier line wins (preserving `%PATH%`
/// precedence).
///
/// Falls back to the first non-blank line so callers can still report
/// a precise "unsupported extension" error for genuinely unrecognised
/// targets (e.g. `.ps1`).
pub fn pickBestWherePath(stdout: []const u8) ?[]const u8 {
    var fallback: ?[]const u8 = null;
    var best: ?[]const u8 = null;
    var best_rank: u8 = 255;
    var it = std.mem.tokenizeAny(u8, stdout, "\r\n");
    while (it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, &[_]u8{ ' ', '\t' });
        if (trimmed.len == 0) continue;
        if (fallback == null) fallback = trimmed;
        const rank = extensionRank(trimmed) orelse continue;
        if (rank < best_rank) {
            best = trimmed;
            best_rank = rank;
        }
    }
    return best orelse fallback;
}

/// Numeric rank for an extension recognised by `classifyTarget`. Lower
/// is preferred. Mirrors the default `PATHEXT` order so a dispatchable
/// file beats an extensionless sibling when both appear in the same
/// directory.
fn extensionRank(p: []const u8) ?u8 {
    if (std.ascii.endsWithIgnoreCase(p, ".com")) return 0;
    if (std.ascii.endsWithIgnoreCase(p, ".exe")) return 1;
    if (std.ascii.endsWithIgnoreCase(p, ".cmd")) return 2;
    if (std.ascii.endsWithIgnoreCase(p, ".bat")) return 3;
    return null;
}

/// True for a path that lives under a drvfs mount — i.e. `/mnt/<letter>/...`
/// with a single ASCII letter drive. Refuses `/mnt/wsl/...`, `/mnt/`,
/// `\\wsl$\...`, and anything else where WSL interop would not pass the
/// translated Win32 path through to CreateProcess.
pub fn looksLikeMntDrvfsPath(p: []const u8) bool {
    const prefix = "/mnt/";
    if (!std.mem.startsWith(u8, p, prefix)) return false;
    if (p.len < prefix.len + 2) return false;
    const drive = p[prefix.len];
    if (!std.ascii.isAlphabetic(drive)) return false;
    if (p[prefix.len + 1] != '/') return false;
    return true;
}

/// Full path of the bare-exec manifest file for `name_lower`. Owned by caller.
fn bareExeManifestPath(
    allocator: std.mem.Allocator,
    environ: *const EnvironMap,
    name_lower: []const u8,
) ![]u8 {
    const root = try linksRoot(allocator, environ);
    defer allocator.free(root);
    var fname_buf: [128]u8 = undefined;
    const fname = try std.fmt.bufPrint(&fname_buf, "{s}.json", .{name_lower});
    return std.fs.path.join(allocator, &.{ root, "by-path", fname });
}

/// Containing directory of bare-exec manifests. Owned by caller.
fn bareExeManifestDir(
    allocator: std.mem.Allocator,
    environ: *const EnvironMap,
) ![]u8 {
    const root = try linksRoot(allocator, environ);
    defer allocator.free(root);
    return std.fs.path.join(allocator, &.{ root, "by-path" });
}

/// Atomically write a bare-exec manifest at `by-path/<name_lower>.json`.
/// Mirrors `writeManifest` but uses the flat `by-path/` tree and stamps
/// `kind = "wsl-path"`.
fn writeBareExeManifest(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    name_lower: []const u8,
    source: []const u8,
    entry: LinkEntry,
) !void {
    var body_writer = std.Io.Writer.Allocating.init(allocator);
    defer body_writer.deinit();
    const body_w = &body_writer.writer;
    try body_w.print("{{\"kind\":\"wsl-path\",\"source\":\"", .{});
    try writeJsonEscaped(body_w, source);
    try body_w.print("\",\"links\":[{{\"name\":\"", .{});
    try writeJsonEscaped(body_w, entry.name);
    try body_w.print("\",\"target\":\"", .{});
    try writeJsonEscaped(body_w, entry.target);
    try body_w.print("\",\"target_kind\":\"", .{});
    try writeJsonEscaped(body_w, entry.target_kind);
    try body_w.print("\"}}]}}\n", .{});
    if (body_writer.written().len > max_manifest_bytes) return error.ManifestTooLarge;

    const dir = try bareExeManifestDir(allocator, environ);
    defer allocator.free(dir);
    install.ensureDirAbsoluteRecursive(io, dir) catch {};

    const final_path = try bareExeManifestPath(allocator, environ, name_lower);
    defer allocator.free(final_path);
    const tmp_path = try allocator.print("{s}.tmp", .{final_path});
    defer allocator.free(tmp_path);

    Dir.deleteFileAbsolute(io, tmp_path) catch {};

    {
        var f = try Dir.createFileAbsolute(io, tmp_path, .{});
        defer f.close(io);
        try f.writeStreamingAll(io, body_writer.written());
    }

    Dir.renameAbsolute(tmp_path, final_path, io) catch |err| {
        Dir.deleteFileAbsolute(io, tmp_path) catch {};
        return err;
    };
}

fn deleteBareExeManifest(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    name_lower: []const u8,
) !void {
    const final_path = try bareExeManifestPath(allocator, environ, name_lower);
    defer allocator.free(final_path);
    Dir.deleteFileAbsolute(io, final_path) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
}

/// Run `where.exe <query>` via WSL interop and return its trimmed stdout.
/// Caller owns the returned slice. Returns `error.NotFound` when
/// `where.exe` exits non-zero (the canonical "no match" outcome) or
/// when its stdout is empty.
fn runWhereExe(allocator: std.mem.Allocator, io: Io, query: []const u8) ![]u8 {
    const r = std.process.run(allocator, io, .{
        .argv = &.{ "where.exe", query },
        .stdout_limit = Io.Limit.limited(64 * 1024),
        .stderr_limit = Io.Limit.limited(16 * 1024),
    }) catch return error.WhereExeFailed;
    defer allocator.free(r.stderr);
    errdefer allocator.free(r.stdout);
    if (r.term != .exited or r.term.exited != 0) {
        allocator.free(r.stdout);
        return error.NotFound;
    }
    if (pickBestWherePath(r.stdout) == null) {
        allocator.free(r.stdout);
        return error.NotFound;
    }
    return r.stdout;
}

// Magic comment that marks a bash wrapper script as created by `ghr link --path`.
// Used at unlink time so we never delete a file the user wrote themselves.
const WRAPPER_MAGIC = "# ghr-link wrapper";

// Distinct magic comment for `ghr link <id>` wrapper scripts so `--path` mode
// (`WRAPPER_MAGIC`) can never treat an ID-owned wrapper as bare-PATH owned.
pub const ID_WRAPPER_MAGIC = "# ghr-link-id wrapper";

fn writeBashSingleQuotedEscaped(w: *Writer, s: []const u8) !void {
    for (s) |c| {
        if (c == '\'') {
            try w.writeAll("'\\''");
        } else {
            try w.writeByte(c);
        }
    }
}

/// Build the bash wrapper script bytes for a `.cmd` command owned by a v2
/// install ID. Uses `cmd.exe /d /c call '<win_path>' "$@"` so AutoRun is
/// disabled (`/d`) and `cmd.exe` does not strip outer quotes when `<win_path>`
/// contains spaces (e.g. `C:\Users\John Smith\...`) alongside quoted user args.
pub fn buildIdWrapperScript(
    allocator: std.mem.Allocator,
    id: []const u8,
    link_name: []const u8,
    cmd_exe_wsl: []const u8,
    win_path: []const u8,
) ![]u8 {
    var w = std.Io.Writer.Allocating.init(allocator);
    errdefer w.deinit();
    try w.writer.print(
        "#!/usr/bin/env bash\n" ++
            ID_WRAPPER_MAGIC ++ " for {s} ({s})\n" ++
            "# Created by 'ghr link {s}'. Edit at your own risk; 'ghr unlink {s}'\n" ++
            "# refuses to remove a wrapper whose contents have been changed.\n" ++
            "exec '",
        .{ id, link_name, id, id },
    );
    try writeBashSingleQuotedEscaped(&w.writer, cmd_exe_wsl);
    try w.writer.writeAll("' /d /c call '");
    try writeBashSingleQuotedEscaped(&w.writer, win_path);
    try w.writer.writeAll("' \"$@\"\n");
    return w.toOwnedSlice();
}

/// Build the bash wrapper script bytes for a `.cmd`/`.bat` target. The
/// returned slice is owned by `allocator`.
///
/// The wrapper invokes `cmd.exe /c '<win_path>' "$@"` via WSL interop.
/// `cmd.exe` is referenced by absolute drvfs path so the wrapper works
/// regardless of the user's `$PATH`. The Windows target path is single-
/// quoted in bash with the `'\''` escape pattern so spaces and `&`
/// characters in path components (e.g. `Program Files`) cannot break
/// argument parsing.
pub fn buildWrapperScript(
    allocator: std.mem.Allocator,
    link_name: []const u8,
    win_path: []const u8,
) ![]u8 {
    var w = std.Io.Writer.Allocating.init(allocator);
    errdefer w.deinit();
    try w.writer.print(
        "#!/usr/bin/env bash\n" ++
            WRAPPER_MAGIC ++ " for {s}\n" ++
            "# Created by 'ghr link {s}'. Edit at your own risk; 'ghr unlink {s}'\n" ++
            "# refuses to remove a wrapper whose contents have been changed.\n" ++
            "exec '/mnt/c/Windows/System32/cmd.exe' /c '",
        .{ link_name, link_name, link_name },
    );
    // Escape single quotes in the Windows path so the bash single-quoted
    // string above stays well-formed: ' -> '\''
    for (win_path) |c| {
        if (c == '\'') {
            try w.writer.print("'\\''", .{});
        } else {
            try w.writer.print("{c}", .{c});
        }
    }
    try w.writer.print("' \"$@\"\n", .{});
    return w.toOwnedSlice();
}

/// Verify that `bytes` is a wrapper script we created, by checking for
/// the magic comment AND the literal `'<expected_win_path>'` argument
/// to cmd.exe. Returns false on any mismatch — at which point unlink
/// leaves the file alone instead of clobbering user edits.
pub fn wrapperMatches(allocator: std.mem.Allocator, bytes: []const u8, expected_win_path: []const u8) !bool {
    if (std.mem.indexOf(u8, bytes, WRAPPER_MAGIC) == null) return false;
    // The Windows path appears inside `cmd.exe /c '...'` with single
    // quotes escaped as '\''. Re-encode the expected path the same way
    // and check the wrapped form appears literally.
    var quoted = std.ArrayListUnmanaged(u8).empty;
    defer quoted.deinit(allocator);
    try quoted.append(allocator, '\'');
    for (expected_win_path) |c| {
        if (c == '\'') {
            try quoted.appendSlice(allocator, "'\\''");
        } else {
            try quoted.append(allocator, c);
        }
    }
    try quoted.append(allocator, '\'');
    return std.mem.indexOf(u8, bytes, quoted.items) != null;
}

pub fn cmdLinkBareExe(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    name: []const u8,
    bin_filters: []const []const u8,
    w: *Writer,
    err_w: *Writer,
) !void {
    requireWsl(environ, err_w, "link") catch return LinkCmdError.LinkStepFailed;

    if (bin_filters.len > 0) {
        try err_w.print("error: '--bin' is not supported with a bare executable name\n", .{});
        try err_w.print("       (the bare-name form links exactly one Windows-PATH executable)\n", .{});
        try err_w.flush();
        return LinkCmdError.LinkStepFailed;
    }

    if (!isValidBareExeName(name)) {
        try err_w.print("error: invalid spec '{s}'\n", .{name});
        try err_w.print("       expected either <owner/repo> or a bare executable name (e.g. 'git')\n", .{});
        try err_w.print("       allowed characters: letters, digits, '_', '-', '.', '+'\n", .{});
        try err_w.flush();
        return LinkCmdError.LinkStepFailed;
    }

    // Pass the user-supplied name as-is to where.exe so PATHEXT does its
    // job: `where.exe az` returns `az.cmd` if that's the first match on
    // PATH, `where.exe git` returns `git.exe`. We accept whichever
    // extension comes back and dispatch on it below.
    const where_out = runWhereExe(allocator, io, name) catch |err| switch (err) {
        error.NotFound => {
            try err_w.print("error: '{s}' was not found on the Windows %PATH%\n", .{name});
            try err_w.print("       (looked up via `where.exe {s}`)\n", .{name});
            try err_w.flush();
            return LinkCmdError.LinkStepFailed;
        },
        error.WhereExeFailed => {
            try err_w.print("error: failed to run `where.exe` via WSL interop\n", .{});
            try err_w.flush();
            return LinkCmdError.LinkStepFailed;
        },
    };
    defer allocator.free(where_out);

    const win_path_raw = pickBestWherePath(where_out) orelse {
        try err_w.print("error: `where.exe {s}` returned no usable path\n", .{name});
        try err_w.flush();
        return LinkCmdError.LinkStepFailed;
    };
    const win_path = try allocator.dupe(u8, win_path_raw);
    defer allocator.free(win_path);

    const wsl_path = wslpathToUnix(allocator, io, win_path) catch {
        try err_w.print(
            "error: could not convert Windows path '{s}' to a WSL path\n",
            .{win_path},
        );
        try err_w.flush();
        return LinkCmdError.LinkStepFailed;
    };
    defer allocator.free(wsl_path);

    if (!looksLikeMntDrvfsPath(wsl_path)) {
        try err_w.print(
            "error: resolved path '{s}' is not under /mnt/<drive>/ (drvfs); refusing to link\n",
            .{wsl_path},
        );
        try err_w.print("       WSL interop only runs Windows executables reached via /mnt/<letter>/\n", .{});
        try err_w.flush();
        return LinkCmdError.LinkStepFailed;
    }

    // Dispatch on the resolved extension. `.exe`/`.com` get a direct
    // symlink (WSL interop direct-executes the PE image). `.cmd`/`.bat`
    // get a bash wrapper that routes through `cmd.exe`, because neither
    // WSL interop nor `CreateProcessW` can run them directly. Everything
    // else (notably `.ps1`) is rejected; running PowerShell scripts
    // properly requires a different launcher and quoting model.
    const kind = classifyTarget(wsl_path) orelse {
        try err_w.print(
            "error: resolved path '{s}' has an unsupported extension\n",
            .{wsl_path},
        );
        try err_w.print("       supported: .exe, .com (symlink), .cmd, .bat (bash wrapper via cmd.exe)\n", .{});
        try err_w.flush();
        return LinkCmdError.LinkStepFailed;
    };

    Dir.accessAbsolute(io, wsl_path, .{}) catch |err| {
        try err_w.print(
            "error: resolved path '{s}' does not exist in WSL: {t}\n",
            .{ wsl_path, err },
        );
        try err_w.flush();
        return LinkCmdError.LinkStepFailed;
    };

    const link_name_raw = std.fs.path.basenamePosix(wsl_path);
    const link_name = stripExecutableExtension(link_name_raw);
    if (link_name.len == 0) {
        try err_w.print("error: derived link name is empty for '{s}'\n", .{wsl_path});
        try err_w.flush();
        return LinkCmdError.LinkStepFailed;
    }

    var name_lower_buf: [128]u8 = undefined;
    if (link_name.len > name_lower_buf.len) {
        try err_w.print("error: derived link name '{s}' exceeds 128 bytes\n", .{link_name});
        try err_w.flush();
        return LinkCmdError.LinkStepFailed;
    }
    for (link_name, 0..) |c, i| name_lower_buf[i] = std.ascii.toLower(c);
    const name_lower = name_lower_buf[0..link_name.len];

    const d = try Dirs.detect(allocator, environ);
    defer d.deinit();
    install.ensureDirAbsoluteRecursive(io, d.bin) catch {};
    var bin_dir = Dir.openDirAbsolute(io, d.bin, .{}) catch |err| {
        try err_w.print("error: failed to open bin directory '{s}': {t}\n", .{ d.bin, err });
        try err_w.flush();
        return LinkCmdError.LinkStepFailed;
    };
    defer bin_dir.close(io);

    // Load any prior bare-exec manifest so we can recognise our own
    // entry and avoid adopting a foreign one with the same target.
    const manifest_abs = try bareExeManifestPath(allocator, environ, name_lower);
    defer allocator.free(manifest_abs);
    var prior_parsed = readManifest(allocator, io, manifest_abs) catch |err| switch (err) {
        error.InvalidManifest => blk: {
            try err_w.print("warning: ignoring corrupt manifest at {s}\n", .{manifest_abs});
            break :blk null;
        },
        else => return err,
    };
    defer if (prior_parsed) |*p| p.deinit();
    const prior_links: []const LinkEntry = if (prior_parsed) |p| p.value.links else &.{};

    // Look up whether the prior manifest already records this name, so
    // we can distinguish "ghr is updating its own entry" from "something
    // else owns this name; bail out".
    var prior_owned: ?LinkEntry = null;
    for (prior_links) |old| {
        if (std.mem.eql(u8, old.name, link_name)) {
            prior_owned = old;
            break;
        }
    }

    switch (kind) {
        .exe => try installSymlinkEntry(io, bin_dir, d.bin, link_name, wsl_path, prior_owned, w, err_w),
        .script => try installWrapperEntry(allocator, io, bin_dir, d.bin, link_name, wsl_path, win_path, prior_owned, w, err_w),
    }

    // Persist the manifest with the (possibly updated) target + kind.
    const target_for_manifest = switch (kind) {
        .exe => wsl_path,
        // For wrapper scripts, store the Windows path so unlink can
        // re-derive the literal embedded in the wrapper without
        // shelling out to wslpath at teardown time.
        .script => win_path,
    };
    const kind_str: []const u8 = switch (kind) {
        .exe => "symlink",
        .script => "script",
    };
    try writeBareExeManifest(allocator, io, environ, name_lower, wsl_path, .{
        .name = link_name,
        .target = target_for_manifest,
        .target_kind = kind_str,
    });
}

/// Create or refresh a symlink entry. Factored out of `cmdLinkBareExe`
/// so the `.exe` and `.cmd` branches each stay readable. The
/// already-loaded prior manifest entry (if any) is consulted to decide
/// adopt-vs-overwrite-vs-conflict.
fn installSymlinkEntry(
    io: Io,
    bin_dir: Dir,
    bin_dir_str: []const u8,
    link_name: []const u8,
    wsl_path: []const u8,
    prior_owned: ?LinkEntry,
    w: *Writer,
    err_w: *Writer,
) !void {
    var link_buf: [Dir.max_path_bytes]u8 = undefined;
    if (bin_dir.readLink(io, link_name, &link_buf)) |n| {
        const current = link_buf[0..n];
        const owned_by_us = prior_owned != null;
        if (std.mem.eql(u8, current, wsl_path) and owned_by_us) {
            try w.print("  ok       {s} -> {s}\n", .{ link_name, wsl_path });
            return;
        }
        if (!owned_by_us) {
            try err_w.print(
                "error: {s}/{s} already exists and is not a ghr-created link; refusing to overwrite\n",
                .{ bin_dir_str, link_name },
            );
            try err_w.flush();
            return LinkCmdError.LinkStepFailed;
        }
        bin_dir.deleteFile(io, link_name) catch {};
        try bin_dir.symLink(io, wsl_path, link_name, .{});
        try w.print("  updated  {s} -> {s}\n", .{ link_name, wsl_path });
    } else |err| switch (err) {
        error.FileNotFound => {
            // No symlink — but could still be a regular file or directory
            // (e.g. an old wrapper from a prior `.cmd` link). Adopt it
            // only when our manifest already owns this name.
            if (bin_dir.statFile(io, link_name, .{})) |_| {
                if (prior_owned == null) {
                    try err_w.print(
                        "error: {s}/{s} already exists and is not a symlink; refusing to overwrite\n",
                        .{ bin_dir_str, link_name },
                    );
                    try err_w.flush();
                    return LinkCmdError.LinkStepFailed;
                }
                bin_dir.deleteFile(io, link_name) catch {};
            } else |_| {}
            try bin_dir.symLink(io, wsl_path, link_name, .{});
            try w.print("  linked   {s} -> {s}\n", .{ link_name, wsl_path });
        },
        error.NotLink => {
            if (prior_owned == null) {
                try err_w.print(
                    "error: {s}/{s} already exists and is not a symlink; refusing to overwrite\n",
                    .{ bin_dir_str, link_name },
                );
                try err_w.flush();
                return LinkCmdError.LinkStepFailed;
            }
            bin_dir.deleteFile(io, link_name) catch {};
            try bin_dir.symLink(io, wsl_path, link_name, .{});
            try w.print("  updated  {s} -> {s}\n", .{ link_name, wsl_path });
        },
        else => return err,
    }
}

/// Create or refresh a bash wrapper file that routes through cmd.exe.
/// `win_path` is the Windows-style target path embedded into the
/// wrapper; `wsl_path` is reported in user-facing messages.
fn installWrapperEntry(
    allocator: std.mem.Allocator,
    io: Io,
    bin_dir: Dir,
    bin_dir_str: []const u8,
    link_name: []const u8,
    wsl_path: []const u8,
    win_path: []const u8,
    prior_owned: ?LinkEntry,
    w: *Writer,
    err_w: *Writer,
) !void {
    const new_bytes = try buildWrapperScript(allocator, link_name, win_path);
    defer allocator.free(new_bytes);

    // Inspect what's currently at `link_name`. We accept three states:
    //   * absent             -> create
    //   * existing symlink   -> only adopt if our manifest owns it; replace
    //   * existing wrapper   -> if magic+target match -> "ok"
    //                            elif owned by us       -> "updated"
    //                            else                   -> conflict
    //   * unrelated file     -> conflict
    var link_buf: [Dir.max_path_bytes]u8 = undefined;
    const link_outcome = bin_dir.readLink(io, link_name, &link_buf);
    if (link_outcome) |_| {
        if (prior_owned == null) {
            try err_w.print(
                "error: {s}/{s} already exists as a symlink and is not a ghr-created entry; refusing to overwrite\n",
                .{ bin_dir_str, link_name },
            );
            try err_w.flush();
            return LinkCmdError.LinkStepFailed;
        }
        bin_dir.deleteFile(io, link_name) catch {};
        try writeWrapperFile(io, bin_dir, link_name, new_bytes);
        try w.print("  updated  {s} -> {s} (via cmd.exe)\n", .{ link_name, wsl_path });
        return;
    } else |readlink_err| switch (readlink_err) {
        error.FileNotFound => {
            // Nothing in the way (no symlink AND no regular file).
            if (bin_dir.statFile(io, link_name, .{})) |_| {
                // The stat surfaced something: it's a regular file or
                // directory. Fall through to the existing-file branch.
            } else |_| {
                try writeWrapperFile(io, bin_dir, link_name, new_bytes);
                try w.print("  linked   {s} -> {s} (via cmd.exe)\n", .{ link_name, wsl_path });
                return;
            }
        },
        error.NotLink => {}, // existing regular file; handled below
        else => return readlink_err,
    }

    // Existing regular file path: read it and decide based on contents.
    const existing = readFileBytes(allocator, io, bin_dir, link_name, 64 * 1024) catch |err| {
        try err_w.print("warning: failed to read existing {s}/{s}: {t}\n", .{ bin_dir_str, link_name, err });
        try err_w.flush();
        return LinkCmdError.LinkStepFailed;
    };
    defer allocator.free(existing);

    if (std.mem.eql(u8, existing, new_bytes)) {
        try w.print("  ok       {s} -> {s} (via cmd.exe)\n", .{ link_name, wsl_path });
        return;
    }

    const looks_like_ours = std.mem.indexOf(u8, existing, WRAPPER_MAGIC) != null;
    if (prior_owned != null or looks_like_ours) {
        bin_dir.deleteFile(io, link_name) catch {};
        try writeWrapperFile(io, bin_dir, link_name, new_bytes);
        try w.print("  updated  {s} -> {s} (via cmd.exe)\n", .{ link_name, wsl_path });
        return;
    }

    try err_w.print(
        "error: {s}/{s} already exists and is not a ghr-created wrapper; refusing to overwrite\n",
        .{ bin_dir_str, link_name },
    );
    try err_w.flush();
    return LinkCmdError.LinkStepFailed;
}

/// Atomically write `bytes` to `bin_dir/<name>` with the executable bit
/// set. Goes through a `.tmp` companion + rename so a crashed writer
/// can never leave a half-written wrapper that bash would mis-execute.
fn writeWrapperFile(io: Io, bin_dir: Dir, name: []const u8, bytes: []const u8) !void {
    var tmp_buf: [Dir.max_path_bytes]u8 = undefined;
    const tmp_name = std.fmt.bufPrint(&tmp_buf, "{s}.tmp", .{name}) catch return error.PathTooLong;
    bin_dir.deleteFile(io, tmp_name) catch {};
    {
        var f = try bin_dir.createFile(io, tmp_name, .{ .permissions = .executable_file });
        defer f.close(io);
        try f.writeStreamingAll(io, bytes);
    }
    bin_dir.rename(tmp_name, bin_dir, name, io) catch |err| {
        bin_dir.deleteFile(io, tmp_name) catch {};
        return err;
    };
}

/// Slurp a regular file into a heap-allocated buffer. Caller owns the
/// returned slice. Refuses files larger than `max_bytes` to avoid an
/// arbitrarily-large allocation if the user replaced our wrapper with
/// something huge.
fn readFileBytes(
    allocator: std.mem.Allocator,
    io: Io,
    bin_dir: Dir,
    name: []const u8,
    max_bytes: usize,
) ![]u8 {
    var f = try bin_dir.openFile(io, name, .{});
    defer f.close(io);
    var read_buf: [4096]u8 = undefined;
    var reader = f.reader(io, &read_buf);
    var aw = std.Io.Writer.Allocating.init(allocator);
    defer aw.deinit();
    _ = reader.interface.streamRemaining(&aw.writer) catch |err| return err;
    if (aw.written().len > max_bytes) return error.FileTooBig;
    return aw.toOwnedSlice();
}

pub fn cmdUnlinkBareExe(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    name: []const u8,
    bin_filters: []const []const u8,
    w: *Writer,
    err_w: *Writer,
) !void {
    requireWsl(environ, err_w, "unlink") catch return LinkCmdError.LinkStepFailed;

    if (bin_filters.len > 0) {
        try err_w.print("error: '--bin' is not supported with a bare executable name\n", .{});
        try err_w.flush();
        return LinkCmdError.LinkStepFailed;
    }

    if (!isValidBareExeName(name)) {
        try err_w.print("error: invalid spec '{s}'\n", .{name});
        try err_w.print("       expected either <owner/repo> or a bare executable name (e.g. 'git')\n", .{});
        try err_w.flush();
        return LinkCmdError.LinkStepFailed;
    }

    // Manifest key is the link name (basename minus its executable
    // extension) lowercased.
    const link_name_raw = stripExecutableExtension(name);
    var name_lower_buf: [128]u8 = undefined;
    if (link_name_raw.len == 0 or link_name_raw.len > name_lower_buf.len) {
        try err_w.print("error: invalid bare executable name '{s}'\n", .{name});
        try err_w.flush();
        return LinkCmdError.LinkStepFailed;
    }
    for (link_name_raw, 0..) |c, i| name_lower_buf[i] = std.ascii.toLower(c);
    const name_lower = name_lower_buf[0..link_name_raw.len];

    const manifest_abs = try bareExeManifestPath(allocator, environ, name_lower);
    defer allocator.free(manifest_abs);
    var parsed = readManifest(allocator, io, manifest_abs) catch |err| switch (err) {
        error.InvalidManifest => null,
        else => return err,
    };
    defer if (parsed) |*p| p.deinit();

    const p = parsed orelse {
        try err_w.print("error: no link manifest for bare executable '{s}'\n", .{name});
        try err_w.print("       (looked at {s})\n", .{manifest_abs});
        try err_w.flush();
        return LinkCmdError.LinkStepFailed;
    };

    const d = try Dirs.detect(allocator, environ);
    defer d.deinit();
    var bin_dir = Dir.openDirAbsolute(io, d.bin, .{}) catch |err| {
        try err_w.print("error: failed to open bin directory '{s}': {t}\n", .{ d.bin, err });
        try err_w.flush();
        return LinkCmdError.LinkStepFailed;
    };
    defer bin_dir.close(io);

    var any_kept = false;
    for (p.value.links) |entry| {
        // Dispatch on the recorded entry kind. Older manifests omit
        // `target_kind` and parse as "symlink", preserving the existing
        // behaviour for owner/repo and pre-script bare-exec entries.
        if (std.mem.eql(u8, entry.target_kind, "script")) {
            const outcome = removeOwnedWrapper(allocator, io, bin_dir, entry) catch |err| {
                try err_w.print("warning: failed to unlink {s}: {t}\n", .{ entry.name, err });
                any_kept = true;
                continue;
            };
            switch (outcome) {
                .removed => try w.print("  unlinked {s}\n", .{entry.name}),
                .missing => try w.print("  ok       {s} (already absent)\n", .{entry.name}),
                .target_mismatch => {
                    try err_w.print(
                        "warning: {s}/{s} is not a ghr-created wrapper (or its target changed); leaving it alone\n",
                        .{ d.bin, entry.name },
                    );
                    any_kept = true;
                },
            }
        } else {
            const outcome = removeOwnedLink(io, bin_dir, entry) catch |err| {
                try err_w.print("warning: failed to unlink {s}: {t}\n", .{ entry.name, err });
                any_kept = true;
                continue;
            };
            switch (outcome) {
                .removed => try w.print("  unlinked {s}\n", .{entry.name}),
                .missing => try w.print("  ok       {s} (already absent)\n", .{entry.name}),
                .target_mismatch => {
                    try err_w.print(
                        "warning: {s}/{s} no longer points where ghr recorded it; leaving it alone\n",
                        .{ d.bin, entry.name },
                    );
                    any_kept = true;
                },
            }
        }
    }

    if (!any_kept) {
        deleteBareExeManifest(allocator, io, environ, name_lower) catch {};
    }
}

/// Remove a wrapper-script entry safely: read the file, verify the
/// magic comment and embedded Windows target match what the manifest
/// recorded, then delete. Same safety posture as `removeOwnedLink` —
/// a user-rewritten wrapper is reported as a target_mismatch and left
/// in place.
fn removeOwnedWrapper(
    allocator: std.mem.Allocator,
    io: Io,
    bin_dir: Dir,
    entry: LinkEntry,
) !RemoveOutcome {
    const existing = readFileBytes(allocator, io, bin_dir, entry.name, 64 * 1024) catch |err| switch (err) {
        error.FileNotFound => return .missing,
        else => return err,
    };
    defer allocator.free(existing);

    if (!try wrapperMatches(allocator, existing, entry.target)) return .target_mismatch;
    try bin_dir.deleteFile(io, entry.name);
    return .removed;
}

// ---------------------------------------------------------------------------
// Tests for the pure helpers.
// ---------------------------------------------------------------------------

fn testAbsoluteChild(
    allocator: std.mem.Allocator,
    base: []const u8,
    child: []const u8,
) ![]u8 {
    return std.fs.path.join(allocator, &.{ base, child });
}

fn writeTestV2Unit(
    allocator: std.mem.Allocator,
    io: Io,
    tools: []const u8,
    id: []const u8,
    command_name: []const u8,
    relative_target: []const u8,
) !void {
    const relative_unit = try install_state.encodeRelPath(allocator, id);
    defer allocator.free(relative_unit);
    const unit = try std.fs.path.join(allocator, &.{ tools, relative_unit });
    defer allocator.free(unit);
    try install.ensureDirAbsoluteRecursive(io, unit);

    const target = try std.fs.path.join(allocator, &.{ unit, relative_target });
    defer allocator.free(target);
    if (std.fs.path.dirname(target)) |parent| try install.ensureDirAbsoluteRecursive(io, parent);
    {
        var file = try Dir.createFileAbsolute(io, target, .{});
        defer file.close(io);
        try file.writeStreamingAll(io, "test\n");
    }

    const body = try install_state_write.stringify(allocator, .{
        .id = id,
        .source = .{ .kind = .github, .owner = "cataggar", .repo = "zig", .tag = "v1" },
        .resolved = .{ .tag = "v1", .asset = "zig.zip" },
        .commands = &.{.{
            .name = command_name,
            .relative_target = relative_target,
            .kind = .native,
        }},
        .verification = .{ .result = "none" },
    }, .windows);
    defer allocator.free(body);
    const metadata = try std.fs.path.join(allocator, &.{ unit, install_state.metadata_file });
    defer allocator.free(metadata);
    var file = try Dir.createFileAbsolute(io, metadata, .{});
    defer file.close(io);
    try file.writeStreamingAll(io, body);
}

fn initLinkTestEnv(
    env: *EnvironMap,
    base: []const u8,
    tools: []const u8,
    bin: []const u8,
) !void {
    try env.put("WSL_INTEROP", "test");
    try env.put("GHR_WIN_TOOLS_DIR", tools);
    try env.put("GHR_BIN_DIR", bin);
    try env.put("XDG_DATA_HOME", base);
    try env.put("GHR_CACHE_DIR", base);
}

test "normalizeBinPathInPlace: replaces backslashes" {
    var buf = [_]u8{ 'b', 'i', 'n', '\\', 'f', 'o', 'o', '.', 'e', 'x', 'e' };
    normalizeBinPathInPlace(&buf);
    try std.testing.expectEqualStrings("bin/foo.exe", &buf);
}

test "normalizeBinPathInPlace: leaves already-clean alone" {
    var buf = [_]u8{ 'b', 'i', 'n', '/', 'f', 'o', 'o' };
    normalizeBinPathInPlace(&buf);
    try std.testing.expectEqualStrings("bin/foo", &buf);
}

test "isSafeRelativeBinPath: rejects unsafe inputs" {
    try std.testing.expect(!isSafeRelativeBinPath(""));
    try std.testing.expect(!isSafeRelativeBinPath("/abs/path"));
    try std.testing.expect(!isSafeRelativeBinPath("C:/foo"));
    try std.testing.expect(!isSafeRelativeBinPath("c:/foo"));
    try std.testing.expect(!isSafeRelativeBinPath("../escape"));
    try std.testing.expect(!isSafeRelativeBinPath("bin/../escape"));
    try std.testing.expect(!isSafeRelativeBinPath("./relative"));
}

test "isSafeRelativeBinPath: accepts plain relative" {
    try std.testing.expect(isSafeRelativeBinPath("foo.exe"));
    try std.testing.expect(isSafeRelativeBinPath("bin/foo.exe"));
    try std.testing.expect(isSafeRelativeBinPath("sub/dir/tool.exe"));
}

test "linkNameForBin: strips trailing .exe case-insensitively" {
    try std.testing.expectEqualStrings("foo", linkNameForBin("foo.exe"));
    try std.testing.expectEqualStrings("foo", linkNameForBin("foo.EXE"));
    try std.testing.expectEqualStrings("foo", linkNameForBin("bin/foo.Exe"));
    try std.testing.expectEqualStrings("tool", linkNameForBin("sub/dir/tool"));
    // .exe in the middle is not a tail strip.
    try std.testing.expectEqualStrings("foo.exec", linkNameForBin("foo.exec"));
    // Just ".exe" with no stem -> empty, not stripped (length-guard).
    try std.testing.expectEqualStrings(".exe", linkNameForBin(".exe"));
}

test "looksLikeWindowsPath: recognizes drive-letter prefixes" {
    try std.testing.expect(looksLikeWindowsPath("C:\\foo"));
    try std.testing.expect(looksLikeWindowsPath("c:/foo"));
    try std.testing.expect(looksLikeWindowsPath("Z:\\Users\\x"));
    try std.testing.expect(!looksLikeWindowsPath("/mnt/c/foo"));
    try std.testing.expect(!looksLikeWindowsPath(""));
    try std.testing.expect(!looksLikeWindowsPath("C:"));
}

test "manifest write/read round-trip" {
    const allocator = std.testing.allocator;
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &path_buf);
    const base = path_buf[0..base_len];

    var env = EnvironMap.init(allocator);
    defer env.deinit();
    try env.put("XDG_DATA_HOME", base);

    var links_buf = [_]LinkEntry{
        .{ .name = "azureauth", .target = "/mnt/c/Users/x/AppData/Roaming/ghr/data/tools/azuread/foo/azureauth.exe" },
    };
    try writeManifest(allocator, tio, &env, "azuread", "foo", .{
        .source = "/mnt/c/Users/x/AppData/Roaming/ghr/data/tools/azuread/foo",
        .links = &links_buf,
    });

    const final_abs = try manifestPath(allocator, &env, "azuread", "foo");
    defer allocator.free(final_abs);
    const parsed = (try readManifest(allocator, tio, final_abs)) orelse {
        try std.testing.expect(false);
        return;
    };
    defer parsed.deinit();
    try std.testing.expectEqualStrings("wsl", parsed.value.kind);
    try std.testing.expectEqualStrings(
        "/mnt/c/Users/x/AppData/Roaming/ghr/data/tools/azuread/foo",
        parsed.value.source,
    );
    try std.testing.expectEqual(@as(usize, 1), parsed.value.links.len);
    try std.testing.expectEqualStrings("azureauth", parsed.value.links[0].name);
    try std.testing.expectEqualStrings(
        "/mnt/c/Users/x/AppData/Roaming/ghr/data/tools/azuread/foo/azureauth.exe",
        parsed.value.links[0].target,
    );
}

test "ID manifest path is encoded and prefix-safe" {
    const allocator = std.testing.allocator;
    var env = EnvironMap.init(allocator);
    defer env.deinit();
    try env.put("XDG_DATA_HOME", "/home/u/.local/share");

    const parent = try idManifestPath(allocator, &env, "a");
    defer allocator.free(parent);
    const child = try idManifestPath(allocator, &env, "a/b");
    defer allocator.free(child);

    try std.testing.expect(std.mem.indexOf(u8, parent, "by-id") != null);
    try std.testing.expect(std.mem.indexOf(u8, parent, "u-a") != null);
    try std.testing.expect(std.mem.endsWith(u8, parent, "_manifest.json"));
    try std.testing.expect(std.mem.indexOf(u8, child, "u-a") != null);
    try std.testing.expect(std.mem.indexOf(u8, child, "u-b") != null);
    try std.testing.expect(!std.mem.eql(u8, parent, child));
    try std.testing.expectError(error.InvalidId, idManifestPath(allocator, &env, "../escape"));
    try std.testing.expectError(error.InvalidId, idManifestPath(allocator, &env, "Upper"));
}

test "ID manifest write and strict read round-trip" {
    const allocator = std.testing.allocator;
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &path_buf);
    const base = path_buf[0..base_len];

    var env = EnvironMap.init(allocator);
    defer env.deinit();
    try env.put("XDG_DATA_HOME", base);

    const links = [_]LinkEntry{.{
        .name = "zigb",
        .target = "/mnt/c/ghr/tools/_v2/units/u-zigb/_unit/zig.exe",
    }};
    try writeIdManifest(
        allocator,
        tio,
        &env,
        "zigb",
        "_v2/units/u-zigb/_unit",
        "/mnt/c/ghr/tools/_v2/units/u-zigb/_unit",
        &links,
    );

    const path = try idManifestPath(allocator, &env, "zigb");
    defer allocator.free(path);
    const parsed = (try readIdManifest(allocator, tio, path, "zigb")).?;
    defer parsed.deinit();
    try std.testing.expectEqual(id_manifest_schema, parsed.value.schema.?);
    try std.testing.expectEqual(id_manifest_layout, parsed.value.layout_generation.?);
    try std.testing.expectEqualStrings(id_manifest_kind, parsed.value.kind);
    try std.testing.expectEqualStrings("zigb", parsed.value.id.?);
    try std.testing.expectEqualStrings("_v2/units/u-zigb/_unit", parsed.value.unit_path.?);
    try std.testing.expectEqualStrings("zigb", parsed.value.links[0].name);
    try std.testing.expectEqualStrings("symlink", parsed.value.links[0].target_kind);
    try std.testing.expectError(
        error.InvalidManifest,
        readIdManifest(allocator, tio, path, "other"),
    );
}

test "ID manifest larger than 64 KiB round-trips within shared bound" {
    const allocator = std.testing.allocator;
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &path_buf);
    const base = path_buf[0..base_len];

    var env = EnvironMap.init(allocator);
    defer env.deinit();
    try env.put("XDG_DATA_HOME", base);

    const links = try allocator.alloc(LinkEntry, 1000);
    var initialized: usize = 0;
    defer {
        for (links[0..initialized]) |entry| {
            allocator.free(entry.name);
            allocator.free(entry.target);
        }
        allocator.free(links);
    }
    for (links, 0..) |*entry, i| {
        const name = try allocator.print("tool-{d}", .{i});
        const target = allocator.print(
            "/mnt/c/ghr/tools/_v2/units/u-tool/_unit/bin/{s}.exe",
            .{name},
        ) catch |err| {
            allocator.free(name);
            return err;
        };
        entry.* = .{ .name = name, .target = target };
        initialized += 1;
    }

    const body = try stringifyIdManifest(
        allocator,
        "tool",
        "_v2/units/u-tool/_unit",
        "/mnt/c/ghr/tools/_v2/units/u-tool/_unit",
        links,
    );
    defer allocator.free(body);
    try std.testing.expect(body.len > 64 * 1024);
    try std.testing.expect(body.len <= max_manifest_bytes);
    try persistIdManifestBody(allocator, tio, &env, "tool", body);

    const path = try idManifestPath(allocator, &env, "tool");
    defer allocator.free(path);
    const parsed = (try readIdManifest(allocator, tio, path, "tool")).?;
    defer parsed.deinit();
    try std.testing.expectEqual(links.len, parsed.value.links.len);
    try std.testing.expectEqualStrings("tool-999", parsed.value.links[999].name);
}

test "readManifest returns null for missing file" {
    const allocator = std.testing.allocator;
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &path_buf);
    const base = path_buf[0..base_len];

    var miss_buf: [Dir.max_path_bytes]u8 = undefined;
    const missing = try std.fmt.bufPrint(&miss_buf, "{s}/nope.json", .{base});
    try std.testing.expect((try readManifest(allocator, tio, missing)) == null);
}

test "deleteManifest is idempotent on missing file" {
    const allocator = std.testing.allocator;
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &path_buf);
    const base = path_buf[0..base_len];

    var env = EnvironMap.init(allocator);
    defer env.deinit();
    try env.put("XDG_DATA_HOME", base);

    // No write — just delete. Should silently succeed.
    try deleteManifest(allocator, tio, &env, "azuread", "foo");
}

test "computeDesiredLinks: unfiltered, normalizes separators and strips .exe" {
    const bins = [_][]const u8{ "bin\\foo.exe", "tool.exe" };
    var c = try computeDesiredLinks(std.testing.allocator, &bins, "/mnt/c/x", &.{});
    defer c.deinit();
    try std.testing.expectEqual(@as(usize, 2), c.links.len);
    try std.testing.expectEqualStrings("foo", c.links[0].name);
    try std.testing.expectEqualStrings("/mnt/c/x/bin/foo.exe", c.links[0].target);
    try std.testing.expectEqualStrings("tool", c.links[1].name);
    try std.testing.expectEqualStrings("/mnt/c/x/tool.exe", c.links[1].target);
    try std.testing.expectEqual(@as(usize, 0), c.unmatched_filters.len);
}

test "computeDesiredLinks: filter narrows to matching bins" {
    const bins = [_][]const u8{ "azureauth.exe", "azureauth-helper.exe" };
    const filters = [_][]const u8{"AzureAuth"};
    var c = try computeDesiredLinks(std.testing.allocator, &bins, "/mnt/c/x", &filters);
    defer c.deinit();
    try std.testing.expectEqual(@as(usize, 1), c.links.len);
    try std.testing.expectEqualStrings("azureauth", c.links[0].name);
    try std.testing.expectEqual(@as(usize, 0), c.unmatched_filters.len);
}

test "computeDesiredLinks: unmatched filter is reported" {
    const bins = [_][]const u8{"foo.exe"};
    const filters = [_][]const u8{ "bar", "baz" };
    var c = try computeDesiredLinks(std.testing.allocator, &bins, "/mnt/c/x", &filters);
    defer c.deinit();
    try std.testing.expectEqual(@as(usize, 0), c.links.len);
    try std.testing.expectEqual(@as(usize, 2), c.unmatched_filters.len);
    try std.testing.expectEqualStrings("bar", c.unmatched_filters[0]);
    try std.testing.expectEqualStrings("baz", c.unmatched_filters[1]);
}

test "computeDesiredLinks: duplicate link names error out" {
    const bins = [_][]const u8{ "foo.exe", "bin/foo.exe" };
    try std.testing.expectError(
        DesiredError.DuplicateLinkName,
        computeDesiredLinks(std.testing.allocator, &bins, "/mnt/c/x", &.{}),
    );
}

test "computeDesiredLinks: unsafe paths are dropped silently" {
    // At least one valid bin remains, so this should succeed with the
    // good one and silently drop the unsafe entries.
    const bins = [_][]const u8{ "../escape.exe", "/abs.exe", "good.exe" };
    var c = try computeDesiredLinks(std.testing.allocator, &bins, "/mnt/c/x", &.{});
    defer c.deinit();
    try std.testing.expectEqual(@as(usize, 1), c.links.len);
    try std.testing.expectEqualStrings("good", c.links[0].name);
}

test "computeDesiredLinks: all-unsafe bins are flagged as corrupt metadata" {
    const bins = [_][]const u8{ "../escape.exe", "/abs.exe", "C:/win.exe" };
    try std.testing.expectError(
        DesiredError.NoValidBinsAfterNormalize,
        computeDesiredLinks(std.testing.allocator, &bins, "/mnt/c/x", &.{}),
    );
}

test "computeDesiredLinks: no bins returns error" {
    try std.testing.expectError(
        DesiredError.NoBinsInMetadata,
        computeDesiredLinks(std.testing.allocator, &.{}, "/mnt/c/x", &.{}),
    );
}

test "computeDesiredLinks: duplicate filter doesn't duplicate link entry" {
    const bins = [_][]const u8{"azureauth.exe"};
    const filters = [_][]const u8{ "azureauth", "AzureAuth" };
    var c = try computeDesiredLinks(std.testing.allocator, &bins, "/mnt/c/x", &filters);
    defer c.deinit();
    try std.testing.expectEqual(@as(usize, 1), c.links.len);
}

test "computeDesiredCommandLinks uses final names without suffix inference" {
    const commands = [_]install_state.OwnedCommand{
        .{
            .name = "zigb",
            .source_name = "zig",
            .relative_target = "bin\\zig.exe",
            .kind = "native",
        },
        .{
            .name = "literal.exe",
            .relative_target = "other.exe",
            .kind = "native",
        },
    };
    var c = try computeDesiredCommandLinks(
        std.testing.allocator,
        &commands,
        "/mnt/c/tools/_v2/units/u-zigb/_unit",
        &.{},
    );
    defer c.deinit();
    try std.testing.expectEqual(@as(usize, 2), c.links.len);
    try std.testing.expectEqualStrings("zigb", c.links[0].name);
    try std.testing.expectEqualStrings(
        "/mnt/c/tools/_v2/units/u-zigb/_unit/bin/zig.exe",
        c.links[0].target,
    );
    try std.testing.expectEqualStrings("literal.exe", c.links[1].name);
}

test "computeDesiredCommandLinks refuses raw wasm modules" {
    const commands = [_]install_state.OwnedCommand{.{
        .name = "parser",
        .relative_target = "parser.wasm",
        .kind = "wasm",
    }};
    try std.testing.expectError(
        DesiredError.UnsupportedCommandKind,
        computeDesiredCommandLinks(
            std.testing.allocator,
            &commands,
            "/mnt/c/tools/_v2/units/u-parser/_unit",
            &.{},
        ),
    );
}

test "ID link manifests separate two releases from one repository" {
    if (builtin.target.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var base_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &base_buf);
    const base = base_buf[0..base_len];
    const tools = try testAbsoluteChild(allocator, base, "win-tools");
    defer allocator.free(tools);
    const bin = try testAbsoluteChild(allocator, base, "bin");
    defer allocator.free(bin);
    try install.ensureDirAbsoluteRecursive(tio, tools);
    try install.ensureDirAbsoluteRecursive(tio, bin);
    try writeTestV2Unit(allocator, tio, tools, "zigb", "zigb", "zig.exe");
    try writeTestV2Unit(allocator, tio, tools, "ziga", "ziga", "zig.exe");

    var env = EnvironMap.init(allocator);
    defer env.deinit();
    try initLinkTestEnv(&env, base, tools, bin);
    var out = std.Io.Writer.Allocating.init(allocator);
    defer out.deinit();
    var err_out = std.Io.Writer.Allocating.init(allocator);
    defer err_out.deinit();

    try cmdLinkAuto(allocator, tio, &env, "zigb", &.{}, false, false, &out.writer, &err_out.writer);
    try cmdLinkAuto(allocator, tio, &env, "ziga", &.{}, false, false, &out.writer, &err_out.writer);

    var bin_dir = try Dir.openDirAbsolute(tio, bin, .{});
    defer bin_dir.close(tio);
    var target_buf: [Dir.max_path_bytes]u8 = undefined;
    const zigb_len = try bin_dir.readLink(tio, "zigb", &target_buf);
    try std.testing.expect(std.mem.endsWith(u8, target_buf[0..zigb_len], "u-zigb/_unit/zig.exe"));
    const ziga_len = try bin_dir.readLink(tio, "ziga", &target_buf);
    try std.testing.expect(std.mem.endsWith(u8, target_buf[0..ziga_len], "u-ziga/_unit/zig.exe"));

    const zigb_manifest = try idManifestPath(allocator, &env, "zigb");
    defer allocator.free(zigb_manifest);
    const ziga_manifest = try idManifestPath(allocator, &env, "ziga");
    defer allocator.free(ziga_manifest);
    var zigb_parsed = (try readIdManifest(allocator, tio, zigb_manifest, "zigb")).?;
    defer zigb_parsed.deinit();
    var ziga_parsed = (try readIdManifest(allocator, tio, ziga_manifest, "ziga")).?;
    defer ziga_parsed.deinit();

    const zigb_rel = try install_state.encodeRelPath(allocator, "zigb");
    defer allocator.free(zigb_rel);
    const zigb_unit = try std.fs.path.join(allocator, &.{ tools, zigb_rel });
    defer allocator.free(zigb_unit);
    try Dir.cwd().deleteTree(tio, zigb_unit);
    try cmdUnlinkAuto(allocator, tio, &env, "zigb", &.{}, false, false, &out.writer, &err_out.writer);
    try std.testing.expectError(error.FileNotFound, bin_dir.readLink(tio, "zigb", &target_buf));
    _ = try bin_dir.readLink(tio, "ziga", &target_buf);
    try std.testing.expect(!try idManifestEntryExists(allocator, tio, &env, "zigb"));
    try std.testing.expect(try idManifestEntryExists(allocator, tio, &env, "ziga"));
}

test "ID reconciliation refuses a modified owned link" {
    if (builtin.target.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var base_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &base_buf);
    const base = base_buf[0..base_len];
    const tools = try testAbsoluteChild(allocator, base, "win-tools");
    defer allocator.free(tools);
    const bin = try testAbsoluteChild(allocator, base, "bin");
    defer allocator.free(bin);
    try install.ensureDirAbsoluteRecursive(tio, tools);
    try install.ensureDirAbsoluteRecursive(tio, bin);
    try writeTestV2Unit(allocator, tio, tools, "zigb", "zigb", "zig.exe");

    var env = EnvironMap.init(allocator);
    defer env.deinit();
    try initLinkTestEnv(&env, base, tools, bin);
    var out = std.Io.Writer.Allocating.init(allocator);
    defer out.deinit();
    var err_out = std.Io.Writer.Allocating.init(allocator);
    defer err_out.deinit();
    try cmdLink(allocator, tio, &env, "zigb", &.{}, &out.writer, &err_out.writer);

    var bin_dir = try Dir.openDirAbsolute(tio, bin, .{});
    defer bin_dir.close(tio);
    try bin_dir.deleteFile(tio, "zigb");
    try bin_dir.symLink(tio, "/tmp/user-target.exe", "zigb", .{});
    try std.testing.expectError(
        LinkCmdError.LinkStepFailed,
        cmdLink(allocator, tio, &env, "zigb", &.{}, &out.writer, &err_out.writer),
    );
    var target_buf: [Dir.max_path_bytes]u8 = undefined;
    const target_len = try bin_dir.readLink(tio, "zigb", &target_buf);
    try std.testing.expectEqualStrings("/tmp/user-target.exe", target_buf[0..target_len]);
    try std.testing.expect(std.mem.indexOf(u8, err_out.written(), "refusing destructive reconciliation") != null);
}

test "link lazily imports an unambiguous legacy manifest" {
    if (builtin.target.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var base_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &base_buf);
    const base = base_buf[0..base_len];
    const tools = try testAbsoluteChild(allocator, base, "win-tools");
    defer allocator.free(tools);
    const bin = try testAbsoluteChild(allocator, base, "bin");
    defer allocator.free(bin);
    try install.ensureDirAbsoluteRecursive(tio, tools);
    try install.ensureDirAbsoluteRecursive(tio, bin);
    try writeTestV2Unit(allocator, tio, tools, "cataggar/zig", "zig", "zig.exe");

    var env = EnvironMap.init(allocator);
    defer env.deinit();
    try initLinkTestEnv(&env, base, tools, bin);
    const old_source = try std.fs.path.join(allocator, &.{ tools, "Cataggar", "Zig" });
    defer allocator.free(old_source);
    const old_target = try std.fs.path.join(allocator, &.{ old_source, "zig.exe" });
    defer allocator.free(old_target);
    var legacy_links = [_]LinkEntry{.{ .name = "zig", .target = old_target }};
    try writeManifest(allocator, tio, &env, "cataggar", "zig", .{
        .source = old_source,
        .links = &legacy_links,
    });

    var bin_dir = try Dir.openDirAbsolute(tio, bin, .{});
    defer bin_dir.close(tio);
    try bin_dir.symLink(tio, old_target, "zig", .{});
    var out = std.Io.Writer.Allocating.init(allocator);
    defer out.deinit();
    var err_out = std.Io.Writer.Allocating.init(allocator);
    defer err_out.deinit();
    try cmdLink(allocator, tio, &env, "cataggar/zig", &.{}, &out.writer, &err_out.writer);

    var target_buf: [Dir.max_path_bytes]u8 = undefined;
    const target_len = try bin_dir.readLink(tio, "zig", &target_buf);
    try std.testing.expect(std.mem.endsWith(u8, target_buf[0..target_len], "u-cataggar/u-zig/_unit/zig.exe"));
    try std.testing.expect(try idManifestEntryExists(allocator, tio, &env, "cataggar/zig"));
    const legacy_path = try manifestPath(allocator, &env, "cataggar", "zig");
    defer allocator.free(legacy_path);
    try std.testing.expect((try readManifest(allocator, tio, legacy_path)) == null);
}

test "modified legacy link blocks import without deleting legacy state" {
    if (builtin.target.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var base_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &base_buf);
    const base = base_buf[0..base_len];
    const tools = try testAbsoluteChild(allocator, base, "win-tools");
    defer allocator.free(tools);
    const bin = try testAbsoluteChild(allocator, base, "bin");
    defer allocator.free(bin);
    try install.ensureDirAbsoluteRecursive(tio, tools);
    try install.ensureDirAbsoluteRecursive(tio, bin);
    try writeTestV2Unit(allocator, tio, tools, "cataggar/zig", "zig", "zig.exe");

    var env = EnvironMap.init(allocator);
    defer env.deinit();
    try initLinkTestEnv(&env, base, tools, bin);
    const old_source = try std.fs.path.join(allocator, &.{ tools, "Cataggar", "Zig" });
    defer allocator.free(old_source);
    const old_target = try std.fs.path.join(allocator, &.{ old_source, "zig.exe" });
    defer allocator.free(old_target);
    var legacy_links = [_]LinkEntry{.{ .name = "zig", .target = old_target }};
    try writeManifest(allocator, tio, &env, "cataggar", "zig", .{
        .source = old_source,
        .links = &legacy_links,
    });

    var bin_dir = try Dir.openDirAbsolute(tio, bin, .{});
    defer bin_dir.close(tio);
    try bin_dir.symLink(tio, "/tmp/user-zig.exe", "zig", .{});
    var out = std.Io.Writer.Allocating.init(allocator);
    defer out.deinit();
    var err_out = std.Io.Writer.Allocating.init(allocator);
    defer err_out.deinit();
    try std.testing.expectError(
        LinkCmdError.LinkStepFailed,
        cmdLink(allocator, tio, &env, "cataggar/zig", &.{}, &out.writer, &err_out.writer),
    );

    try std.testing.expect(!try idManifestEntryExists(allocator, tio, &env, "cataggar/zig"));
    const legacy_path = try manifestPath(allocator, &env, "cataggar", "zig");
    defer allocator.free(legacy_path);
    var legacy = (try readManifest(allocator, tio, legacy_path)).?;
    legacy.deinit();
    var target_buf: [Dir.max_path_bytes]u8 = undefined;
    const target_len = try bin_dir.readLink(tio, "zig", &target_buf);
    try std.testing.expectEqualStrings("/tmp/user-zig.exe", target_buf[0..target_len]);
}

test "legacy manifest can unlink after Windows install removal" {
    if (builtin.target.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var base_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &base_buf);
    const base = base_buf[0..base_len];
    const tools = try testAbsoluteChild(allocator, base, "win-tools");
    defer allocator.free(tools);
    const bin = try testAbsoluteChild(allocator, base, "bin");
    defer allocator.free(bin);
    try install.ensureDirAbsoluteRecursive(tio, tools);
    try install.ensureDirAbsoluteRecursive(tio, bin);

    var env = EnvironMap.init(allocator);
    defer env.deinit();
    try initLinkTestEnv(&env, base, tools, bin);
    const old_source = try std.fs.path.join(allocator, &.{ tools, "Cataggar", "Zig" });
    defer allocator.free(old_source);
    const old_target = try std.fs.path.join(allocator, &.{ old_source, "zig.exe" });
    defer allocator.free(old_target);
    var legacy_links = [_]LinkEntry{.{ .name = "zig", .target = old_target }};
    try writeManifest(allocator, tio, &env, "cataggar", "zig", .{
        .source = old_source,
        .links = &legacy_links,
    });

    var bin_dir = try Dir.openDirAbsolute(tio, bin, .{});
    defer bin_dir.close(tio);
    try bin_dir.symLink(tio, old_target, "zig", .{});
    var out = std.Io.Writer.Allocating.init(allocator);
    defer out.deinit();
    var err_out = std.Io.Writer.Allocating.init(allocator);
    defer err_out.deinit();
    try cmdUnlink(allocator, tio, &env, "cataggar/zig", &.{}, &out.writer, &err_out.writer);

    var target_buf: [Dir.max_path_bytes]u8 = undefined;
    try std.testing.expectError(error.FileNotFound, bin_dir.readLink(tio, "zig", &target_buf));
    const legacy_path = try manifestPath(allocator, &env, "cataggar", "zig");
    defer allocator.free(legacy_path);
    try std.testing.expect((try readManifest(allocator, tio, legacy_path)) == null);
}

test "filtered legacy unlink refuses partial manifest import" {
    if (builtin.target.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var base_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &base_buf);
    const base = base_buf[0..base_len];
    const tools = try testAbsoluteChild(allocator, base, "win-tools");
    defer allocator.free(tools);
    const bin = try testAbsoluteChild(allocator, base, "bin");
    defer allocator.free(bin);
    try install.ensureDirAbsoluteRecursive(tio, tools);
    try install.ensureDirAbsoluteRecursive(tio, bin);

    var env = EnvironMap.init(allocator);
    defer env.deinit();
    try initLinkTestEnv(&env, base, tools, bin);
    const old_source = try std.fs.path.join(allocator, &.{ tools, "cataggar", "tool" });
    defer allocator.free(old_source);
    const first_target = try std.fs.path.join(allocator, &.{ old_source, "first.exe" });
    defer allocator.free(first_target);
    const second_target = try std.fs.path.join(allocator, &.{ old_source, "second.exe" });
    defer allocator.free(second_target);
    var legacy_links = [_]LinkEntry{
        .{ .name = "first", .target = first_target },
        .{ .name = "second", .target = second_target },
    };
    try writeManifest(allocator, tio, &env, "cataggar", "tool", .{
        .source = old_source,
        .links = &legacy_links,
    });

    var bin_dir = try Dir.openDirAbsolute(tio, bin, .{});
    defer bin_dir.close(tio);
    try bin_dir.symLink(tio, first_target, "first", .{});
    try bin_dir.symLink(tio, second_target, "second", .{});
    var out = std.Io.Writer.Allocating.init(allocator);
    defer out.deinit();
    var err_out = std.Io.Writer.Allocating.init(allocator);
    defer err_out.deinit();
    try std.testing.expectError(
        LinkCmdError.LinkStepFailed,
        cmdUnlink(
            allocator,
            tio,
            &env,
            "cataggar/tool",
            &.{"first"},
            &out.writer,
            &err_out.writer,
        ),
    );

    var target_buf: [Dir.max_path_bytes]u8 = undefined;
    _ = try bin_dir.readLink(tio, "first", &target_buf);
    _ = try bin_dir.readLink(tio, "second", &target_buf);
    try std.testing.expect(!try idManifestEntryExists(allocator, tio, &env, "cataggar/tool"));
    const legacy_path = try manifestPath(allocator, &env, "cataggar", "tool");
    defer allocator.free(legacy_path);
    var legacy = (try readManifest(allocator, tio, legacy_path)).?;
    legacy.deinit();
}

test "manifest write failure rolls back newly-created ID links" {
    if (builtin.target.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var base_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &base_buf);
    const base = base_buf[0..base_len];
    const tools = try testAbsoluteChild(allocator, base, "win-tools");
    defer allocator.free(tools);
    const bin = try testAbsoluteChild(allocator, base, "bin");
    defer allocator.free(bin);
    try install.ensureDirAbsoluteRecursive(tio, tools);
    try install.ensureDirAbsoluteRecursive(tio, bin);
    try writeTestV2Unit(allocator, tio, tools, "zigb", "zigb", "zig.exe");

    var env = EnvironMap.init(allocator);
    defer env.deinit();
    try initLinkTestEnv(&env, base, tools, bin);
    const manifest_dir = try idManifestDir(allocator, &env, "zigb");
    defer allocator.free(manifest_dir);
    try install.ensureDirAbsoluteRecursive(tio, manifest_dir);
    const blocked_tmp = try std.fs.path.join(allocator, &.{ manifest_dir, id_manifest_file ++ ".tmp" });
    defer allocator.free(blocked_tmp);
    try install.ensureDirAbsoluteRecursive(tio, blocked_tmp);

    var out = std.Io.Writer.Allocating.init(allocator);
    defer out.deinit();
    var err_out = std.Io.Writer.Allocating.init(allocator);
    defer err_out.deinit();
    try std.testing.expectError(
        error.IsDir,
        cmdLink(allocator, tio, &env, "zigb", &.{}, &out.writer, &err_out.writer),
    );

    var bin_dir = try Dir.openDirAbsolute(tio, bin, .{});
    defer bin_dir.close(tio);
    var target_buf: [Dir.max_path_bytes]u8 = undefined;
    try std.testing.expectError(error.FileNotFound, bin_dir.readLink(tio, "zigb", &target_buf));
}

test "filtered ID unlink restores removed links when manifest write fails" {
    if (builtin.target.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var base_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &base_buf);
    const base = base_buf[0..base_len];
    const tools = try testAbsoluteChild(allocator, base, "win-tools");
    defer allocator.free(tools);
    const bin = try testAbsoluteChild(allocator, base, "bin");
    defer allocator.free(bin);
    try install.ensureDirAbsoluteRecursive(tio, tools);
    try install.ensureDirAbsoluteRecursive(tio, bin);

    var env = EnvironMap.init(allocator);
    defer env.deinit();
    try initLinkTestEnv(&env, base, tools, bin);
    const links = [_]LinkEntry{
        .{ .name = "first", .target = "/tmp/first.exe" },
        .{ .name = "second", .target = "/tmp/second.exe" },
    };
    try writeIdManifest(
        allocator,
        tio,
        &env,
        "tool",
        "_v2/units/u-tool/_unit",
        "/mnt/c/ghr/tools/_v2/units/u-tool/_unit",
        &links,
    );

    var bin_dir = try Dir.openDirAbsolute(tio, bin, .{});
    defer bin_dir.close(tio);
    for (links) |entry| try bin_dir.symLink(tio, entry.target, entry.name, .{});

    const manifest_dir = try idManifestDir(allocator, &env, "tool");
    defer allocator.free(manifest_dir);
    const blocked_tmp = try std.fs.path.join(allocator, &.{ manifest_dir, id_manifest_file ++ ".tmp" });
    defer allocator.free(blocked_tmp);
    try install.ensureDirAbsoluteRecursive(tio, blocked_tmp);

    var out = std.Io.Writer.Allocating.init(allocator);
    defer out.deinit();
    var err_out = std.Io.Writer.Allocating.init(allocator);
    defer err_out.deinit();
    try std.testing.expectError(
        error.IsDir,
        cmdUnlink(
            allocator,
            tio,
            &env,
            "tool",
            &.{"first"},
            &out.writer,
            &err_out.writer,
        ),
    );

    var target_buf: [Dir.max_path_bytes]u8 = undefined;
    for (links) |entry| {
        const target_len = try bin_dir.readLink(tio, entry.name, &target_buf);
        try std.testing.expectEqualStrings(entry.target, target_buf[0..target_len]);
    }
    try std.testing.expectEqual(@as(usize, 0), out.written().len);
    const manifest_path = try idManifestPath(allocator, &env, "tool");
    defer allocator.free(manifest_path);
    const parsed = (try readIdManifest(allocator, tio, manifest_path, "tool")).?;
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 2), parsed.value.links.len);
}

test "full ID unlink restores links when manifest deletion fails" {
    if (builtin.target.os.tag == .windows or !File.Permissions.has_executable_bit)
        return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var base_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &base_buf);
    const base = base_buf[0..base_len];
    const tools = try testAbsoluteChild(allocator, base, "win-tools");
    defer allocator.free(tools);
    const bin = try testAbsoluteChild(allocator, base, "bin");
    defer allocator.free(bin);
    try install.ensureDirAbsoluteRecursive(tio, tools);
    try install.ensureDirAbsoluteRecursive(tio, bin);

    var env = EnvironMap.init(allocator);
    defer env.deinit();
    try initLinkTestEnv(&env, base, tools, bin);
    const links = [_]LinkEntry{
        .{ .name = "first", .target = "/tmp/first.exe" },
        .{ .name = "second", .target = "/tmp/second.exe" },
    };
    try writeIdManifest(
        allocator,
        tio,
        &env,
        "tool",
        "_v2/units/u-tool/_unit",
        "/mnt/c/ghr/tools/_v2/units/u-tool/_unit",
        &links,
    );

    var bin_dir = try Dir.openDirAbsolute(tio, bin, .{});
    defer bin_dir.close(tio);
    for (links) |entry| try bin_dir.symLink(tio, entry.target, entry.name, .{});

    const manifest_dir = try idManifestDir(allocator, &env, "tool");
    defer allocator.free(manifest_dir);
    var manifest_dir_handle = try Dir.openDirAbsolute(tio, manifest_dir, .{ .iterate = true });
    defer manifest_dir_handle.close(tio);
    try manifest_dir_handle.setPermissions(tio, @fromBackingInt(@intCast(0o500)));
    defer manifest_dir_handle.setPermissions(tio, @fromBackingInt(@intCast(0o700))) catch {};

    var out = std.Io.Writer.Allocating.init(allocator);
    defer out.deinit();
    var err_out = std.Io.Writer.Allocating.init(allocator);
    defer err_out.deinit();
    try std.testing.expectError(
        error.AccessDenied,
        cmdUnlink(allocator, tio, &env, "tool", &.{}, &out.writer, &err_out.writer),
    );

    var target_buf: [Dir.max_path_bytes]u8 = undefined;
    for (links) |entry| {
        const target_len = try bin_dir.readLink(tio, entry.name, &target_buf);
        try std.testing.expectEqualStrings(entry.target, target_buf[0..target_len]);
    }
    try std.testing.expectEqual(@as(usize, 0), out.written().len);
    try std.testing.expect(try idManifestEntryExists(allocator, tio, &env, "tool"));
}

test "one-segment discovery failure refuses PATH fallback" {
    if (builtin.target.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(tio, .{ .sub_path = "win-tools", .data = "not a directory" });
    var base_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &base_buf);
    const base = base_buf[0..base_len];
    const tools = try testAbsoluteChild(allocator, base, "win-tools");
    defer allocator.free(tools);
    const bin = try testAbsoluteChild(allocator, base, "bin");
    defer allocator.free(bin);

    var env = EnvironMap.init(allocator);
    defer env.deinit();
    try initLinkTestEnv(&env, base, tools, bin);
    var out = std.Io.Writer.Allocating.init(allocator);
    defer out.deinit();
    var err_out = std.Io.Writer.Allocating.init(allocator);
    defer err_out.deinit();
    try std.testing.expectError(
        LinkCmdError.LinkStepFailed,
        cmdLinkAuto(
            allocator,
            tio,
            &env,
            "git",
            &.{},
            false,
            false,
            &out.writer,
            &err_out.writer,
        ),
    );

    try std.testing.expectEqual(@as(usize, 0), out.written().len);
    try std.testing.expect(std.mem.indexOf(
        u8,
        err_out.written(),
        "cannot disambiguate 'git' as an install ID",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        err_out.written(),
        "use --path only when Windows PATH mode is intended",
    ) != null);
}

test "writeJsonEscaped: escapes control characters per RFC 8259" {
    const allocator = std.testing.allocator;
    var collected = std.Io.Writer.Allocating.init(allocator);
    defer collected.deinit();
    try writeJsonEscaped(&collected.writer, "a\nb\tc\"d\\e\x01f");
    const out = try collected.toOwnedSlice();
    defer allocator.free(out);
    try std.testing.expectEqualStrings(
        "a\\nb\\tc\\\"d\\\\e\\u0001f",
        out,
    );
}

test "isValidBareExeName: accepts plain names and .exe suffix" {
    try std.testing.expect(isValidBareExeName("git"));
    try std.testing.expect(isValidBareExeName("git.exe"));
    try std.testing.expect(isValidBareExeName("rg"));
    try std.testing.expect(isValidBareExeName("clang-format"));
    try std.testing.expect(isValidBareExeName("g++"));
    try std.testing.expect(isValidBareExeName("python3.12.exe"));
}

test "isValidBareExeName: rejects path-y, flag-y, empty, and odd inputs" {
    try std.testing.expect(!isValidBareExeName(""));
    try std.testing.expect(!isValidBareExeName("."));
    try std.testing.expect(!isValidBareExeName(".."));
    try std.testing.expect(!isValidBareExeName(".git"));
    try std.testing.expect(!isValidBareExeName("-h"));
    try std.testing.expect(!isValidBareExeName("a/b"));
    try std.testing.expect(!isValidBareExeName("a\\b"));
    try std.testing.expect(!isValidBareExeName("a..b"));
    try std.testing.expect(!isValidBareExeName("a b"));
    try std.testing.expect(!isValidBareExeName("a*b"));
    try std.testing.expect(!isValidBareExeName("a|b"));
    try std.testing.expect(!isValidBareExeName("a;b"));
    try std.testing.expect(!isValidBareExeName("C:foo"));
    // 65 chars exceeds the cap
    const long: [65]u8 = @splat('a');
    try std.testing.expect(!isValidBareExeName(&long));
}

test "parseFirstWherePath: returns the first non-blank line trimmed" {
    try std.testing.expectEqualStrings(
        "C:\\Program Files\\Git\\cmd\\git.exe",
        parseFirstWherePath("C:\\Program Files\\Git\\cmd\\git.exe\r\nC:\\foo\\git.exe\r\n").?,
    );
    try std.testing.expectEqualStrings(
        "C:\\only.exe",
        parseFirstWherePath("\r\n  C:\\only.exe  \r\n").?,
    );
    try std.testing.expect(parseFirstWherePath("") == null);
    try std.testing.expect(parseFirstWherePath("\r\n\r\n   \r\n") == null);
}

test "pickBestWherePath: prefers PATHEXT-dispatchable extension over extensionless" {
    // The exact pattern from `where.exe az` against Azure CLI: a bare
    // `az` file is enumerated before `az.cmd` in the same directory.
    // cmd.exe would dispatch via PATHEXT and run `az.cmd`; we mirror
    // that here.
    const out = "C:\\Program Files\\Microsoft SDKs\\Azure\\CLI2\\wbin\\az\r\n" ++
        "C:\\Program Files\\Microsoft SDKs\\Azure\\CLI2\\wbin\\az.cmd\r\n";
    try std.testing.expectEqualStrings(
        "C:\\Program Files\\Microsoft SDKs\\Azure\\CLI2\\wbin\\az.cmd",
        pickBestWherePath(out).?,
    );
}

test "pickBestWherePath: prefers .exe over .cmd over .bat (PATHEXT order)" {
    const out = "C:\\x\\foo.bat\r\nC:\\x\\foo.cmd\r\nC:\\x\\foo.exe\r\n";
    try std.testing.expectEqualStrings("C:\\x\\foo.exe", pickBestWherePath(out).?);

    const out2 = "C:\\x\\foo.bat\r\nC:\\x\\foo.cmd\r\n";
    try std.testing.expectEqualStrings("C:\\x\\foo.cmd", pickBestWherePath(out2).?);
}

test "pickBestWherePath: PATH order wins within same extension class" {
    const out = "C:\\first\\foo.exe\r\nC:\\second\\foo.exe\r\n";
    try std.testing.expectEqualStrings("C:\\first\\foo.exe", pickBestWherePath(out).?);
}

test "pickBestWherePath: falls back to first line when no recognised extension" {
    const out = "C:\\x\\script.ps1\r\nC:\\x\\other.ps1\r\n";
    try std.testing.expectEqualStrings("C:\\x\\script.ps1", pickBestWherePath(out).?);
}

test "pickBestWherePath: returns null on empty input" {
    try std.testing.expect(pickBestWherePath("") == null);
    try std.testing.expect(pickBestWherePath("\r\n\r\n") == null);
}

test "looksLikeMntDrvfsPath: accepts drvfs and rejects others" {
    try std.testing.expect(looksLikeMntDrvfsPath("/mnt/c/Program Files/Git/cmd/git.exe"));
    try std.testing.expect(looksLikeMntDrvfsPath("/mnt/d/foo.exe"));
    try std.testing.expect(!looksLikeMntDrvfsPath("/mnt/wsl/foo.exe"));
    try std.testing.expect(!looksLikeMntDrvfsPath("/mnt//foo.exe"));
    try std.testing.expect(!looksLikeMntDrvfsPath("/mnt/"));
    try std.testing.expect(!looksLikeMntDrvfsPath("/mnt"));
    try std.testing.expect(!looksLikeMntDrvfsPath(""));
    try std.testing.expect(!looksLikeMntDrvfsPath("//wsl$/Ubuntu/usr/bin/foo.exe"));
    try std.testing.expect(!looksLikeMntDrvfsPath("/usr/bin/foo.exe"));
}

test "stripExecutableExtension: drops .exe/.com/.cmd/.bat case-insensitively" {
    try std.testing.expectEqualStrings("git", stripExecutableExtension("git.exe"));
    try std.testing.expectEqualStrings("git", stripExecutableExtension("git.EXE"));
    try std.testing.expectEqualStrings("git", stripExecutableExtension("git.Exe"));
    try std.testing.expectEqualStrings("az", stripExecutableExtension("az.cmd"));
    try std.testing.expectEqualStrings("az", stripExecutableExtension("az.CMD"));
    try std.testing.expectEqualStrings("setup", stripExecutableExtension("setup.bat"));
    try std.testing.expectEqualStrings("foo", stripExecutableExtension("foo.com"));
    try std.testing.expectEqualStrings("git", stripExecutableExtension("git"));
    // length guard: ".exe" alone is not stripped because there'd be no stem
    try std.testing.expectEqualStrings(".exe", stripExecutableExtension(".exe"));
    try std.testing.expectEqualStrings(".cmd", stripExecutableExtension(".cmd"));
    // Unrelated extensions are left alone.
    try std.testing.expectEqualStrings("readme.txt", stripExecutableExtension("readme.txt"));
    try std.testing.expectEqualStrings("script.ps1", stripExecutableExtension("script.ps1"));
}

test "classifyTarget: maps extensions to symlink/script/null" {
    try std.testing.expectEqual(TargetKind.exe, classifyTarget("/mnt/c/x/git.exe").?);
    try std.testing.expectEqual(TargetKind.exe, classifyTarget("/mnt/c/x/foo.COM").?);
    try std.testing.expectEqual(TargetKind.script, classifyTarget("/mnt/c/x/az.cmd").?);
    try std.testing.expectEqual(TargetKind.script, classifyTarget("/mnt/c/x/setup.BAT").?);
    try std.testing.expect(classifyTarget("/mnt/c/x/script.ps1") == null);
    try std.testing.expect(classifyTarget("/mnt/c/x/readme.txt") == null);
    try std.testing.expect(classifyTarget("/mnt/c/x/nonext") == null);
}

test "buildWrapperScript: includes magic, name, escaped Windows target" {
    const a = std.testing.allocator;
    const s = try buildWrapperScript(a, "az", "C:\\Program Files\\Microsoft SDKs\\Azure\\CLI2\\wbin\\az.cmd");
    defer a.free(s);
    try std.testing.expect(std.mem.startsWith(u8, s, "#!/usr/bin/env bash\n"));
    try std.testing.expect(std.mem.indexOf(u8, s, WRAPPER_MAGIC) != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "for az\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "'/mnt/c/Windows/System32/cmd.exe' /c '") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "C:\\Program Files\\Microsoft SDKs\\Azure\\CLI2\\wbin\\az.cmd") != null);
    try std.testing.expect(std.mem.endsWith(u8, s, "\"$@\"\n"));
}

test "buildWrapperScript: escapes single quotes in target" {
    const a = std.testing.allocator;
    const s = try buildWrapperScript(a, "weird", "C:\\Tools\\it's a path\\foo.cmd");
    defer a.free(s);
    // Each ' in the path becomes '\'' inside the bash single-quoted
    // argument so the surrounding 'cmd.exe /c ...' string stays valid.
    try std.testing.expect(std.mem.indexOf(u8, s, "C:\\Tools\\it'\\''s a path\\foo.cmd") != null);
}

test "wrapperMatches: accepts our own output, rejects strangers" {
    const a = std.testing.allocator;
    const win = "C:\\Program Files\\Microsoft SDKs\\Azure\\CLI2\\wbin\\az.cmd";
    const s = try buildWrapperScript(a, "az", win);
    defer a.free(s);
    try std.testing.expect(try wrapperMatches(a, s, win));
    try std.testing.expect(!try wrapperMatches(a, s, "C:\\Wrong\\az.cmd"));
    try std.testing.expect(!try wrapperMatches(a, "#!/bin/sh\necho hi\n", win));
    try std.testing.expect(!try wrapperMatches(a, "", win));
}

test "wrapperMatches: round-trips through single-quote escaping" {
    const a = std.testing.allocator;
    const win = "C:\\Tools\\it's a path\\foo.cmd";
    const s = try buildWrapperScript(a, "weird", win);
    defer a.free(s);
    try std.testing.expect(try wrapperMatches(a, s, win));
}

test "bareExeManifestPath: builds the by-path/<name>.json under links root" {
    const allocator = std.testing.allocator;
    var env = EnvironMap.init(allocator);
    defer env.deinit();
    try env.put("XDG_DATA_HOME", "/home/u/.local/share");

    const p = try bareExeManifestPath(allocator, &env, "git");
    defer allocator.free(p);
    // Path separator differs between Linux and the test host; check shape
    // by sentinel substrings rather than exact equality.
    try std.testing.expect(std.mem.indexOf(u8, p, "ghr") != null);
    try std.testing.expect(std.mem.indexOf(u8, p, "links") != null);
    try std.testing.expect(std.mem.indexOf(u8, p, "by-path") != null);
    try std.testing.expect(std.mem.endsWith(u8, p, "git.json"));
}

test "writeBareExeManifest then readManifest round-trip (symlink kind)" {
    const allocator = std.testing.allocator;
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &path_buf);
    const base = path_buf[0..base_len];

    var env = EnvironMap.init(allocator);
    defer env.deinit();
    try env.put("XDG_DATA_HOME", base);

    try writeBareExeManifest(allocator, tio, &env, "git", "/mnt/c/Program Files/Git/cmd/git.exe", .{
        .name = "git",
        .target = "/mnt/c/Program Files/Git/cmd/git.exe",
        .target_kind = "symlink",
    });

    const final_abs = try bareExeManifestPath(allocator, &env, "git");
    defer allocator.free(final_abs);
    const parsed = (try readManifest(allocator, tio, final_abs)) orelse {
        try std.testing.expect(false);
        return;
    };
    defer parsed.deinit();
    try std.testing.expectEqualStrings("wsl-path", parsed.value.kind);
    try std.testing.expectEqualStrings("/mnt/c/Program Files/Git/cmd/git.exe", parsed.value.source);
    try std.testing.expectEqual(@as(usize, 1), parsed.value.links.len);
    try std.testing.expectEqualStrings("git", parsed.value.links[0].name);
    try std.testing.expectEqualStrings(
        "/mnt/c/Program Files/Git/cmd/git.exe",
        parsed.value.links[0].target,
    );
    try std.testing.expectEqualStrings("symlink", parsed.value.links[0].target_kind);
}

test "drvfsToWindowsPath: converts /mnt/<letter>/... and rejects non-drvfs" {
    const a = std.testing.allocator;
    const win = (try drvfsToWindowsPath(
        a,
        "/mnt/c/Users/John Smith/AppData/Roaming/ghr/data/tools/_v2/units/u-nodejs/u-node/_unit/npm.cmd",
    )).?;
    defer a.free(win);
    try std.testing.expectEqualStrings(
        "C:\\Users\\John Smith\\AppData\\Roaming\\ghr\\data\\tools\\_v2\\units\\u-nodejs\\u-node\\_unit\\npm.cmd",
        win,
    );

    const d_drive = (try drvfsToWindowsPath(a, "/mnt/d/tools/npx.CMD")).?;
    defer a.free(d_drive);
    try std.testing.expectEqualStrings("D:\\tools\\npx.CMD", d_drive);

    try std.testing.expect((try drvfsToWindowsPath(a, "/mnt/wsl/foo.cmd")) == null);
    try std.testing.expect((try drvfsToWindowsPath(a, "/usr/local/bin/npm.cmd")) == null);
}

test "buildIdWrapperScript: uses distinct ID magic and /d /c call quoting" {
    const a = std.testing.allocator;
    const win = "C:\\Users\\John O'Neil\\AppData\\Roaming\\ghr\\npm.cmd";
    const s = try buildIdWrapperScript(
        a,
        "nodejs/node",
        "npm",
        "/windir/c/Windows/System32/cmd.exe",
        win,
    );
    defer a.free(s);

    try std.testing.expect(std.mem.startsWith(u8, s, "#!/usr/bin/env bash\n"));
    try std.testing.expect(std.mem.indexOf(u8, s, ID_WRAPPER_MAGIC) != null);
    // Must NEVER match bare-PATH `WRAPPER_MAGIC` so `ghr link --path` refuses
    // to overwrite an ID-owned wrapper.
    try std.testing.expect(std.mem.indexOf(u8, s, WRAPPER_MAGIC) == null);
    try std.testing.expect(!try wrapperMatches(a, s, win));
    try std.testing.expect(std.mem.indexOf(
        u8,
        s,
        "exec '/windir/c/Windows/System32/cmd.exe' /d /c call 'C:\\Users\\John O'\\''Neil\\AppData\\Roaming\\ghr\\npm.cmd' \"$@\"\n",
    ) != null);
}

test "computeDesiredCommandLinks classifies .exe as symlink and .cmd as script" {
    const commands = [_]install_state.OwnedCommand{
        .{ .name = "node", .source_name = "node", .relative_target = "node.exe", .kind = "native" },
        .{ .name = "npm", .source_name = "npm", .relative_target = "npm.cmd", .kind = "native" },
        .{ .name = "npx", .source_name = "npx", .relative_target = "bin\\npx.CMD", .kind = "native" },
    };
    var all = try computeDesiredCommandLinks(
        std.testing.allocator,
        &commands,
        "/mnt/c/Users/John Smith/AppData/Roaming/ghr/data/tools/_v2/units/u-nodejs/u-node/_unit",
        &.{},
    );
    defer all.deinit();
    try std.testing.expectEqual(@as(usize, 3), all.links.len);
    try std.testing.expectEqual(DesiredLinkKind.symlink, all.links[0].kind);
    try std.testing.expectEqualStrings("node", all.links[0].name);
    try std.testing.expectEqual(DesiredLinkKind.script, all.links[1].kind);
    try std.testing.expectEqualStrings("npm", all.links[1].name);
    try std.testing.expectEqual(DesiredLinkKind.script, all.links[2].kind);
    try std.testing.expectEqualStrings("npx", all.links[2].name);

    var filtered = try computeDesiredCommandLinks(
        std.testing.allocator,
        &commands,
        "/mnt/c/tools/_unit",
        &.{"NPM"},
    );
    defer filtered.deinit();
    try std.testing.expectEqual(@as(usize, 1), filtered.links.len);
    try std.testing.expectEqualStrings("npm", filtered.links[0].name);
    try std.testing.expectEqual(DesiredLinkKind.script, filtered.links[0].kind);
}

test "ID manifest round-trips mixed symlink + script entries and rejects unsafe script metadata" {
    const allocator = std.testing.allocator;
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const wrapper = try buildIdWrapperScript(
        allocator,
        "nodejs/node",
        "npm",
        "/mnt/c/Windows/System32/cmd.exe",
        "C:\\Users\\John Smith\\AppData\\Roaming\\ghr\\npm.cmd",
    );
    defer allocator.free(wrapper);
    const hex = sha256Hex(wrapper);

    const valid_links = [_]LinkEntry{
        .{
            .name = "node",
            .target = "/mnt/c/Users/John Smith/AppData/Roaming/ghr/node.exe",
            .target_kind = "symlink",
        },
        .{
            .name = "npm",
            .target = "C:\\Users\\John Smith\\AppData\\Roaming\\ghr\\npm.cmd",
            .target_kind = "script",
            .wrapper_sha256 = &hex,
        },
    };
    try std.testing.expect(validLinkEntries(&valid_links));

    const body = try stringifyIdManifest(
        allocator,
        "nodejs/node",
        "_v2/units/u-nodejs/u-node/_unit",
        "/mnt/c/Users/John Smith/AppData/Roaming/ghr/data/tools/_v2/units/u-nodejs/u-node/_unit",
        &valid_links,
    );
    defer allocator.free(body);
    try tmp.dir.writeFile(tio, .{ .sub_path = "_manifest.json", .data = body });

    var base_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &base_buf);
    const manifest_abs = try std.fs.path.join(allocator, &.{ base_buf[0..base_len], "_manifest.json" });
    defer allocator.free(manifest_abs);

    var parsed = (try readIdManifest(allocator, tio, manifest_abs, "nodejs/node")).?;
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 2), parsed.value.links.len);
    try std.testing.expectEqualStrings("symlink", parsed.value.links[0].target_kind);
    try std.testing.expect(parsed.value.links[0].wrapper_sha256 == null);
    try std.testing.expectEqualStrings("script", parsed.value.links[1].target_kind);
    try std.testing.expectEqualStrings(&hex, parsed.value.links[1].wrapper_sha256.?);

    // Reject script without wrapper_sha256, with uppercase hex, with `%` or UNC target,
    // and symlink carrying wrapper_sha256.
    try std.testing.expect(!validLinkEntries(&.{.{
        .name = "npm",
        .target = "C:\\Tools\\npm.cmd",
        .target_kind = "script",
    }}));
    try std.testing.expect(!validLinkEntries(&.{.{
        .name = "npm",
        .target = "C:\\Tools\\%APPDATA%\\npm.cmd",
        .target_kind = "script",
        .wrapper_sha256 = &hex,
    }}));
    try std.testing.expect(!validLinkEntries(&.{.{
        .name = "npm",
        .target = "\\\\wsl.localhost\\Ubuntu\\tmp\\npm.cmd",
        .target_kind = "script",
        .wrapper_sha256 = &hex,
    }}));
    try std.testing.expect(!validLinkEntries(&.{.{
        .name = "node",
        .target = "/mnt/c/Tools/node.exe",
        .target_kind = "symlink",
        .wrapper_sha256 = &hex,
    }}));
}

fn writeTestV2MultiCommandUnit(
    allocator: std.mem.Allocator,
    io: Io,
    tools: []const u8,
    id: []const u8,
    specs: []const install_state_write.Command,
) !void {
    const relative_unit = try install_state.encodeRelPath(allocator, id);
    defer allocator.free(relative_unit);
    const unit = try std.fs.path.join(allocator, &.{ tools, relative_unit });
    defer allocator.free(unit);
    try install.ensureDirAbsoluteRecursive(io, unit);

    for (specs) |spec| {
        const target = try std.fs.path.join(allocator, &.{ unit, spec.relative_target });
        defer allocator.free(target);
        if (std.fs.path.dirname(target)) |parent| try install.ensureDirAbsoluteRecursive(io, parent);
        var file = try Dir.createFileAbsolute(io, target, .{});
        defer file.close(io);
        try file.writeStreamingAll(io, "test\n");
    }

    const body = try install_state_write.stringify(allocator, .{
        .id = id,
        .source = .{ .kind = .github, .owner = "nodejs", .repo = "node", .tag = "v22.0.0" },
        .resolved = .{ .tag = "v22.0.0", .asset = "node-v22.0.0-win-x64.zip" },
        .commands = specs,
        .verification = .{ .result = "none" },
    }, .windows);
    defer allocator.free(body);
    const metadata = try std.fs.path.join(allocator, &.{ unit, install_state.metadata_file });
    defer allocator.free(metadata);
    var file = try Dir.createFileAbsolute(io, metadata, .{});
    defer file.close(io);
    try file.writeStreamingAll(io, body);
}

fn installFakeWslpath(
    allocator: std.mem.Allocator,
    io: Io,
    base: []const u8,
    tools_root: []const u8,
    env: *EnvironMap,
) !void {
    const mock_bin = try testAbsoluteChild(allocator, base, "mock-bin");
    defer allocator.free(mock_bin);
    try install.ensureDirAbsoluteRecursive(io, mock_bin);
    var mock_dir = try Dir.openDirAbsolute(io, mock_bin, .{});
    defer mock_dir.close(io);

    const script = try std.fmt.allocPrint(
        allocator,
        "#!/bin/sh\n" ++
            "mode=\"$1\"\n" ++
            "arg=\"$2\"\n" ++
            "if [ \"$mode\" = \"-u\" ]; then\n" ++
            "  printf '/windir/c/Windows/System32/cmd.exe\\n'\n" ++
            "  exit 0\n" ++
            "fi\n" ++
            "if [ \"$mode\" = \"-w\" ]; then\n" ++
            "  rel=\"${{arg#{s}/}}\"\n" ++
            "  win_rel=$(printf '%s' \"$rel\" | tr '/' '\\\\')\n" ++
            "  printf 'C:\\\\Users\\\\John Smith\\\\AppData\\\\Roaming\\\\ghr\\\\tools\\\\%s\\n' \"$win_rel\"\n" ++
            "  exit 0\n" ++
            "fi\n" ++
            "exit 1\n",
        .{tools_root},
    );
    defer allocator.free(script);

    {
        var f = try mock_dir.createFile(io, "wslpath", .{ .permissions = .executable_file });
        defer f.close(io);
        try f.writeStreamingAll(io, script);
    }

    const path_val = try std.fmt.allocPrint(allocator, "{s}:/usr/bin:/bin", .{mock_bin});
    defer allocator.free(path_val);
    try env.put("PATH", path_val);
}

test "WSL ID link/unlink manages mixed .exe symlinks and .cmd wrappers, edits, transitions, and rollback" {
    if (builtin.target.os.tag == .windows or !File.Permissions.has_executable_bit)
        return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var base_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &base_buf);
    const base = base_buf[0..base_len];
    const tools = try testAbsoluteChild(allocator, base, "win-tools");
    defer allocator.free(tools);
    const bin = try testAbsoluteChild(allocator, base, "bin");
    defer allocator.free(bin);
    try install.ensureDirAbsoluteRecursive(tio, tools);
    try install.ensureDirAbsoluteRecursive(tio, bin);

    try writeTestV2MultiCommandUnit(allocator, tio, tools, "nodejs/node", &.{
        .{ .name = "node", .relative_target = "node.exe", .kind = .native },
        .{ .name = "npm", .relative_target = "npm.cmd", .kind = .native },
        .{ .name = "npx", .relative_target = "npx.cmd", .kind = .native },
    });

    var env = EnvironMap.init(allocator);
    defer env.deinit();
    try initLinkTestEnv(&env, base, tools, bin);
    try installFakeWslpath(allocator, tio, base, tools, &env);

    var out = std.Io.Writer.Allocating.init(allocator);
    defer out.deinit();
    var err_out = std.Io.Writer.Allocating.init(allocator);
    defer err_out.deinit();

    try cmdLink(allocator, tio, &env, "nodejs/node", &.{}, &out.writer, &err_out.writer);

    var bin_dir = try Dir.openDirAbsolute(tio, bin, .{});
    defer bin_dir.close(tio);
    var link_buf: [Dir.max_path_bytes]u8 = undefined;
    const node_len = try bin_dir.readLink(tio, "node", &link_buf);
    try std.testing.expect(std.mem.endsWith(u8, link_buf[0..node_len], "u-nodejs/u-node/_unit/node.exe"));

    // `npm` and `npx` must be regular executable wrapper scripts using `/d /c call`.
    try std.testing.expectError(error.NotLink, bin_dir.readLink(tio, "npm", &link_buf));
    const npm_bytes = try readFileBytes(allocator, tio, bin_dir, "npm", 64 * 1024);
    defer allocator.free(npm_bytes);
    try std.testing.expect(std.mem.indexOf(u8, npm_bytes, ID_WRAPPER_MAGIC) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        npm_bytes,
        "exec '/windir/c/Windows/System32/cmd.exe' /d /c call 'C:\\Users\\John Smith\\AppData\\Roaming\\ghr\\tools\\_v2\\units\\u-nodejs\\u-node\\_unit\\npm.cmd' \"$@\"\n",
    ) != null);

    // Filtered unlink removes `npm` while keeping `node` and `npx`.
    out.clearRetainingCapacity();
    try cmdUnlink(allocator, tio, &env, "nodejs/node", &.{"npm"}, &out.writer, &err_out.writer);
    try std.testing.expectError(error.FileNotFound, bin_dir.statFile(tio, "npm", .{ .follow_symlinks = false }));

    // User edits 1 byte in `npx` -> both `cmdLink` and `cmdUnlink` refuse to clobber!
    const npx_orig = try readFileBytes(allocator, tio, bin_dir, "npx", 64 * 1024);
    defer allocator.free(npx_orig);
    try bin_dir.writeFile(tio, .{ .sub_path = "npx", .data = "#!/bin/sh\necho user-edited\n" });

    err_out.clearRetainingCapacity();
    try std.testing.expectError(
        LinkCmdError.LinkStepFailed,
        cmdLink(allocator, tio, &env, "nodejs/node", &.{}, &out.writer, &err_out.writer),
    );
    try std.testing.expect(std.mem.indexOf(u8, err_out.written(), "refusing destructive reconciliation") != null);

    err_out.clearRetainingCapacity();
    try std.testing.expectError(
        LinkCmdError.LinkStepFailed,
        cmdUnlink(allocator, tio, &env, "nodejs/node", &.{}, &out.writer, &err_out.writer),
    );
    try std.testing.expect(std.mem.indexOf(u8, err_out.written(), "refusing destructive unlink") != null);

    // Restore original `npx`, then transition `npx` from `.cmd` -> `.exe` (script -> symlink)
    // and drop `node` to verify stale removal + transition.
    try writeIdWrapperFile(tio, bin_dir, "npx", npx_orig);
    try writeTestV2MultiCommandUnit(allocator, tio, tools, "nodejs/node", &.{
        .{ .name = "npm", .relative_target = "npm.cmd", .kind = .native },
        .{ .name = "npx", .relative_target = "npx.exe", .kind = .native },
    });
    out.clearRetainingCapacity();
    err_out.clearRetainingCapacity();
    try cmdLink(allocator, tio, &env, "nodejs/node", &.{}, &out.writer, &err_out.writer);
    try std.testing.expectError(error.FileNotFound, bin_dir.statFile(tio, "node", .{ .follow_symlinks = false }));
    const npx_link_len = try bin_dir.readLink(tio, "npx", &link_buf);
    try std.testing.expect(std.mem.endsWith(u8, link_buf[0..npx_link_len], "u-nodejs/u-node/_unit/npx.exe"));

    // Rollback on manifest deletion failure during full `cmdUnlink` restores `npm` wrapper AND `npx` symlink!
    const manifest_dir = try idManifestDir(allocator, &env, "nodejs/node");
    defer allocator.free(manifest_dir);
    var manifest_dir_handle = try Dir.openDirAbsolute(tio, manifest_dir, .{ .iterate = true });
    defer manifest_dir_handle.close(tio);
    try manifest_dir_handle.setPermissions(tio, @fromBackingInt(@intCast(0o500)));
    var perms_restored = false;
    defer if (!perms_restored) manifest_dir_handle.setPermissions(tio, @fromBackingInt(@intCast(0o700))) catch {};

    try std.testing.expectError(
        error.AccessDenied,
        cmdUnlink(allocator, tio, &env, "nodejs/node", &.{}, &out.writer, &err_out.writer),
    );
    const restored_npm = try readFileBytes(allocator, tio, bin_dir, "npm", 64 * 1024);
    defer allocator.free(restored_npm);
    try std.testing.expectEqualStrings(npm_bytes, restored_npm);
    _ = try bin_dir.readLink(tio, "npx", &link_buf);

    try manifest_dir_handle.setPermissions(tio, @fromBackingInt(@intCast(0o700)));
    perms_restored = true;
    try cmdUnlink(allocator, tio, &env, "nodejs/node", &.{}, &out.writer, &err_out.writer);
    try std.testing.expectError(error.FileNotFound, bin_dir.statFile(tio, "npm", .{ .follow_symlinks = false }));
    try std.testing.expectError(error.FileNotFound, bin_dir.statFile(tio, "npx", .{ .follow_symlinks = false }));
    try std.testing.expect(!try idManifestEntryExists(allocator, tio, &env, "nodejs/node"));
}

test "ID script wrapper apply, edit detection, removal, and zero-alloc rollback work cross-platform" {
    const allocator = std.testing.allocator;
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const v1_bytes = try buildIdWrapperScript(
        allocator,
        "nodejs/node",
        "npm",
        "/mnt/c/Windows/System32/cmd.exe",
        "C:\\Users\\John Smith\\AppData\\Roaming\\ghr\\v1\\npm.cmd",
    );
    defer allocator.free(v1_bytes);
    const v1_sha = sha256Hex(v1_bytes);

    const v2_bytes = try buildIdWrapperScript(
        allocator,
        "nodejs/node",
        "npm",
        "/mnt/c/Windows/System32/cmd.exe",
        "C:\\Users\\John Smith\\AppData\\Roaming\\ghr\\v2\\npm.cmd",
    );
    defer allocator.free(v2_bytes);
    const v2_sha = sha256Hex(v2_bytes);

    const desired_v1 = DesiredLink{
        .name = "npm",
        .target = "/mnt/c/Users/John Smith/AppData/Roaming/ghr/v1/npm.cmd",
        .kind = .script,
        .win_target = "C:\\Users\\John Smith\\AppData\\Roaming\\ghr\\v1\\npm.cmd",
        .script_bytes = v1_bytes,
        .wrapper_sha256 = &v1_sha,
    };
    const desired_v2 = DesiredLink{
        .name = "npm",
        .target = "/mnt/c/Users/John Smith/AppData/Roaming/ghr/v2/npm.cmd",
        .kind = .script,
        .win_target = "C:\\Users\\John Smith\\AppData\\Roaming\\ghr\\v2\\npm.cmd",
        .script_bytes = v2_bytes,
        .wrapper_sha256 = &v2_sha,
    };
    const prior_v1 = LinkEntry{
        .name = "npm",
        .target = desired_v1.win_target.?,
        .target_kind = "script",
        .wrapper_sha256 = &v1_sha,
    };

    // 1. Fresh creation + unchanged check.
    try std.testing.expect((try preflightLinkReconciliation(tio, tmp.dir, &.{desired_v1}, &.{}, true)) == null);
    try std.testing.expect(try applyOneLink(allocator, tio, tmp.dir, desired_v1, &.{}) == .created);
    try std.testing.expect(try applyOneLink(allocator, tio, tmp.dir, desired_v1, &.{prior_v1}) == .unchanged);

    // 2. Replacement captures prior_script_bytes and zero-alloc rollback restores v1.
    const replace_outcome = try applyOneLink(allocator, tio, tmp.dir, desired_v2, &.{prior_v1});
    const captured_v1 = replace_outcome.replaced.?;
    defer allocator.free(captured_v1);
    const replaced_applied = [_]AppliedLink{.{ .replaced = .{
        .desired = desired_v2,
        .prior = prior_v1,
        .prior_script_bytes = captured_v1,
    } }};
    rollbackAppliedLinks(tio, tmp.dir, &replaced_applied);
    const after_replace_rb = try readFileBytes(allocator, tio, tmp.dir, "npm", 64 * 1024);
    defer allocator.free(after_replace_rb);
    try std.testing.expectEqualStrings(v1_bytes, after_replace_rb);

    // 3. 1-byte user edit triggers `.modified` in preflightLinkReconciliation and preflightUnlink.
    try tmp.dir.writeFile(tio, .{ .sub_path = "npm", .data = "#!/usr/bin/env bash\necho custom\n" });
    const conflict = (try preflightLinkReconciliation(tio, tmp.dir, &.{desired_v2}, &.{prior_v1}, true)).?;
    try std.testing.expectEqual(LinkConflictKind.modified, conflict.kind);
    try std.testing.expectEqualStrings("npm", (try preflightUnlink(tio, tmp.dir, &.{prior_v1}, &.{})).?);

    // 4. Restore v1, remove via removeOwnedIdEntry, then zero-alloc rollback restores v1.
    try writeIdWrapperFile(tio, tmp.dir, "npm", v1_bytes);
    const rm_outcome = try removeOwnedIdEntry(allocator, tio, tmp.dir, prior_v1);
    const rm_bytes = rm_outcome.removed.?;
    defer allocator.free(rm_bytes);
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(tio, "npm", .{ .follow_symlinks = false }));
    const removed_applied = [_]AppliedLink{.{ .removed = .{
        .entry = prior_v1,
        .prior_script_bytes = rm_bytes,
    } }};
    rollbackAppliedLinks(tio, tmp.dir, &removed_applied);
    const after_rm_rb = try readFileBytes(allocator, tio, tmp.dir, "npm", 64 * 1024);
    defer allocator.free(after_rm_rb);
    try std.testing.expectEqualStrings(v1_bytes, after_rm_rb);

    // 5. `resolveWslpathArgv0` honors `environ.get("PATH")` directly (including
    // returning `FileNotFound` when `PATH` has no `wslpath`).
    var env = EnvironMap.init(allocator);
    defer env.deinit();
    var base_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &base_buf);
    const base = base_buf[0..base_len];

    try env.put("PATH", base);
    try std.testing.expectError(error.FileNotFound, resolveWslpathArgv0(allocator, tio, &env));

    try tmp.dir.writeFile(tio, .{ .sub_path = "wslpath", .data = "#!/bin/sh\n" });
    const resolved_exe = try resolveWslpathArgv0(allocator, tio, &env);
    defer allocator.free(resolved_exe);
    const expected_exe = try std.fs.path.join(allocator, &.{ base, "wslpath" });
    defer allocator.free(expected_exe);
    try std.testing.expectEqualStrings(expected_exe, resolved_exe);
}


