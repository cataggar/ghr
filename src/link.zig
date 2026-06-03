//! WSL-side `ghr link` / `ghr unlink`.
//!
//! These commands let a tool that was installed on the Windows side run
//! from inside WSL by creating Linux symlinks in `~/.local/bin` that point
//! at the original Windows-side `.exe` (e.g. `/mnt/c/Users/<u>/AppData/
//! Roaming/ghr/data/tools/<owner>/<repo>/<bin>`). WSL interop runs the
//! `.exe` transparently when the symlink is invoked.
//!
//! The link target is the real executable, NOT the shim — the shim lives
//! in the Windows bin dir, not under `tools/`, and going through it adds
//! a useless process hop. A raw `C:\…` symlink target would not work;
//! WSL interop requires a `/mnt/<drive>/…` path.

const std = @import("std");
const builtin = @import("builtin");
const Dirs = @import("dirs.zig").Dirs;
const install = @import("install.zig");
const release_mod = @import("release.zig");

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
// Records, per `<owner>/<repo>`, the set of `~/.local/bin/<name>` symlinks
// ghr created and where each one points. Used by `ghr unlink` so removal
// is safe even if the Windows-side install has since been removed or
// `GHR_WIN_TOOLS_DIR` has changed.
// ---------------------------------------------------------------------------

pub const LinkEntry = struct {
    name: []const u8,
    target: []const u8,
};

pub const Manifest = struct {
    kind: []const u8 = "wsl",
    /// Windows-side tool dir at link time, e.g.
    /// `/mnt/c/Users/x/AppData/Roaming/ghr/data/tools/azuread/foo`.
    source: []const u8,
    links: []LinkEntry,
};

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

/// Read a manifest from disk. Returns `null` when missing (a first
/// `ghr link` for the repo). On parse failure returns `error.InvalidManifest`.
pub fn readManifest(
    allocator: std.mem.Allocator,
    io: Io,
    abs_path: []const u8,
) !?std.json.Parsed(Manifest) {
    var f = Dir.openFileAbsolute(io, abs_path, .{}) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer f.close(io);
    var read_buf: [4096]u8 = undefined;
    var reader = f.reader(io, &read_buf);
    var body_w = std.Io.Writer.Allocating.init(allocator);
    defer body_w.deinit();
    _ = reader.interface.streamRemaining(&body_w.writer) catch |err| return err;
    const body = try body_w.toOwnedSlice();
    defer allocator.free(body);
    return std.json.parseFromSlice(Manifest, allocator, body, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch return error.InvalidManifest;
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
    const owner_dir = try manifestDir(allocator, environ, owner_lower);
    defer allocator.free(owner_dir);
    install.ensureDirAbsoluteRecursive(io, owner_dir);

    const final_path = try manifestPath(allocator, environ, owner_lower, repo_lower);
    defer allocator.free(final_path);
    const tmp_path = try std.fmt.allocPrint(allocator, "{s}.tmp", .{final_path});
    defer allocator.free(tmp_path);

    // Truncate any leftover tombstone.
    Dir.deleteFileAbsolute(io, tmp_path) catch {};

    {
        var f = try Dir.createFileAbsolute(io, tmp_path, .{});
        defer f.close(io);
        var wbuf: [4096]u8 = undefined;
        var fw = f.writer(io, &wbuf);
        const w = &fw.interface;
        try w.print("{{\"kind\":\"", .{});
        try writeJsonEscaped(w, manifest.kind);
        try w.print("\",\"source\":\"", .{});
        try writeJsonEscaped(w, manifest.source);
        try w.print("\",\"links\":[", .{});
        for (manifest.links, 0..) |entry, i| {
            if (i > 0) try w.print(",", .{});
            try w.print("{{\"name\":\"", .{});
            try writeJsonEscaped(w, entry.name);
            try w.print("\",\"target\":\"", .{});
            try writeJsonEscaped(w, entry.target);
            try w.print("\"}}", .{});
        }
        try w.print("]}}\n", .{});
        try fw.end();
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
pub fn windowsToolsDirFromWsl(
    allocator: std.mem.Allocator,
    environ: *const EnvironMap,
    io: Io,
    err_w: *Writer,
) ![]u8 {
    if (environ.get("GHR_WIN_TOOLS_DIR")) |v| {
        if (looksLikeWindowsPath(v)) {
            if (wslpathToUnix(allocator, io, v)) |p| return p else |_| {
                try err_w.print(
                    "warning: GHR_WIN_TOOLS_DIR='{s}' looked like a Windows path but wslpath conversion failed; using verbatim\n",
                    .{v},
                );
            }
        }
        return allocator.dupe(u8, v);
    }

    if (queryAppDataViaCmd(allocator, io)) |appdata_unix| {
        defer allocator.free(appdata_unix);
        return std.fs.path.join(allocator, &.{ appdata_unix, "ghr", "data", "tools" });
    } else |_| {}

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
    return std.fmt.allocPrint(allocator, "/mnt/c/Users/{s}/AppData/Roaming/ghr/data/tools", .{user});
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

fn wslpathToUnix(allocator: std.mem.Allocator, io: Io, win_path: []const u8) ![]u8 {
    const r = try std.process.run(allocator, io, .{
        .argv = &.{ "wslpath", "-u", win_path },
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

// ---------------------------------------------------------------------------
// Desired-link computation (pure, testable).
// ---------------------------------------------------------------------------

pub const DesiredLink = struct {
    /// Linux-side link name (basename, with trailing `.exe` stripped).
    /// Owned by the arena attached to `ComputedLinks`.
    name: []const u8,
    /// Absolute symlink target — `<win_tools_root>/<owner>/<repo>/<bin>`
    /// with `/` separators. Owned by the arena.
    target: []const u8,
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
        const target = try std.fmt.allocPrint(aa, "{s}/{s}", .{ tool_dir_abs, normalized });
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

// ---------------------------------------------------------------------------
// `ghr link` and `ghr unlink` commands.
// ---------------------------------------------------------------------------

pub const LinkCmdError = error{LinkStepFailed};

/// Emit a friendly "not installed" error for `ghr link`. The original
/// wording printed only the tools dir path, which read like a wrong-dir
/// bug whenever the real issue was a typo in the owner or repo. We now
/// distinguish three cases:
///
///   1. tools dir doesn't exist on disk
///   2. tools dir exists but is empty
///   3. tools dir has other tools installed — list them so a typo is
///      immediately obvious
///
/// On any I/O error while listing, we degrade to a generic message
/// rather than failing the command with a confusing nested error.
fn writeNotInstalledError(
    allocator: std.mem.Allocator,
    io: Io,
    err_w: *Writer,
    win_tools: []const u8,
    owner: []const u8,
    repo: []const u8,
) !void {
    try err_w.print("error: {s}/{s} is not installed on the Windows side\n", .{ owner, repo });

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const aa = arena.allocator();

    if (listInstalledSlugs(aa, io, win_tools)) |result| {
        if (result.present) {
            if (result.slugs.len == 0) {
                try err_w.print("       Windows tools dir exists but is empty: {s}\n", .{win_tools});
            } else {
                try err_w.print("       installed tools under {s}:\n", .{win_tools});
                for (result.slugs) |slug| try err_w.print("         {s}\n", .{slug});
            }
        } else {
            try err_w.print("       Windows tools dir does not exist: {s}\n", .{win_tools});
        }
    } else |_| {
        try err_w.print("       looked under {s}\n", .{win_tools});
    }

    try err_w.print("       run `ghr install {s}/{s}` from Windows to add it\n", .{ owner, repo });
    try err_w.flush();
}

const InstalledListing = struct {
    /// True when `tools_dir` exists on disk (whether or not any tools
    /// are installed inside it).
    present: bool,
    /// `<owner>/<repo>` slugs of installed tools, sorted alphabetically.
    /// `.old` tombstone directories are filtered out so they don't
    /// pollute user-facing output.
    slugs: []const []const u8,
};

/// Enumerate `<tools_dir>/<owner>/<repo>` entries, returning the listing
/// in `arena`-owned memory. The arena owns every returned slice.
fn listInstalledSlugs(
    arena: std.mem.Allocator,
    io: Io,
    tools_dir: []const u8,
) !InstalledListing {
    var tools = Dir.openDirAbsolute(io, tools_dir, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return .{ .present = false, .slugs = &.{} },
        else => return err,
    };
    defer tools.close(io);

    var out: std.ArrayListUnmanaged([]const u8) = .empty;

    var it = tools.iterate();
    while (try it.next(io)) |entry| {
        if (entry.kind != .directory) continue;
        if (std.mem.endsWith(u8, entry.name, ".old")) continue;
        const owner_name = entry.name;
        var owner_dir = tools.openDir(io, owner_name, .{ .iterate = true }) catch continue;
        defer owner_dir.close(io);
        var it2 = owner_dir.iterate();
        while (try it2.next(io)) |sub| {
            if (sub.kind != .directory) continue;
            if (std.mem.endsWith(u8, sub.name, ".old")) continue;
            const slug = try std.fmt.allocPrint(arena, "{s}/{s}", .{ owner_name, sub.name });
            try out.append(arena, slug);
        }
    }

    std.mem.sort([]const u8, out.items, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lt);

    return .{ .present = true, .slugs = out.items };
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

    const owned = release_mod.parseRepoSpecOwned(allocator, spec_str) catch {
        try err_w.print("error: invalid spec '{s}', expected owner/repo\n", .{spec_str});
        try err_w.flush();
        return LinkCmdError.LinkStepFailed;
    };
    defer owned.deinit();

    if (owned.tag != null) {
        try err_w.print("error: 'ghr link' does not accept a tag — link reflects whatever is installed on Windows\n", .{});
        try err_w.flush();
        return LinkCmdError.LinkStepFailed;
    }

    const win_tools = windowsToolsDirFromWsl(allocator, environ, io, err_w) catch return LinkCmdError.LinkStepFailed;
    defer allocator.free(win_tools);

    const tool_path = (try install.resolveInstalledToolPath(allocator, io, win_tools, owned.owner, owned.repo)) orelse {
        try writeNotInstalledError(allocator, io, err_w, win_tools, owned.owner, owned.repo);
        return LinkCmdError.LinkStepFailed;
    };
    defer allocator.free(tool_path);

    const meta = install.readMetadata(allocator, io, tool_path) orelse {
        try err_w.print("error: failed to read {s}/ghr.json\n", .{tool_path});
        try err_w.flush();
        return LinkCmdError.LinkStepFailed;
    };
    defer {
        meta.parsed.deinit();
        allocator.free(meta.body);
    }

    var computed = computeDesiredLinks(allocator, meta.parsed.value.bins, tool_path, bin_filters) catch |err| switch (err) {
        DesiredError.DuplicateLinkName => {
            try err_w.print(
                "error: two or more entries in {s}/ghr.json collapse to the same link name\n",
                .{tool_path},
            );
            try err_w.print("       refusing to link to avoid clobbering one with the other\n", .{});
            try err_w.flush();
            return LinkCmdError.LinkStepFailed;
        },
        DesiredError.NoBinsInMetadata => {
            try err_w.print("error: {s}/ghr.json lists no bins\n", .{tool_path});
            try err_w.flush();
            return LinkCmdError.LinkStepFailed;
        },
        DesiredError.NoValidBinsAfterNormalize => {
            try err_w.print(
                "error: every bin entry in {s}/ghr.json is unsafe (absolute or contains '..'); metadata looks corrupt\n",
                .{tool_path},
            );
            try err_w.print("       refusing to reconcile to avoid removing existing valid links\n", .{});
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
    install.ensureDirAbsoluteRecursive(io, d.bin);
    var bin_dir = Dir.openDirAbsolute(io, d.bin, .{}) catch |err| {
        try err_w.print("error: failed to open bin directory '{s}': {t}\n", .{ d.bin, err });
        try err_w.flush();
        return LinkCmdError.LinkStepFailed;
    };
    defer bin_dir.close(io);

    // Load prior manifest (may be absent on first link).
    const manifest_abs = try manifestPath(allocator, environ, owned.owner, owned.repo);
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

    // Apply the desired set: add / no-op / replace / record conflicts.
    var written = std.ArrayListUnmanaged(LinkEntry).empty;
    defer written.deinit(allocator);
    var any_explicit_failure = false;
    var conflicts: usize = 0;

    for (computed.links) |desired| {
        const explicit = bin_filters.len > 0;
        const outcome = applyOneLink(io, bin_dir, desired, prior_links) catch |err| {
            try err_w.print("warning: failed to link {s}: {t}\n", .{ desired.name, err });
            if (explicit) any_explicit_failure = true;
            continue;
        };
        switch (outcome) {
            .created => try w.print("  linked   {s} -> {s}\n", .{ desired.name, desired.target }),
            .replaced => try w.print("  updated  {s} -> {s}\n", .{ desired.name, desired.target }),
            .unchanged => try w.print("  ok       {s} -> {s}\n", .{ desired.name, desired.target }),
            .conflict => {
                conflicts += 1;
                if (explicit) {
                    try err_w.print(
                        "error: {s}/{s} already exists and is not a ghr-created link; refusing to overwrite\n",
                        .{ d.bin, desired.name },
                    );
                    any_explicit_failure = true;
                } else {
                    try w.print(
                        "  skipped  {s} ({s}/{s} already exists and is not a ghr-created link)\n",
                        .{ desired.name, d.bin, desired.name },
                    );
                }
                continue;
            },
        }
        try written.append(allocator, .{ .name = desired.name, .target = desired.target });
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
            const outcome = removeOwnedLink(io, bin_dir, old) catch |err| {
                try err_w.print("warning: failed to remove stale link {s}: {t}\n", .{ old.name, err });
                continue;
            };
            switch (outcome) {
                .removed => try w.print("  removed  {s} (no longer present in {s}/{s})\n", .{ old.name, owned.owner, owned.repo }),
                .missing => {}, // already gone, no message
                .target_mismatch => try w.print(
                    "  kept     {s} (live symlink target differs from manifest; leaving it alone)\n",
                    .{old.name},
                ),
            }
        }
    } else {
        // Filtered mode: carry over prior entries that weren't touched so
        // the persisted manifest still reflects what's actually linked.
        for (prior_links) |old| {
            var touched = false;
            for (computed.links) |desired| {
                if (std.mem.eql(u8, desired.name, old.name)) {
                    touched = true;
                    break;
                }
            }
            if (touched) continue;
            // Verify the link still exists and points where we recorded
            // before keeping it in the manifest; otherwise drop it.
            var lb: [Dir.max_path_bytes]u8 = undefined;
            const n = bin_dir.readLink(io, old.name, &lb) catch continue;
            if (!std.mem.eql(u8, lb[0..n], old.target)) continue;
            try written.append(allocator, old);
        }
    }

    // Write manifest atomically. If there are no live links, delete the
    // manifest file outright.
    if (written.items.len == 0) {
        deleteManifest(allocator, io, environ, owned.owner, owned.repo) catch {};
    } else {
        try writeManifest(allocator, io, environ, owned.owner, owned.repo, .{
            .source = tool_path,
            .links = written.items,
        });
    }

    if (any_explicit_failure) {
        try err_w.flush();
        return LinkCmdError.LinkStepFailed;
    }
}

const LinkOutcome = enum { created, replaced, unchanged, conflict };

/// Apply one desired link in `bin_dir`. Considers an existing symlink
/// ghr-owned only if a prior manifest had an entry with the same
/// `name` — the recorded target may differ from the new target, so we
/// can still update after a Windows-side reinstall moved the bin to a
/// new relative path. A non-symlink (regular file, directory) or a
/// symlink that was never in our manifest is reported as a conflict;
/// the caller decides whether to warn-and-skip or fail.
fn applyOneLink(
    io: Io,
    bin_dir: Dir,
    desired: DesiredLink,
    prior_links: []const LinkEntry,
) !LinkOutcome {
    var link_buf: [Dir.max_path_bytes]u8 = undefined;
    if (bin_dir.readLink(io, desired.name, &link_buf)) |n| {
        const current = link_buf[0..n];
        if (std.mem.eql(u8, current, desired.target)) return .unchanged;
        // Owned by us if previously manifested under this name, regardless
        // of the recorded target (lets us update after a Windows-side
        // reinstall changed the bin's relative path).
        var owned_by_us = false;
        for (prior_links) |old| {
            if (std.mem.eql(u8, old.name, desired.name)) {
                owned_by_us = true;
                break;
            }
        }
        if (!owned_by_us) return .conflict;
        bin_dir.deleteFile(io, desired.name) catch {};
        try bin_dir.symLink(io, desired.target, desired.name, .{});
        return .replaced;
    } else |err| switch (err) {
        error.FileNotFound => {
            // No symlink — but could be a regular file or directory.
            if (bin_dir.statFile(io, desired.name, .{})) |_| {
                return .conflict;
            } else |_| {}
            try bin_dir.symLink(io, desired.target, desired.name, .{});
            return .created;
        },
        // `readLink` of a non-symlink returns this on Linux.
        error.NotLink => return .conflict,
        else => return err,
    }
}

/// Outcome of attempting to remove a previously-linked symlink.
const RemoveOutcome = enum {
    removed,
    missing,
    target_mismatch,
};

/// Remove a manifested symlink, but only when its live target still
/// matches what was recorded. Returns the outcome so the caller can
/// distinguish "we deleted it" from "we left it alone for safety" —
/// `cmdUnlink` keeps the entry in the manifest on `target_mismatch`
/// rather than silently forgetting about the user's rewritten link.
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

    const owned = release_mod.parseRepoSpecOwned(allocator, spec_str) catch {
        try err_w.print("error: invalid spec '{s}', expected owner/repo\n", .{spec_str});
        try err_w.flush();
        return LinkCmdError.LinkStepFailed;
    };
    defer owned.deinit();

    if (owned.tag != null) {
        try err_w.print("error: 'ghr unlink' does not accept a tag\n", .{});
        try err_w.flush();
        return LinkCmdError.LinkStepFailed;
    }

    const manifest_abs = try manifestPath(allocator, environ, owned.owner, owned.repo);
    defer allocator.free(manifest_abs);
    var parsed = readManifest(allocator, io, manifest_abs) catch |err| switch (err) {
        error.InvalidManifest => null,
        else => return err,
    };
    defer if (parsed) |*p| p.deinit();

    const p = parsed orelse {
        try err_w.print("error: no link manifest for {s}/{s}\n", .{ owned.owner, owned.repo });
        try err_w.print("       (looked at {s})\n", .{manifest_abs});
        try err_w.flush();
        return LinkCmdError.LinkStepFailed;
    };

    // Pre-validate: every explicitly-requested filter must match a
    // manifest entry. Bail out before touching the filesystem so a
    // typo in one --bin doesn't half-unlink the rest.
    if (bin_filters.len > 0) {
        var any_unmatched = false;
        for (bin_filters) |f| {
            var matched = false;
            for (p.value.links) |entry| {
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
            for (p.value.links, 0..) |entry, i| {
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

    var any_explicit_failure = false;
    var kept = std.ArrayListUnmanaged(LinkEntry).empty;
    defer kept.deinit(allocator);

    for (p.value.links) |entry| {
        const explicit = bin_filters.len > 0;
        if (explicit) {
            var requested = false;
            for (bin_filters) |f| {
                if (std.ascii.eqlIgnoreCase(f, entry.name)) {
                    requested = true;
                    break;
                }
            }
            if (!requested) {
                try kept.append(allocator, entry);
                continue;
            }
        }

        const outcome = removeOwnedLink(io, bin_dir, entry) catch |err| {
            try err_w.print("warning: failed to unlink {s}: {t}\n", .{ entry.name, err });
            if (explicit) any_explicit_failure = true;
            try kept.append(allocator, entry);
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
                if (explicit) any_explicit_failure = true;
                try kept.append(allocator, entry);
            },
        }
    }

    if (kept.items.len == 0) {
        deleteManifest(allocator, io, environ, owned.owner, owned.repo) catch {};
    } else {
        try writeManifest(allocator, io, environ, owned.owner, owned.repo, .{
            .source = p.value.source,
            .links = kept.items,
        });
    }

    if (any_explicit_failure) {
        try err_w.flush();
        return LinkCmdError.LinkStepFailed;
    }
}

// ---------------------------------------------------------------------------
// Tests for the pure helpers.
// ---------------------------------------------------------------------------

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

test "listInstalledSlugs: reports tools dir missing" {
    const tio = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &path_buf);
    const base = path_buf[0..base_len];

    var nonexistent_buf: [Dir.max_path_bytes]u8 = undefined;
    const nonexistent = try std.fmt.bufPrint(&nonexistent_buf, "{s}{c}nope", .{ base, std.fs.path.sep });

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const result = try listInstalledSlugs(arena.allocator(), tio, nonexistent);
    try std.testing.expect(!result.present);
    try std.testing.expectEqual(@as(usize, 0), result.slugs.len);
}

test "listInstalledSlugs: empty dir reports present with no slugs" {
    const tio = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &path_buf);
    const base = path_buf[0..base_len];

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const result = try listInstalledSlugs(arena.allocator(), tio, base);
    try std.testing.expect(result.present);
    try std.testing.expectEqual(@as(usize, 0), result.slugs.len);
}

test "listInstalledSlugs: lists owner/repo slugs sorted and skips tombstones" {
    const tio = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(tio, "azuread/microsoft-authentication-cli");
    try tmp.dir.createDirPath(tio, "cataggar/ghr");
    try tmp.dir.createDirPath(tio, "cataggar/ghr.old"); // tombstone
    try tmp.dir.createDirPath(tio, "ctaggart/zig");
    try tmp.dir.createDirPath(tio, "lonely-owner"); // owner with no repos

    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &path_buf);
    const base = path_buf[0..base_len];

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const result = try listInstalledSlugs(arena.allocator(), tio, base);
    try std.testing.expect(result.present);
    try std.testing.expectEqual(@as(usize, 3), result.slugs.len);
    try std.testing.expectEqualStrings("azuread/microsoft-authentication-cli", result.slugs[0]);
    try std.testing.expectEqualStrings("cataggar/ghr", result.slugs[1]);
    try std.testing.expectEqualStrings("ctaggart/zig", result.slugs[2]);
}

test "writeNotInstalledError: lists siblings so typos are obvious" {
    const tio = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(tio, "azuread/microsoft-authentication-cli");
    try tmp.dir.createDirPath(tio, "ctaggart/zig");

    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &path_buf);
    const base = path_buf[0..base_len];

    var out = std.Io.Writer.Allocating.init(allocator);
    defer out.deinit();
    try writeNotInstalledError(allocator, tio, &out.writer, base, "cataggar", "microsoft-authentication-cli");

    const text = out.written();
    try std.testing.expect(std.mem.indexOf(u8, text, "error: cataggar/microsoft-authentication-cli is not installed on the Windows side\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "azuread/microsoft-authentication-cli") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "ctaggart/zig") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "run `ghr install cataggar/microsoft-authentication-cli` from Windows") != null);
}

test "writeNotInstalledError: distinguishes missing tools dir from empty" {
    const tio = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &path_buf);
    const base = path_buf[0..base_len];

    var nonexistent_buf: [Dir.max_path_bytes]u8 = undefined;
    const nonexistent = try std.fmt.bufPrint(&nonexistent_buf, "{s}{c}nope", .{ base, std.fs.path.sep });

    var out1 = std.Io.Writer.Allocating.init(allocator);
    defer out1.deinit();
    try writeNotInstalledError(allocator, tio, &out1.writer, nonexistent, "x", "y");
    try std.testing.expect(std.mem.indexOf(u8, out1.written(), "Windows tools dir does not exist") != null);

    var out2 = std.Io.Writer.Allocating.init(allocator);
    defer out2.deinit();
    try writeNotInstalledError(allocator, tio, &out2.writer, base, "x", "y");
    try std.testing.expect(std.mem.indexOf(u8, out2.written(), "Windows tools dir exists but is empty") != null);
}
