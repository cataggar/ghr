const std = @import("std");
const builtin = @import("builtin");
const Dirs = @import("dirs.zig").Dirs;

const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;
const Writer = Io.Writer;
const Environ = std.process.Environ;
const EnvironMap = Environ.Map;

// Guarded-block markers. Must appear at the start of a line, on their own line,
// so that idempotency detection and in-place replacement are unambiguous.
const begin_marker = "# >>> ghr >>>";
const end_marker = "# <<< ghr <<<";

pub const Action = enum { up_to_date, appended, updated };

pub const Error = error{
    BinContainsNewline,
    BinContainsPathSep,
    HomeNotFound,
};

// --- Pure helpers (platform-independent) ---

fn validateBinPosix(bin: []const u8) !void {
    for (bin) |c| {
        if (c == '\n' or c == '\r') return error.BinContainsNewline;
        if (c == ':') return error.BinContainsPathSep;
    }
}

fn validateBinWindows(bin: []const u8) !void {
    for (bin) |c| {
        if (c == '\n' or c == '\r') return error.BinContainsNewline;
        if (c == ';') return error.BinContainsPathSep;
    }
}

/// Nushell `'...'` single-quoted literals have no escape sequences, so we
/// cannot embed a single quote or newline. Newlines are already rejected by
/// `validateBinPosix`; this additionally forbids the single quote.
fn binIsNushellSafe(bin: []const u8) bool {
    for (bin) |c| {
        if (c == '\'') return false;
    }
    return true;
}

/// Escape a string so that it can be safely embedded inside a POSIX shell
/// double-quoted literal. Inside `"..."` only `\`, `"`, `$`, and `` ` `` are
/// special and must be backslash-escaped.
fn shellEscapeDoubleQuoted(allocator: std.mem.Allocator, bin: []const u8) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);
    for (bin) |c| {
        switch (c) {
            '\\', '"', '$', '`' => try out.append(allocator, '\\'),
            else => {},
        }
        try out.append(allocator, c);
    }
    return out.toOwnedSlice(allocator);
}

/// Escape a string so it can be safely embedded inside a nushell single-quoted
/// literal. Nushell's `'...'` literals have **no** escape sequences, so a
/// single quote or newline cannot be represented inside one — we reject such
/// inputs earlier via `validateBinNushell`.
fn nushellEscapeSingleQuoted(allocator: std.mem.Allocator, bin: []const u8) ![]u8 {
    return allocator.dupe(u8, bin);
}

fn buildPosixBlock(allocator: std.mem.Allocator, bin: []const u8) ![]u8 {
    const esc = try shellEscapeDoubleQuoted(allocator, bin);
    defer allocator.free(esc);
    return std.fmt.allocPrint(
        allocator,
        "{s}\ncase \":$PATH:\" in\n  *\":{s}:\"*) ;;\n  *) export PATH=\"{s}:$PATH\" ;;\nesac\n{s}\n",
        .{ begin_marker, esc, esc, end_marker },
    );
}

fn buildNushellBlock(allocator: std.mem.Allocator, bin: []const u8) ![]u8 {
    const esc = try nushellEscapeSingleQuoted(allocator, bin);
    defer allocator.free(esc);
    return std.fmt.allocPrint(
        allocator,
        "{s}\nif ('{s}' not-in $env.PATH) {{\n    $env.PATH = ($env.PATH | prepend '{s}')\n}}\n{s}\n",
        .{ begin_marker, esc, esc, end_marker },
    );
}

const BlockRange = struct { start: usize, end: usize };

/// Locate a `# >>> ghr >>>` ... `# <<< ghr <<<` block in `contents`. Both
/// markers must begin at the start of a line. The returned `end` is positioned
/// just past the newline following the end marker (if any).
fn findBlock(contents: []const u8) ?BlockRange {
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, contents, i, begin_marker)) |pos| {
        if (pos != 0 and contents[pos - 1] != '\n') {
            i = pos + 1;
            continue;
        }
        const search_from = pos + begin_marker.len;
        const end_pos = std.mem.indexOfPos(u8, contents, search_from, end_marker) orelse return null;
        if (end_pos != 0 and contents[end_pos - 1] != '\n') {
            i = pos + 1;
            continue;
        }
        var block_end = end_pos + end_marker.len;
        if (block_end < contents.len and contents[block_end] == '\r') block_end += 1;
        if (block_end < contents.len and contents[block_end] == '\n') block_end += 1;
        return .{ .start = pos, .end = block_end };
    }
    return null;
}

pub const TransformResult = struct {
    new_contents: []u8,
    action: Action,
};

/// Apply the managed-block transform to rc-file contents.
///  - If no managed block exists, append `desired_block` (with a blank-line
///    separator if the file is non-empty).
///  - If an existing managed block is byte-identical to `desired_block`, the
///    file is up to date; `new_contents` is a fresh copy of `existing`.
///  - Otherwise the existing block is replaced in place.
/// Caller owns `new_contents`.
fn transformRcFile(
    allocator: std.mem.Allocator,
    existing: []const u8,
    desired_block: []const u8,
) !TransformResult {
    if (findBlock(existing)) |b| {
        const cur = existing[b.start..b.end];
        if (std.mem.eql(u8, cur, desired_block)) {
            return .{
                .new_contents = try allocator.dupe(u8, existing),
                .action = .up_to_date,
            };
        }
        const new_len = existing.len - (b.end - b.start) + desired_block.len;
        const buf = try allocator.alloc(u8, new_len);
        @memcpy(buf[0..b.start], existing[0..b.start]);
        @memcpy(buf[b.start .. b.start + desired_block.len], desired_block);
        @memcpy(buf[b.start + desired_block.len ..], existing[b.end..]);
        return .{ .new_contents = buf, .action = .updated };
    }
    var list: std.ArrayListUnmanaged(u8) = .empty;
    errdefer list.deinit(allocator);
    try list.appendSlice(allocator, existing);
    if (existing.len > 0) {
        if (!std.mem.endsWith(u8, existing, "\n")) try list.append(allocator, '\n');
        try list.append(allocator, '\n'); // blank-line separator
    }
    try list.appendSlice(allocator, desired_block);
    return .{
        .new_contents = try list.toOwnedSlice(allocator),
        .action = .appended,
    };
}

/// Segment-aware PATH containment. Treats `sep`-delimited segments literally;
/// does not expand environment variables.
fn pathSegmentsContain(path_value: []const u8, bin: []const u8, sep: u8) bool {
    var it = std.mem.splitScalar(u8, path_value, sep);
    while (it.next()) |seg| {
        if (seg.len == 0) continue;
        if (std.mem.eql(u8, seg, bin)) return true;
    }
    return false;
}

/// Case-insensitive ASCII path segment comparison. Trailing backslashes on
/// either side are stripped before comparing. Suitable for Windows PATH
/// entries after environment-variable expansion.
fn windowsPathSegmentEquals(a: []const u8, b: []const u8) bool {
    const an = std.mem.trimEnd(u8, a, "\\/");
    const bn = std.mem.trimEnd(u8, b, "\\/");
    if (an.len != bn.len) return false;
    for (an, bn) |ca, cb| {
        if (std.ascii.toLower(ca) != std.ascii.toLower(cb)) return false;
    }
    return true;
}

/// Prepend `bin` to a `sep`-delimited PATH string if it isn't already present.
/// Returns the possibly-unchanged value; caller owns the returned slice.
fn prependIfMissing(
    allocator: std.mem.Allocator,
    existing: []const u8,
    bin: []const u8,
    sep: u8,
    already_present: *bool,
) ![]u8 {
    if (pathSegmentsContain(existing, bin, sep)) {
        already_present.* = true;
        return allocator.dupe(u8, existing);
    }
    already_present.* = false;
    if (existing.len == 0) return allocator.dupe(u8, bin);
    var out = try allocator.alloc(u8, bin.len + 1 + existing.len);
    @memcpy(out[0..bin.len], bin);
    out[bin.len] = sep;
    @memcpy(out[bin.len + 1 ..], existing);
    return out;
}

// --- I/O helpers ---

fn readFileAllOptional(
    allocator: std.mem.Allocator,
    io: Io,
    path: []const u8,
) !?[]u8 {
    const parent_path = std.fs.path.dirname(path) orelse return null;
    const basename = std.fs.path.basename(path);
    var parent = Dir.openDirAbsolute(io, parent_path, .{}) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer parent.close(io);
    return parent.readFileAlloc(io, basename, allocator, Io.Limit.limited(1024 * 1024)) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
}

fn writeFileAtomic(
    io: Io,
    path: []const u8,
    contents: []const u8,
) !void {
    const parent_path = std.fs.path.dirname(path) orelse ".";
    const basename = std.fs.path.basename(path);
    var parent = try Dir.openDirAbsolute(io, parent_path, .{});
    defer parent.close(io);

    const tmp_name_buf_len = basename.len + ".ghr.tmp".len;
    var tmp_name_buf: [512]u8 = undefined;
    if (tmp_name_buf_len > tmp_name_buf.len) return error.PathTooLong;
    @memcpy(tmp_name_buf[0..basename.len], basename);
    @memcpy(tmp_name_buf[basename.len..tmp_name_buf_len], ".ghr.tmp");
    const tmp_name = tmp_name_buf[0..tmp_name_buf_len];

    {
        var f = try parent.createFile(io, tmp_name, .{});
        errdefer parent.deleteFile(io, tmp_name) catch {};
        defer f.close(io);
        try f.writeStreamingAll(io, contents);
    }
    try parent.rename(tmp_name, parent, basename, io);
}

fn ensureParentDir(io: Io, path: []const u8) !void {
    const parent = std.fs.path.dirname(path) orelse return;
    makeDirRecursiveAbs(io, parent) catch {};
}

fn makeDirRecursiveAbs(io: Io, path: []const u8) !void {
    Dir.createDirAbsolute(io, path, .default_dir) catch |err| switch (err) {
        error.PathAlreadyExists => return,
        error.FileNotFound => {
            const parent = std.fs.path.dirname(path) orelse return err;
            try makeDirRecursiveAbs(io, parent);
            Dir.createDirAbsolute(io, path, .default_dir) catch |err2| switch (err2) {
                error.PathAlreadyExists => return,
                else => return err2,
            };
        },
        else => |e| return e,
    };
}

fn pathExists(io: Io, path: []const u8) bool {
    const parent_path = std.fs.path.dirname(path) orelse return false;
    const basename = std.fs.path.basename(path);
    var parent = Dir.openDirAbsolute(io, parent_path, .{}) catch return false;
    defer parent.close(io);
    _ = parent.statFile(io, basename, .{}) catch return false;
    return true;
}

fn joinHome(allocator: std.mem.Allocator, home: []const u8, rel: []const u8) ![]u8 {
    return std.fs.path.join(allocator, &.{ home, rel });
}

fn basenameOf(s: []const u8) []const u8 {
    return std.fs.path.basename(s);
}

// --- Unix implementation ---

const UnixTargetKind = enum { posix, nushell };

const UnixTarget = struct {
    path: []u8, // owned
    kind: UnixTargetKind,
    create_if_missing: bool,
};

fn addTargetOnce(
    allocator: std.mem.Allocator,
    list: *std.ArrayListUnmanaged(UnixTarget),
    path: []const u8,
    kind: UnixTargetKind,
    create_if_missing: bool,
) !void {
    for (list.items) |t| {
        if (std.mem.eql(u8, t.path, path)) return;
    }
    const copy = try allocator.dupe(u8, path);
    try list.append(allocator, .{
        .path = copy,
        .kind = kind,
        .create_if_missing = create_if_missing,
    });
}

fn buildUnixTargets(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    home: []const u8,
    shell: ?[]const u8,
) !std.ArrayListUnmanaged(UnixTarget) {
    var out: std.ArrayListUnmanaged(UnixTarget) = .empty;
    errdefer {
        for (out.items) |t| allocator.free(t.path);
        out.deinit(allocator);
    }

    const shell_name: []const u8 = if (shell) |s| basenameOf(s) else "";
    const is_bash = std.mem.eql(u8, shell_name, "bash");
    const is_zsh = std.mem.eql(u8, shell_name, "zsh");
    const is_nu = std.mem.eql(u8, shell_name, "nu");

    const bash_profile = try joinHome(allocator, home, ".bash_profile");
    defer allocator.free(bash_profile);
    const bashrc = try joinHome(allocator, home, ".bashrc");
    defer allocator.free(bashrc);
    const zprofile = try joinHome(allocator, home, ".zprofile");
    defer allocator.free(zprofile);
    const profile = try joinHome(allocator, home, ".profile");
    defer allocator.free(profile);

    // Nushell honours $XDG_CONFIG_HOME; fall back to ~/.config.
    const config_home: []u8 = if (environ.get("XDG_CONFIG_HOME")) |xdg|
        try allocator.dupe(u8, xdg)
    else
        try joinHome(allocator, home, ".config");
    defer allocator.free(config_home);
    const nu_dir = try std.fs.path.join(allocator, &.{ config_home, "nushell" });
    defer allocator.free(nu_dir);
    const nu_env = try std.fs.path.join(allocator, &.{ nu_dir, "env.nu" });
    defer allocator.free(nu_env);

    const bash_profile_exists = pathExists(io, bash_profile);
    const bashrc_exists = pathExists(io, bashrc);
    const zprofile_exists = pathExists(io, zprofile);
    const profile_exists = pathExists(io, profile);
    const nu_dir_exists = pathExists(io, nu_dir);

    // bash rc files
    if (bash_profile_exists) {
        try addTargetOnce(allocator, &out, bash_profile, .posix, false);
    }
    if (bashrc_exists) {
        try addTargetOnce(allocator, &out, bashrc, .posix, false);
    }
    if (is_bash and !bash_profile_exists and !bashrc_exists) {
        // Create .profile so login bash picks it up. (.profile is more portable
        // than .bash_profile and is read by login sh too.)
        try addTargetOnce(allocator, &out, profile, .posix, true);
    }

    // zsh
    if (zprofile_exists or is_zsh) {
        try addTargetOnce(allocator, &out, zprofile, .posix, true);
    }

    // .profile: touch if it already exists (POSIX sh / dash / login sh).
    if (profile_exists) {
        try addTargetOnce(allocator, &out, profile, .posix, false);
    }

    // nushell
    if (is_nu or nu_dir_exists) {
        try addTargetOnce(allocator, &out, nu_env, .nushell, true);
    }

    return out;
}

fn processUnixTarget(
    allocator: std.mem.Allocator,
    io: Io,
    target: UnixTarget,
    posix_block: []const u8,
    nushell_block: []const u8,
    dry_run: bool,
    out_w: *Writer,
) !void {
    const desired = switch (target.kind) {
        .posix => posix_block,
        .nushell => nushell_block,
    };

    const existing_opt = try readFileAllOptional(allocator, io, target.path);
    defer if (existing_opt) |e| allocator.free(e);

    if (existing_opt == null and !target.create_if_missing) return;

    const existing = existing_opt orelse "";
    const res = try transformRcFile(allocator, existing, desired);
    defer allocator.free(res.new_contents);

    switch (res.action) {
        .up_to_date => {
            try out_w.print("  up-to-date: {s}\n", .{target.path});
            return;
        },
        .appended => {
            if (dry_run) {
                try out_w.print("  would-append: {s}\n    block:\n", .{target.path});
                try printIndented(out_w, desired, "      ");
                return;
            }
            try out_w.print("  appended: {s}\n", .{target.path});
        },
        .updated => {
            if (dry_run) {
                try out_w.print("  would-update: {s}\n    new block:\n", .{target.path});
                try printIndented(out_w, desired, "      ");
                return;
            }
            try out_w.print("  updated: {s}\n", .{target.path});
        },
    }

    // Ensure parent directory exists (matters for ~/.config/nushell/env.nu).
    try ensureParentDir(io, target.path);
    const parent_path = std.fs.path.dirname(target.path) orelse ".";
    // For nested config dirs, parent may itself not exist.
    makeDirRecursiveAbs(io, parent_path) catch {};

    try writeFileAtomic(io, target.path, res.new_contents);
}

fn printIndented(w: *Writer, text: []const u8, indent: []const u8) !void {
    var it = std.mem.splitScalar(u8, text, '\n');
    var first = true;
    while (it.next()) |line| {
        if (first) {
            first = false;
        } else {
            try w.print("\n", .{});
        }
        if (line.len == 0) continue;
        try w.print("{s}{s}", .{ indent, line });
    }
    try w.print("\n", .{});
}

fn runUnix(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    dirs: Dirs,
    dry_run: bool,
    out_w: *Writer,
) !void {
    try validateBinPosix(dirs.bin);

    const posix_block = try buildPosixBlock(allocator, dirs.bin);
    defer allocator.free(posix_block);
    const nushell_block = try buildNushellBlock(allocator, dirs.bin);
    defer allocator.free(nushell_block);

    const home = environ.get("HOME") orelse return error.HomeNotFound;
    const shell = environ.get("SHELL");

    var targets = try buildUnixTargets(allocator, io, environ, home, shell);
    defer {
        for (targets.items) |t| allocator.free(t.path);
        targets.deinit(allocator);
    }

    try out_w.print("ghr bin: {s}\n", .{dirs.bin});
    if (targets.items.len == 0) {
        try out_w.print("no shell rc files detected; nothing to do.\n", .{});
        try out_w.print("add this to your shell config manually:\n\n", .{});
        try printIndented(out_w, posix_block, "  ");
        return;
    }

    for (targets.items) |t| {
        if (t.kind == .nushell and !binIsNushellSafe(dirs.bin)) {
            try out_w.print("  skipping: {s} (bin path contains ' which nushell single-quoted literals cannot escape)\n", .{t.path});
            continue;
        }
        processUnixTarget(allocator, io, t, posix_block, nushell_block, dry_run, out_w) catch |err| {
            try out_w.print("  error processing {s}: {s}\n", .{ t.path, @errorName(err) });
        };
    }

    if (!dry_run) {
        try out_w.print("\nopen a new shell for the change to take effect.\n", .{});
    }
}

// --- Windows implementation ---

const windows_impl = if (builtin.os.tag == .windows) struct {
    const windows = std.os.windows;
    const HKEY = windows.HKEY;
    const LSTATUS = windows.LSTATUS;
    const WCHAR = windows.WCHAR;
    const DWORD = windows.DWORD;
    const LRESULT = isize;

    const HKEY_CURRENT_USER: HKEY = @ptrFromInt(0x80000001);

    const KEY_QUERY_VALUE: DWORD = 0x0001;
    const KEY_SET_VALUE: DWORD = 0x0002;
    const KEY_WRITE: DWORD = 0x20006;
    const KEY_READ: DWORD = 0x20019;

    const REG_NONE: DWORD = 0;
    const REG_SZ: DWORD = 1;
    const REG_EXPAND_SZ: DWORD = 2;

    const ERROR_SUCCESS: LSTATUS = 0;
    const ERROR_FILE_NOT_FOUND: LSTATUS = 2;
    const ERROR_MORE_DATA: LSTATUS = 234;

    const HWND_BROADCAST: windows.HWND = @ptrFromInt(0xFFFF);
    const WM_SETTINGCHANGE: windows.UINT = 0x001A;
    const SMTO_ABORTIFHUNG: windows.UINT = 0x0002;

    extern "advapi32" fn RegOpenKeyExW(
        hKey: HKEY,
        lpSubKey: [*:0]const u16,
        ulOptions: DWORD,
        samDesired: DWORD,
        phkResult: *HKEY,
    ) callconv(.winapi) LSTATUS;

    extern "advapi32" fn RegCreateKeyExW(
        hKey: HKEY,
        lpSubKey: [*:0]const u16,
        Reserved: DWORD,
        lpClass: ?[*:0]u16,
        dwOptions: DWORD,
        samDesired: DWORD,
        lpSecurityAttributes: ?*anyopaque,
        phkResult: *HKEY,
        lpdwDisposition: ?*DWORD,
    ) callconv(.winapi) LSTATUS;

    extern "advapi32" fn RegCloseKey(hKey: HKEY) callconv(.winapi) LSTATUS;

    extern "advapi32" fn RegQueryValueExW(
        hKey: HKEY,
        lpValueName: [*:0]const u16,
        lpReserved: ?*DWORD,
        lpType: ?*DWORD,
        lpData: ?[*]u8,
        lpcbData: ?*DWORD,
    ) callconv(.winapi) LSTATUS;

    extern "advapi32" fn RegSetValueExW(
        hKey: HKEY,
        lpValueName: [*:0]const u16,
        Reserved: DWORD,
        dwType: DWORD,
        lpData: [*]const u8,
        cbData: DWORD,
    ) callconv(.winapi) LSTATUS;

    extern "kernel32" fn ExpandEnvironmentStringsW(
        lpSrc: [*:0]const u16,
        lpDst: ?[*]u16,
        nSize: DWORD,
    ) callconv(.winapi) DWORD;

    extern "user32" fn SendMessageTimeoutW(
        hWnd: windows.HWND,
        Msg: windows.UINT,
        wParam: usize,
        lParam: isize,
        fuFlags: windows.UINT,
        uTimeout: windows.UINT,
        lpdwResult: ?*usize,
    ) callconv(.winapi) LRESULT;

    pub fn utf8ToWideZ(allocator: std.mem.Allocator, s: []const u8) ![:0]u16 {
        return std.unicode.utf8ToUtf16LeAllocZ(allocator, s);
    }

    pub fn wideToUtf8(allocator: std.mem.Allocator, w: []const u16) ![]u8 {
        return std.unicode.utf16LeToUtf8Alloc(allocator, w);
    }

    fn expandEnvStrings(allocator: std.mem.Allocator, src: []const u8) ![]u8 {
        const src_w = try utf8ToWideZ(allocator, src);
        defer allocator.free(src_w);
        const needed = ExpandEnvironmentStringsW(src_w.ptr, null, 0);
        if (needed == 0) return try allocator.dupe(u8, src);
        const buf = try allocator.alloc(u16, needed);
        defer allocator.free(buf);
        _ = ExpandEnvironmentStringsW(src_w.ptr, buf.ptr, @intCast(needed));
        // Trim trailing NUL.
        var end: usize = buf.len;
        while (end > 0 and buf[end - 1] == 0) : (end -= 1) {}
        return try wideToUtf8(allocator, buf[0..end]);
    }

    /// Return true if any semicolon-delimited segment of `path_value`, after
    /// env-var expansion, matches `bin_expanded` (case-insensitive, ignoring
    /// trailing slashes).
    fn windowsPathContainsExpanded(
        allocator: std.mem.Allocator,
        path_value: []const u8,
        bin_expanded: []const u8,
    ) !bool {
        var it = std.mem.splitScalar(u8, path_value, ';');
        while (it.next()) |seg_raw| {
            const seg = std.mem.trim(u8, seg_raw, " \t");
            if (seg.len == 0) continue;
            const expanded = expandEnvStrings(allocator, seg) catch continue;
            defer allocator.free(expanded);
            if (windowsPathSegmentEquals(expanded, bin_expanded)) return true;
        }
        return false;
    }

    pub fn run(
        allocator: std.mem.Allocator,
        io: Io,
        environ: *const EnvironMap,
        dirs: Dirs,
        dry_run: bool,
        out_w: *Writer,
    ) !void {
        try validateBinWindows(dirs.bin);

        const sub_key_w = try utf8ToWideZ(allocator, "Environment");
        defer allocator.free(sub_key_w);
        const value_name_w = try utf8ToWideZ(allocator, "Path");
        defer allocator.free(value_name_w);

        var hkey: HKEY = undefined;
        var disposition: DWORD = 0;
        var status = RegCreateKeyExW(
            HKEY_CURRENT_USER,
            sub_key_w.ptr,
            0,
            null,
            0,
            KEY_QUERY_VALUE | KEY_SET_VALUE,
            null,
            &hkey,
            &disposition,
        );
        if (status != ERROR_SUCCESS) {
            try out_w.print("error: RegCreateKeyExW failed: {d}\n", .{status});
            return error.RegistryOpenFailed;
        }
        defer _ = RegCloseKey(hkey);

        var value_type: DWORD = REG_NONE;
        var data_size: DWORD = 0;
        status = RegQueryValueExW(hkey, value_name_w.ptr, null, &value_type, null, &data_size);
        var existing_utf8: []u8 = &.{};
        defer if (existing_utf8.len != 0) allocator.free(existing_utf8);

        var effective_type: DWORD = REG_EXPAND_SZ;
        if (status == ERROR_SUCCESS) {
            if (value_type != REG_SZ and value_type != REG_EXPAND_SZ) {
                try out_w.print("error: HKCU\\Environment\\Path has unsupported registry type {d}\n", .{value_type});
                return error.UnsupportedRegistryType;
            }
            effective_type = value_type;
            if (data_size > 0) {
                const buf = try allocator.alloc(u8, data_size);
                defer allocator.free(buf);
                var size_inout: DWORD = data_size;
                status = RegQueryValueExW(hkey, value_name_w.ptr, null, &value_type, buf.ptr, &size_inout);
                if (status != ERROR_SUCCESS) {
                    try out_w.print("error: RegQueryValueExW failed: {d}\n", .{status});
                    return error.RegistryReadFailed;
                }
                // buf is a WCHAR string, possibly NUL-terminated.
                const wchar_count = size_inout / 2;
                const wslice = @as([*]const u16, @alignCast(@ptrCast(buf.ptr)))[0..wchar_count];
                var end: usize = wslice.len;
                while (end > 0 and wslice[end - 1] == 0) : (end -= 1) {}
                existing_utf8 = try wideToUtf8(allocator, wslice[0..end]);
            }
        } else if (status != ERROR_FILE_NOT_FOUND) {
            try out_w.print("error: RegQueryValueExW failed: {d}\n", .{status});
            return error.RegistryReadFailed;
        }

        const bin_expanded = try expandEnvStrings(allocator, dirs.bin);
        defer allocator.free(bin_expanded);

        try out_w.print("ghr bin: {s}\n", .{dirs.bin});
        try out_w.print("  target: HKCU\\Environment\\Path\n", .{});

        if (try windowsPathContainsExpanded(allocator, existing_utf8, bin_expanded)) {
            try out_w.print("  up-to-date: already on user PATH\n", .{});
            try maybeProcessNushell(allocator, io, environ, dirs, dry_run, out_w);
            return;
        }

        // Prepend.
        const new_value = blk: {
            if (existing_utf8.len == 0) break :blk try allocator.dupe(u8, dirs.bin);
            var out = try allocator.alloc(u8, dirs.bin.len + 1 + existing_utf8.len);
            @memcpy(out[0..dirs.bin.len], dirs.bin);
            out[dirs.bin.len] = ';';
            @memcpy(out[dirs.bin.len + 1 ..], existing_utf8);
            break :blk out;
        };
        defer allocator.free(new_value);

        if (dry_run) {
            try out_w.print("  would-update: prepend bin dir to user PATH\n    new value: {s}\n", .{new_value});
            try maybeProcessNushell(allocator, io, environ, dirs, dry_run, out_w);
            return;
        }

        const new_w = try utf8ToWideZ(allocator, new_value);
        defer allocator.free(new_w);
        // cbData counts bytes including the trailing NUL wchar.
        const cb_data: DWORD = @intCast((new_w.len + 1) * 2);
        status = RegSetValueExW(
            hkey,
            value_name_w.ptr,
            0,
            effective_type,
            @ptrCast(new_w.ptr),
            cb_data,
        );
        if (status != ERROR_SUCCESS) {
            try out_w.print("error: RegSetValueExW failed: {d}\n", .{status});
            return error.RegistryWriteFailed;
        }
        try out_w.print("  updated: user PATH now starts with {s}\n", .{dirs.bin});

        // Broadcast so Explorer and any env-var-watching processes refresh.
        const env_w = try utf8ToWideZ(allocator, "Environment");
        defer allocator.free(env_w);
        var result: usize = 0;
        _ = SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0,
            @bitCast(@intFromPtr(env_w.ptr)),
            SMTO_ABORTIFHUNG,
            5000,
            &result,
        );

        try maybeProcessNushell(allocator, io, environ, dirs, dry_run, out_w);

        try out_w.print("\nopen a new terminal for the change to take effect.\n", .{});
    }

    fn maybeProcessNushell(
        allocator: std.mem.Allocator,
        io: Io,
        environ: *const EnvironMap,
        dirs: Dirs,
        dry_run: bool,
        out_w: *Writer,
    ) !void {
        const appdata = environ.get("APPDATA") orelse return;
        const nu_dir = try std.fs.path.join(allocator, &.{ appdata, "nushell" });
        defer allocator.free(nu_dir);
        // Only touch nushell's config if it already exists — don't create it
        // for users who don't use nushell.
        if (!pathExists(io, nu_dir)) return;

        const nu_env = try std.fs.path.join(allocator, &.{ nu_dir, "env.nu" });
        defer allocator.free(nu_env);

        if (!binIsNushellSafe(dirs.bin)) {
            try out_w.print("  skipping: {s} (bin path contains ' which nushell single-quoted literals cannot escape)\n", .{nu_env});
            return;
        }

        const nushell_block = try buildNushellBlock(allocator, dirs.bin);
        defer allocator.free(nushell_block);

        const target = UnixTarget{
            .path = @constCast(nu_env),
            .kind = .nushell,
            .create_if_missing = true,
        };
        processUnixTarget(allocator, io, target, "", nushell_block, dry_run, out_w) catch |err| {
            try out_w.print("  error processing {s}: {s}\n", .{ nu_env, @errorName(err) });
        };
    }
} else struct {};

// --- Public entry point ---

pub fn cmdEnsurePath(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    dry_run: bool,
    stdout: *Writer,
    stderr: *Writer,
) !void {
    const dirs = try Dirs.detect(allocator, environ);
    defer dirs.deinit();

    if (builtin.os.tag == .windows) {
        try windows_impl.run(allocator, io, environ, dirs, dry_run, stdout);
    } else {
        try runUnix(allocator, io, environ, dirs, dry_run, stdout);
    }
    _ = stderr;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "validateBinPosix rejects newline and colon" {
    try std.testing.expectError(error.BinContainsNewline, validateBinPosix("/tmp/a\nb"));
    try std.testing.expectError(error.BinContainsPathSep, validateBinPosix("/tmp/a:b"));
    try validateBinPosix("/home/u/.local/bin");
}

test "validateBinWindows rejects newline and semicolon" {
    try std.testing.expectError(error.BinContainsNewline, validateBinWindows("C:\\x\ny"));
    try std.testing.expectError(error.BinContainsPathSep, validateBinWindows("C:\\a;b"));
    try validateBinWindows("C:\\Users\\u\\.local\\bin");
}

test "shellEscapeDoubleQuoted escapes shell metachars" {
    const a = std.testing.allocator;
    const out = try shellEscapeDoubleQuoted(a, "a\\b\"c$d`e");
    defer a.free(out);
    try std.testing.expectEqualStrings("a\\\\b\\\"c\\$d\\`e", out);
}

test "binIsNushellSafe rejects single quote" {
    try std.testing.expect(binIsNushellSafe("/home/u/.local/bin"));
    try std.testing.expect(!binIsNushellSafe("/home/o'connor/.local/bin"));
}

test "buildNushellBlock produces a prepend guard" {
    const a = std.testing.allocator;
    const out = try buildNushellBlock(a, "/home/u/.local/bin");
    defer a.free(out);
    try std.testing.expect(std.mem.startsWith(u8, out, begin_marker));
    try std.testing.expect(std.mem.indexOf(u8, out, "'/home/u/.local/bin' not-in $env.PATH") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "$env.PATH | prepend '/home/u/.local/bin'") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, end_marker) != null);
}

test "buildPosixBlock round-trips trivially" {
    const a = std.testing.allocator;
    const out = try buildPosixBlock(a, "/home/u/.local/bin");
    defer a.free(out);
    try std.testing.expect(std.mem.startsWith(u8, out, begin_marker));
    try std.testing.expect(std.mem.indexOf(u8, out, "/home/u/.local/bin") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, end_marker) != null);
}

test "findBlock finds marker on a dedicated line" {
    const contents = "export X=1\n# >>> ghr >>>\nmid\n# <<< ghr <<<\nexport Y=2\n";
    const b = findBlock(contents) orelse return error.MissingBlock;
    try std.testing.expectEqualStrings("# >>> ghr >>>\nmid\n# <<< ghr <<<\n", contents[b.start..b.end]);
}

test "findBlock ignores markers embedded mid-line" {
    const contents = "echo '# >>> ghr >>>' # fake\nreal_end? no\n";
    try std.testing.expect(findBlock(contents) == null);
}

test "transformRcFile appends when absent" {
    const a = std.testing.allocator;
    const desired = "# >>> ghr >>>\nX\n# <<< ghr <<<\n";
    const res = try transformRcFile(a, "export A=1\n", desired);
    defer a.free(res.new_contents);
    try std.testing.expectEqual(Action.appended, res.action);
    try std.testing.expectEqualStrings("export A=1\n\n# >>> ghr >>>\nX\n# <<< ghr <<<\n", res.new_contents);
}

test "transformRcFile appends into empty file" {
    const a = std.testing.allocator;
    const desired = "# >>> ghr >>>\nX\n# <<< ghr <<<\n";
    const res = try transformRcFile(a, "", desired);
    defer a.free(res.new_contents);
    try std.testing.expectEqual(Action.appended, res.action);
    try std.testing.expectEqualStrings(desired, res.new_contents);
}

test "transformRcFile reports up-to-date" {
    const a = std.testing.allocator;
    const desired = "# >>> ghr >>>\nX\n# <<< ghr <<<\n";
    const existing = "prefix\n\n# >>> ghr >>>\nX\n# <<< ghr <<<\nsuffix\n";
    const res = try transformRcFile(a, existing, desired);
    defer a.free(res.new_contents);
    try std.testing.expectEqual(Action.up_to_date, res.action);
    try std.testing.expectEqualStrings(existing, res.new_contents);
}

test "transformRcFile replaces differing block in place" {
    const a = std.testing.allocator;
    const desired = "# >>> ghr >>>\nNEW\n# <<< ghr <<<\n";
    const existing = "prefix\n# >>> ghr >>>\nOLD_A\nOLD_B\n# <<< ghr <<<\nsuffix\n";
    const res = try transformRcFile(a, existing, desired);
    defer a.free(res.new_contents);
    try std.testing.expectEqual(Action.updated, res.action);
    try std.testing.expectEqualStrings("prefix\n# >>> ghr >>>\nNEW\n# <<< ghr <<<\nsuffix\n", res.new_contents);
}

test "pathSegmentsContain is segment-aware" {
    try std.testing.expect(pathSegmentsContain("/a:/b:/c", "/b", ':'));
    try std.testing.expect(!pathSegmentsContain("/aa:/bb", "/a", ':'));
    try std.testing.expect(!pathSegmentsContain("", "/a", ':'));
    try std.testing.expect(pathSegmentsContain(":/a:", "/a", ':'));
}

test "windowsPathSegmentEquals ignores case and trailing slashes" {
    try std.testing.expect(windowsPathSegmentEquals("C:\\Users\\U\\bin\\", "c:\\users\\u\\bin"));
    try std.testing.expect(!windowsPathSegmentEquals("C:\\binx", "C:\\bin"));
}

test "prependIfMissing prepends when absent and no-ops when present" {
    const a = std.testing.allocator;
    var present = false;
    {
        const out = try prependIfMissing(a, "/x:/y", "/z", ':', &present);
        defer a.free(out);
        try std.testing.expect(!present);
        try std.testing.expectEqualStrings("/z:/x:/y", out);
    }
    {
        const out = try prependIfMissing(a, "/x:/y:/z", "/y", ':', &present);
        defer a.free(out);
        try std.testing.expect(present);
        try std.testing.expectEqualStrings("/x:/y:/z", out);
    }
    {
        const out = try prependIfMissing(a, "", "/z", ':', &present);
        defer a.free(out);
        try std.testing.expect(!present);
        try std.testing.expectEqualStrings("/z", out);
    }
}
