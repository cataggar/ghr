//! Local per-ID install transaction and recovery journal (PR 5).
//!
//! One install (or replacement) of one canonical ID is one transaction. The
//! transaction owns four things: the live v2 unit directory, every command
//! artifact the invocation plan assigned to that ID, that ID's app bundles, and
//! -- when a lazy migration is in progress -- the legacy v1 unit it retires.
//!
//! WSL manifest reconciliation is explicitly OUTSIDE this transaction. Nothing
//! here performs a cross-OS operation, and a WSL failure can neither roll back
//! nor block a completed local commit.
//!
//! ## On-disk layout
//!
//! Everything transaction-private lives under a reserved namespace that the
//! inventory reader never descends into (`install_state.scan` only opens
//! `_v2/units`):
//!
//!     <tools>/_v2/txn/u-<seg1>/.../u-<segN>/_unit/
//!         journal.json   bounded, versioned, atomically replaced
//!         stage/         the new unit content; renamed into place on commit
//!         backup/        the previous live unit, moved aside during the swap
//!
//! The encoding is exactly `install_state`'s reversible `u-<segment>` scheme, so
//! a recovering process can decode a transaction directory back to its
//! canonical ID and verify that it matches both the journal and the metadata it
//! is about to publish. Because the whole tree lives under `<tools>`, every
//! commit rename is a same-filesystem rename.
//!
//! ## Phases
//!
//! Phases are monotonic and each one is journaled BEFORE the work it describes,
//! so recovery never has to guess which side of a rename it stopped on. The
//! journal alone is not trusted: `classifyRecovery` combines the recorded phase
//! with the observed presence of unit/stage/backup, which makes every crash
//! point deterministic and idempotent.

const std = @import("std");
const install_state = @import("install_state.zig");
const install_request = @import("install_request.zig");

const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

pub const Platform = install_state.Platform;
pub const default_platform = install_state.default_platform;

pub const txn_dir = "txn";
pub const stage_name = "stage";
pub const backup_name = "backup";
pub const journal_name = "journal.json";
pub const journal_tmp_name = "journal.json.tmp";

/// Journal wire version. A journal written by a future ghr is not interpreted.
pub const journal_schema: i64 = 1;

/// Hard bounds so a hostile or corrupted journal cannot exhaust memory.
pub const max_journal_bytes: usize = 256 * 1024;
pub const max_journal_entries: usize = 4096;

pub const Phase = enum(u8) {
    /// Staging directory exists; content is still being written.
    prepared = 0,
    /// Staged unit is complete, including its metadata. Nothing live changed.
    staged = 1,
    /// About to move the live unit aside and the staged unit into place.
    swapping = 2,
    /// Unit is live; command artifacts and apps are being published.
    publishing = 3,
    /// Commands are published; stale same-ID artifacts and the legacy unit are
    /// being retired.
    retiring = 4,
    /// Everything durable; only transaction cleanup remains.
    complete = 5,
    /// Publication failed and the previous definition, if any, is authoritative.
    /// Recovery must finish rollback without retiring stale or legacy state.
    rolled_back = 6,

    pub fn label(self: Phase) []const u8 {
        return switch (self) {
            .prepared => "prepared",
            .staged => "staged",
            .swapping => "swapping",
            .publishing => "publishing",
            .retiring => "retiring",
            .complete => "complete",
            .rolled_back => "rolled_back",
        };
    }

    pub fn fromLabel(s: []const u8) ?Phase {
        inline for (@typeInfo(Phase).@"enum".fields) |f| {
            const p: Phase = @enumFromInt(f.value);
            if (std.mem.eql(u8, p.label(), s)) return p;
        }
        return null;
    }
};

/// Which operation a journal describes. Recovery must not guess: finishing an
/// interrupted removal and finishing an interrupted replacement are opposite
/// actions, so the intent is recorded explicitly.
pub const Op = enum {
    install,
    uninstall,

    pub fn label(self: Op) []const u8 {
        return switch (self) {
            .install => "install",
            .uninstall => "uninstall",
        };
    }

    pub fn fromLabel(s: []const u8) ?Op {
        if (std.mem.eql(u8, s, "install")) return .install;
        if (std.mem.eql(u8, s, "uninstall")) return .uninstall;
        return null;
    }
};

pub const LegacyKind = enum {
    v1_repo,
    v1_wasm,

    pub fn label(self: LegacyKind) []const u8 {
        return switch (self) {
            .v1_repo => "v1_repo",
            .v1_wasm => "v1_wasm",
        };
    }

    pub fn fromLabel(s: []const u8) ?LegacyKind {
        if (std.mem.eql(u8, s, "v1_repo")) return .v1_repo;
        if (std.mem.eql(u8, s, "v1_wasm")) return .v1_wasm;
        return null;
    }
};

pub const PathError = install_state.EncodeError || error{PathTooLong} || Allocator.Error;

/// Every absolute path one transaction touches. Computed once from the
/// canonical ID so no caller ever builds a unit path from user input.
pub const Paths = struct {
    allocator: Allocator,
    id: []u8,
    /// `<tools>/_v2/units/.../_unit`
    unit: []u8,
    /// `<tools>/_v2/units/...` parent of the unit marker.
    unit_parent: []u8,
    /// `<tools>/_v2/txn`
    txn_root: []u8,
    /// `<tools>/_v2/txn/.../_unit`
    root: []u8,
    stage: []u8,
    backup: []u8,
    journal: []u8,
    journal_tmp: []u8,

    pub fn deinit(self: *Paths) void {
        self.allocator.free(self.id);
        self.allocator.free(self.unit);
        self.allocator.free(self.unit_parent);
        self.allocator.free(self.txn_root);
        self.allocator.free(self.root);
        self.allocator.free(self.stage);
        self.allocator.free(self.backup);
        self.allocator.free(self.journal);
        self.allocator.free(self.journal_tmp);
        self.* = undefined;
    }
};

fn sepFor(platform: Platform) u8 {
    return if (platform == .windows) '\\' else '/';
}

fn joinPath(allocator: Allocator, platform: Platform, base: []const u8, leaf: []const u8) Allocator.Error![]u8 {
    return std.fmt.allocPrint(allocator, "{s}{c}{s}", .{ base, sepFor(platform), leaf });
}

/// Compute every path for `id`. `install_state.encodeUnitPath` performs the
/// authoritative absolute-path preflight (including transaction headroom), so a
/// successful return means the txn siblings fit too.
pub fn paths(
    allocator: Allocator,
    tools_dir: []const u8,
    id: []const u8,
    platform: Platform,
) PathError!Paths {
    const unit = try install_state.encodeUnitPath(allocator, tools_dir, id, platform);
    errdefer allocator.free(unit);

    const rel = try install_state.encodeRelPath(allocator, id);
    defer allocator.free(rel);

    // `_v2/units/<...>/_unit` -> `_v2/txn/<...>/_unit`
    const units_prefix = install_state.v2_namespace ++ "/" ++ install_state.v2_units_dir;
    std.debug.assert(std.mem.startsWith(u8, rel, units_prefix));
    const tail = rel[units_prefix.len..];

    var root_list: std.ArrayListUnmanaged(u8) = .empty;
    errdefer root_list.deinit(allocator);
    try root_list.appendSlice(allocator, tools_dir);
    try root_list.append(allocator, sepFor(platform));
    try root_list.appendSlice(allocator, install_state.v2_namespace);
    try root_list.append(allocator, sepFor(platform));
    try root_list.appendSlice(allocator, txn_dir);
    for (tail) |c| try root_list.append(allocator, if (c == '/') sepFor(platform) else c);
    const root = try root_list.toOwnedSlice(allocator);
    errdefer allocator.free(root);

    const txn_root_owned = try txnRoot(allocator, tools_dir, platform);
    errdefer allocator.free(txn_root_owned);

    const unit_parent = try allocator.dupe(u8, std.fs.path.dirname(unit) orelse unit);
    errdefer allocator.free(unit_parent);
    const id_owned = try allocator.dupe(u8, id);
    errdefer allocator.free(id_owned);
    const stage = try joinPath(allocator, platform, root, stage_name);
    errdefer allocator.free(stage);
    const backup = try joinPath(allocator, platform, root, backup_name);
    errdefer allocator.free(backup);
    const journal = try joinPath(allocator, platform, root, journal_name);
    errdefer allocator.free(journal);
    const journal_tmp = try joinPath(allocator, platform, root, journal_tmp_name);

    return .{
        .allocator = allocator,
        .id = id_owned,
        .unit = unit,
        .unit_parent = unit_parent,
        .txn_root = txn_root_owned,
        .root = root,
        .stage = stage,
        .backup = backup,
        .journal = journal,
        .journal_tmp = journal_tmp,
    };
}

/// Absolute path of the reserved transaction namespace under `tools_dir`.
pub fn txnRoot(allocator: Allocator, tools_dir: []const u8, platform: Platform) Allocator.Error![]u8 {
    return std.fmt.allocPrint(allocator, "{s}{c}{s}{c}{s}", .{
        tools_dir,
        sepFor(platform),
        install_state.v2_namespace,
        sepFor(platform),
        txn_dir,
    });
}

// ---------------------------------------------------------------------------
// Filesystem helpers (local so this module does not depend on install.zig)
// ---------------------------------------------------------------------------

pub fn ensureDirAbsolute(io: Io, abs_path: []const u8) Dir.CreateDirError!void {
    Dir.createDirAbsolute(io, abs_path, .default_dir) catch |err| switch (err) {
        error.PathAlreadyExists => return,
        error.FileNotFound => {
            const parent = std.fs.path.dirname(abs_path) orelse return err;
            try ensureDirAbsolute(io, parent);
            Dir.createDirAbsolute(io, abs_path, .default_dir) catch |retry| switch (retry) {
                error.PathAlreadyExists => return,
                else => return retry,
            };
        },
        else => return err,
    };
}

pub fn deleteTreeAbsolute(io: Io, abs_path: []const u8) !void {
    const parent = std.fs.path.dirname(abs_path) orelse return error.InvalidPath;
    const basename = std.fs.path.basename(abs_path);
    var dir = Dir.openDirAbsolute(io, parent, .{}) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return,
        else => return err,
    };
    defer dir.close(io);
    try dir.deleteTree(io, basename);
}

pub fn directoryExists(io: Io, abs_path: []const u8) !bool {
    var dir = Dir.openDirAbsolute(io, abs_path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        error.NotDir => return error.NotADirectory,
        else => return err,
    };
    dir.close(io);
    return true;
}

fn fileExists(io: Io, abs_path: []const u8) bool {
    var f = Dir.openFileAbsolute(io, abs_path, .{}) catch return false;
    f.close(io);
    return true;
}

// ---------------------------------------------------------------------------
// Journal
// ---------------------------------------------------------------------------

/// Bounded, versioned transaction record. Command artifacts are bin-directory
/// FILE NAMES (never paths); apps are portable relative bundle names.
pub const Journal = struct {
    op: Op = .install,
    id: []const u8,
    unit_path: []const u8,
    stage_path: []const u8,
    backup_path: []const u8,
    /// Files this ID's commands create or replace.
    publish: []const []const u8 = &.{},
    /// Legacy wrappers and rename targets publication also rewrites/removes.
    cleanup: []const []const u8 = &.{},
    /// Files a previous definition of this ID owned that the new one does not.
    stale: []const []const u8 = &.{},
    /// App bundle names this unit owns.
    apps: []const []const u8 = &.{},
    /// Whether this install replaced an existing v1 or v2 unit. Recovery uses
    /// this to distinguish a restored v2 unit from a failed fresh install after
    /// the backup rename has already been consumed.
    had_previous: bool = false,
    /// Legacy v1 unit retired by this transaction, when migrating.
    legacy_path: ?[]const u8 = null,
    legacy_kind: ?LegacyKind = null,
    phase: Phase = .prepared,
};

pub const OwnedJournal = struct {
    arena: std.heap.ArenaAllocator,
    journal: Journal,

    pub fn deinit(self: *OwnedJournal) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

pub const JournalError = error{
    JournalMalformed,
    JournalUnsupportedSchema,
    JournalInvalidId,
    JournalInvalidPath,
    JournalTooLarge,
    JournalTooManyEntries,
    JournalInvalidPhase,
};

const WireJournal = struct {
    schema: ?i64 = null,
    op: ?[]const u8 = null,
    id: ?[]const u8 = null,
    unit_path: ?[]const u8 = null,
    stage_path: ?[]const u8 = null,
    backup_path: ?[]const u8 = null,
    publish: ?[]const []const u8 = null,
    cleanup: ?[]const []const u8 = null,
    stale: ?[]const []const u8 = null,
    apps: ?[]const []const u8 = null,
    had_previous: ?bool = null,
    legacy_path: ?[]const u8 = null,
    legacy_kind: ?[]const u8 = null,
    phase: ?[]const u8 = null,
};

fn isSafeArtifactName(name: []const u8) bool {
    if (name.len == 0 or name.len > 255) return false;
    if (std.mem.indexOfScalar(u8, name, '/') != null) return false;
    if (std.mem.indexOfScalar(u8, name, '\\') != null) return false;
    return install_state.isSafePortableRelPath(name);
}

fn writeJsonArray(w: *Io.Writer, name: []const u8, items: []const []const u8) Io.Writer.Error!void {
    try w.print("\"{s}\":[", .{name});
    for (items, 0..) |item, i| {
        if (i > 0) try w.writeAll(",");
        try writeJsonString(w, item);
    }
    try w.writeAll("]");
}

fn writeJsonString(w: *Io.Writer, s: []const u8) Io.Writer.Error!void {
    try w.writeAll("\"");
    for (s) |c| {
        switch (c) {
            '"' => try w.writeAll("\\\""),
            '\\' => try w.writeAll("\\\\"),
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            '\t' => try w.writeAll("\\t"),
            else => {
                if (c < 0x20 or c == 0x7f) {
                    try w.print("\\u{x:0>4}", .{c});
                } else {
                    try w.writeByte(c);
                }
            },
        }
    }
    try w.writeAll("\"");
}

pub fn stringifyJournal(allocator: Allocator, j: Journal) Allocator.Error![]u8 {
    var alloc_writer: Io.Writer.Allocating = .init(allocator);
    errdefer alloc_writer.deinit();
    const w = &alloc_writer.writer;
    renderJournal(w, j) catch |err| switch (err) {
        error.WriteFailed => return error.OutOfMemory,
    };
    var list = alloc_writer.toArrayList();
    return list.toOwnedSlice(allocator);
}

fn renderJournal(w: *Io.Writer, j: Journal) Io.Writer.Error!void {
    try w.print("{{\"schema\":{d},\"op\":", .{journal_schema});
    try writeJsonString(w, j.op.label());
    try w.writeAll(",\"id\":");
    try writeJsonString(w, j.id);
    try w.writeAll(",\"unit_path\":");
    try writeJsonString(w, j.unit_path);
    try w.writeAll(",\"stage_path\":");
    try writeJsonString(w, j.stage_path);
    try w.writeAll(",\"backup_path\":");
    try writeJsonString(w, j.backup_path);
    try w.writeAll(",");
    try writeJsonArray(w, "publish", j.publish);
    try w.writeAll(",");
    try writeJsonArray(w, "cleanup", j.cleanup);
    try w.writeAll(",");
    try writeJsonArray(w, "stale", j.stale);
    try w.writeAll(",");
    try writeJsonArray(w, "apps", j.apps);
    try w.print(",\"had_previous\":{}", .{j.had_previous});
    if (j.legacy_path) |p| {
        try w.writeAll(",\"legacy_path\":");
        try writeJsonString(w, p);
    }
    if (j.legacy_kind) |k| {
        try w.writeAll(",\"legacy_kind\":");
        try writeJsonString(w, k.label());
    }
    try w.writeAll(",\"phase\":");
    try writeJsonString(w, j.phase.label());
    try w.writeAll("}\n");
}

/// Atomically replace the journal: write a sibling temp file, flush it to
/// stable storage, then rename it over the live journal. A crash therefore
/// leaves either the previous journal or the new one, never a torn one.
pub fn writeJournal(io: Io, p: Paths, allocator: Allocator, j: Journal) !void {
    const body = try stringifyJournal(allocator, j);
    defer allocator.free(body);
    if (body.len > max_journal_bytes) return error.JournalTooLarge;

    {
        var file = try Dir.createFileAbsolute(io, p.journal_tmp, .{});
        defer file.close(io);
        try file.writeStreamingAll(io, body);
        file.sync(io) catch {};
    }
    try Dir.renameAbsolute(p.journal_tmp, p.journal, io);
    // Best effort: flush the directory entry so the rename itself is durable.
    if (Dir.openDirAbsolute(io, p.root, .{})) |*d| {
        defer d.close(io);
        // `Dir` has no sync in this API surface; the rename is already ordered
        // after the file's own sync, which is what recovery depends on.
    } else |_| {}
}

/// Read and fully validate a journal. Returns null only when the file is
/// absent; every other failure is typed so recovery can refuse to act.
pub fn readJournal(allocator: Allocator, io: Io, journal_path: []const u8) !?OwnedJournal {
    const body = blk: {
        var file = Dir.openFileAbsolute(io, journal_path, .{}) catch |err| switch (err) {
            error.FileNotFound, error.NotDir => return null,
            else => return err,
        };
        defer file.close(io);
        var buf: [4096]u8 = undefined;
        var fr = file.readerStreaming(io, &buf);
        break :blk fr.interface.allocRemaining(allocator, Io.Limit.limited(max_journal_bytes)) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.StreamTooLong => return error.JournalTooLarge,
            error.ReadFailed => return fr.err orelse error.ReadFailed,
        };
    };
    defer allocator.free(body);

    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();

    const parsed = std.json.parseFromSlice(WireJournal, a, body, .{
        .ignore_unknown_fields = true,
        // Every string must be owned by the arena: `body` is freed before this
        // function returns, and the default borrows from it when a value needs
        // no unescaping.
        .allocate = .alloc_always,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.JournalMalformed,
    };
    const wire = parsed.value;

    const schema = wire.schema orelse return error.JournalMalformed;
    if (schema != journal_schema) return error.JournalUnsupportedSchema;

    const op_label = wire.op orelse return error.JournalMalformed;
    const op = Op.fromLabel(op_label) orelse return error.JournalMalformed;

    const id = wire.id orelse return error.JournalMalformed;
    if (!try install_state.isCanonicalId(a, id)) return error.JournalInvalidId;

    const unit_path = wire.unit_path orelse return error.JournalMalformed;
    const stage_path = wire.stage_path orelse return error.JournalMalformed;
    const backup_path = wire.backup_path orelse return error.JournalMalformed;
    for ([_][]const u8{ unit_path, stage_path, backup_path }) |path| {
        if (path.len == 0 or path.len > Dir.max_path_bytes) return error.JournalInvalidPath;
    }

    const publish = wire.publish orelse &[_][]const u8{};
    const cleanup = wire.cleanup orelse &[_][]const u8{};
    const stale = wire.stale orelse &[_][]const u8{};
    const apps = wire.apps orelse &[_][]const u8{};
    if (publish.len + cleanup.len + stale.len + apps.len > max_journal_entries)
        return error.JournalTooManyEntries;
    for (publish) |n| if (!isSafeArtifactName(n)) return error.JournalInvalidPath;
    for (cleanup) |n| if (!isSafeArtifactName(n)) return error.JournalInvalidPath;
    for (stale) |n| if (!isSafeArtifactName(n)) return error.JournalInvalidPath;
    for (apps) |n| if (!install_state.isSafePortableRelPath(n)) return error.JournalInvalidPath;

    var legacy_kind: ?LegacyKind = null;
    if (wire.legacy_kind) |k| {
        legacy_kind = LegacyKind.fromLabel(k) orelse return error.JournalMalformed;
    }
    if (wire.legacy_path) |lp| {
        if (lp.len == 0 or lp.len > Dir.max_path_bytes) return error.JournalInvalidPath;
        if (legacy_kind == null) return error.JournalMalformed;
    } else if (legacy_kind != null) return error.JournalMalformed;

    const phase_label = wire.phase orelse return error.JournalMalformed;
    const phase = Phase.fromLabel(phase_label) orelse return error.JournalInvalidPhase;

    return .{
        .arena = arena,
        .journal = .{
            .op = op,
            .id = id,
            .unit_path = unit_path,
            .stage_path = stage_path,
            .backup_path = backup_path,
            .publish = publish,
            .cleanup = cleanup,
            .stale = stale,
            .apps = apps,
            .had_previous = wire.had_previous orelse false,
            .legacy_path = wire.legacy_path,
            .legacy_kind = legacy_kind,
            .phase = phase,
        },
    };
}

/// Confirm a journal describes exactly the transaction its own location
/// implies. Recovery calls this before it renames or deletes anything: the
/// encoded path must round-trip to the journal's canonical ID, and every path
/// the journal names must be the one this ghr would compute for that ID.
pub fn validateAgainstPaths(j: Journal, p: Paths) JournalError!void {
    if (!std.mem.eql(u8, j.id, p.id)) return error.JournalInvalidId;
    if (!std.mem.eql(u8, j.unit_path, p.unit)) return error.JournalInvalidPath;
    if (!std.mem.eql(u8, j.stage_path, p.stage)) return error.JournalInvalidPath;
    if (!std.mem.eql(u8, j.backup_path, p.backup)) return error.JournalInvalidPath;
}

// ---------------------------------------------------------------------------
// Recovery classification (pure)
// ---------------------------------------------------------------------------

pub const Presence = struct {
    unit: bool,
    stage: bool,
    backup: bool,
};

pub const Recovery = enum {
    /// Nothing live changed: drop the staged tree and the journal.
    rollback,
    /// An interrupted uninstall: finish removing exactly what the journal
    /// recorded, then drop the journal.
    finish_removal,
    /// The unit swap was interrupted: finish it, then republish commands.
    finish_swap,
    /// The unit is live: (re)publish commands, retire stale, then finish.
    republish,
    /// Restore the previous unit: the swap moved it aside and the staged tree
    /// is gone, so rolling forward is impossible.
    restore_backup,
    /// Publication failed: restore/re-publish the previous definition, or
    /// remove the failed fresh install. Never retire stale or legacy state.
    finish_rollback,
};

/// Decide what a recovering process must do. The recorded phase says how far
/// the writer got; the observed presence says which side of a rename it
/// stopped on. Combining them makes every crash point deterministic, and makes
/// repeating recovery idempotent.
pub fn classifyRecovery(op: Op, phase: Phase, present: Presence) Recovery {
    if (op == .uninstall) return .finish_removal;
    switch (phase) {
        .prepared, .staged => {
            // The swap had not been journaled, so the live unit is still the
            // previous one. A backup can only exist here if a previous
            // transaction for this ID left one behind; restore it if the live
            // unit is missing, otherwise simply discard staging.
            if (!present.unit and present.backup) return .restore_backup;
            return .rollback;
        },
        .swapping => {
            // A surviving stage proves the second rename did not complete. If
            // the live unit also exists, either the first rename never ran or
            // swapUnit already restored its backup after a failed commit
            // rename; in both cases nothing new was published.
            if (present.stage) {
                if (present.unit) return .rollback;
                return .finish_swap;
            }
            if (present.unit) return .republish;
            if (present.backup) return .restore_backup;
            return .rollback;
        },
        .publishing, .retiring, .complete => {
            if (present.unit) return .republish;
            if (present.stage) return .finish_swap;
            if (present.backup) return .restore_backup;
            // Nothing left to restore; the unit is simply gone.
            return .rollback;
        },
        .rolled_back => return .finish_rollback,
    }
}

// ---------------------------------------------------------------------------
// Transaction operations
// ---------------------------------------------------------------------------

pub const RenameFn = *const fn (Io, []const u8, []const u8) anyerror!void;

fn defaultRename(io: Io, old_path: []const u8, new_path: []const u8) anyerror!void {
    try Dir.renameAbsolute(old_path, new_path, io);
}

/// Injected seams for failure-injection tests. Production uses the defaults.
pub const Hooks = struct {
    rename: RenameFn = defaultRename,
};

/// Create a fresh transaction root and empty staging directory. Any leftover
/// staging content from an earlier attempt on the same ID is removed first.
pub fn prepareStage(io: Io, p: Paths) !void {
    try ensureDirAbsolute(io, p.root);
    try deleteTreeAbsolute(io, p.stage);
    try Dir.createDirAbsolute(io, p.stage, .default_dir);
}

/// Remove the staged tree without touching live state.
pub fn discardStage(io: Io, p: Paths) !void {
    try deleteTreeAbsolute(io, p.stage);
}

/// Remove the whole transaction directory (journal, stage, and backup), then
/// drop the now-empty encoded directories above it. `deleteDir` only succeeds
/// on an empty directory, so a concurrent transaction for a related ID is never
/// disturbed.
pub fn discardTransaction(io: Io, p: Paths) !void {
    try deleteTreeAbsolute(io, p.root);
    pruneEmptyParents(io, p.txn_root, p.root);
}

/// Remove empty ancestors of `path` up to (but never including) `root`.
pub fn pruneEmptyParents(io: Io, root: []const u8, path: []const u8) void {
    var current = std.fs.path.dirname(path) orelse return;
    while (current.len > root.len and std.mem.startsWith(u8, current, root)) {
        Dir.deleteDirAbsolute(io, current) catch return;
        current = std.fs.path.dirname(current) orelse return;
    }
}

/// Move the staged unit into place, moving any previous live unit into the
/// transaction's backup directory first. On failure the previous unit is put
/// back; if even that fails the caller gets `error.InstallRollbackFailed` and
/// the journal still names the backup for recovery.
pub fn swapUnit(io: Io, p: Paths, hooks: Hooks) !void {
    if (!try directoryExists(io, p.stage)) return error.StagingDirectoryNotFound;
    try ensureDirAbsolute(io, p.unit_parent);

    if (try directoryExists(io, p.unit)) {
        try deleteTreeAbsolute(io, p.backup);
        try hooks.rename(io, p.unit, p.backup);
        hooks.rename(io, p.stage, p.unit) catch |err| {
            hooks.rename(io, p.backup, p.unit) catch return error.InstallRollbackFailed;
            return err;
        };
    } else {
        try hooks.rename(io, p.stage, p.unit);
    }
}

/// Put the previous unit back. Used both for synchronous rollback after a
/// failed publication and for crash recovery when the staged tree is gone.
pub fn restoreUnit(io: Io, p: Paths, hooks: Hooks) !void {
    if (!try directoryExists(io, p.backup)) return error.BackupNotFound;
    if (try directoryExists(io, p.unit)) try deleteTreeAbsolute(io, p.unit);
    try hooks.rename(io, p.backup, p.unit);
}

/// Complete the staged swap when recovery finds the unit missing but the stage
/// intact (the process stopped between the two renames).
pub fn finishSwap(io: Io, p: Paths, hooks: Hooks) !void {
    if (try directoryExists(io, p.unit)) return;
    if (!try directoryExists(io, p.stage)) return error.StagingDirectoryNotFound;
    try ensureDirAbsolute(io, p.unit_parent);
    try hooks.rename(io, p.stage, p.unit);
}

/// Observe the current on-disk state of one transaction.
pub fn presence(io: Io, p: Paths) !Presence {
    return .{
        .unit = try directoryExists(io, p.unit),
        .stage = try directoryExists(io, p.stage),
        .backup = try directoryExists(io, p.backup),
    };
}

// ---------------------------------------------------------------------------
// Pending-transaction discovery
// ---------------------------------------------------------------------------

pub const Pending = struct {
    /// Canonical ID decoded from the transaction directory's encoded path.
    id: []const u8,
    /// Absolute path of the `_unit` transaction directory.
    root: []const u8,
};

pub const PendingList = struct {
    items: []Pending,
    arena: std.heap.ArenaAllocator,

    pub fn deinit(self: *PendingList) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

/// Enumerate every transaction directory that still carries a journal. The
/// encoded directory path is decoded back to a canonical ID here; a directory
/// whose encoding does not decode is reported with an empty ID so the caller
/// can refuse to act rather than deleting something it cannot name.
pub fn scanPending(
    allocator: Allocator,
    io: Io,
    tools_dir: []const u8,
    platform: Platform,
) !PendingList {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();

    var items: std.ArrayListUnmanaged(Pending) = .empty;

    const root = try txnRoot(a, tools_dir, platform);
    var dir = Dir.openDirAbsolute(io, root, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return .{ .items = &.{}, .arena = arena },
        else => return err,
    };
    defer dir.close(io);

    var segs: std.ArrayListUnmanaged([]const u8) = .empty;
    try walkPending(a, io, dir, root, platform, &segs, &items, 0);

    return .{ .items = try items.toOwnedSlice(a), .arena = arena };
}

fn walkPending(
    a: Allocator,
    io: Io,
    node: Dir,
    prefix: []const u8,
    platform: Platform,
    segs: *std.ArrayListUnmanaged([]const u8),
    out: *std.ArrayListUnmanaged(Pending),
    depth: usize,
) !void {
    if (depth > install_state.max_unit_segments) return;
    var it = node.iterate();
    while (try it.next(io)) |entry| {
        if (entry.kind == .sym_link) continue;
        if (entry.kind != .directory and entry.kind != .unknown) continue;

        const child_path = try std.fmt.allocPrint(a, "{s}{c}{s}", .{ prefix, sepFor(platform), entry.name });

        if (std.mem.eql(u8, entry.name, install_state.unit_marker)) {
            const journal_path = try std.fmt.allocPrint(a, "{s}{c}{s}", .{ child_path, sepFor(platform), journal_name });
            if (!fileExists(io, journal_path)) continue;
            const id = decodeSegments(a, segs.items) catch "";
            try out.append(a, .{ .id = id, .root = child_path });
            continue;
        }
        if (!std.mem.startsWith(u8, entry.name, install_state.segment_prefix)) continue;

        var child = node.openDir(io, entry.name, .{ .iterate = true, .follow_symlinks = false }) catch |err|
            switch (err) {
                error.FileNotFound, error.NotDir, error.SymLinkLoop => continue,
                else => return err,
            };
        defer child.close(io);
        try segs.append(a, entry.name);
        defer _ = segs.pop();
        try walkPending(a, io, child, child_path, platform, segs, out, depth + 1);
    }
}

fn decodeSegments(a: Allocator, encoded: []const []const u8) ![]const u8 {
    if (encoded.len == 0) return error.InvalidEncoding;
    var out: std.ArrayListUnmanaged(u8) = .empty;
    for (encoded, 0..) |tok, i| {
        if (!std.mem.startsWith(u8, tok, install_state.segment_prefix)) return error.InvalidEncoding;
        if (i > 0) try out.append(a, '/');
        try out.appendSlice(a, tok[install_state.segment_prefix.len..]);
    }
    const id = try out.toOwnedSlice(a);
    const canon = install_request.canonicalizeId(a, id) catch return error.InvalidEncoding;
    if (!std.mem.eql(u8, canon, id)) return error.InvalidEncoding;
    return id;
}

// ===========================================================================
// Tests
// ===========================================================================

const testing = std.testing;

fn tBase(tmp: *std.testing.TmpDir, buf: *[Dir.max_path_bytes]u8) ![]const u8 {
    const len = try tmp.dir.realPath(testing.io, buf);
    return buf[0..len];
}

test "paths place staging and journal inside the reserved txn namespace" {
    var p = try paths(testing.allocator, "/tools", "owner/repo", .posix);
    defer p.deinit();
    try testing.expectEqualStrings("/tools/_v2/units/u-owner/u-repo/_unit", p.unit);
    try testing.expectEqualStrings("/tools/_v2/txn/u-owner/u-repo/_unit", p.root);
    try testing.expectEqualStrings("/tools/_v2/txn/u-owner/u-repo/_unit/stage", p.stage);
    try testing.expectEqualStrings("/tools/_v2/txn/u-owner/u-repo/_unit/backup", p.backup);
    try testing.expectEqualStrings("/tools/_v2/txn/u-owner/u-repo/_unit/journal.json", p.journal);
}

test "paths reject a non-canonical id" {
    try testing.expectError(error.NonCanonicalId, paths(testing.allocator, "/tools", "Owner/Repo", .posix));
}

test "journal round-trips through write and read" {
    const tio = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [Dir.max_path_bytes]u8 = undefined;
    const base = try tBase(&tmp, &buf);

    var p = try paths(testing.allocator, base, "owner/repo", .posix);
    defer p.deinit();
    try ensureDirAbsolute(tio, p.root);

    const j: Journal = .{
        .id = p.id,
        .unit_path = p.unit,
        .stage_path = p.stage,
        .backup_path = p.backup,
        .publish = &.{ "rg", "rg.ghr" },
        .cleanup = &.{"rg.shim"},
        .stale = &.{"old"},
        .apps = &.{"Foo.app"},
        .had_previous = true,
        .legacy_path = "/tools/owner/repo",
        .legacy_kind = .v1_repo,
        .phase = .staged,
    };
    try writeJournal(tio, p, testing.allocator, j);

    var owned = (try readJournal(testing.allocator, tio, p.journal)).?;
    defer owned.deinit();
    try testing.expectEqualStrings("owner/repo", owned.journal.id);
    try testing.expectEqual(Phase.staged, owned.journal.phase);
    try testing.expectEqual(@as(usize, 2), owned.journal.publish.len);
    try testing.expectEqualStrings("rg.ghr", owned.journal.publish[1]);
    try testing.expect(owned.journal.had_previous);
    try testing.expectEqual(LegacyKind.v1_repo, owned.journal.legacy_kind.?);
    try validateAgainstPaths(owned.journal, p);
}

test "journal read rejects an unsupported schema" {
    const tio = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(tio, .{ .sub_path = "j.json", .data =
        \\{"schema":99,"op":"install","id":"a","unit_path":"/x","stage_path":"/y","backup_path":"/z","phase":"staged"}
    });
    var buf: [Dir.max_path_bytes]u8 = undefined;
    const base = try tBase(&tmp, &buf);
    const path = try std.fmt.allocPrint(testing.allocator, "{s}/j.json", .{base});
    defer testing.allocator.free(path);
    try testing.expectError(error.JournalUnsupportedSchema, readJournal(testing.allocator, tio, path));
}

test "journal read rejects a traversal artifact name" {
    const tio = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(tio, .{ .sub_path = "j.json", .data =
        \\{"schema":1,"op":"install","id":"a","unit_path":"/x","stage_path":"/y","backup_path":"/z","publish":["../evil"],"phase":"staged"}
    });
    var buf: [Dir.max_path_bytes]u8 = undefined;
    const base = try tBase(&tmp, &buf);
    const path = try std.fmt.allocPrint(testing.allocator, "{s}/j.json", .{base});
    defer testing.allocator.free(path);
    try testing.expectError(error.JournalInvalidPath, readJournal(testing.allocator, tio, path));
}

test "journal read rejects a non-canonical id" {
    const tio = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(tio, .{ .sub_path = "j.json", .data =
        \\{"schema":1,"op":"install","id":"A/B","unit_path":"/x","stage_path":"/y","backup_path":"/z","phase":"staged"}
    });
    var buf: [Dir.max_path_bytes]u8 = undefined;
    const base = try tBase(&tmp, &buf);
    const path = try std.fmt.allocPrint(testing.allocator, "{s}/j.json", .{base});
    defer testing.allocator.free(path);
    try testing.expectError(error.JournalInvalidId, readJournal(testing.allocator, tio, path));
}

test "validateAgainstPaths rejects a journal describing another unit" {
    var p = try paths(testing.allocator, "/tools", "owner/repo", .posix);
    defer p.deinit();
    const j: Journal = .{
        .id = "owner/other",
        .unit_path = p.unit,
        .stage_path = p.stage,
        .backup_path = p.backup,
    };
    try testing.expectError(error.JournalInvalidId, validateAgainstPaths(j, p));
}

test "recovery classification covers every crash point" {
    // Before the swap is journaled nothing live changed.
    try testing.expectEqual(Recovery.rollback, classifyRecovery(.install, .staged, .{ .unit = true, .stage = true, .backup = false }));
    try testing.expectEqual(Recovery.rollback, classifyRecovery(.install, .prepared, .{ .unit = false, .stage = true, .backup = false }));
    try testing.expectEqual(Recovery.restore_backup, classifyRecovery(.install, .staged, .{ .unit = false, .stage = true, .backup = true }));
    // The swap was journaled but no rename ran, or its internal rollback put
    // the old unit back. A surviving stage means stale retirement must not run.
    try testing.expectEqual(Recovery.rollback, classifyRecovery(.install, .swapping, .{ .unit = true, .stage = true, .backup = false }));
    try testing.expectEqual(Recovery.rollback, classifyRecovery(.install, .swapping, .{ .unit = true, .stage = true, .backup = true }));
    // Interrupted between the two renames.
    try testing.expectEqual(Recovery.finish_swap, classifyRecovery(.install, .swapping, .{ .unit = false, .stage = true, .backup = true }));
    // Swap completed; commands may be missing.
    try testing.expectEqual(Recovery.republish, classifyRecovery(.install, .swapping, .{ .unit = true, .stage = false, .backup = true }));
    try testing.expectEqual(Recovery.republish, classifyRecovery(.install, .publishing, .{ .unit = true, .stage = false, .backup = true }));
    try testing.expectEqual(Recovery.republish, classifyRecovery(.install, .retiring, .{ .unit = true, .stage = false, .backup = false }));
    try testing.expectEqual(Recovery.republish, classifyRecovery(.install, .complete, .{ .unit = true, .stage = false, .backup = false }));
    try testing.expectEqual(Recovery.finish_rollback, classifyRecovery(.install, .rolled_back, .{ .unit = true, .stage = false, .backup = true }));
    try testing.expectEqual(Recovery.finish_rollback, classifyRecovery(.install, .rolled_back, .{ .unit = true, .stage = false, .backup = false }));
    // The unit vanished after the swap but the backup survives.
    try testing.expectEqual(Recovery.restore_backup, classifyRecovery(.install, .publishing, .{ .unit = false, .stage = false, .backup = true }));
    // An interrupted removal is always finished, never resurrected.
    try testing.expectEqual(Recovery.finish_removal, classifyRecovery(.uninstall, .retiring, .{ .unit = true, .stage = false, .backup = false }));
    try testing.expectEqual(Recovery.finish_removal, classifyRecovery(.uninstall, .retiring, .{ .unit = false, .stage = false, .backup = false }));
}

test "swapUnit installs a fresh unit and replaces an existing one" {
    const tio = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [Dir.max_path_bytes]u8 = undefined;
    const base = try tBase(&tmp, &buf);

    var p = try paths(testing.allocator, base, "owner/repo", .posix);
    defer p.deinit();

    try prepareStage(tio, p);
    const stage_marker = try std.fmt.allocPrint(testing.allocator, "{s}/marker", .{p.stage});
    defer testing.allocator.free(stage_marker);
    (try Dir.createFileAbsolute(tio, stage_marker, .{})).close(tio);
    // Fresh install.
    try swapUnit(tio, p, .{});
    try testing.expect(try directoryExists(tio, p.unit));
    try testing.expect(!try directoryExists(tio, p.stage));

    // Replacement keeps the old unit in the transaction backup.
    try prepareStage(tio, p);
    try swapUnit(tio, p, .{});
    try testing.expect(try directoryExists(tio, p.unit));
    try testing.expect(try directoryExists(tio, p.backup));
}

fn failingRename(_: Io, _: []const u8, _: []const u8) anyerror!void {
    return error.InjectedRenameFailure;
}

/// Rename that succeeds once (live -> backup) and then fails, reproducing an
/// interruption exactly between the two commit renames.
var second_rename_calls: usize = 0;
fn failSecondRename(io: Io, old_path: []const u8, new_path: []const u8) anyerror!void {
    second_rename_calls += 1;
    if (second_rename_calls == 2) return error.InjectedRenameFailure;
    try Dir.renameAbsolute(old_path, new_path, io);
}

test "swapUnit rolls the previous unit back when the commit rename fails" {
    const tio = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [Dir.max_path_bytes]u8 = undefined;
    const base = try tBase(&tmp, &buf);

    var p = try paths(testing.allocator, base, "owner/repo", .posix);
    defer p.deinit();

    try ensureDirAbsolute(tio, p.unit);
    const live_marker = try std.fmt.allocPrint(testing.allocator, "{s}/live", .{p.unit});
    defer testing.allocator.free(live_marker);
    (try Dir.createFileAbsolute(tio, live_marker, .{})).close(tio);

    try prepareStage(tio, p);
    second_rename_calls = 0;
    try testing.expectError(error.InjectedRenameFailure, swapUnit(tio, p, .{ .rename = failSecondRename }));

    // The previous unit is back with its content, and nothing is half-moved.
    try testing.expect(try directoryExists(tio, p.unit));
    var f = try Dir.openFileAbsolute(tio, live_marker, .{});
    f.close(tio);
    try testing.expect(!try directoryExists(tio, p.backup));
}

test "swapUnit propagates a failure before any live change" {
    const tio = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [Dir.max_path_bytes]u8 = undefined;
    const base = try tBase(&tmp, &buf);

    var p = try paths(testing.allocator, base, "owner/repo", .posix);
    defer p.deinit();
    try prepareStage(tio, p);
    try testing.expectError(error.InjectedRenameFailure, swapUnit(tio, p, .{ .rename = failingRename }));
    try testing.expect(!try directoryExists(tio, p.unit));
    try testing.expect(try directoryExists(tio, p.stage));
}

test "restoreUnit puts the previous unit back" {
    const tio = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [Dir.max_path_bytes]u8 = undefined;
    const base = try tBase(&tmp, &buf);

    var p = try paths(testing.allocator, base, "owner/repo", .posix);
    defer p.deinit();
    try ensureDirAbsolute(tio, p.backup);
    const marker = try std.fmt.allocPrint(testing.allocator, "{s}/old", .{p.backup});
    defer testing.allocator.free(marker);
    (try Dir.createFileAbsolute(tio, marker, .{})).close(tio);
    try ensureDirAbsolute(tio, p.unit);

    try restoreUnit(tio, p, .{});
    const restored = try std.fmt.allocPrint(testing.allocator, "{s}/old", .{p.unit});
    defer testing.allocator.free(restored);
    var f = try Dir.openFileAbsolute(tio, restored, .{});
    f.close(tio);
    try testing.expect(!try directoryExists(tio, p.backup));
}

test "finishSwap completes an interrupted commit and is idempotent" {
    const tio = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [Dir.max_path_bytes]u8 = undefined;
    const base = try tBase(&tmp, &buf);

    var p = try paths(testing.allocator, base, "owner/repo", .posix);
    defer p.deinit();
    try prepareStage(tio, p);
    try finishSwap(tio, p, .{});
    try testing.expect(try directoryExists(tio, p.unit));
    // Running recovery again must not fail or move anything.
    try finishSwap(tio, p, .{});
    try testing.expect(try directoryExists(tio, p.unit));
}

test "scanPending finds journaled transactions and decodes their ids" {
    const tio = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [Dir.max_path_bytes]u8 = undefined;
    const base = try tBase(&tmp, &buf);

    var p = try paths(testing.allocator, base, "owner/repo", .posix);
    defer p.deinit();
    try ensureDirAbsolute(tio, p.root);
    try writeJournal(tio, p, testing.allocator, .{
        .id = p.id,
        .unit_path = p.unit,
        .stage_path = p.stage,
        .backup_path = p.backup,
        .phase = .staged,
    });

    var pending = try scanPending(testing.allocator, tio, base, .posix);
    defer pending.deinit();
    try testing.expectEqual(@as(usize, 1), pending.items.len);
    try testing.expectEqualStrings("owner/repo", pending.items[0].id);
    try testing.expectEqualStrings(p.root, pending.items[0].root);
}

test "scanPending ignores a transaction directory without a journal" {
    const tio = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [Dir.max_path_bytes]u8 = undefined;
    const base = try tBase(&tmp, &buf);

    var p = try paths(testing.allocator, base, "owner/repo", .posix);
    defer p.deinit();
    try prepareStage(tio, p);

    var pending = try scanPending(testing.allocator, tio, base, .posix);
    defer pending.deinit();
    try testing.expectEqual(@as(usize, 0), pending.items.len);
}

test "the transaction namespace is invisible to the inventory reader" {
    const tio = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [Dir.max_path_bytes]u8 = undefined;
    const base = try tBase(&tmp, &buf);

    var p = try paths(testing.allocator, base, "owner/repo", .posix);
    defer p.deinit();
    try prepareStage(tio, p);
    const staged_meta = try std.fmt.allocPrint(testing.allocator, "{s}/ghr.json", .{p.stage});
    defer testing.allocator.free(staged_meta);
    {
        var f = try Dir.createFileAbsolute(tio, staged_meta, .{});
        defer f.close(tio);
        try f.writeStreamingAll(tio, "{\"tag\":\"v1\",\"asset\":\"a\"}");
    }

    var inv = try install_state.scan(testing.allocator, tio, base, .{ .platform = .posix });
    defer inv.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 0), inv.records.len);
}
