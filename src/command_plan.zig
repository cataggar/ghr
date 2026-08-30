//! Collision-safe command publication planner (PR 4).
//!
//! This module is intentionally INACTIVE: nothing in the running `ghr` binary
//! calls `plan` or `snapshotBinDir`. It exists so the activation PR can decide,
//! BEFORE the first live mutation of the bin directory, exactly which files an
//! invocation would create, refresh, and retire -- and refuse the whole
//! invocation when any of those files is owned by another install ID or is not
//! managed by ghr at all.
//!
//! ## Shape
//!
//! `plan` is pure: it takes already-expanded install units, an
//! `install_state.Inventory`, an injected bin-directory snapshot, and an
//! explicit `install_state.Platform`. It performs no I/O and mutates nothing.
//! `snapshotBinDir` is the only function here that touches the filesystem; it
//! is read-only and produces the snapshot `plan` consumes. Splitting them lets
//! every ownership rule be tested for both platforms on one host.
//!
//! Dependency direction is acyclic: this module imports `install_state` (whose
//! canonical-ID rules come from `install_request`) and deliberately does NOT
//! import `install.zig`, because the activation PR will import this module from
//! there.
//!
//! ## Command names
//!
//! Two different names are involved and must never be conflated:
//!
//!   * a DISCOVERED SOURCE name, derived from a unit-relative target exactly
//!     once by `install_state.sourceCommandSlice` (basename; a true `.wasm`
//!     target strips exactly one lowercase `.wasm` and keeps any residual
//!     `.exe`; otherwise Windows strips one case-insensitive `.exe`); and
//!   * a FINAL PUBLISHED name, which is either that source name or the exact
//!     name an `alias=` requested. A final name is never re-normalized: on
//!     POSIX an alias to `foo.wasm` publishes `foo.wasm`.
//!
//! Collisions between distinct final names (Windows `foo` vs `foo.exe`, or a
//! wasm launcher's `.ghr` companion vs a native command literally named
//! `foo.ghr`) are found by expanding each final name into its exact PHYSICAL
//! artifact family and comparing files -- not by normalizing names repeatedly.
//!
//! ## Fail-closed rules
//!
//! Checks run in this order, and every one of them covers the COMPLETE
//! invocation before any plan is returned:
//!
//!   1. inventory health (a damaged, ID-less, or kind-inconsistent record
//!      anywhere blocks all planning, even if it looks unrelated);
//!   2. bin snapshot sanity (platform-equivalent duplicate names block);
//!   3. per-unit ID/target/alias resolution;
//!   4. invocation-wide duplicate IDs, duplicate final names, and duplicate or
//!      merely touching physical artifacts;
//!   5. ownership: another ID's claimed artifact blocks even when it is absent
//!      from disk, and any present-but-unowned bin entry (file, directory,
//!      symlink, or unknown) blocks; and
//!   6. same-ID stale-removal intent for every file a previous definition of
//!      that ID owned and its new definition does not.
//!
//! A plan describes operations only. Actually revalidating a stale entry's
//! content/target ownership before deleting it is the activation PR's job.

const std = @import("std");
const install_state = @import("install_state.zig");

const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

pub const Platform = install_state.Platform;
pub const default_platform = install_state.default_platform;

/// Longest suffix any artifact expansion appends to a final published name
/// (`<name>.exe.old`). Reserved as headroom so a name that passes the preflight
/// can always grow into every companion file.
pub const max_artifact_suffix_bytes: usize = ".exe.old".len;

/// Hard bound on a materialized artifact file name.
pub const max_artifact_name_bytes: usize = 255;

/// Hard bound on a final published command name, leaving suffix headroom. A
/// longer name fails typed (`error.CommandNameTooLong`); it is never truncated.
pub const max_final_name_bytes: usize = @min(
    install_state.max_v2_command_bytes,
    max_artifact_name_bytes - max_artifact_suffix_bytes,
);

/// Largest artifact family (Windows native: shim exe, `.ghr`, `.cmd`, `.shim`,
/// `.old`).
pub const max_family_artifacts: usize = 5;

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------

pub const Kind = enum { native, wasm };

/// One discovered command selected for a unit. `relative_target` is
/// unit-relative and portable (forward slashes only); `kind` is explicit and
/// must agree with the target's `.wasm` suffix.
pub const Command = struct {
    relative_target: []const u8,
    kind: Kind,
};

/// One `alias=<source>:<published>` pair. Both sides are borrowed const slices
/// so the planner does not depend on the request parser's mutable ownership.
/// `published` is the EXACT requested published name; `.wasm`/`.exe` suffixes
/// are neither required nor stripped.
pub const Alias = struct {
    source: []const u8,
    published: []const u8,
};

/// One already-expanded install unit (a wasm sibling is its own unit).
pub const Unit = struct {
    /// Canonical install ID; must already satisfy `install_request.canonicalizeId`.
    id: []const u8,
    commands: []const Command = &.{},
    aliases: []const Alias = &.{},
};

pub const Options = struct {
    platform: Platform = default_platform,
};

// ---------------------------------------------------------------------------
// Bin snapshot
// ---------------------------------------------------------------------------

/// What a bin-directory entry is. Every variant counts as PRESENT: the entry
/// type never makes an unowned name safe to overwrite.
pub const EntryKind = enum { file, directory, sym_link, other, unknown };

pub const SnapshotEntry = struct {
    name: []const u8,
    kind: EntryKind,
};

/// A read-only, deterministically ordered view of the bin directory's direct
/// children. Owns its entries.
pub const BinSnapshot = struct {
    entries: []const SnapshotEntry,
    arena_state: std.heap.ArenaAllocator.State,
    gpa: Allocator,

    pub fn deinit(self: *BinSnapshot) void {
        self.arena_state.promote(self.gpa).deinit();
        self.* = undefined;
    }
};

pub const SnapshotError = error{
    /// The directory listing produced the same name twice.
    DuplicateEntry,
};

fn classifyEntryKind(kind: Io.File.Kind) EntryKind {
    return switch (kind) {
        .file => .file,
        .directory => .directory,
        .sym_link => .sym_link,
        .unknown => .unknown,
        else => .other,
    };
}

fn entryLessThan(_: void, a: SnapshotEntry, b: SnapshotEntry) bool {
    return std.mem.order(u8, a.name, b.name) == .lt;
}

/// Snapshot the direct children of the bin directory at `bin_dir_path`.
///
/// The bin root itself is the trusted anchor (exactly as in
/// `install_state.scan`), so it may legitimately be a symlink; children are
/// only enumerated, never opened, stat'ed, or followed, so a hostile child
/// symlink cannot redirect this read. An entry kind the listing reports as
/// unknown stays unknown rather than being resolved.
///
/// Entries are sorted by exact name and validated to be distinct, so the result
/// is deterministic and `SnapshotError.DuplicateEntry` (in the inferred error
/// set) reports a listing that cannot be reasoned about.
///
/// A missing bin directory yields an empty snapshot. EVERY other error --
/// `NotDir`, permission, and any other I/O failure -- propagates. The caller
/// owns the result and must `deinit` it.
pub fn snapshotBinDir(gpa: Allocator, io: Io, bin_dir_path: []const u8) !BinSnapshot {
    var arena_inst = std.heap.ArenaAllocator.init(gpa);
    errdefer arena_inst.deinit();
    const arena = arena_inst.allocator();

    var dir = Dir.openDirAbsolute(io, bin_dir_path, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return .{
            .entries = &.{},
            .arena_state = arena_inst.state,
            .gpa = gpa,
        },
        else => return err,
    };
    defer dir.close(io);

    var list: std.ArrayListUnmanaged(SnapshotEntry) = .empty;
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        const name = try arena.dupe(u8, entry.name);
        try list.append(arena, .{ .name = name, .kind = classifyEntryKind(entry.kind) });
    }

    const entries = try list.toOwnedSlice(arena);
    std.mem.sort(SnapshotEntry, entries, {}, entryLessThan);
    var i: usize = 1;
    while (i < entries.len) : (i += 1) {
        if (std.mem.eql(u8, entries[i - 1].name, entries[i].name)) return error.DuplicateEntry;
    }

    return .{ .entries = entries, .arena_state = arena_inst.state, .gpa = gpa };
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

/// One command the invocation would publish.
pub const PlannedCommand = struct {
    id: []const u8,
    /// Name derived from `relative_target`, before any alias.
    source_name: []const u8,
    /// Name actually published (the alias, when one applied).
    final_name: []const u8,
    relative_target: []const u8,
    kind: Kind,
    /// Files created or replaced, in write order.
    publish: []const []const u8,
    /// Legacy wrappers and rename targets this publication also removes or
    /// rewrites. Ownership-checked exactly like `publish`.
    cleanup: []const []const u8,
};

/// A previous definition of one of this ID's commands whose files the new
/// definition no longer covers. `name`/`relative_target`/`kind` describe the
/// RETIRED definition, so a record can appear for a name the ID still publishes
/// when only the command's kind changed. Removal is INTENT only: the activation
/// PR must still revalidate each entry's content or symlink target before
/// unlinking it.
pub const StaleCommand = struct {
    id: []const u8,
    name: []const u8,
    relative_target: []const u8,
    kind: Kind,
    /// The retired definition's artifact family, minus everything the same ID
    /// publishes or touches in this plan. Never empty.
    remove: []const []const u8,
};

/// A fully owned, deterministically ordered publication plan.
pub const Plan = struct {
    platform: Platform,
    commands: []const PlannedCommand,
    stale: []const StaleCommand,
    arena_state: std.heap.ArenaAllocator.State,
    gpa: Allocator,

    pub fn deinit(self: *Plan) void {
        self.arena_state.promote(self.gpa).deinit();
        self.* = undefined;
    }
};

// ---------------------------------------------------------------------------
// Errors and diagnostics
// ---------------------------------------------------------------------------

pub const PlanError = error{
    // Invocation shape.
    NonCanonicalId,
    DuplicateId,
    UnsafeRelativeTarget,
    CommandKindMismatch,
    UnsafeCommandName,
    CommandNameTooLong,
    DuplicateSourceCommand,
    UnsafeAliasName,
    AliasSourceNotFound,
    DuplicateAliasSource,
    DuplicateAliasPublished,
    DuplicateCommandName,
    DuplicateArtifact,
    // Inventory health (global fail-closed).
    InventoryNotOk,
    InventoryIdMissing,
    InventoryInvalidId,
    InventoryDuplicateId,
    InventoryInvalidCommand,
    InventoryUnknownKind,
    InventoryKindMismatch,
    InventoryAmbiguousArtifact,
    // Bin ownership.
    AmbiguousBinEntry,
    ArtifactOwnedByOtherId,
    UnmanagedArtifact,
};

pub const Error = PlanError || Allocator.Error;

pub const max_diagnostic_text_bytes: usize = 128;

/// A bounded copy of a name/artifact/ID for reporting. Fixed storage means a
/// diagnostic never outlives -- or dangles into -- the caller's input or the
/// plan arena.
pub const BoundedText = struct {
    buf: [max_diagnostic_text_bytes]u8 = @splat(0),
    len: usize = 0,
    truncated: bool = false,

    pub fn slice(self: *const BoundedText) []const u8 {
        return self.buf[0..self.len];
    }

    fn set(self: *BoundedText, text: []const u8) void {
        const n = @min(text.len, max_diagnostic_text_bytes);
        @memcpy(self.buf[0..n], text[0..n]);
        self.len = n;
        self.truncated = text.len > n;
    }
};

/// Deterministic, position-bearing failure context. All fields are optional
/// because not every rule has every position.
pub const Diagnostic = struct {
    /// Index into the invocation slice.
    unit_index: ?usize = null,
    /// Index into that unit's `commands`.
    command_index: ?usize = null,
    /// Index into that unit's `aliases`.
    alias_index: ?usize = null,
    /// Index into `inventory.records`.
    record_index: ?usize = null,
    /// Index into that record's `commands`.
    record_command_index: ?usize = null,
    /// The ID being planned (or the damaged record's ID).
    id: BoundedText = .{},
    /// The offending command name, alias side, or relative target.
    name: BoundedText = .{},
    /// The offending physical artifact file name.
    artifact: BoundedText = .{},
    /// The ID that already claims `artifact`, when there is one.
    owner_id: BoundedText = .{},
    /// What the blocking bin entry is, when the failure was an unmanaged entry.
    entry_kind: ?EntryKind = null,
};

/// Failure context supplied at the point of failure. Nothing is written to the
/// caller's `Diagnostic` on a successful path, so a diagnostic can never carry
/// positions left over from a check that passed.
const Report = struct {
    unit_index: ?usize = null,
    command_index: ?usize = null,
    alias_index: ?usize = null,
    record_index: ?usize = null,
    record_command_index: ?usize = null,
    entry_kind: ?EntryKind = null,
    id: []const u8 = "",
    name: []const u8 = "",
    artifact: []const u8 = "",
    owner_id: []const u8 = "",
};

fn fail(diag: ?*Diagnostic, err: PlanError, report: Report) PlanError {
    if (diag) |d| {
        d.* = .{
            .unit_index = report.unit_index,
            .command_index = report.command_index,
            .alias_index = report.alias_index,
            .record_index = report.record_index,
            .record_command_index = report.record_command_index,
            .entry_kind = report.entry_kind,
        };
        d.id.set(report.id);
        d.name.set(report.name);
        d.artifact.set(report.artifact);
        d.owner_id.set(report.owner_id);
    }
    return err;
}

// ---------------------------------------------------------------------------
// Physical artifact families
// ---------------------------------------------------------------------------

/// One artifact file, expressed as a borrowed base plus a static suffix so the
/// expansion allocates nothing until the plan is materialized.
const Piece = struct {
    base: []const u8,
    suffix: []const u8,

    fn len(self: Piece) usize {
        return self.base.len + self.suffix.len;
    }

    fn write(self: Piece, out: []u8) []u8 {
        std.debug.assert(self.len() <= max_artifact_name_bytes);
        @memcpy(out[0..self.base.len], self.base);
        @memcpy(out[self.base.len..][0..self.suffix.len], self.suffix);
        return out[0..self.len()];
    }
};

const Family = struct {
    items: [max_family_artifacts]Piece = undefined,
    publish_len: usize = 0,
    total_len: usize = 0,

    fn publish(self: *const Family) []const Piece {
        return self.items[0..self.publish_len];
    }

    fn cleanup(self: *const Family) []const Piece {
        return self.items[self.publish_len..self.total_len];
    }

    fn all(self: *const Family) []const Piece {
        return self.items[0..self.total_len];
    }
};

fn hasExeSuffix(name: []const u8) bool {
    return name.len >= 4 and std.ascii.eqlIgnoreCase(name[name.len - 4 ..], ".exe");
}

fn windowsExeStem(name: []const u8) []const u8 {
    if (hasExeSuffix(name)) return name[0 .. name.len - 4];
    return name;
}

/// Expand a FINAL published name plus its kind into the exact set of files the
/// current writers create and clean up. `name` is used verbatim; it is never
/// re-normalized. This mirrors `install.zig`'s `linkToBin`, `linkWasmToBin`,
/// `cleanupWasmBinEntry`, and `cleanupWindowsBinEntry` byte for byte, including
/// the deliberately odd Windows wasm case where a `tool.exe.wasm` module has
/// stem `tool.exe` and therefore a `tool.exe.exe` launcher.
fn artifactFamily(name: []const u8, kind: Kind, platform: Platform) Family {
    var f = Family{};
    switch (platform) {
        .posix => switch (kind) {
            // Symlink at <name>.
            .native => {
                f.items[0] = .{ .base = name, .suffix = "" };
                f.publish_len = 1;
                f.total_len = 1;
            },
            // Launcher <name> + manifest <name>.ghr; a legacy <name>.shim from
            // an older install is removed.
            .wasm => {
                f.items[0] = .{ .base = name, .suffix = "" };
                f.items[1] = .{ .base = name, .suffix = ".ghr" };
                f.publish_len = 2;
                f.items[2] = .{ .base = name, .suffix = ".shim" };
                f.total_len = 3;
            },
        },
        .windows => switch (kind) {
            // Shim exe (<name> when it already ends in `.exe`, else
            // <name>.exe) + <stem>.ghr; legacy <stem>.cmd / <stem>.shim and the
            // locked-exe rename target <shim>.old are also touched.
            .native => {
                const stem = windowsExeStem(name);
                // `windowsShimExeName`: append `.exe` only when the final name
                // does not already carry one (case-insensitively).
                const needs_exe = stem.len == name.len;
                f.items[0] = .{ .base = name, .suffix = if (needs_exe) ".exe" else "" };
                f.items[1] = .{ .base = stem, .suffix = ".ghr" };
                f.publish_len = 2;
                f.items[2] = .{ .base = stem, .suffix = ".cmd" };
                f.items[3] = .{ .base = stem, .suffix = ".shim" };
                f.items[4] = .{ .base = name, .suffix = if (needs_exe) ".exe.old" else ".old" };
                f.total_len = 5;
            },
            // Launcher <name>.exe (appended unconditionally) + <name>.ghr;
            // legacy <name>.shim and the rename target <name>.exe.old.
            .wasm => {
                f.items[0] = .{ .base = name, .suffix = ".exe" };
                f.items[1] = .{ .base = name, .suffix = ".ghr" };
                f.publish_len = 2;
                f.items[2] = .{ .base = name, .suffix = ".shim" };
                f.items[3] = .{ .base = name, .suffix = ".exe.old" };
                f.total_len = 4;
            },
        },
    }
    return f;
}

/// Comparison key for a physical artifact: Windows folds ASCII case, POSIX is
/// exact.
fn artifactKey(allocator: Allocator, piece: Piece, platform: Platform) Allocator.Error![]u8 {
    const out = try allocator.alloc(u8, piece.len());
    _ = piece.write(out);
    if (platform == .windows) {
        for (out) |*c| c.* = std.ascii.toLower(c.*);
    }
    return out;
}

fn nameKey(allocator: Allocator, name: []const u8, platform: Platform) Allocator.Error![]u8 {
    return install_state.conflictKey(allocator, name, platform);
}

// ---------------------------------------------------------------------------
// Internal working state
// ---------------------------------------------------------------------------

const ResolvedCommand = struct {
    unit_index: usize,
    id: []const u8,
    source_name: []const u8,
    final_name: []const u8,
    relative_target: []const u8,
    kind: Kind,
};

/// A retired same-ID command, before its artifacts are materialized.
const StaleIntent = struct {
    id: []const u8,
    name: []const u8,
    relative_target: []const u8,
    kind: Kind,
    remove: []const Piece,
};

const Claim = struct {
    unit_index: usize,
};

const Owner = struct {
    record_index: usize,
    id: []const u8,
};

/// Map a persisted `kind` onto the planner's enum. An absent kind is native
/// (the v1 convention `install_state` preserves); anything else is unknown and
/// blocks planning.
fn kindFromInventory(cmd: install_state.OwnedCommand) ?Kind {
    const raw = cmd.kind orelse return .native;
    if (std.mem.eql(u8, raw, "native")) return .native;
    if (std.mem.eql(u8, raw, "wasm")) return .wasm;
    return null;
}

// ---------------------------------------------------------------------------
// Planner
// ---------------------------------------------------------------------------

/// Plan the complete invocation. See the module comment for the rule order.
pub fn plan(
    gpa: Allocator,
    units: []const Unit,
    inventory: install_state.Inventory,
    snapshot: []const SnapshotEntry,
    options: Options,
) Error!Plan {
    return planWithDiagnostic(gpa, units, inventory, snapshot, options, null);
}

/// `plan` with deterministic failure context. `diag` is written only on the
/// failing path, and only ever receives bounded copies.
pub fn planWithDiagnostic(
    gpa: Allocator,
    units: []const Unit,
    inventory: install_state.Inventory,
    snapshot: []const SnapshotEntry,
    options: Options,
    diag: ?*Diagnostic,
) Error!Plan {
    const platform = options.platform;

    var scratch_inst = std.heap.ArenaAllocator.init(gpa);
    defer scratch_inst.deinit();
    const scratch = scratch_inst.allocator();

    // 1. Inventory health + physical ownership map. A damaged record anywhere
    //    blocks the whole invocation: mutation preparation is global.
    var owners: std.StringHashMapUnmanaged(Owner) = .empty;
    var inventory_ids: std.StringHashMapUnmanaged(usize) = .empty;
    try buildOwnership(scratch, inventory, platform, &owners, &inventory_ids, diag);

    // 2. Bin snapshot sanity: two entries that name the same file under the
    //    platform's case rules make ownership undecidable.
    var present: std.StringHashMapUnmanaged(EntryKind) = .empty;
    for (snapshot) |entry| {
        const key = try nameKey(scratch, entry.name, platform);
        const gop = try present.getOrPut(scratch, key);
        if (gop.found_existing) return fail(diag, error.AmbiguousBinEntry, .{
            .artifact = entry.name,
            .entry_kind = entry.kind,
        });
        gop.value_ptr.* = entry.kind;
    }

    // 3. Per-unit ID / target / alias resolution.
    var resolved: std.ArrayListUnmanaged(ResolvedCommand) = .empty;
    var unit_ids: std.StringHashMapUnmanaged(void) = .empty;
    for (units, 0..) |unit, ui| {
        if (unit.id.len == 0 or !try install_state.isCanonicalId(scratch, unit.id))
            return fail(diag, error.NonCanonicalId, .{ .unit_index = ui, .id = unit.id });
        if ((try unit_ids.getOrPut(scratch, unit.id)).found_existing)
            return fail(diag, error.DuplicateId, .{ .unit_index = ui, .id = unit.id });
        try resolveUnit(scratch, unit, ui, platform, &resolved, diag);
    }

    // 4. Invocation-wide duplicate final names and duplicate/touching physical
    //    artifacts, plus 5. ownership of every requested artifact.
    var final_names: std.StringHashMapUnmanaged(void) = .empty;
    var artifact_claims: std.StringHashMapUnmanaged(Claim) = .empty;
    for (resolved.items) |rc| {
        const fk = try nameKey(scratch, rc.final_name, platform);
        if ((try final_names.getOrPut(scratch, fk)).found_existing)
            return fail(diag, error.DuplicateCommandName, .{
                .unit_index = rc.unit_index,
                .id = rc.id,
                .name = rc.final_name,
            });

        const family = artifactFamily(rc.final_name, rc.kind, platform);
        for (family.all()) |piece| {
            var buf: [max_artifact_name_bytes]u8 = undefined;
            const artifact = piece.write(&buf);
            const key = try artifactKey(scratch, piece, platform);
            const gop = try artifact_claims.getOrPut(scratch, key);
            if (gop.found_existing) return fail(diag, error.DuplicateArtifact, .{
                .unit_index = rc.unit_index,
                .id = rc.id,
                .name = rc.final_name,
                .artifact = artifact,
            });
            gop.value_ptr.* = .{ .unit_index = rc.unit_index };

            if (owners.get(key)) |owner| {
                if (!std.mem.eql(u8, owner.id, rc.id)) {
                    return fail(diag, error.ArtifactOwnedByOtherId, .{
                        .unit_index = rc.unit_index,
                        .record_index = owner.record_index,
                        .id = rc.id,
                        .name = rc.final_name,
                        .artifact = artifact,
                        .owner_id = owner.id,
                    });
                }
            } else if (present.get(key)) |entry_kind| {
                // Present in the bin directory with no reliable owner. The
                // entry type is irrelevant: a directory or a symlink is just as
                // unsafe to replace as a regular file.
                return fail(diag, error.UnmanagedArtifact, .{
                    .unit_index = rc.unit_index,
                    .id = rc.id,
                    .name = rc.final_name,
                    .artifact = artifact,
                    .entry_kind = entry_kind,
                });
            }
        }
    }

    // 6. Same-ID stale-removal intent, computed per PHYSICAL artifact rather
    //    than per name. Retention is "this same ID still claims the file", so a
    //    command that keeps its name but changes kind still retires the
    //    companions its new kind no longer owns (e.g. a POSIX wasm `mod`
    //    becoming native leaves `mod.ghr`/`mod.shim` behind otherwise).
    var stale: std.ArrayListUnmanaged(StaleIntent) = .empty;
    var stale_artifacts: std.StringHashMapUnmanaged(void) = .empty;
    for (units, 0..) |unit, ui| {
        const record_index = inventory_ids.get(unit.id) orelse continue;
        for (inventory.records[record_index].commands) |cmd| {
            const kind = kindFromInventory(cmd).?;
            const family = artifactFamily(cmd.name, kind, platform);
            var remove: std.ArrayListUnmanaged(Piece) = .empty;
            for (family.all()) |piece| {
                const key = try artifactKey(scratch, piece, platform);
                // Overlap with what this same ID now publishes or touches is
                // expected; dropping it keeps removal from undoing the
                // replacement. Ownership above guarantees a surviving claim on
                // one of this record's files cannot belong to another unit.
                if (artifact_claims.get(key)) |claim| {
                    if (claim.unit_index == ui) continue;
                }
                if ((try stale_artifacts.getOrPut(scratch, key)).found_existing) continue;
                try remove.append(scratch, piece);
            }
            if (remove.items.len == 0) continue;
            try stale.append(scratch, .{
                .id = unit.id,
                .name = cmd.name,
                .relative_target = cmd.relative_target,
                .kind = kind,
                .remove = try remove.toOwnedSlice(scratch),
            });
        }
    }

    return materialize(gpa, platform, resolved.items, stale.items);
}

/// Validate every inventory record and map every physical artifact it claims to
/// its owning ID. Claims by different IDs are ambiguous; repeated claims by one
/// ID are coalesced because ownership is still reliable for replacement.
fn buildOwnership(
    scratch: Allocator,
    inventory: install_state.Inventory,
    platform: Platform,
    owners: *std.StringHashMapUnmanaged(Owner),
    inventory_ids: *std.StringHashMapUnmanaged(usize),
    diag: ?*Diagnostic,
) Error!void {
    for (inventory.records, 0..) |record, ri| {
        if (record.status != .ok) return fail(diag, error.InventoryNotOk, .{
            .record_index = ri,
            .id = record.id orelse "",
            .name = record.path,
        });
        const id = record.id orelse return fail(diag, error.InventoryIdMissing, .{
            .record_index = ri,
            .name = record.path,
        });
        if (!try install_state.isCanonicalId(scratch, id))
            return fail(diag, error.InventoryInvalidId, .{
                .record_index = ri,
                .id = id,
                .name = record.path,
            });
        const igop = try inventory_ids.getOrPut(scratch, id);
        if (igop.found_existing) return fail(diag, error.InventoryDuplicateId, .{
            .record_index = ri,
            .id = id,
            .name = record.path,
        });
        igop.value_ptr.* = ri;

        for (record.commands, 0..) |cmd, ci| {
            // Accept exactly what the reader marked OK. A v1 unit on a POSIX
            // store may legitimately carry a name the stricter v2 rule forbids
            // (non-ASCII, leading dot, or 241-255 bytes); refusing to track its
            // ownership would wedge every unrelated install instead of
            // protecting it. POSIX compares names byte-exactly, so such a name
            // is still unambiguous, and Windows still requires the ASCII rule.
            if (!install_state.isSafeDerivedCommandName(cmd.name, platform))
                return fail(diag, error.InventoryInvalidCommand, .{
                    .record_index = ri,
                    .record_command_index = ci,
                    .id = id,
                    .name = cmd.name,
                });
            // v1 records legitimately carry the install platform's separator;
            // a v2 forward-slash target is a subset of the same rule.
            if (!install_state.isSafeLegacyRelPath(cmd.relative_target, platform))
                return fail(diag, error.InventoryInvalidCommand, .{
                    .record_index = ri,
                    .record_command_index = ci,
                    .id = id,
                    .name = cmd.relative_target,
                });
            const kind = kindFromInventory(cmd) orelse
                return fail(diag, error.InventoryUnknownKind, .{
                    .record_index = ri,
                    .record_command_index = ci,
                    .id = id,
                    .name = cmd.kind orelse "",
                });
            if (install_state.isWasmTarget(cmd.relative_target) != (kind == .wasm))
                return fail(diag, error.InventoryKindMismatch, .{
                    .record_index = ri,
                    .record_command_index = ci,
                    .id = id,
                    .name = cmd.relative_target,
                });

            const family = artifactFamily(cmd.name, kind, platform);
            // A name the reader accepted can still be too long to carry its own
            // companions. Check before materializing any artifact name.
            for (family.all()) |piece| {
                if (piece.len() > max_artifact_name_bytes)
                    return fail(diag, error.InventoryInvalidCommand, .{
                        .record_index = ri,
                        .record_command_index = ci,
                        .id = id,
                        .name = cmd.name,
                    });
            }
            for (family.all()) |piece| {
                var buf: [max_artifact_name_bytes]u8 = undefined;
                const key = try artifactKey(scratch, piece, platform);
                const gop = try owners.getOrPut(scratch, key);
                if (gop.found_existing) {
                    if (std.mem.eql(u8, gop.value_ptr.id, id)) continue;
                    return fail(diag, error.InventoryAmbiguousArtifact, .{
                        .record_index = ri,
                        .record_command_index = ci,
                        .id = id,
                        .name = cmd.name,
                        .artifact = piece.write(&buf),
                        .owner_id = gop.value_ptr.id,
                    });
                }
                gop.value_ptr.* = .{ .record_index = ri, .id = id };
            }
        }
    }
}

/// Validate one unit's targets, derive each source name exactly once, apply
/// aliases, and append the unit's resolved commands.
fn resolveUnit(
    scratch: Allocator,
    unit: Unit,
    unit_index: usize,
    platform: Platform,
    out: *std.ArrayListUnmanaged(ResolvedCommand),
    diag: ?*Diagnostic,
) Error!void {
    const sources = try scratch.alloc([]const u8, unit.commands.len);
    const finals = try scratch.alloc(?[]const u8, unit.commands.len);
    @memset(finals, null);

    var source_index: std.StringHashMapUnmanaged(usize) = .empty;
    for (unit.commands, 0..) |cmd, ci| {
        if (!install_state.isSafePortableRelPath(cmd.relative_target))
            return fail(diag, error.UnsafeRelativeTarget, .{
                .unit_index = unit_index,
                .command_index = ci,
                .id = unit.id,
                .name = cmd.relative_target,
            });
        if (install_state.isWasmTarget(cmd.relative_target) != (cmd.kind == .wasm))
            return fail(diag, error.CommandKindMismatch, .{
                .unit_index = unit_index,
                .command_index = ci,
                .id = unit.id,
                .name = cmd.relative_target,
            });

        // Derived exactly once, from the raw target.
        const source = install_state.sourceCommandSlice(cmd.relative_target, platform);
        if (source.len > max_final_name_bytes)
            return fail(diag, error.CommandNameTooLong, .{
                .unit_index = unit_index,
                .command_index = ci,
                .id = unit.id,
                .name = source,
            });
        if (!install_state.isSafeV2CommandName(source))
            return fail(diag, error.UnsafeCommandName, .{
                .unit_index = unit_index,
                .command_index = ci,
                .id = unit.id,
                .name = source,
            });

        const key = try nameKey(scratch, source, platform);
        const gop = try source_index.getOrPut(scratch, key);
        if (gop.found_existing) return fail(diag, error.DuplicateSourceCommand, .{
            .unit_index = unit_index,
            .command_index = ci,
            .id = unit.id,
            .name = source,
        });
        gop.value_ptr.* = ci;
        sources[ci] = source;
    }

    var alias_sources: std.StringHashMapUnmanaged(void) = .empty;
    var alias_published: std.StringHashMapUnmanaged(void) = .empty;
    for (unit.aliases, 0..) |alias, ai| {
        if (!install_state.isSafeV2CommandName(alias.source))
            return fail(diag, error.UnsafeAliasName, .{
                .unit_index = unit_index,
                .alias_index = ai,
                .id = unit.id,
                .name = alias.source,
            });
        if (alias.published.len > max_final_name_bytes)
            return fail(diag, error.CommandNameTooLong, .{
                .unit_index = unit_index,
                .alias_index = ai,
                .id = unit.id,
                .name = alias.published,
            });
        // The published side is the EXACT requested name. A trailing `.wasm` or
        // `.exe` is a legitimate part of it and is never stripped here; a
        // resulting file collision is caught by artifact expansion instead.
        if (!install_state.isSafeV2CommandName(alias.published))
            return fail(diag, error.UnsafeAliasName, .{
                .unit_index = unit_index,
                .alias_index = ai,
                .id = unit.id,
                .name = alias.published,
            });

        const skey = try nameKey(scratch, alias.source, platform);
        if ((try alias_sources.getOrPut(scratch, skey)).found_existing)
            return fail(diag, error.DuplicateAliasSource, .{
                .unit_index = unit_index,
                .alias_index = ai,
                .id = unit.id,
                .name = alias.source,
            });
        const pkey = try nameKey(scratch, alias.published, platform);
        if ((try alias_published.getOrPut(scratch, pkey)).found_existing)
            return fail(diag, error.DuplicateAliasPublished, .{
                .unit_index = unit_index,
                .alias_index = ai,
                .id = unit.id,
                .name = alias.published,
            });

        const ci = source_index.get(skey) orelse
            return fail(diag, error.AliasSourceNotFound, .{
                .unit_index = unit_index,
                .alias_index = ai,
                .id = unit.id,
                .name = alias.source,
            });
        // Sources are deduplicated above, so an alias applies to exactly one
        // command and an unaliased command keeps its discovered name.
        finals[ci] = alias.published;
    }

    for (unit.commands, 0..) |cmd, ci| {
        try out.append(scratch, .{
            .unit_index = unit_index,
            .id = unit.id,
            .source_name = sources[ci],
            .final_name = finals[ci] orelse sources[ci],
            .relative_target = cmd.relative_target,
            .kind = cmd.kind,
        });
    }
}

// ---------------------------------------------------------------------------
// Deterministic materialization
// ---------------------------------------------------------------------------

fn commandLessThan(_: void, a: PlannedCommand, b: PlannedCommand) bool {
    return switch (std.mem.order(u8, a.id, b.id)) {
        .lt => true,
        .gt => false,
        .eq => std.mem.order(u8, a.final_name, b.final_name) == .lt,
    };
}

fn staleLessThan(_: void, a: StaleCommand, b: StaleCommand) bool {
    switch (std.mem.order(u8, a.id, b.id)) {
        .lt => return true,
        .gt => return false,
        .eq => {},
    }
    switch (std.mem.order(u8, a.name, b.name)) {
        .lt => return true,
        .gt => return false,
        .eq => {},
    }
    if (@intFromEnum(a.kind) != @intFromEnum(b.kind))
        return @intFromEnum(a.kind) < @intFromEnum(b.kind);
    return std.mem.order(u8, a.relative_target, b.relative_target) == .lt;
}

fn dupePieces(arena: Allocator, pieces: []const Piece) Allocator.Error![]const []const u8 {
    const out = try arena.alloc([]const u8, pieces.len);
    for (pieces, 0..) |piece, i| {
        const buf = try arena.alloc(u8, piece.len());
        out[i] = piece.write(buf);
    }
    return out;
}

fn materialize(
    gpa: Allocator,
    platform: Platform,
    resolved: []const ResolvedCommand,
    stale_in: []const StaleIntent,
) Allocator.Error!Plan {
    var arena_inst = std.heap.ArenaAllocator.init(gpa);
    errdefer arena_inst.deinit();
    const arena = arena_inst.allocator();

    const commands = try arena.alloc(PlannedCommand, resolved.len);
    for (resolved, 0..) |rc, i| {
        const family = artifactFamily(rc.final_name, rc.kind, platform);
        commands[i] = .{
            .id = try arena.dupe(u8, rc.id),
            .source_name = try arena.dupe(u8, rc.source_name),
            .final_name = try arena.dupe(u8, rc.final_name),
            .relative_target = try arena.dupe(u8, rc.relative_target),
            .kind = rc.kind,
            .publish = try dupePieces(arena, family.publish()),
            .cleanup = try dupePieces(arena, family.cleanup()),
        };
    }
    std.mem.sort(PlannedCommand, commands, {}, commandLessThan);

    const stale = try arena.alloc(StaleCommand, stale_in.len);
    for (stale_in, 0..) |sc, i| {
        stale[i] = .{
            .id = try arena.dupe(u8, sc.id),
            .name = try arena.dupe(u8, sc.name),
            .relative_target = try arena.dupe(u8, sc.relative_target),
            .kind = sc.kind,
            .remove = try dupePieces(arena, sc.remove),
        };
    }
    std.mem.sort(StaleCommand, stale, {}, staleLessThan);

    return .{
        .platform = platform,
        .commands = commands,
        .stale = stale,
        .arena_state = arena_inst.state,
        .gpa = gpa,
    };
}

// ===========================================================================
// Tests (pure; no runtime behavior is activated by this module)
// ===========================================================================

const testing = std.testing;
const builtin = @import("builtin");

fn tNative(target: []const u8) Command {
    return .{ .relative_target = target, .kind = .native };
}

fn tWasm(target: []const u8) Command {
    return .{ .relative_target = target, .kind = .wasm };
}

fn tOwned(name: []const u8, target: []const u8, kind: ?[]const u8) install_state.OwnedCommand {
    return .{ .name = name, .relative_target = target, .kind = kind };
}

fn tRecord(id: []const u8, commands: []install_state.OwnedCommand) install_state.InventoryRecord {
    return .{
        .kind = .v2,
        .status = .ok,
        .reason = .none,
        .path = "_v2/units/_unit",
        .id = id,
        .commands = commands,
    };
}

fn tInventory(records: []install_state.InventoryRecord) install_state.Inventory {
    return .{ .records = records };
}

const empty_inventory = install_state.Inventory{ .records = &.{} };
const empty_snapshot: []const SnapshotEntry = &.{};

fn tExpectNames(expected: []const []const u8, actual: []const []const u8) !void {
    try testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |e, a| try testing.expectEqualStrings(e, a);
}

fn tFindCommand(p: Plan, final_name: []const u8) ?PlannedCommand {
    for (p.commands) |c| {
        if (std.mem.eql(u8, c.final_name, final_name)) return c;
    }
    return null;
}

// --- source-name derivation -------------------------------------------------

test "source names derive from the raw target exactly once" {
    const a = testing.allocator;
    const cases = .{
        .{ "bin/tool", Kind.native, Platform.posix, "tool" },
        .{ "bin/tool.exe", Kind.native, Platform.windows, "tool" },
        // POSIX keeps `.exe`: it is not a suffix POSIX publication understands.
        .{ "bin/tool.exe", Kind.native, Platform.posix, "tool.exe" },
        .{ "pkg/mod.wasm", Kind.wasm, Platform.posix, "mod" },
        .{ "pkg/mod.wasm", Kind.wasm, Platform.windows, "mod" },
        // wasm strips exactly one lowercase `.wasm` and does NOT then strip the
        // residual `.exe`, on either platform.
        .{ "pkg/tool.exe.wasm", Kind.wasm, Platform.posix, "tool.exe" },
        .{ "pkg/tool.exe.wasm", Kind.wasm, Platform.windows, "tool.exe" },
        // `.WASM` is not the lowercase wasm rule, so the name survives intact.
        .{ "bin/Foo.WASM", Kind.native, Platform.posix, "Foo.WASM" },
        .{ "bin/App.EXE", Kind.native, Platform.windows, "App" },
    };
    inline for (cases) |c| {
        const units = [_]Unit{.{ .id = "x/y", .commands = &.{
            .{ .relative_target = c[0], .kind = c[1] },
        } }};
        var p = try plan(a, &units, empty_inventory, empty_snapshot, .{ .platform = c[2] });
        defer p.deinit();
        try testing.expectEqualStrings(c[3], p.commands[0].source_name);
        try testing.expectEqualStrings(c[3], p.commands[0].final_name);
    }
}

test "an ID never renames a command" {
    const a = testing.allocator;
    const units = [_]Unit{.{ .id = "zigb", .commands = &.{tNative("bin/zig")} }};
    var p = try plan(a, &units, empty_inventory, empty_snapshot, .{ .platform = .posix });
    defer p.deinit();
    try testing.expectEqual(@as(usize, 1), p.commands.len);
    try testing.expectEqualStrings("zigb", p.commands[0].id);
    try testing.expectEqualStrings("zig", p.commands[0].final_name);
}

// --- aliases ----------------------------------------------------------------

test "aliases rename exactly the named command" {
    const a = testing.allocator;
    const units = [_]Unit{.{
        .id = "zigb",
        .commands = &.{ tNative("bin/zig"), tNative("bin/zls") },
        .aliases = &.{.{ .source = "zig", .published = "zigb" }},
    }};
    var p = try plan(a, &units, empty_inventory, empty_snapshot, .{ .platform = .posix });
    defer p.deinit();
    try testing.expectEqual(@as(usize, 2), p.commands.len);
    const renamed = tFindCommand(p, "zigb").?;
    try testing.expectEqualStrings("zig", renamed.source_name);
    try testing.expectEqualStrings("bin/zig", renamed.relative_target);
    const untouched = tFindCommand(p, "zls").?;
    try testing.expectEqualStrings("zls", untouched.source_name);
}

test "an alias publishes the exact requested name, suffix included" {
    const a = testing.allocator;
    // On POSIX an alias to `foo.wasm` must remain `foo.wasm`.
    {
        const units = [_]Unit{.{
            .id = "w",
            .commands = &.{tWasm("pkg/mod.wasm")},
            .aliases = &.{.{ .source = "mod", .published = "foo.wasm" }},
        }};
        var p = try plan(a, &units, empty_inventory, empty_snapshot, .{ .platform = .posix });
        defer p.deinit();
        try testing.expectEqualStrings("foo.wasm", p.commands[0].final_name);
        try tExpectNames(&.{ "foo.wasm", "foo.wasm.ghr" }, p.commands[0].publish);
    }
    // On Windows an alias that already carries `.exe` is not doubled.
    {
        const units = [_]Unit{.{
            .id = "n",
            .commands = &.{tNative("bin/tool.exe")},
            .aliases = &.{.{ .source = "tool", .published = "other.exe" }},
        }};
        var p = try plan(a, &units, empty_inventory, empty_snapshot, .{ .platform = .windows });
        defer p.deinit();
        try testing.expectEqualStrings("other.exe", p.commands[0].final_name);
        try tExpectNames(&.{ "other.exe", "other.ghr" }, p.commands[0].publish);
    }
}

test "alias source must name a selected command" {
    const a = testing.allocator;
    const units = [_]Unit{.{
        .id = "x",
        .commands = &.{tNative("bin/zig")},
        .aliases = &.{.{ .source = "zls", .published = "zlsb" }},
    }};
    var diag = Diagnostic{};
    try testing.expectError(
        error.AliasSourceNotFound,
        planWithDiagnostic(a, &units, empty_inventory, empty_snapshot, .{ .platform = .posix }, &diag),
    );
    try testing.expectEqual(@as(?usize, 0), diag.alias_index);
    try testing.expectEqualStrings("zls", diag.name.slice());
}

test "duplicate alias sources and published names collide under Windows case rules" {
    const a = testing.allocator;
    {
        const units = [_]Unit{.{
            .id = "x",
            .commands = &.{tNative("bin/zig")},
            .aliases = &.{
                .{ .source = "zig", .published = "one" },
                .{ .source = "ZIG", .published = "two" },
            },
        }};
        try testing.expectError(error.DuplicateAliasSource, plan(a, &units, empty_inventory, empty_snapshot, .{ .platform = .windows }));
        // POSIX compares exactly, so `ZIG` is simply an unknown source.
        try testing.expectError(error.AliasSourceNotFound, plan(a, &units, empty_inventory, empty_snapshot, .{ .platform = .posix }));
    }
    {
        const units = [_]Unit{.{
            .id = "x",
            .commands = &.{ tNative("bin/zig"), tNative("bin/zls") },
            .aliases = &.{
                .{ .source = "zig", .published = "same" },
                .{ .source = "zls", .published = "SAME" },
            },
        }};
        try testing.expectError(error.DuplicateAliasPublished, plan(a, &units, empty_inventory, empty_snapshot, .{ .platform = .windows }));
    }
}

test "unsafe alias names are rejected, never sanitized" {
    const a = testing.allocator;
    inline for (.{ "a/b", "..", "aux", "", "trailing.", "q?" }) |bad| {
        const units = [_]Unit{.{
            .id = "x",
            .commands = &.{tNative("bin/zig")},
            .aliases = &.{.{ .source = "zig", .published = bad }},
        }};
        try testing.expectError(
            error.UnsafeAliasName,
            plan(a, &units, empty_inventory, empty_snapshot, .{ .platform = .posix }),
        );
    }
}

test "over-long names fail typed rather than being truncated" {
    const a = testing.allocator;
    const long = "a" ** (max_final_name_bytes + 5);
    {
        const target = "bin/" ++ long;
        const units = [_]Unit{.{ .id = "x", .commands = &.{tNative(target)} }};
        try testing.expectError(error.CommandNameTooLong, plan(a, &units, empty_inventory, empty_snapshot, .{ .platform = .posix }));
    }
    {
        const units = [_]Unit{.{
            .id = "x",
            .commands = &.{tNative("bin/zig")},
            .aliases = &.{.{ .source = "zig", .published = long }},
        }};
        try testing.expectError(error.CommandNameTooLong, plan(a, &units, empty_inventory, empty_snapshot, .{ .platform = .posix }));
    }
    // The boundary name still plans, and every companion fits the file-name bound.
    {
        const at_limit = "b" ** max_final_name_bytes;
        const units = [_]Unit{.{
            .id = "x",
            .commands = &.{tNative("bin/zig")},
            .aliases = &.{.{ .source = "zig", .published = at_limit }},
        }};
        var p = try plan(a, &units, empty_inventory, empty_snapshot, .{ .platform = .windows });
        defer p.deinit();
        for (p.commands[0].publish) |n| try testing.expect(n.len <= max_artifact_name_bytes);
        for (p.commands[0].cleanup) |n| try testing.expect(n.len <= max_artifact_name_bytes);
    }
}

// --- invocation-level duplicates -------------------------------------------

test "duplicate IDs and duplicate discovered names are rejected" {
    const a = testing.allocator;
    {
        const units = [_]Unit{
            .{ .id = "a/b", .commands = &.{tNative("bin/one")} },
            .{ .id = "a/b", .commands = &.{tNative("bin/two")} },
        };
        var diag = Diagnostic{};
        try testing.expectError(error.DuplicateId, planWithDiagnostic(a, &units, empty_inventory, empty_snapshot, .{ .platform = .posix }, &diag));
        try testing.expectEqual(@as(?usize, 1), diag.unit_index);
        try testing.expectEqualStrings("a/b", diag.id.slice());
    }
    {
        const units = [_]Unit{.{ .id = "a/b", .commands = &.{ tNative("x/tool"), tNative("y/tool") } }};
        try testing.expectError(error.DuplicateSourceCommand, plan(a, &units, empty_inventory, empty_snapshot, .{ .platform = .posix }));
    }
    {
        // Same discovered name only under Windows case folding.
        const units = [_]Unit{.{ .id = "a/b", .commands = &.{ tNative("x/tool"), tNative("y/TOOL") } }};
        try testing.expectError(error.DuplicateSourceCommand, plan(a, &units, empty_inventory, empty_snapshot, .{ .platform = .windows }));
        var p = try plan(a, &units, empty_inventory, empty_snapshot, .{ .platform = .posix });
        defer p.deinit();
        try testing.expectEqual(@as(usize, 2), p.commands.len);
    }
}

test "duplicate final logical names across units are rejected" {
    const a = testing.allocator;
    const units = [_]Unit{
        .{ .id = "a", .commands = &.{tNative("bin/tool")} },
        .{ .id = "b", .commands = &.{tNative("bin/other")}, .aliases = &.{.{ .source = "other", .published = "tool" }} },
    };
    try testing.expectError(error.DuplicateCommandName, plan(a, &units, empty_inventory, empty_snapshot, .{ .platform = .posix }));
}

test "physical companion overlap is rejected even when logical names differ" {
    const a = testing.allocator;
    // POSIX: the wasm launcher `foo` also owns `foo.ghr`.
    {
        const units = [_]Unit{
            .{ .id = "a", .commands = &.{tWasm("pkg/foo.wasm")} },
            .{ .id = "b", .commands = &.{tNative("bin/other")}, .aliases = &.{.{ .source = "other", .published = "foo.ghr" }} },
        };
        var diag = Diagnostic{};
        try testing.expectError(error.DuplicateArtifact, planWithDiagnostic(a, &units, empty_inventory, empty_snapshot, .{ .platform = .posix }, &diag));
        try testing.expectEqualStrings("foo.ghr", diag.artifact.slice());
    }
    // Windows: `foo` and `foo.exe` are distinct logical names but one file.
    {
        const units = [_]Unit{
            .{ .id = "a", .commands = &.{tNative("bin/foo")} },
            .{ .id = "b", .commands = &.{tNative("bin/other")}, .aliases = &.{.{ .source = "other", .published = "foo.exe" }} },
        };
        try testing.expectError(error.DuplicateArtifact, plan(a, &units, empty_inventory, empty_snapshot, .{ .platform = .windows }));
        // The same pair is fine on POSIX, where the files really are distinct.
        var p = try plan(a, &units, empty_inventory, empty_snapshot, .{ .platform = .posix });
        defer p.deinit();
        try testing.expectEqual(@as(usize, 2), p.commands.len);
    }
}

// --- artifact matrices ------------------------------------------------------

test "artifact families match the current writers exactly" {
    const a = testing.allocator;
    {
        const units = [_]Unit{.{ .id = "u", .commands = &.{tNative("bin/tool")} }};
        var p = try plan(a, &units, empty_inventory, empty_snapshot, .{ .platform = .posix });
        defer p.deinit();
        try tExpectNames(&.{"tool"}, p.commands[0].publish);
        try tExpectNames(&.{}, p.commands[0].cleanup);
    }
    {
        const units = [_]Unit{.{ .id = "u", .commands = &.{tWasm("pkg/tool.wasm")} }};
        var p = try plan(a, &units, empty_inventory, empty_snapshot, .{ .platform = .posix });
        defer p.deinit();
        try tExpectNames(&.{ "tool", "tool.ghr" }, p.commands[0].publish);
        try tExpectNames(&.{"tool.shim"}, p.commands[0].cleanup);
    }
    {
        const units = [_]Unit{.{ .id = "u", .commands = &.{tNative("bin/tool")} }};
        var p = try plan(a, &units, empty_inventory, empty_snapshot, .{ .platform = .windows });
        defer p.deinit();
        try tExpectNames(&.{ "tool.exe", "tool.ghr" }, p.commands[0].publish);
        try tExpectNames(&.{ "tool.cmd", "tool.shim", "tool.exe.old" }, p.commands[0].cleanup);
    }
    {
        // A Windows name that already ends in `.exe` is not doubled, and the
        // stem drops exactly one `.exe` for its companions.
        const units = [_]Unit{.{
            .id = "u",
            .commands = &.{tNative("bin/tool")},
            .aliases = &.{.{ .source = "tool", .published = "tool.exe" }},
        }};
        var p = try plan(a, &units, empty_inventory, empty_snapshot, .{ .platform = .windows });
        defer p.deinit();
        try tExpectNames(&.{ "tool.exe", "tool.ghr" }, p.commands[0].publish);
        try tExpectNames(&.{ "tool.cmd", "tool.shim", "tool.exe.old" }, p.commands[0].cleanup);
    }
    {
        const units = [_]Unit{.{ .id = "u", .commands = &.{tWasm("pkg/tool.wasm")} }};
        var p = try plan(a, &units, empty_inventory, empty_snapshot, .{ .platform = .windows });
        defer p.deinit();
        try tExpectNames(&.{ "tool.exe", "tool.ghr" }, p.commands[0].publish);
        try tExpectNames(&.{ "tool.shim", "tool.exe.old" }, p.commands[0].cleanup);
    }
    {
        // The deliberately odd default wasm stem: `tool.exe.wasm` publishes a
        // `tool.exe.exe` launcher on Windows.
        const units = [_]Unit{.{ .id = "u", .commands = &.{tWasm("pkg/tool.exe.wasm")} }};
        var p = try plan(a, &units, empty_inventory, empty_snapshot, .{ .platform = .windows });
        defer p.deinit();
        try testing.expectEqualStrings("tool.exe", p.commands[0].final_name);
        try tExpectNames(&.{ "tool.exe.exe", "tool.exe.ghr" }, p.commands[0].publish);
        try tExpectNames(&.{ "tool.exe.shim", "tool.exe.exe.old" }, p.commands[0].cleanup);
    }
}

// --- target validation ------------------------------------------------------

test "unsafe or misclassified targets are rejected" {
    const a = testing.allocator;
    inline for (.{ "../evil", "/abs", "C:\\x", "bin\\tool", "", "a/../b", "bin/tool\x01" }) |bad| {
        const units = [_]Unit{.{ .id = "x", .commands = &.{tNative(bad)} }};
        try testing.expectError(error.UnsafeRelativeTarget, plan(a, &units, empty_inventory, empty_snapshot, .{ .platform = .posix }));
    }
    {
        const units = [_]Unit{.{ .id = "x", .commands = &.{tNative("pkg/mod.wasm")} }};
        try testing.expectError(error.CommandKindMismatch, plan(a, &units, empty_inventory, empty_snapshot, .{ .platform = .posix }));
    }
    {
        const units = [_]Unit{.{ .id = "x", .commands = &.{tWasm("bin/tool")} }};
        try testing.expectError(error.CommandKindMismatch, plan(a, &units, empty_inventory, empty_snapshot, .{ .platform = .posix }));
    }
    inline for (.{ "Zig/B", "a//b", "-x", "" }) |bad_id| {
        const units = [_]Unit{.{ .id = bad_id, .commands = &.{tNative("bin/tool")} }};
        try testing.expectError(error.NonCanonicalId, plan(a, &units, empty_inventory, empty_snapshot, .{ .platform = .posix }));
    }
}

// --- inventory health -------------------------------------------------------

test "a damaged inventory record anywhere blocks the whole invocation" {
    const a = testing.allocator;
    const units = [_]Unit{.{ .id = "mine", .commands = &.{tNative("bin/tool")} }};
    var unrelated = [_]install_state.OwnedCommand{tOwned("elsewhere", "bin/elsewhere", null)};

    // Corrupt, unsupported, and conflicting records all block, even though the
    // damaged record has nothing to do with the requested command.
    inline for (.{ install_state.Status.corrupt, .unsupported, .conflict }) |status| {
        var records = [_]install_state.InventoryRecord{
            .{ .kind = .v2, .status = status, .reason = .malformed_json, .path = "p", .id = "other", .commands = &unrelated },
        };
        var diag = Diagnostic{};
        try testing.expectError(error.InventoryNotOk, planWithDiagnostic(a, &units, tInventory(&records), empty_snapshot, .{ .platform = .posix }, &diag));
        try testing.expectEqual(@as(?usize, 0), diag.record_index);
        try testing.expectEqualStrings("other", diag.id.slice());
    }
    {
        var records = [_]install_state.InventoryRecord{
            .{ .kind = .v1_repo, .status = .ok, .reason = .none, .path = "p", .id = null, .commands = &unrelated },
        };
        try testing.expectError(error.InventoryIdMissing, plan(a, &units, tInventory(&records), empty_snapshot, .{ .platform = .posix }));
    }
    {
        var records = [_]install_state.InventoryRecord{tRecord("Other/Id", &unrelated)};
        try testing.expectError(error.InventoryInvalidId, plan(a, &units, tInventory(&records), empty_snapshot, .{ .platform = .posix }));
    }
    {
        var one = [_]install_state.OwnedCommand{tOwned("a", "bin/a", null)};
        var two = [_]install_state.OwnedCommand{tOwned("b", "bin/b", null)};
        var records = [_]install_state.InventoryRecord{ tRecord("same", &one), tRecord("same", &two) };
        try testing.expectError(error.InventoryDuplicateId, plan(a, &units, tInventory(&records), empty_snapshot, .{ .platform = .posix }));
    }
}

test "invalid, unknown-kind, and kind-mismatched inventory commands block" {
    const a = testing.allocator;
    const units = [_]Unit{.{ .id = "mine", .commands = &.{tNative("bin/tool")} }};
    {
        var cmds = [_]install_state.OwnedCommand{tOwned("bad/name", "bin/x", null)};
        var records = [_]install_state.InventoryRecord{tRecord("other", &cmds)};
        try testing.expectError(error.InventoryInvalidCommand, plan(a, &units, tInventory(&records), empty_snapshot, .{ .platform = .posix }));
    }
    {
        var cmds = [_]install_state.OwnedCommand{tOwned("x", "../escape", null)};
        var records = [_]install_state.InventoryRecord{tRecord("other", &cmds)};
        try testing.expectError(error.InventoryInvalidCommand, plan(a, &units, tInventory(&records), empty_snapshot, .{ .platform = .posix }));
    }
    {
        var cmds = [_]install_state.OwnedCommand{tOwned("x", "bin/x", "script")};
        var records = [_]install_state.InventoryRecord{tRecord("other", &cmds)};
        var diag = Diagnostic{};
        try testing.expectError(error.InventoryUnknownKind, planWithDiagnostic(a, &units, tInventory(&records), empty_snapshot, .{ .platform = .posix }, &diag));
        try testing.expectEqualStrings("script", diag.name.slice());
    }
    {
        // `kind` says native but the target is a module (and vice versa).
        var cmds = [_]install_state.OwnedCommand{tOwned("mod", "pkg/mod.wasm", "native")};
        var records = [_]install_state.InventoryRecord{tRecord("other", &cmds)};
        try testing.expectError(error.InventoryKindMismatch, plan(a, &units, tInventory(&records), empty_snapshot, .{ .platform = .posix }));
    }
    {
        var cmds = [_]install_state.OwnedCommand{tOwned("x", "bin/x", "wasm")};
        var records = [_]install_state.InventoryRecord{tRecord("other", &cmds)};
        try testing.expectError(error.InventoryKindMismatch, plan(a, &units, tInventory(&records), empty_snapshot, .{ .platform = .posix }));
    }
    {
        // A v1 record's legacy separator is accepted for a Windows store.
        var cmds = [_]install_state.OwnedCommand{tOwned("app", "bin\\app.exe", null)};
        var records = [_]install_state.InventoryRecord{tRecord("other", &cmds)};
        var p = try plan(a, &units, tInventory(&records), empty_snapshot, .{ .platform = .windows });
        defer p.deinit();
        try testing.expectEqual(@as(usize, 1), p.commands.len);
        // ...but not for a POSIX one.
        try testing.expectError(error.InventoryInvalidCommand, plan(a, &units, tInventory(&records), empty_snapshot, .{ .platform = .posix }));
    }
}

test "same-ID inventory overlaps coalesce while cross-ID overlaps block" {
    const a = testing.allocator;
    const units = [_]Unit{.{ .id = "mine", .commands = &.{tNative("bin/tool")} }};
    {
        // One ID, two logical names whose companion files overlap. Ownership
        // remains unambiguous because both claims belong to the same unit.
        var cmds = [_]install_state.OwnedCommand{
            tOwned("foo", "pkg/foo.wasm", "wasm"),
            tOwned("foo.ghr", "bin/foo.ghr", "native"),
        };
        var records = [_]install_state.InventoryRecord{tRecord("other", &cmds)};
        var p = try plan(a, &units, tInventory(&records), empty_snapshot, .{ .platform = .posix });
        defer p.deinit();
        try testing.expectEqual(@as(usize, 1), p.commands.len);
    }
    {
        // Two IDs claiming one Windows file through `foo` and `foo.exe`.
        var one = [_]install_state.OwnedCommand{tOwned("foo", "bin/foo", null)};
        var two = [_]install_state.OwnedCommand{tOwned("foo.exe", "bin/foo.exe", null)};
        var records = [_]install_state.InventoryRecord{ tRecord("a", &one), tRecord("b", &two) };
        try testing.expectError(error.InventoryAmbiguousArtifact, plan(a, &units, tInventory(&records), empty_snapshot, .{ .platform = .windows }));
        // On POSIX the two files are genuinely distinct.
        var p = try plan(a, &units, tInventory(&records), empty_snapshot, .{ .platform = .posix });
        defer p.deinit();
        try testing.expectEqual(@as(usize, 1), p.commands.len);
    }
}

// --- ownership --------------------------------------------------------------

test "another ID's artifact blocks even when it is absent from disk" {
    const a = testing.allocator;
    var cmds = [_]install_state.OwnedCommand{tOwned("tool", "bin/tool", null)};
    var records = [_]install_state.InventoryRecord{tRecord("other/pkg", &cmds)};
    const units = [_]Unit{.{ .id = "mine/pkg", .commands = &.{tNative("bin/tool")} }};
    var diag = Diagnostic{};
    try testing.expectError(
        error.ArtifactOwnedByOtherId,
        planWithDiagnostic(a, &units, tInventory(&records), empty_snapshot, .{ .platform = .posix }, &diag),
    );
    try testing.expectEqualStrings("other/pkg", diag.owner_id.slice());
    try testing.expectEqualStrings("tool", diag.artifact.slice());
}

test "a companion file owned by another ID blocks too" {
    const a = testing.allocator;
    // `other` owns the wasm launcher `foo` plus `foo.ghr`; nobody may publish a
    // native command literally named `foo.ghr`.
    var cmds = [_]install_state.OwnedCommand{tOwned("foo", "pkg/foo.wasm", "wasm")};
    var records = [_]install_state.InventoryRecord{tRecord("other", &cmds)};
    const units = [_]Unit{.{
        .id = "mine",
        .commands = &.{tNative("bin/x")},
        .aliases = &.{.{ .source = "x", .published = "foo.ghr" }},
    }};
    try testing.expectError(
        error.ArtifactOwnedByOtherId,
        plan(a, &units, tInventory(&records), empty_snapshot, .{ .platform = .posix }),
    );
}

test "unmanaged bin entries block regardless of entry type" {
    const a = testing.allocator;
    const units = [_]Unit{.{ .id = "mine", .commands = &.{tNative("bin/tool")} }};
    inline for (.{ EntryKind.file, .directory, .sym_link, .other, .unknown }) |kind| {
        const snapshot = [_]SnapshotEntry{.{ .name = "tool", .kind = kind }};
        var diag = Diagnostic{};
        try testing.expectError(
            error.UnmanagedArtifact,
            planWithDiagnostic(a, &units, empty_inventory, &snapshot, .{ .platform = .posix }, &diag),
        );
        try testing.expectEqualStrings("tool", diag.artifact.slice());
        try testing.expectEqual(@as(?EntryKind, kind), diag.entry_kind);
    }
    // A cleanup/touch artifact is checked just like a published one.
    {
        const snapshot = [_]SnapshotEntry{.{ .name = "tool.cmd", .kind = .file }};
        try testing.expectError(error.UnmanagedArtifact, plan(a, &units, empty_inventory, &snapshot, .{ .platform = .windows }));
    }
    // An unrelated bin entry does not block.
    {
        const snapshot = [_]SnapshotEntry{.{ .name = "somethingelse", .kind = .file }};
        var p = try plan(a, &units, empty_inventory, &snapshot, .{ .platform = .posix });
        defer p.deinit();
        try testing.expectEqual(@as(usize, 1), p.commands.len);
    }
}

test "unmanaged detection uses platform case rules" {
    const a = testing.allocator;
    const units = [_]Unit{.{ .id = "mine", .commands = &.{tNative("bin/tool")} }};
    // Windows publishes `tool.exe` and folds case, so `TOOL.EXE` blocks.
    {
        const snapshot = [_]SnapshotEntry{.{ .name = "TOOL.EXE", .kind = .file }};
        try testing.expectError(error.UnmanagedArtifact, plan(a, &units, empty_inventory, &snapshot, .{ .platform = .windows }));
    }
    // POSIX publishes `tool` and compares exactly: `TOOL` is a different file.
    {
        const snapshot = [_]SnapshotEntry{.{ .name = "TOOL", .kind = .file }};
        var p = try plan(a, &units, empty_inventory, &snapshot, .{ .platform = .posix });
        defer p.deinit();
        try testing.expectEqual(@as(usize, 1), p.commands.len);
    }
    {
        const snapshot = [_]SnapshotEntry{.{ .name = "tool", .kind = .file }};
        try testing.expectError(error.UnmanagedArtifact, plan(a, &units, empty_inventory, &snapshot, .{ .platform = .posix }));
    }
}

test "platform-equivalent duplicate snapshot names fail closed" {
    const a = testing.allocator;
    const units = [_]Unit{.{ .id = "mine", .commands = &.{tNative("bin/tool")} }};
    const snapshot = [_]SnapshotEntry{
        .{ .name = "other", .kind = .file },
        .{ .name = "OTHER", .kind = .file },
    };
    var diag = Diagnostic{};
    try testing.expectError(
        error.AmbiguousBinEntry,
        planWithDiagnostic(a, &units, empty_inventory, &snapshot, .{ .platform = .windows }, &diag),
    );
    try testing.expectEqualStrings("OTHER", diag.artifact.slice());
    // Case-sensitive stores really can hold both.
    var p = try plan(a, &units, empty_inventory, &snapshot, .{ .platform = .posix });
    defer p.deinit();
    try testing.expectEqual(@as(usize, 1), p.commands.len);
}

test "a cross-ID command swap is refused even inside one invocation" {
    const a = testing.allocator;
    var one = [_]install_state.OwnedCommand{tOwned("foo", "bin/foo", null)};
    var two = [_]install_state.OwnedCommand{tOwned("bar", "bin/bar", null)};
    var records = [_]install_state.InventoryRecord{ tRecord("a", &one), tRecord("b", &two) };
    const units = [_]Unit{
        .{ .id = "a", .commands = &.{tNative("bin/x")}, .aliases = &.{.{ .source = "x", .published = "bar" }} },
        .{ .id = "b", .commands = &.{tNative("bin/y")}, .aliases = &.{.{ .source = "y", .published = "foo" }} },
    };
    try testing.expectError(
        error.ArtifactOwnedByOtherId,
        plan(a, &units, tInventory(&records), empty_snapshot, .{ .platform = .posix }),
    );
}

// --- same-ID replacement ----------------------------------------------------

test "same-ID replacement republishes retained commands and retires the rest" {
    const a = testing.allocator;
    var cmds = [_]install_state.OwnedCommand{
        tOwned("keep", "bin/keep", null),
        tOwned("old", "bin/old", null),
    };
    var records = [_]install_state.InventoryRecord{tRecord("demo/tool", &cmds)};
    const snapshot = [_]SnapshotEntry{
        .{ .name = "keep", .kind = .sym_link },
        .{ .name = "old", .kind = .sym_link },
    };
    const units = [_]Unit{.{
        .id = "demo/tool",
        .commands = &.{ tNative("bin/keep"), tNative("bin/new") },
    }};
    var p = try plan(a, &units, tInventory(&records), &snapshot, .{ .platform = .posix });
    defer p.deinit();
    try testing.expectEqual(@as(usize, 2), p.commands.len);
    try testing.expectEqualStrings("keep", p.commands[0].final_name);
    try testing.expectEqualStrings("new", p.commands[1].final_name);
    try testing.expectEqual(@as(usize, 1), p.stale.len);
    try testing.expectEqualStrings("demo/tool", p.stale[0].id);
    try testing.expectEqualStrings("old", p.stale[0].name);
    try tExpectNames(&.{"old"}, p.stale[0].remove);
}

test "stale removal never cancels the same ID's replacement artifacts" {
    const a = testing.allocator;
    // `foo` was a wasm launcher owning `foo`, `foo.ghr`, `foo.shim`. The new
    // definition publishes a native command literally named `foo.ghr`.
    var cmds = [_]install_state.OwnedCommand{tOwned("foo", "pkg/foo.wasm", "wasm")};
    var records = [_]install_state.InventoryRecord{tRecord("demo", &cmds)};
    const units = [_]Unit{.{
        .id = "demo",
        .commands = &.{tNative("bin/x")},
        .aliases = &.{.{ .source = "x", .published = "foo.ghr" }},
    }};
    var p = try plan(a, &units, tInventory(&records), empty_snapshot, .{ .platform = .posix });
    defer p.deinit();
    try tExpectNames(&.{"foo.ghr"}, p.commands[0].publish);
    try testing.expectEqual(@as(usize, 1), p.stale.len);
    try tExpectNames(&.{ "foo", "foo.shim" }, p.stale[0].remove);
}

test "a retained wasm command produces no stale record" {
    const a = testing.allocator;
    var cmds = [_]install_state.OwnedCommand{tOwned("mod", "pkg/mod.wasm", "wasm")};
    var records = [_]install_state.InventoryRecord{tRecord("demo", &cmds)};
    const units = [_]Unit{.{ .id = "demo", .commands = &.{tWasm("pkg/mod.wasm")} }};
    var p = try plan(a, &units, tInventory(&records), empty_snapshot, .{ .platform = .windows });
    defer p.deinit();
    try testing.expectEqual(@as(usize, 0), p.stale.len);
    try tExpectNames(&.{ "mod.exe", "mod.ghr" }, p.commands[0].publish);
}

test "a retained name that changes kind still retires the old companions" {
    const a = testing.allocator;
    // POSIX: `mod` was a wasm launcher (`mod`, `mod.ghr`, `mod.shim`) and is now
    // a plain native symlink, which owns only `mod`.
    {
        var cmds = [_]install_state.OwnedCommand{tOwned("mod", "pkg/mod.wasm", "wasm")};
        var records = [_]install_state.InventoryRecord{tRecord("demo", &cmds)};
        const units = [_]Unit{.{ .id = "demo", .commands = &.{tNative("bin/mod")} }};
        var p = try plan(a, &units, tInventory(&records), empty_snapshot, .{ .platform = .posix });
        defer p.deinit();
        try tExpectNames(&.{"mod"}, p.commands[0].publish);
        try testing.expectEqual(@as(usize, 1), p.stale.len);
        try testing.expectEqualStrings("mod", p.stale[0].name);
        try testing.expectEqual(Kind.wasm, p.stale[0].kind);
        try tExpectNames(&.{ "mod.ghr", "mod.shim" }, p.stale[0].remove);
    }
    // Windows: a native command owns a legacy `<stem>.cmd` that the wasm
    // launcher family does not.
    {
        var cmds = [_]install_state.OwnedCommand{tOwned("mod", "bin/mod.exe", "native")};
        var records = [_]install_state.InventoryRecord{tRecord("demo", &cmds)};
        const units = [_]Unit{.{ .id = "demo", .commands = &.{tWasm("pkg/mod.wasm")} }};
        var p = try plan(a, &units, tInventory(&records), empty_snapshot, .{ .platform = .windows });
        defer p.deinit();
        try testing.expectEqual(@as(usize, 1), p.stale.len);
        try tExpectNames(&.{"mod.cmd"}, p.stale[0].remove);
    }
}

test "legacy names the reader accepts stay ownable, not fatal" {
    const a = testing.allocator;
    // `install_state` accepts a non-ASCII v1 name on a POSIX store, where names
    // compare byte-exactly. The planner must track its ownership instead of
    // refusing every unrelated install because of it.
    inline for (.{"caf\xc3\xa9"}) |legacy| {
        var cmds = [_]install_state.OwnedCommand{tOwned(legacy, "bin/" ++ legacy, null)};
        var records = [_]install_state.InventoryRecord{tRecord("legacy/unit", &cmds)};
        {
            const units = [_]Unit{.{ .id = "mine", .commands = &.{tNative("bin/tool")} }};
            var p = try plan(a, &units, tInventory(&records), empty_snapshot, .{ .platform = .posix });
            defer p.deinit();
            try testing.expectEqual(@as(usize, 1), p.commands.len);
        }
        {
            // The same ID can still retire it: ownership was really recorded.
            const units = [_]Unit{.{ .id = "legacy/unit", .commands = &.{tNative("bin/tool")} }};
            var p = try plan(a, &units, tInventory(&records), empty_snapshot, .{ .platform = .posix });
            defer p.deinit();
            try testing.expectEqual(@as(usize, 1), p.stale.len);
            try testing.expectEqualStrings(legacy, p.stale[0].name);
            try tExpectNames(&.{legacy}, p.stale[0].remove);
        }
        {
            // A NEW command may never be given such a name, on either platform.
            const units = [_]Unit{.{
                .id = "mine",
                .commands = &.{tNative("bin/tool")},
                .aliases = &.{.{ .source = "tool", .published = legacy }},
            }};
            try testing.expectError(
                error.UnsafeAliasName,
                plan(a, &units, tInventory(&records), empty_snapshot, .{ .platform = .posix }),
            );
        }
        {
            // Windows folds case, so such a name cannot be compared reliably and
            // the record blocks planning there.
            const units = [_]Unit{.{ .id = "mine", .commands = &.{tNative("bin/tool")} }};
            try testing.expectError(
                error.InventoryInvalidCommand,
                plan(a, &units, tInventory(&records), empty_snapshot, .{ .platform = .windows }),
            );
        }
    }
}

test "leading-dot published names remain exact and ownable" {
    const a = testing.allocator;
    var cmds = [_]install_state.OwnedCommand{tOwned(".hidden", "bin/.hidden", null)};
    var records = [_]install_state.InventoryRecord{tRecord("legacy/unit", &cmds)};
    const units = [_]Unit{.{
        .id = "legacy/unit",
        .commands = &.{tNative("bin/tool")},
        .aliases = &.{.{ .source = "tool", .published = ".hidden" }},
    }};
    const snapshot = [_]SnapshotEntry{.{ .name = ".hidden", .kind = .sym_link }};
    var p = try plan(a, &units, tInventory(&records), &snapshot, .{ .platform = .posix });
    defer p.deinit();
    try testing.expectEqualStrings(".hidden", p.commands[0].final_name);
    try tExpectNames(&.{".hidden"}, p.commands[0].publish);
    try testing.expectEqual(@as(usize, 0), p.stale.len);
}

test "duplicate legacy command paths coalesce ownership and stale artifacts" {
    const a = testing.allocator;
    var cmds = [_]install_state.OwnedCommand{
        tOwned("tool", "bin/tool", null),
        tOwned("tool", "libexec/tool", null),
    };
    var records = [_]install_state.InventoryRecord{tRecord("legacy/unit", &cmds)};
    const units = [_]Unit{.{ .id = "legacy/unit", .commands = &.{tNative("bin/new")} }};
    var p = try plan(a, &units, tInventory(&records), empty_snapshot, .{ .platform = .posix });
    defer p.deinit();
    try testing.expectEqual(@as(usize, 1), p.stale.len);
    try testing.expectEqualStrings("tool", p.stale[0].name);
    try tExpectNames(&.{"tool"}, p.stale[0].remove);
}

test "an inventory name too long for its own companions fails typed" {
    const a = testing.allocator;
    const units = [_]Unit{.{ .id = "mine", .commands = &.{tNative("bin/tool")} }};
    const long = "n" ** (max_artifact_name_bytes - 2);
    {
        // POSIX wasm needs `<name>.ghr`, which no longer fits.
        var cmds = [_]install_state.OwnedCommand{tOwned(long, "pkg/mod.wasm", "wasm")};
        var records = [_]install_state.InventoryRecord{tRecord("legacy/unit", &cmds)};
        try testing.expectError(
            error.InventoryInvalidCommand,
            plan(a, &units, tInventory(&records), empty_snapshot, .{ .platform = .posix }),
        );
    }
    {
        // POSIX native has no companions, so the same name is still ownable.
        var cmds = [_]install_state.OwnedCommand{tOwned(long, "bin/" ++ long, null)};
        var records = [_]install_state.InventoryRecord{tRecord("legacy/unit", &cmds)};
        var p = try plan(a, &units, tInventory(&records), empty_snapshot, .{ .platform = .posix });
        defer p.deinit();
        try testing.expectEqual(@as(usize, 1), p.commands.len);
    }
}

test "same-ID stale records carry the full retired family" {
    const a = testing.allocator;
    var cmds = [_]install_state.OwnedCommand{tOwned("gone", "pkg/gone.wasm", "wasm")};
    var records = [_]install_state.InventoryRecord{tRecord("demo", &cmds)};
    const units = [_]Unit{.{ .id = "demo", .commands = &.{tNative("bin/fresh")} }};
    var p = try plan(a, &units, tInventory(&records), empty_snapshot, .{ .platform = .windows });
    defer p.deinit();
    try testing.expectEqual(@as(usize, 1), p.stale.len);
    try testing.expectEqual(Kind.wasm, p.stale[0].kind);
    try testing.expectEqualStrings("pkg/gone.wasm", p.stale[0].relative_target);
    try tExpectNames(&.{ "gone.exe", "gone.ghr", "gone.shim", "gone.exe.old" }, p.stale[0].remove);
}

// --- determinism and purity -------------------------------------------------

test "plan output is deterministically ordered" {
    const a = testing.allocator;
    const units = [_]Unit{
        .{ .id = "zeta", .commands = &.{ tNative("bin/zb"), tNative("bin/za") } },
        .{ .id = "alpha", .commands = &.{tNative("bin/aa")} },
    };
    var p = try plan(a, &units, empty_inventory, empty_snapshot, .{ .platform = .posix });
    defer p.deinit();
    try testing.expectEqualStrings("alpha", p.commands[0].id);
    try testing.expectEqualStrings("aa", p.commands[0].final_name);
    try testing.expectEqualStrings("zeta", p.commands[1].id);
    try testing.expectEqualStrings("za", p.commands[1].final_name);
    try testing.expectEqualStrings("zb", p.commands[2].final_name);
}

test "an empty invocation plans nothing" {
    const a = testing.allocator;
    var p = try plan(a, &.{}, empty_inventory, empty_snapshot, .{ .platform = .posix });
    defer p.deinit();
    try testing.expectEqual(@as(usize, 0), p.commands.len);
    try testing.expectEqual(@as(usize, 0), p.stale.len);
}

test "a reused diagnostic is fully reset and never dangles" {
    const a = testing.allocator;
    var diag = Diagnostic{};
    {
        var cmds = [_]install_state.OwnedCommand{tOwned("tool", "bin/tool", null)};
        var records = [_]install_state.InventoryRecord{tRecord("other/pkg", &cmds)};
        const units = [_]Unit{.{ .id = "mine/pkg", .commands = &.{tNative("bin/tool")} }};
        try testing.expectError(
            error.ArtifactOwnedByOtherId,
            planWithDiagnostic(a, &units, tInventory(&records), empty_snapshot, .{ .platform = .posix }, &diag),
        );
        try testing.expectEqualStrings("other/pkg", diag.owner_id.slice());
        try testing.expectEqual(@as(?usize, 0), diag.record_index);
    }
    {
        // A later, unrelated failure must not inherit the earlier positions.
        const units = [_]Unit{
            .{ .id = "a", .commands = &.{tNative("bin/one")} },
            .{ .id = "a", .commands = &.{tNative("bin/two")} },
        };
        try testing.expectError(
            error.DuplicateId,
            planWithDiagnostic(a, &units, empty_inventory, empty_snapshot, .{ .platform = .posix }, &diag),
        );
        try testing.expectEqual(@as(?usize, null), diag.record_index);
        try testing.expectEqual(@as(?EntryKind, null), diag.entry_kind);
        try testing.expectEqualStrings("", diag.owner_id.slice());
        try testing.expectEqualStrings("", diag.artifact.slice());
        try testing.expectEqualStrings("a", diag.id.slice());
    }
    {
        // Reported text is a bounded copy, so it stays readable after the plan
        // it described is freed.
        const units = [_]Unit{.{ .id = "mine", .commands = &.{tNative("bin/tool")} }};
        var p = try plan(a, &units, empty_inventory, empty_snapshot, .{ .platform = .posix });
        p.deinit();
        try testing.expectEqualStrings("a", diag.id.slice());
    }
}

test "diagnostic text is bounded, not unbounded input" {
    const a = testing.allocator;
    const long_id = "q" ** (max_diagnostic_text_bytes + 40);
    const units = [_]Unit{.{ .id = long_id, .commands = &.{tNative("bin/tool")} }};
    var diag = Diagnostic{};
    try testing.expectError(
        error.NonCanonicalId,
        planWithDiagnostic(a, &units, empty_inventory, empty_snapshot, .{ .platform = .posix }, &diag),
    );
    try testing.expectEqual(max_diagnostic_text_bytes, diag.id.slice().len);
    try testing.expect(diag.id.truncated);
}

test "the core planner takes no io handle" {
    const info = @typeInfo(@TypeOf(plan)).@"fn";
    inline for (info.params) |param| {
        const T = param.type.?;
        try testing.expect(T != Io);
        try testing.expect(T != Dir);
    }
}

// --- bin snapshot -----------------------------------------------------------

fn tSnapshotPath(dir: Dir, io: Io, buf: []u8, sub: []const u8) ![]const u8 {
    var root_buf: [Dir.max_path_bytes]u8 = undefined;
    const len = try dir.realPath(io, &root_buf);
    if (sub.len == 0) {
        @memcpy(buf[0..len], root_buf[0..len]);
        return buf[0..len];
    }
    return std.fmt.bufPrint(buf, "{s}/{s}", .{ root_buf[0..len], sub });
}

test "snapshot: a missing bin directory is empty, not an error" {
    const a = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [Dir.max_path_bytes]u8 = undefined;
    const path = try tSnapshotPath(tmp.dir, io, &buf, "absent");
    var snap = try snapshotBinDir(a, io, path);
    defer snap.deinit();
    try testing.expectEqual(@as(usize, 0), snap.entries.len);
}

test "snapshot: direct children are sorted and typed, symlinks not followed" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const a = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "zed", .data = "x" });
    try tmp.dir.writeFile(io, .{ .sub_path = "abe", .data = "x" });
    try tmp.dir.createDirPath(io, "mid");
    // A dangling symlink must still be reported, and never resolved.
    try tmp.dir.symLink(io, "/nonexistent/target", "linky", .{});
    // A child directory that would fail to open if we descended into it.
    try tmp.dir.createDirPath(io, "mid/deeper");

    var buf: [Dir.max_path_bytes]u8 = undefined;
    const path = try tSnapshotPath(tmp.dir, io, &buf, "");
    var snap = try snapshotBinDir(a, io, path);
    defer snap.deinit();

    try testing.expectEqual(@as(usize, 4), snap.entries.len);
    try testing.expectEqualStrings("abe", snap.entries[0].name);
    try testing.expectEqualStrings("linky", snap.entries[1].name);
    try testing.expectEqualStrings("mid", snap.entries[2].name);
    try testing.expectEqualStrings("zed", snap.entries[3].name);
    try testing.expectEqual(EntryKind.file, snap.entries[0].kind);
    try testing.expectEqual(EntryKind.sym_link, snap.entries[1].kind);
    try testing.expectEqual(EntryKind.directory, snap.entries[2].kind);
}

test "snapshot: a non-directory bin path fails closed" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const a = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "notadir", .data = "x" });
    var buf: [Dir.max_path_bytes]u8 = undefined;
    const path = try tSnapshotPath(tmp.dir, io, &buf, "notadir");
    try testing.expectError(error.NotDir, snapshotBinDir(a, io, path));
}

test "snapshot: a symlinked bin root is a trusted anchor" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const a = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "real");
    try tmp.dir.writeFile(io, .{ .sub_path = "real/tool", .data = "x" });
    var root_buf: [Dir.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &root_buf);
    var target_buf: [Dir.max_path_bytes]u8 = undefined;
    const target = try std.fmt.bufPrint(&target_buf, "{s}/real", .{root_buf[0..root_len]});
    try tmp.dir.symLink(io, target, "bin", .{});

    var buf: [Dir.max_path_bytes]u8 = undefined;
    const path = try tSnapshotPath(tmp.dir, io, &buf, "bin");
    var snap = try snapshotBinDir(a, io, path);
    defer snap.deinit();
    try testing.expectEqual(@as(usize, 1), snap.entries.len);
    try testing.expectEqualStrings("tool", snap.entries[0].name);
}

// --- allocation failure -----------------------------------------------------

fn tPlanUnderOom(allocator: Allocator) anyerror!void {
    var inv_cmds = [_]install_state.OwnedCommand{
        tOwned("keep", "bin/keep", "native"),
        tOwned("gone", "pkg/gone.wasm", "wasm"),
    };
    var records = [_]install_state.InventoryRecord{tRecord("demo/tool", &inv_cmds)};
    const snapshot = [_]SnapshotEntry{.{ .name = "unrelated", .kind = .file }};
    const units = [_]Unit{
        .{
            .id = "demo/tool",
            .commands = &.{ tNative("bin/keep"), tWasm("pkg/mod.wasm") },
            .aliases = &.{.{ .source = "mod", .published = "modx" }},
        },
        .{ .id = "other/thing", .commands = &.{tNative("bin/thing")} },
    };
    var p = try plan(allocator, &units, tInventory(&records), &snapshot, .{ .platform = .windows });
    defer p.deinit();
    try testing.expectEqual(@as(usize, 3), p.commands.len);
    try testing.expectEqual(@as(usize, 1), p.stale.len);
    try testing.expectEqualStrings("gone", p.stale[0].name);
}

test "plan construction frees all allocations under induced OOM" {
    try testing.checkAllAllocationFailures(testing.allocator, tPlanUnderOom, .{});
}

fn tSnapshotUnderOom(allocator: Allocator, path: []const u8) anyerror!void {
    var snap = try snapshotBinDir(allocator, testing.io, path);
    defer snap.deinit();
    try testing.expectEqual(@as(usize, 2), snap.entries.len);
}

test "snapshot ownership survives induced OOM" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "one", .data = "x" });
    try tmp.dir.writeFile(io, .{ .sub_path = "two", .data = "x" });
    var buf: [Dir.max_path_bytes]u8 = undefined;
    const path = try tSnapshotPath(tmp.dir, io, &buf, "");
    try testing.checkAllAllocationFailures(testing.allocator, tSnapshotUnderOom, .{path});
}
