//! v2 install-metadata writer (PR 5).
//!
//! `install_state.zig` reads and classifies metadata; this module is the only
//! place that produces it. Keeping the writer separate preserves the reader's
//! "never mutates" property while letting both share one set of validators, so
//! the two cannot drift: every record this module emits is validated against
//! the reader's public predicates BEFORE any byte reaches the filesystem, and
//! the round-trip is covered by tests that write with this module and read with
//! `install_state.scan`.
//!
//! Dependency direction stays acyclic: this imports `install_state` (and
//! through it `install_request`); neither imports this file.
//!
//! Three rules are load-bearing:
//!
//!   * `commands[].name` is the EXACT final published name. The writer never
//!     normalizes, strips, or re-derives it.
//!   * `relative_target` is portable: components are joined with `/`, never the
//!     host separator, so a store written on Windows reads correctly from WSL.
//!   * Resolved provenance is non-sensitive. A `download_url` is persisted only
//!     when it is stable and credential-free; anything else is dropped in favor
//!     of repository/tag/asset/`api_asset_id`/digest identity. Auth headers,
//!     tokens, and signed query parameters are never accepted here at all.

const std = @import("std");
const install_state = @import("install_state.zig");

const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const Writer = Io.Writer;

pub const schema_version: i64 = 2;
pub const layout_generation: i64 = 2;

pub const SourceKind = install_state.SourceKind;
pub const Platform = install_state.Platform;

pub const Kind = enum {
    native,
    wasm,

    fn label(self: Kind) []const u8 {
        return switch (self) {
            .native => "native",
            .wasm => "wasm",
        };
    }
};

pub const Digest = struct {
    algorithm: []const u8,
    value: []const u8,
};

pub const Alias = struct {
    from: []const u8,
    to: []const u8,
};

/// Durable source intent. Never conflated with `Resolved`.
pub const Source = struct {
    kind: SourceKind,
    owner: ?[]const u8 = null,
    repo: ?[]const u8 = null,
    tag: ?[]const u8 = null,
    asset_selector: ?[]const u8 = null,
    url: ?[]const u8 = null,
};

/// Effective verification policy for the install, recorded so a later upgrade
/// can reproduce the same gates. Written as a flat object; the reader accepts
/// any bounded-depth object here.
pub const VerificationPolicy = struct {
    skip_verify: bool = false,
    skip_checksum: bool = false,
    skip_minisign: bool = false,
    skip_sigstore: bool = false,
    skip_attestation: bool = false,
    skip_authenticode: bool = false,
};

pub const Config = struct {
    aliases: []const Alias = &.{},
    /// Commands explicitly selected by `--bin`, in request order. Null when the
    /// install published everything it discovered.
    selected_commands: ?[]const []const u8 = null,
    /// Effective minisign key required for this install (per-request key, or
    /// the command-level default when the request had none).
    minisign: ?[]const u8 = null,
    verification_policy: ?VerificationPolicy = null,
};

/// Provenance of one completed install. Every field is optional because a
/// generic URL and a GitHub release describe an artifact differently; the
/// required minimum per source kind is enforced in `validate`.
pub const Resolved = struct {
    tag: ?[]const u8 = null,
    asset: ?[]const u8 = null,
    api_asset_id: ?i64 = null,
    download_url: ?[]const u8 = null,
    digest: ?Digest = null,
};

pub const Command = struct {
    /// Exact final published name. Never re-derived.
    name: []const u8,
    /// Discovered name before aliasing, when it differs or is worth recording.
    source_name: ?[]const u8 = null,
    /// Unit-relative, portable (forward-slash) path of the executable.
    relative_target: []const u8,
    kind: Kind,
};

pub const Verification = struct {
    /// Strongest successful outcome label, e.g. `checksum`, `minisign`,
    /// `github-attestation`, `none`, `skipped`.
    result: []const u8,
    /// Key the install actually verified against, when minisign succeeded.
    minisign: ?[]const u8 = null,
};

pub const Metadata = struct {
    id: []const u8,
    source: Source,
    config: Config = .{},
    resolved: Resolved = .{},
    commands: []const Command = &.{},
    apps: []const []const u8 = &.{},
    verification: Verification,
};

pub const ValidateError = error{
    InvalidId,
    InvalidSource,
    InvalidConfig,
    InvalidResolved,
    InvalidCommand,
    InvalidApps,
    InvalidVerification,
    UnsafeCommandName,
    UnsafeRelativeTarget,
    CredentialUrl,
    DuplicateCommand,
    CommandKindMismatch,
};

pub const Error = ValidateError || Allocator.Error;

/// Reject a `download_url` that is not safe to persist. Callers should use this
/// to decide whether to record the URL at all instead of handing an unsafe URL
/// to the writer and getting a hard failure.
pub fn isPersistableUrl(url: []const u8) bool {
    return install_state.isSafeNonCredentialUrl(url);
}

/// Normalize a host-separator relative path into the portable forward-slash
/// form persisted in v2 metadata. The caller owns the result.
pub fn portableRelPath(allocator: Allocator, raw: []const u8) Allocator.Error![]u8 {
    const out = try allocator.dupe(u8, raw);
    for (out) |*c| {
        if (c.* == '\\') c.* = '/';
    }
    return out;
}

/// Validate a record against exactly the rules `install_state` enforces when
/// reading, so a written unit is never classified `corrupt` by its own writer.
/// Runs before any filesystem work.
pub fn validate(allocator: Allocator, meta: Metadata, platform: Platform) Error!void {
    if (!try install_state.isCanonicalId(allocator, meta.id)) return error.InvalidId;

    switch (meta.source.kind) {
        .github => {
            const owner = meta.source.owner orelse return error.InvalidSource;
            const repo = meta.source.repo orelse return error.InvalidSource;
            if (!install_state.isSafeGithubSegment(owner)) return error.InvalidSource;
            if (!install_state.isSafeGithubSegment(repo)) return error.InvalidSource;
            if (meta.source.url != null) return error.InvalidSource;
        },
        .generic_url => {
            const url = meta.source.url orelse return error.InvalidSource;
            if (!install_state.isSafeNonCredentialUrl(url)) return error.CredentialUrl;
            if (meta.source.owner != null or meta.source.repo != null) return error.InvalidSource;
        },
    }
    if (meta.source.tag) |v| if (!install_state.isBoundedMetaString(v)) return error.InvalidSource;
    if (meta.source.asset_selector) |v| {
        if (!install_state.isBoundedMetaString(v)) return error.InvalidSource;
    }

    var arena_inst = std.heap.ArenaAllocator.init(allocator);
    defer arena_inst.deinit();
    const scratch = arena_inst.allocator();

    var published: std.StringHashMapUnmanaged(void) = .empty;
    var avail: std.StringHashMapUnmanaged(void) = .empty;
    for (meta.commands) |cmd| {
        if (!install_state.isSafeV2CommandName(cmd.name)) return error.UnsafeCommandName;
        if (!install_state.isSafePortableRelPath(cmd.relative_target))
            return error.UnsafeRelativeTarget;
        if (install_state.isWasmTarget(cmd.relative_target) != (cmd.kind == .wasm))
            return error.CommandKindMismatch;
        if (cmd.source_name) |sn| {
            if (!install_state.isSafeV2CommandName(sn)) return error.InvalidCommand;
        }
        const pk = try install_state.conflictKey(scratch, cmd.name, platform);
        if ((try published.getOrPut(scratch, pk)).found_existing) return error.DuplicateCommand;
        try avail.put(scratch, pk, {});
        if (cmd.source_name) |sn| {
            const sk = try install_state.conflictKey(scratch, sn, platform);
            try avail.put(scratch, sk, {});
        }
    }

    var alias_from: std.StringHashMapUnmanaged(void) = .empty;
    var alias_to: std.StringHashMapUnmanaged(void) = .empty;
    for (meta.config.aliases) |a| {
        if (!install_state.isSafeV2CommandName(a.from)) return error.InvalidConfig;
        if (!install_state.isSafeV2CommandName(a.to)) return error.InvalidConfig;
        const fk = try install_state.conflictKey(scratch, a.from, platform);
        if ((try alias_from.getOrPut(scratch, fk)).found_existing) return error.InvalidConfig;
        const tk = try install_state.conflictKey(scratch, a.to, platform);
        if ((try alias_to.getOrPut(scratch, tk)).found_existing) return error.InvalidConfig;
        if (!avail.contains(fk)) return error.InvalidConfig;
        if (!published.contains(tk)) return error.InvalidConfig;
    }
    if (meta.config.selected_commands) |sel| {
        var seen: std.StringHashMapUnmanaged(void) = .empty;
        for (sel) |c| {
            if (!install_state.isSafeV2CommandName(c)) return error.InvalidConfig;
            const k = try install_state.conflictKey(scratch, c, platform);
            if ((try seen.getOrPut(scratch, k)).found_existing) return error.InvalidConfig;
            if (!avail.contains(k)) return error.InvalidConfig;
        }
    }
    if (meta.config.minisign) |m| {
        if (!looksLikeMinisignKey(m)) return error.InvalidConfig;
    }

    if (meta.resolved.tag) |v| if (!install_state.isBoundedMetaString(v)) return error.InvalidResolved;
    if (meta.resolved.asset) |v| if (!install_state.isBoundedMetaString(v)) return error.InvalidResolved;
    if (meta.resolved.api_asset_id) |v| if (v <= 0) return error.InvalidResolved;
    if (meta.resolved.download_url) |u| {
        if (!install_state.isSafeNonCredentialUrl(u)) return error.CredentialUrl;
    }
    if (meta.resolved.digest) |dg| {
        if (dg.algorithm.len == 0 or dg.algorithm.len > 32) return error.InvalidResolved;
        if (dg.value.len == 0 or dg.value.len > 512) return error.InvalidResolved;
        if (!install_state.isBoundedMetaString(dg.algorithm)) return error.InvalidResolved;
        if (!install_state.isBoundedMetaString(dg.value)) return error.InvalidResolved;
    }
    switch (meta.source.kind) {
        .github => {
            if (meta.resolved.tag == null or meta.resolved.asset == null)
                return error.InvalidResolved;
        },
        .generic_url => {
            if (meta.resolved.download_url == null) return error.InvalidResolved;
            if (meta.resolved.asset == null and meta.resolved.digest == null)
                return error.InvalidResolved;
        },
    }

    for (meta.apps) |a| {
        if (!install_state.isSafePortableRelPath(a)) return error.InvalidApps;
    }

    if (!install_state.isBoundedMetaString(meta.verification.result))
        return error.InvalidVerification;
    if (meta.verification.minisign) |m| {
        if (!looksLikeMinisignKey(m)) return error.InvalidVerification;
    }
}

/// `minisign.looksLikePubKey` without importing the minisign module: the reader
/// applies the real check, and this writer only needs to refuse material that
/// obviously cannot round-trip.
fn looksLikeMinisignKey(key: []const u8) bool {
    return @import("minisign.zig").looksLikePubKey(key);
}

/// Serialize a validated record. Field order is fixed so two identical installs
/// produce byte-identical metadata.
pub fn stringify(allocator: Allocator, meta: Metadata, platform: Platform) Error![]u8 {
    try validate(allocator, meta, platform);

    var alloc_writer: Writer.Allocating = .init(allocator);
    errdefer alloc_writer.deinit();
    const w = &alloc_writer.writer;

    render(w, meta) catch |err| switch (err) {
        error.WriteFailed => return error.OutOfMemory,
    };

    var list = alloc_writer.toArrayList();
    return list.toOwnedSlice(allocator);
}

fn render(w: *Writer, meta: Metadata) Writer.Error!void {
    try w.print("{{\n", .{});
    try w.print("  \"schema\": {d},\n", .{schema_version});
    try w.print("  \"layout_generation\": {d},\n", .{layout_generation});
    try w.writeAll("  \"id\": ");
    try writeJsonString(w, meta.id);
    try w.writeAll(",\n");

    // source (durable intent)
    try w.writeAll("  \"source\": {\"kind\": ");
    try writeJsonString(w, switch (meta.source.kind) {
        .github => "github",
        .generic_url => "generic_url",
    });
    try writeOptField(w, "owner", meta.source.owner);
    try writeOptField(w, "repo", meta.source.repo);
    try writeOptField(w, "tag", meta.source.tag);
    try writeOptField(w, "asset_selector", meta.source.asset_selector);
    try writeOptField(w, "url", meta.source.url);
    try w.writeAll("},\n");

    // config (normalized)
    try w.writeAll("  \"config\": {\"aliases\": [");
    for (meta.config.aliases, 0..) |a, i| {
        if (i > 0) try w.writeAll(", ");
        try w.writeAll("{\"from\": ");
        try writeJsonString(w, a.from);
        try w.writeAll(", \"to\": ");
        try writeJsonString(w, a.to);
        try w.writeAll("}");
    }
    try w.writeAll("]");
    if (meta.config.selected_commands) |sel| {
        try w.writeAll(", \"selected_commands\": ");
        try writeJsonStringArray(w, sel);
    } else {
        try w.writeAll(", \"selected_commands\": null");
    }
    try writeOptField(w, "minisign", meta.config.minisign);
    if (meta.config.verification_policy) |p| {
        try w.print(
            ", \"verification_policy\": {{\"skip_verify\": {}, \"skip_checksum\": {}, \"skip_minisign\": {}, \"skip_sigstore\": {}, \"skip_attestation\": {}, \"skip_authenticode\": {}}}",
            .{
                p.skip_verify,
                p.skip_checksum,
                p.skip_minisign,
                p.skip_sigstore,
                p.skip_attestation,
                p.skip_authenticode,
            },
        );
    }
    try w.writeAll("},\n");

    // resolved (provenance)
    try w.writeAll("  \"resolved\": {");
    var wrote_resolved = false;
    if (meta.resolved.tag) |v| {
        try w.writeAll("\"tag\": ");
        try writeJsonString(w, v);
        wrote_resolved = true;
    }
    if (meta.resolved.asset) |v| {
        if (wrote_resolved) try w.writeAll(", ");
        try w.writeAll("\"asset\": ");
        try writeJsonString(w, v);
        wrote_resolved = true;
    }
    if (meta.resolved.api_asset_id) |v| {
        if (wrote_resolved) try w.writeAll(", ");
        try w.print("\"api_asset_id\": {d}", .{v});
        wrote_resolved = true;
    }
    if (meta.resolved.download_url) |v| {
        if (wrote_resolved) try w.writeAll(", ");
        try w.writeAll("\"download_url\": ");
        try writeJsonString(w, v);
        wrote_resolved = true;
    }
    if (meta.resolved.digest) |dg| {
        if (wrote_resolved) try w.writeAll(", ");
        try w.writeAll("\"digest\": {\"algorithm\": ");
        try writeJsonString(w, dg.algorithm);
        try w.writeAll(", \"value\": ");
        try writeJsonString(w, dg.value);
        try w.writeAll("}");
    }
    try w.writeAll("},\n");

    // commands (exact final ownership)
    try w.writeAll("  \"commands\": [");
    for (meta.commands, 0..) |c, i| {
        if (i > 0) try w.writeAll(", ");
        try w.writeAll("{\"name\": ");
        try writeJsonString(w, c.name);
        if (c.source_name) |sn| {
            try w.writeAll(", \"source_name\": ");
            try writeJsonString(w, sn);
        }
        try w.writeAll(", \"relative_target\": ");
        try writeJsonString(w, c.relative_target);
        try w.writeAll(", \"kind\": ");
        try writeJsonString(w, c.kind.label());
        try w.writeAll("}");
    }
    try w.writeAll("],\n");

    try w.writeAll("  \"apps\": ");
    try writeJsonStringArray(w, meta.apps);
    try w.writeAll(",\n");

    try w.writeAll("  \"verification\": {\"result\": ");
    try writeJsonString(w, meta.verification.result);
    try writeOptField(w, "minisign", meta.verification.minisign);
    try w.writeAll("},\n");

    // Legacy-compatible read-only hints. Their presence never authorizes an
    // older ghr to mutate this record; they exist so current diagnostics and
    // `ghr list` fallbacks can describe a v2 unit without a schema bump.
    try w.writeAll("  \"tag\": ");
    try writeJsonString(w, meta.resolved.tag orelse meta.source.tag orelse "");
    try w.writeAll(",\n  \"asset\": ");
    try writeJsonString(w, meta.resolved.asset orelse "");
    try w.writeAll(",\n  \"verified\": ");
    try writeJsonString(w, meta.verification.result);
    try w.writeAll(",\n  \"bins\": [");
    for (meta.commands, 0..) |c, i| {
        if (i > 0) try w.writeAll(", ");
        try writeJsonString(w, c.relative_target);
    }
    try w.writeAll("]\n}\n");
}

fn writeOptField(w: *Writer, name: []const u8, value: ?[]const u8) Writer.Error!void {
    const v = value orelse return;
    try w.print(", \"{s}\": ", .{name});
    try writeJsonString(w, v);
}

fn writeJsonStringArray(w: *Writer, items: []const []const u8) Writer.Error!void {
    try w.writeAll("[");
    for (items, 0..) |item, i| {
        if (i > 0) try w.writeAll(", ");
        try writeJsonString(w, item);
    }
    try w.writeAll("]");
}

/// Write a JSON string literal, escaping quotes, backslashes, and every ASCII
/// control byte (as `\u00XX`) so no metadata value can break the document.
pub fn writeJsonString(w: *Writer, s: []const u8) Writer.Error!void {
    try w.writeAll("\"");
    for (s) |c| {
        switch (c) {
            '"' => try w.writeAll("\\\""),
            '\\' => try w.writeAll("\\\\"),
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            '\t' => try w.writeAll("\\t"),
            0x08 => try w.writeAll("\\b"),
            0x0c => try w.writeAll("\\f"),
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

pub const WriteError = Error || Dir.WriteFileError || Io.File.OpenError || Io.File.WriteError;

/// Write `ghr.json` into an already-open unit directory. The record is
/// validated first, so a rejected record leaves the directory untouched.
pub fn writeUnitMetadata(
    allocator: Allocator,
    io: Io,
    unit_dir: Dir,
    meta: Metadata,
    platform: Platform,
) !void {
    const body = try stringify(allocator, meta, platform);
    defer allocator.free(body);
    var file = try unit_dir.createFile(io, install_state.metadata_file, .{});
    defer file.close(io);
    try file.writeStreamingAll(io, body);
    file.sync(io) catch {};
}

// ===========================================================================
// Tests
// ===========================================================================

const testing = std.testing;

fn tSampleGithub() Metadata {
    return .{
        .id = "cataggar/zig",
        .source = .{
            .kind = .github,
            .owner = "cataggar",
            .repo = "zig",
            .tag = "zigb-0.16.1",
        },
        .config = .{
            .aliases = &.{.{ .from = "zig", .to = "zigb" }},
            .verification_policy = .{},
        },
        .resolved = .{
            .tag = "zigb-0.16.1",
            .asset = "zig.tar.xz",
            .api_asset_id = 42,
            .download_url = "https://github.com/cataggar/zig/releases/download/zigb-0.16.1/zig.tar.xz",
            .digest = .{ .algorithm = "sha256", .value = "deadbeef" },
        },
        .commands = &.{.{
            .name = "zigb",
            .source_name = "zig",
            .relative_target = "bin/zig",
            .kind = .native,
        }},
        .apps = &.{},
        .verification = .{ .result = "checksum" },
    };
}

test "stringify produces reader-parseable v2 metadata" {
    const body = try stringify(testing.allocator, tSampleGithub(), .posix);
    defer testing.allocator.free(body);

    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, body, .{});
    defer parsed.deinit();
    try testing.expectEqual(@as(i64, 2), parsed.value.object.get("schema").?.integer);
    try testing.expectEqual(@as(i64, 2), parsed.value.object.get("layout_generation").?.integer);
    try testing.expectEqualStrings("cataggar/zig", parsed.value.object.get("id").?.string);
    try testing.expectEqualStrings(
        "zigb",
        parsed.value.object.get("commands").?.array.items[0].object.get("name").?.string,
    );
    // Legacy hints are present but are read-only.
    try testing.expectEqualStrings("zigb-0.16.1", parsed.value.object.get("tag").?.string);
}

test "stringify is deterministic" {
    const a = try stringify(testing.allocator, tSampleGithub(), .posix);
    defer testing.allocator.free(a);
    const b = try stringify(testing.allocator, tSampleGithub(), .posix);
    defer testing.allocator.free(b);
    try testing.expectEqualStrings(a, b);
}

test "writer refuses a credential-bearing download url" {
    var meta = tSampleGithub();
    meta.resolved.download_url =
        "https://objects.example.com/x.tgz?X-Amz-Signature=abc&X-Amz-Credential=k";
    try testing.expectError(error.CredentialUrl, stringify(testing.allocator, meta, .posix));
}

test "writer refuses a non-canonical id" {
    var meta = tSampleGithub();
    meta.id = "Cataggar/Zig";
    try testing.expectError(error.InvalidId, stringify(testing.allocator, meta, .posix));
}

test "writer refuses a host-separator relative target" {
    var meta = tSampleGithub();
    meta.commands = &.{.{ .name = "zig", .relative_target = "bin\\zig", .kind = .native }};
    meta.config = .{};
    try testing.expectError(error.UnsafeRelativeTarget, stringify(testing.allocator, meta, .posix));
}

test "writer refuses a command kind that disagrees with its target" {
    var meta = tSampleGithub();
    meta.commands = &.{.{ .name = "mod", .relative_target = "mod.wasm", .kind = .native }};
    meta.config = .{};
    try testing.expectError(error.CommandKindMismatch, stringify(testing.allocator, meta, .posix));
}

test "writer refuses an alias whose source is not a command" {
    var meta = tSampleGithub();
    meta.config = .{ .aliases = &.{.{ .from = "absent", .to = "zigb" }} };
    try testing.expectError(error.InvalidConfig, stringify(testing.allocator, meta, .posix));
}

test "writer refuses github provenance without tag and asset" {
    var meta = tSampleGithub();
    meta.resolved = .{ .download_url = "https://example.com/x" };
    try testing.expectError(error.InvalidResolved, stringify(testing.allocator, meta, .posix));
}

test "writer refuses generic-url provenance without a stable url" {
    const meta: Metadata = .{
        .id = "tool",
        .source = .{ .kind = .generic_url, .url = "https://example.com/tool.tgz" },
        .resolved = .{ .asset = "tool.tgz" },
        .commands = &.{.{ .name = "tool", .relative_target = "tool", .kind = .native }},
        .verification = .{ .result = "none" },
    };
    try testing.expectError(error.InvalidResolved, stringify(testing.allocator, meta, .posix));
}

test "writer escapes quotes and backslashes in metadata values" {
    var meta = tSampleGithub();
    meta.resolved.tag = "v1\"\\x";
    meta.source.tag = "v1\"\\x";
    const body = try stringify(testing.allocator, meta, .posix);
    defer testing.allocator.free(body);
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, body, .{});
    defer parsed.deinit();
    try testing.expectEqualStrings(
        "v1\"\\x",
        parsed.value.object.get("resolved").?.object.get("tag").?.string,
    );
}

test "writer refuses control characters in metadata values" {
    var meta = tSampleGithub();
    meta.resolved.tag = "v1\u{0001}";
    try testing.expectError(error.InvalidResolved, stringify(testing.allocator, meta, .posix));
}

test "portableRelPath rewrites host separators" {
    const p = try portableRelPath(testing.allocator, "bin\\sub\\tool.exe");
    defer testing.allocator.free(p);
    try testing.expectEqualStrings("bin/sub/tool.exe", p);
}

test "writeUnitMetadata round-trips through the inventory reader" {
    const tio = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const rel = try install_state.encodeRelPath(testing.allocator, "cataggar/zig");
    defer testing.allocator.free(rel);
    try tmp.dir.createDirPath(tio, rel);
    var unit_dir = try tmp.dir.openDir(tio, rel, .{});
    defer unit_dir.close(tio);
    try writeUnitMetadata(testing.allocator, tio, unit_dir, tSampleGithub(), .posix);

    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &path_buf);

    var inv = try install_state.scan(testing.allocator, tio, path_buf[0..base_len], .{ .platform = .posix });
    defer inv.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 1), inv.records.len);
    const rec = inv.records[0];
    try testing.expectEqual(install_state.Status.ok, rec.status);
    try testing.expectEqual(install_state.UnitKind.v2, rec.kind);
    try testing.expectEqualStrings("cataggar/zig", rec.id.?);
    try testing.expectEqual(@as(usize, 1), rec.commands.len);
    try testing.expectEqualStrings("zigb", rec.commands[0].name);
    try testing.expectEqualStrings("zig", rec.commands[0].source_name.?);
    try testing.expectEqualStrings("bin/zig", rec.commands[0].relative_target);
    try testing.expectEqualStrings("zigb-0.16.1", rec.resolved.?.tag.?);
    try testing.expectEqual(@as(i64, 42), rec.resolved.?.api_asset_id.?);
    try testing.expectEqualStrings("sha256", rec.resolved.?.digest.?.algorithm);
}

test "round-trip omits a signed redirect url and keeps asset identity" {
    const tio = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // The install resolved through a signed redirect; only non-sensitive
    // identity may be persisted.
    var meta = tSampleGithub();
    meta.resolved.download_url = null;
    meta.config.aliases = &.{};

    const rel = try install_state.encodeRelPath(testing.allocator, "cataggar/zig");
    defer testing.allocator.free(rel);
    try tmp.dir.createDirPath(tio, rel);
    var unit_dir = try tmp.dir.openDir(tio, rel, .{});
    defer unit_dir.close(tio);
    try writeUnitMetadata(testing.allocator, tio, unit_dir, meta, .posix);

    const body = try unit_dir.readFileAlloc(
        tio,
        install_state.metadata_file,
        testing.allocator,
        Io.Limit.limited(65536),
    );
    defer testing.allocator.free(body);
    try testing.expect(std.mem.indexOf(u8, body, "download_url") == null);
    try testing.expect(std.mem.indexOf(u8, body, "X-Amz") == null);
    try testing.expect(std.mem.indexOf(u8, body, "Authorization") == null);
    try testing.expect(std.mem.indexOf(u8, body, "api_asset_id") != null);

    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &path_buf);
    var inv = try install_state.scan(testing.allocator, tio, path_buf[0..base_len], .{ .platform = .posix });
    defer inv.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), inv.records.len);
    try testing.expectEqual(install_state.Status.ok, inv.records[0].status);
    try testing.expect(inv.records[0].resolved.?.download_url == null);
}

test "wasm command round-trips with its kind and exact published name" {
    const tio = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const meta: Metadata = .{
        .id = "example/tools/parser",
        .source = .{ .kind = .github, .owner = "example", .repo = "tools", .tag = "v1" },
        .resolved = .{ .tag = "v1", .asset = "parser.wasm" },
        .commands = &.{.{
            .name = "parser",
            .source_name = "parser",
            .relative_target = "parser.wasm",
            .kind = .wasm,
        }},
        .verification = .{ .result = "none" },
    };

    const rel = try install_state.encodeRelPath(testing.allocator, meta.id);
    defer testing.allocator.free(rel);
    try tmp.dir.createDirPath(tio, rel);
    var unit_dir = try tmp.dir.openDir(tio, rel, .{});
    defer unit_dir.close(tio);
    try writeUnitMetadata(testing.allocator, tio, unit_dir, meta, .posix);

    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(tio, &path_buf);
    var inv = try install_state.scan(testing.allocator, tio, path_buf[0..base_len], .{ .platform = .posix });
    defer inv.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), inv.records.len);
    try testing.expectEqual(install_state.Status.ok, inv.records[0].status);
    try testing.expectEqualStrings("parser", inv.records[0].commands[0].name);
    try testing.expectEqualStrings("wasm", inv.records[0].commands[0].kind.?);
}

test "validate rejects OOM-free duplicate published commands" {
    var meta = tSampleGithub();
    meta.config = .{};
    meta.commands = &.{
        .{ .name = "dup", .relative_target = "a/dup", .kind = .native },
        .{ .name = "dup", .relative_target = "b/dup", .kind = .native },
    };
    try testing.expectError(error.DuplicateCommand, stringify(testing.allocator, meta, .posix));
}

test "stringify survives allocation failure without leaking" {
    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 1 });
    const result = stringify(failing.allocator(), tSampleGithub(), .posix);
    if (result) |body| {
        failing.allocator().free(body);
    } else |err| {
        try testing.expectEqual(error.OutOfMemory, err);
    }
}
