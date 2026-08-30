//! Read-only, schema-versioned install metadata and inventory reader (PR 3).
//!
//! This module is intentionally INACTIVE: nothing in the running `ghr` binary
//! calls `scan`. It exists so a later activation PR can enumerate installed
//! units by canonical ID, classify their state, and refuse mutation on
//! conflicting/corrupt/unsupported records. Because it is a reader, every code
//! path here fails CLOSED: genuine I/O, permission, and traversal errors
//! propagate; only an actually-missing tool store / v2 root / unit metadata is
//! treated as absence. Symlinks are never followed. Nothing on disk is mutated.
//!
//! Dependency direction is acyclic. This module imports `install_request`
//! (canonical ID rules from PR 2) and `release` (wasm asset detection); neither
//! imports this file. It deliberately does NOT import `install.zig` to avoid
//! coupling the reader to the writer; the legacy `ghr.json` wire shape is
//! redefined locally and tested against the current on-disk format.
//!
//! ## ID path encoding
//!
//! v2 units live under a dedicated, versioned namespace:
//!
//!     <tools>/_v2/units/u-<seg1>/u-<seg2>/.../u-<segN>/_unit/ghr.json
//!
//! Every canonical-ID segment `segK` is stored as its own directory named
//! `u-<segK>`. The constant `u-` prefix makes the encoding injective and
//! reversible (decoding strips exactly the prefix) and neutralizes Windows
//! reserved device names (`con`, `nul`, ...) because no encoded directory can
//! equal a bare device name. The terminal `_unit` marker directory holds the
//! metadata; using a marker lets prefix-related IDs coexist as parent/child
//! directories -- e.g. `a` (at `.../u-a/_unit`) and `a/b` (at
//! `.../u-a/u-b/_unit`) are both representable. Raw IDs are never interpolated
//! directly as a path component. Canonical IDs are already lowercase ASCII with
//! a bounded, safe character set (see `install_request.canonicalizeId`), so the
//! encoding cannot inject separators, `.`/`..`, trailing dot/space, or
//! case-folding collisions. A full-path preflight (`encodeUnitPath`) returns
//! `error.PathTooLong` for IDs that would not fit the platform path limit.

const std = @import("std");
const builtin = @import("builtin");
const install_request = @import("install_request.zig");
const release = @import("release.zig");
const minisign = @import("minisign.zig");

const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;
const Allocator = std.mem.Allocator;

/// Canonical-ID limits are reused from PR 2 so the two modules cannot drift.
pub const max_id_bytes = install_request.max_id_bytes;
pub const max_id_segment_bytes = install_request.max_id_segment_bytes;

pub const v2_namespace = "_v2";
pub const v2_units_dir = "units";
pub const segment_prefix = "u-";
pub const unit_marker = "_unit";
pub const metadata_file = "ghr.json";

/// Metadata files above this size are treated as corrupt rather than read into
/// memory. Matches the limit the current writer/reader use for `ghr.json`.
pub const max_metadata_bytes: usize = 65536;

/// Upper bound on the tools-relative encoded unit path. The absolute-path
/// preflight in `encodeUnitPath` is authoritative; this guards the relative
/// form on its own.
pub const max_encoded_relative_bytes: usize = 1024;

/// Extra bytes reserved beyond the `<unit>/ghr.json` path when preflighting a
/// full absolute path: room for the metadata filename plus a sibling
/// transaction directory suffix (`.old` / `.<name>.staging`).
pub const path_headroom_bytes: usize = 32;

/// Hard bound on the number of encoded id segments (directory depth) the
/// inventory traversal will descend before declaring a branch too long. A
/// canonical id is at most `max_id_bytes` and each segment is >= 1 byte plus a
/// separator, so no valid unit can exceed this; the bound exists to stop
/// unbounded recursion on marker-free deep chains.
pub const max_unit_segments: usize = max_id_bytes;

/// Maximum JSON nesting depth allowed for a retained `verification_policy`
/// object. Well below Zig's `Stringify` internal 256-depth assertion so a
/// hostile deeply-nested policy is rejected as `invalid_config` rather than
/// crashing the serializer. Node/string counts are already bounded by
/// `max_metadata_bytes`.
pub const max_policy_depth: usize = 32;

/// Maximum length of a persisted v2 published/source command name. Shorter than
/// the generic portable-name bound so there is room to append shim/companion
/// suffixes (e.g. `.ghr`, `.exe`) when a later PR materializes commands.
pub const max_v2_command_bytes: usize = 240;

/// Path-style / command-name semantics of the store being inventoried. This is
/// explicit (not hardcoded to the host) because WSL will later inventory a
/// Windows store from Linux, where separators and command-name rules differ.
pub const Platform = enum { posix, windows };

pub const default_platform: Platform = if (builtin.os.tag == .windows) .windows else .posix;

pub const ScanOptions = struct {
    platform: Platform = default_platform,
};

fn pathLimit(platform: Platform) usize {
    return switch (platform) {
        .windows => 259,
        .posix => 4096,
    };
}

// ---------------------------------------------------------------------------
// Validators (all allocation-free)
// ---------------------------------------------------------------------------

/// A canonical ID segment: lowercase ASCII, alphanumeric edges, inner set
/// `[a-z0-9._-]`, not `.`/`..`, bounded length. Stricter than
/// `install_request`'s internal check because it also rejects uppercase (the
/// encoding must never accept a non-canonical, case-colliding form).
fn isCanonicalIdSegment(segment: []const u8) bool {
    if (segment.len == 0 or segment.len > max_id_segment_bytes) return false;
    if (std.mem.eql(u8, segment, ".") or std.mem.eql(u8, segment, "..")) return false;
    if (!isLowerAlnum(segment[0]) or !isLowerAlnum(segment[segment.len - 1])) return false;
    for (segment) |c| {
        if (c >= 0x80) return false;
        if (std.ascii.isUpper(c)) return false;
        if (!(isLowerAlnum(c) or c == '.' or c == '_' or c == '-')) return false;
    }
    return true;
}

fn isLowerAlnum(c: u8) bool {
    return (c >= 'a' and c <= 'z') or (c >= '0' and c <= '9');
}

/// A GitHub owner/repo path component: bounded, alphanumeric edges, inner set
/// `[A-Za-z0-9._-]`. Case is preserved (GitHub identifiers are not lowercased).
fn isSafeGithubSegment(segment: []const u8) bool {
    if (segment.len == 0 or segment.len > 100) return false;
    if (std.mem.eql(u8, segment, ".") or std.mem.eql(u8, segment, "..")) return false;
    if (!std.ascii.isAlphanumeric(segment[0]) or !std.ascii.isAlphanumeric(segment[segment.len - 1]))
        return false;
    for (segment) |c| {
        if (c >= 0x80) return false;
        if (!(std.ascii.isAlphanumeric(c) or c == '.' or c == '_' or c == '-')) return false;
    }
    return true;
}

/// A Windows reserved device name (case-insensitive), checked against the stem
/// before the first `.`. These names are unusable as files/dirs on Windows and
/// must never appear as a portable command or path component.
fn isReservedDeviceName(stem: []const u8) bool {
    const three = [_][]const u8{ "con", "prn", "aux", "nul" };
    for (three) |name| if (std.ascii.eqlIgnoreCase(stem, name)) return true;
    if (stem.len == 4 and (std.ascii.startsWithIgnoreCase(stem, "com") or
        std.ascii.startsWithIgnoreCase(stem, "lpt")))
    {
        const d = stem[3];
        if (d >= '1' and d <= '9') return true;
    }
    return false;
}

/// A portable, safe single path/name component valid on Windows, macOS and
/// Linux: no control chars, no `<>:"/\|?*`, no trailing dot/space, not `.`/`..`,
/// not a reserved device name, bounded length. Used for command names and every
/// component of a portable relative target.
fn isSafePortableName(name: []const u8) bool {
    if (name.len == 0 or name.len > 255) return false;
    if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return false;
    for (name) |c| {
        if (c < 0x20) return false;
        switch (c) {
            '<', '>', ':', '"', '/', '\\', '|', '?', '*' => return false,
            else => {},
        }
    }
    const last = name[name.len - 1];
    if (last == '.' or last == ' ') return false;
    const dot = std.mem.indexOfScalar(u8, name, '.') orelse name.len;
    if (isReservedDeviceName(name[0..dot])) return false;
    return true;
}

fn isSafeCommandName(name: []const u8) bool {
    return isSafePortableName(name);
}

/// A portable relative path (v2 `relative_target`, `apps`): forward-slash
/// separated, no absolute/drive/UNC prefix, every component portable-safe.
fn isSafePortableRelPath(path: []const u8) bool {
    if (path.len == 0) return false;
    if (path[0] == '/' or path[0] == '\\') return false;
    if (path.len >= 2 and std.ascii.isAlphabetic(path[0]) and path[1] == ':') return false;
    var it = std.mem.splitScalar(u8, path, '/');
    var any = false;
    while (it.next()) |comp| {
        if (!isSafePortableName(comp)) return false;
        any = true;
    }
    return any;
}

fn isSep(platform: Platform, c: u8) bool {
    return c == '/' or (platform == .windows and c == '\\');
}

/// A legacy (v1 `bins`/`apps`) relative path. Accepts the install platform's
/// separator but rejects absolute/drive/UNC/control/empty/`.`/`..`/traversal and
/// cross-platform separator escapes (a backslash on POSIX).
fn isSafeLegacyRelPath(path: []const u8, platform: Platform) bool {
    if (path.len == 0) return false;
    if (path[0] == '/') return false;
    if (platform == .windows) {
        if (path[0] == '\\') return false;
        if (path.len >= 2 and std.ascii.isAlphabetic(path[0]) and path[1] == ':') return false;
    } else {
        if (std.mem.indexOfScalar(u8, path, '\\') != null) return false;
    }
    var start: usize = 0;
    var i: usize = 0;
    var any = false;
    while (i <= path.len) : (i += 1) {
        if (i == path.len or isSep(platform, path[i])) {
            const comp = path[start..i];
            if (comp.len == 0) return false;
            if (std.mem.eql(u8, comp, ".") or std.mem.eql(u8, comp, "..")) return false;
            for (comp) |c| {
                if (c < 0x20) return false;
                if (platform == .windows) switch (c) {
                    '<', '>', ':', '"', '|', '?', '*' => return false,
                    else => {},
                };
            }
            if (platform == .windows and !isSafePortableName(comp)) return false;
            any = true;
            start = i + 1;
        }
    }
    return any;
}

fn isHexDigit(c: u8) bool {
    return (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
}

/// Every `%` in `s` must introduce a well-formed `%HH` escape (two hex digits).
/// Rejects a truncated or non-hex escape such as `%`, `%2`, or `%zz`.
fn hasValidPercentEscapes(s: []const u8) bool {
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        if (s[i] == '%') {
            if (i + 2 >= s.len) return false;
            if (!isHexDigit(s[i + 1]) or !isHexDigit(s[i + 2])) return false;
            i += 2;
        }
    }
    return true;
}

fn hexVal(c: u8) u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => 0,
    };
}

/// Percent-decode `s` into `out`. Assumes `hasValidPercentEscapes(s)` already
/// held. Returns the decoded slice, or null if it would not fit `out`.
fn percentDecode(s: []const u8, out: []u8) ?[]const u8 {
    var n: usize = 0;
    var i: usize = 0;
    while (i < s.len) {
        if (n >= out.len) return null;
        if (s[i] == '%' and i + 2 < s.len) {
            out[n] = (hexVal(s[i + 1]) << 4) | hexVal(s[i + 2]);
            i += 3;
        } else {
            out[n] = s[i];
            i += 1;
        }
        n += 1;
    }
    return out[0..n];
}

/// A valid ASCII DNS reg-name or IPv4 literal: dot-separated labels, each
/// `[A-Za-z0-9-]`, not edge-`-`, bounded. IPv4 (all-digit labels) is a subset.
fn isValidRegNameHost(host: []const u8) bool {
    if (host.len == 0 or host.len > 253) return false;
    var it = std.mem.splitScalar(u8, host, '.');
    var any = false;
    while (it.next()) |label| {
        if (label.len == 0 or label.len > 63) return false;
        if (label[0] == '-' or label[label.len - 1] == '-') return false;
        for (label) |c| {
            if (!(std.ascii.isAlphanumeric(c) or c == '-')) return false;
        }
        any = true;
    }
    return any;
}

/// A fully bracketed IPv6 literal `[...]`: inner is hex digits and `:` only,
/// with at least two colons (so `[::1]` and `[2001:db8::1]` pass). This is a
/// syntactic check sufficient to reject junk after the bracket at the caller.
fn isValidBracketedIpv6(authority_host: []const u8) bool {
    if (authority_host.len < 4) return false;
    if (authority_host[0] != '[' or authority_host[authority_host.len - 1] != ']') return false;
    const inner = authority_host[1 .. authority_host.len - 1];
    if (inner.len == 0) return false;
    var colons: usize = 0;
    for (inner) |c| {
        if (c == ':') {
            colons += 1;
            continue;
        }
        if (!isHexDigit(c)) return false;
    }
    return colons >= 2;
}

/// Query-parameter names (case-insensitive) that indicate a credential-bearing
/// or expiring signed URL. A URL carrying any of these must never be persisted
/// as durable provenance.
const credential_query_params = [_][]const u8{
    // AWS SigV2/SigV4
    "x-amz-signature",  "x-amz-credential", "x-amz-security-token", "x-amz-date",
    "x-amz-expires",    "x-amz-algorithm",  "awsaccesskeyid",       "signature",
    "expires",
    // Azure SAS
             "sig",              "se",                   "sp",
    "sv",               "sr",               "st",                   "skoid",
    "sktid",            "spr",
    // GCP signed URLs
                 "x-goog-signature",     "x-goog-credential",
    "x-goog-algorithm", "x-goog-date",      "x-goog-expires",       "googleaccessid",
    // Generic bearer/token style
    "token",            "access_token",     "authorization",        "apikey",
    "api_key",
};

/// True only for an `http`/`https` URL that is safe to persist as durable
/// provenance. Rather than trusting `std.Uri.parse`, this validates the full
/// authority by hand, because a URL string that a lenient parser accepts can
/// still smuggle credentials or ambiguity. Specifically it requires:
///   * no whitespace/control/non-ASCII byte anywhere;
///   * `http`/`https` scheme;
///   * no fragment (`#...`) at all (fragment can create fetch ambiguity);
///   * an authority with NO userinfo (`@`) and NO percent escape (which could
///     encode `@`, `/`, or `:` to bypass this check);
///   * a host that is a valid ASCII DNS/IPv4 reg-name OR a fully bracketed IPv6
///     literal with nothing but an optional `:port` after the `]`;
///   * an optional numeric port (digits only, bounded);
///   * every `%HH` escape in the path/query well-formed;
///   * no query parameter name (percent-decoded, case-insensitive) on the
///     credential/expiry denylist.
/// Applied to `source.url` and `resolved.download_url`.
fn isSafeNonCredentialUrl(url: []const u8) bool {
    if (url.len == 0 or url.len > 4096) return false;
    // Reject SP (0x20), all control bytes, DEL, and any non-ASCII byte outright.
    for (url) |c| if (c <= 0x20 or c >= 0x7f) return false;

    const sep = std.mem.indexOf(u8, url, "://") orelse return false;
    const scheme = url[0..sep];
    if (!std.ascii.eqlIgnoreCase(scheme, "http") and !std.ascii.eqlIgnoreCase(scheme, "https"))
        return false;
    const rest = url[sep + 3 ..];

    // A fragment anywhere is rejected (never part of the fetched artifact).
    if (std.mem.indexOfScalar(u8, rest, '#') != null) return false;

    // Authority ends at the first '/' or '?'.
    var auth_end: usize = rest.len;
    for (rest, 0..) |c, i| {
        if (c == '/' or c == '?') {
            auth_end = i;
            break;
        }
    }
    const authority = rest[0..auth_end];
    const after = rest[auth_end..];
    if (authority.len == 0) return false;

    // No userinfo, and no percent escape (which could hide '@', '/', ':').
    if (std.mem.indexOfScalar(u8, authority, '@') != null) return false;
    if (std.mem.indexOfScalar(u8, authority, '%') != null) return false;

    var port: []const u8 = "";
    if (authority[0] == '[') {
        const close = std.mem.indexOfScalar(u8, authority, ']') orelse return false;
        const host = authority[0 .. close + 1];
        if (!isValidBracketedIpv6(host)) return false;
        const remainder = authority[close + 1 ..];
        if (remainder.len > 0) {
            if (remainder[0] != ':') return false; // junk after the bracket
            port = remainder[1..];
        }
    } else {
        if (std.mem.indexOfScalar(u8, authority, '[') != null) return false;
        if (std.mem.indexOfScalar(u8, authority, ']') != null) return false;
        if (std.mem.lastIndexOfScalar(u8, authority, ':')) |ci| {
            if (!isValidRegNameHost(authority[0..ci])) return false;
            port = authority[ci + 1 ..];
        } else {
            if (!isValidRegNameHost(authority)) return false;
        }
    }
    if (port.len > 0) {
        if (port.len > 5) return false;
        for (port) |c| if (!std.ascii.isDigit(c)) return false;
    }

    // All percent escapes in the path/query must be well-formed.
    if (!hasValidPercentEscapes(after)) return false;

    // Query parameter names, percent-decoded before the denylist compare.
    if (std.mem.indexOfScalar(u8, after, '?')) |qi| {
        const query = after[qi + 1 ..];
        var it = std.mem.splitScalar(u8, query, '&');
        while (it.next()) |pair| {
            if (pair.len == 0) continue;
            const name_end = std.mem.indexOfScalar(u8, pair, '=') orelse pair.len;
            const name_enc = pair[0..name_end];
            var buf: [256]u8 = undefined;
            const name = percentDecode(name_enc, &buf) orelse name_enc;
            for (credential_query_params) |bad| {
                if (std.ascii.eqlIgnoreCase(name, bad)) return false;
            }
        }
    }
    return true;
}

/// A bounded, control-free metadata string (non-empty, <= 512 bytes, no ASCII
/// control or DEL). Used for durable-but-freeform fields (tags, selectors,
/// verification result/kind labels) that must not carry arbitrary bytes.
fn isBoundedMetaString(s: []const u8) bool {
    if (s.len == 0 or s.len > 512) return false;
    for (s) |c| if (c < 0x20 or c == 0x7f) return false;
    return true;
}

/// A persisted v2 published/source command name: portable-safe (as for any file
/// component) AND restricted to ASCII with a conservative length bound that
/// leaves room for shim/companion suffixes. ASCII-only avoids attempting
/// incomplete Unicode case folding for Windows case-insensitive collisions --
/// the store may be inventoried from a different platform (WSL), so the persisted
/// name must be comparable regardless of the scanning host.
fn isSafeV2CommandName(name: []const u8) bool {
    if (name.len == 0 or name.len > max_v2_command_bytes) return false;
    for (name) |c| if (c >= 0x80) return false;
    return isSafePortableName(name);
}

/// The derived (post-suffix) publishable command name must itself be safe. On
/// Windows the derived name gains a shim/companion path, so also enforce the
/// ASCII + bounded rule there; POSIX keeps the general portable-name rule.
fn isSafeDerivedCommandName(name: []const u8, platform: Platform) bool {
    if (!isSafeCommandName(name)) return false;
    if (platform == .windows) return isSafeV2CommandName(name);
    return true;
}

/// Enforce a maximum JSON nesting depth without native deep recursion beyond
/// `remaining` frames: descending into a child decrements `remaining`, and a
/// container at `remaining == 0` returns false. Scalars are always within depth.
fn jsonWithinDepth(v: std.json.Value, remaining: usize) bool {
    switch (v) {
        .object => |o| {
            if (remaining == 0) return false;
            var it = o.iterator();
            while (it.next()) |e| {
                if (!jsonWithinDepth(e.value_ptr.*, remaining - 1)) return false;
            }
        },
        .array => |arr| {
            if (remaining == 0) return false;
            for (arr.items) |item| {
                if (!jsonWithinDepth(item, remaining - 1)) return false;
            }
        },
        else => {},
    }
    return true;
}

// ---------------------------------------------------------------------------
// Canonical-ID <-> path encoding
// ---------------------------------------------------------------------------

pub const EncodeError = error{ IdEmpty, NonCanonicalId, PathTooLong } || Allocator.Error;
pub const DecodeError = error{ InvalidEncoding, NonCanonicalId, PathTooLong } || Allocator.Error;

/// Encode a canonical ID into its tools-relative unit path
/// (`_v2/units/u-<seg>/.../_unit`). Rejects a non-canonical ID and an encoding
/// that would exceed `max_encoded_relative_bytes`.
pub fn encodeRelPath(allocator: Allocator, id: []const u8) EncodeError![]u8 {
    if (id.len == 0) return error.IdEmpty;
    if (id.len > max_id_bytes) return error.PathTooLong;

    var list: std.ArrayListUnmanaged(u8) = .empty;
    errdefer list.deinit(allocator);

    try list.appendSlice(allocator, v2_namespace);
    try list.append(allocator, '/');
    try list.appendSlice(allocator, v2_units_dir);

    var it = std.mem.splitScalar(u8, id, '/');
    while (it.next()) |seg| {
        if (!isCanonicalIdSegment(seg)) return error.NonCanonicalId;
        try list.append(allocator, '/');
        try list.appendSlice(allocator, segment_prefix);
        try list.appendSlice(allocator, seg);
    }
    try list.append(allocator, '/');
    try list.appendSlice(allocator, unit_marker);

    if (list.items.len > max_encoded_relative_bytes) return error.PathTooLong;
    return list.toOwnedSlice(allocator);
}

/// Decode a tools-relative unit path back into its canonical ID. Enforces the
/// exact structure (`_v2/units/u-.../_unit`), rejects uppercase/non-canonical
/// segments, and applies the same length/roundtrip constraints as `encode`.
pub fn decodeRelPath(allocator: Allocator, rel: []const u8) DecodeError![]u8 {
    var it = std.mem.splitScalar(u8, rel, '/');
    const ns = it.next() orelse return error.InvalidEncoding;
    if (!std.mem.eql(u8, ns, v2_namespace)) return error.InvalidEncoding;
    const units = it.next() orelse return error.InvalidEncoding;
    if (!std.mem.eql(u8, units, v2_units_dir)) return error.InvalidEncoding;

    var tokens: std.ArrayListUnmanaged([]const u8) = .empty;
    defer tokens.deinit(allocator);
    while (it.next()) |t| try tokens.append(allocator, t);
    if (tokens.items.len < 2) return error.InvalidEncoding;
    if (!std.mem.eql(u8, tokens.items[tokens.items.len - 1], unit_marker))
        return error.InvalidEncoding;

    return decodeSegments(allocator, tokens.items[0 .. tokens.items.len - 1]);
}

/// Turn a list of encoded directory names (`u-<seg>`) into a validated
/// canonical ID. Shared by `decodeRelPath` and the inventory traversal.
fn decodeSegments(allocator: Allocator, encoded: []const []const u8) DecodeError![]u8 {
    if (encoded.len == 0) return error.InvalidEncoding;
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);
    for (encoded, 0..) |tok, i| {
        if (!std.mem.startsWith(u8, tok, segment_prefix)) return error.InvalidEncoding;
        const seg = tok[segment_prefix.len..];
        if (!isCanonicalIdSegment(seg)) return error.NonCanonicalId;
        if (i > 0) try out.append(allocator, '/');
        try out.appendSlice(allocator, seg);
    }
    if (out.items.len > max_id_bytes) return error.PathTooLong;

    // Roundtrip/canonical safety: the reconstructed ID must be exactly what
    // `canonicalizeId` accepts and returns unchanged.
    const id = try out.toOwnedSlice(allocator);
    errdefer allocator.free(id);
    const canon = install_request.canonicalizeId(allocator, id) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.NonCanonicalId,
    };
    defer allocator.free(canon);
    if (!std.mem.eql(u8, canon, id)) return error.NonCanonicalId;
    return id;
}

/// Preflight the FULL absolute unit path for a canonical ID under `tools_dir`.
/// Returns `error.PathTooLong` when the absolute `<unit>/ghr.json` path plus
/// transaction-directory headroom would exceed the platform path limit. On
/// success returns the owned absolute unit directory path.
pub fn encodeUnitPath(
    allocator: Allocator,
    tools_dir: []const u8,
    id: []const u8,
    platform: Platform,
) EncodeError![]u8 {
    const rel = try encodeRelPath(allocator, id);
    defer allocator.free(rel);

    const sep: u8 = if (platform == .windows) '\\' else '/';
    var list: std.ArrayListUnmanaged(u8) = .empty;
    errdefer list.deinit(allocator);
    try list.appendSlice(allocator, tools_dir);
    try list.append(allocator, sep);
    // Rewrite the portable '/' separators in `rel` to the platform separator.
    for (rel) |c| try list.append(allocator, if (c == '/') sep else c);

    // Budget: <unit>/ghr.json plus a sibling transaction suffix.
    const projected = list.items.len + 1 + metadata_file.len + path_headroom_bytes;
    if (projected > pathLimit(platform)) return error.PathTooLong;
    return list.toOwnedSlice(allocator);
}

// ---------------------------------------------------------------------------
// Wire structs (JSON shapes). All fields optional so validation -- not the JSON
// parser -- decides which are required, yielding precise diagnostic reasons.
// ---------------------------------------------------------------------------

const WireV1 = struct {
    tag: ?[]const u8 = null,
    asset: ?[]const u8 = null,
    verified: ?[]const u8 = null,
    minisign: ?[]const u8 = null,
    bins: ?[]const []const u8 = null,
    apps: ?[]const []const u8 = null,
};

const WireDigest = struct {
    algorithm: ?[]const u8 = null,
    value: ?[]const u8 = null,
};

const WireResolved = struct {
    tag: ?[]const u8 = null,
    asset: ?[]const u8 = null,
    api_asset_id: ?i64 = null,
    download_url: ?[]const u8 = null,
    digest: ?WireDigest = null,
};

const WireAlias = struct {
    from: ?[]const u8 = null,
    to: ?[]const u8 = null,
};

const WireConfig = struct {
    aliases: ?[]WireAlias = null,
    selected_commands: ?[]const []const u8 = null,
    minisign: ?[]const u8 = null,
    verification_policy: ?std.json.Value = null,
};

const WireSource = struct {
    kind: ?[]const u8 = null,
    owner: ?[]const u8 = null,
    repo: ?[]const u8 = null,
    tag: ?[]const u8 = null,
    asset_selector: ?[]const u8 = null,
    url: ?[]const u8 = null,
};

const WireCommand = struct {
    name: ?[]const u8 = null,
    source_name: ?[]const u8 = null,
    relative_target: ?[]const u8 = null,
    kind: ?[]const u8 = null,
};

const WireVerification = struct {
    result: ?[]const u8 = null,
    minisign: ?[]const u8 = null,
};

const WireV2 = struct {
    schema: ?i64 = null,
    layout_generation: ?i64 = null,
    id: ?[]const u8 = null,
    source: ?WireSource = null,
    config: ?WireConfig = null,
    resolved: ?WireResolved = null,
    commands: ?[]WireCommand = null,
    apps: ?[]const []const u8 = null,
    verification: ?WireVerification = null,
    // Read-only legacy hints; presence never authorizes downgrade mutation.
    tag: ?[]const u8 = null,
    asset: ?[]const u8 = null,
    verified: ?[]const u8 = null,
    bins: ?[]const []const u8 = null,
};

// ---------------------------------------------------------------------------
// Public classification enums
// ---------------------------------------------------------------------------

pub const Status = enum { ok, corrupt, unsupported, conflict };

pub const UnitKind = enum { v1_repo, v1_wasm, v2, unknown };

pub const SourceKind = enum { github, generic_url };

/// A precise reason paired with every non-trivial record. Exhaustive so callers
/// can branch on the exact failure mode instead of a generic "bad".
pub const RecordReason = enum {
    none,
    // Metadata read / structure
    missing_metadata,
    malformed_json,
    oversized_metadata,
    symlinked_path,
    // Schema/layout classification
    schema_null,
    schema_wrong_type,
    unsupported_schema,
    unsupported_layout,
    invalid_layout,
    wrong_layout,
    encoded_path_mismatch,
    malformed_encoding,
    not_a_directory,
    // Field validation
    missing_required_field,
    invalid_id,
    invalid_source,
    invalid_config,
    invalid_resolved,
    invalid_command,
    invalid_apps,
    invalid_verification,
    unsafe_relative_path,
    unsafe_command_name,
    credential_url,
    duplicate_command_internal,
    path_too_long,
    // Cross-record conflicts
    duplicate_id,
    duplicate_command,
};

const Judgment = struct {
    status: Status,
    reason: RecordReason,
};

fn ok() Judgment {
    return .{ .status = .ok, .reason = .none };
}
fn corrupt(reason: RecordReason) Judgment {
    return .{ .status = .corrupt, .reason = reason };
}
fn unsupported(reason: RecordReason) Judgment {
    return .{ .status = .unsupported, .reason = reason };
}

const SchemaClass = enum { v1, v2, unsupported, corrupt_null, corrupt_type, malformed };

/// Presence-aware schema probe on the parsed JSON tree. Missing `schema` alone
/// is v1; explicit `null`/wrong-type is corrupt; unknown numeric is unsupported.
fn classifySchema(root: std.json.Value) SchemaClass {
    if (root != .object) return .malformed;
    const sv = root.object.get("schema") orelse return .v1;
    return switch (sv) {
        .null => .corrupt_null,
        .integer => |n| if (n == 2) .v2 else .unsupported,
        .number_string => .unsupported, // out-of-i64-range numeric
        else => .corrupt_type,
    };
}

const LayoutClass = enum { ok, missing, wrong_type, unsupported };

/// Probe `layout_generation` directly from the raw root object, BEFORE parsing
/// the typed `WireV2`. This must happen first so a future layout that also
/// changes other field shapes is classified by its layout number rather than
/// failing typed parsing as `malformed_json`. Missing/wrong-type is corrupt;
/// a numeric other than 2 is an unsupported layout.
fn probeLayout(root: std.json.Value) LayoutClass {
    const lv = root.object.get("layout_generation") orelse return .missing;
    return switch (lv) {
        .integer => |n| if (n == 2) .ok else .unsupported,
        .number_string => .unsupported, // out-of-i64-range numeric
        else => .wrong_type,
    };
}

// ---------------------------------------------------------------------------
// Owned inventory data (deep copies of validated metadata)
// ---------------------------------------------------------------------------

fn freeOpt(allocator: Allocator, s: ?[]const u8) void {
    if (s) |v| allocator.free(v);
}

fn dupOpt(allocator: Allocator, s: ?[]const u8) Allocator.Error!?[]const u8 {
    return if (s) |v| try allocator.dupe(u8, v) else null;
}

/// Deep-copy `[]const []const u8`, freeing partial progress on failure.
fn dupStrings(allocator: Allocator, items: []const []const u8) Allocator.Error![][]const u8 {
    const out = try allocator.alloc([]const u8, items.len);
    var filled: usize = 0;
    errdefer {
        for (out[0..filled]) |s| allocator.free(s);
        allocator.free(out);
    }
    for (items, 0..) |s, i| {
        out[i] = try allocator.dupe(u8, s);
        filled = i + 1;
    }
    return out;
}

fn freeStrings(allocator: Allocator, items: [][]const u8) void {
    for (items) |s| allocator.free(s);
    allocator.free(items);
}

pub const OwnedDigest = struct {
    algorithm: []const u8,
    value: []const u8,
};

pub const OwnedSource = struct {
    kind: SourceKind,
    owner: ?[]const u8 = null,
    repo: ?[]const u8 = null,
    tag: ?[]const u8 = null,
    asset_selector: ?[]const u8 = null,
    url: ?[]const u8 = null,

    pub fn deinit(self: *OwnedSource, allocator: Allocator) void {
        freeOpt(allocator, self.owner);
        freeOpt(allocator, self.repo);
        freeOpt(allocator, self.tag);
        freeOpt(allocator, self.asset_selector);
        freeOpt(allocator, self.url);
    }
};

pub const OwnedAlias = struct {
    from: []const u8,
    to: []const u8,
};

pub const OwnedConfig = struct {
    aliases: []OwnedAlias = &.{},
    selected_commands: ?[][]const u8 = null,
    minisign: ?[]const u8 = null,
    /// Canonical JSON serialization of the retained verification policy object
    /// (in-memory retention only; this module never writes metadata). Null when
    /// the manifest had no policy.
    verification_policy_json: ?[]const u8 = null,

    pub fn deinit(self: *OwnedConfig, allocator: Allocator) void {
        for (self.aliases) |a| {
            allocator.free(a.from);
            allocator.free(a.to);
        }
        allocator.free(self.aliases);
        if (self.selected_commands) |sc| freeStrings(allocator, sc);
        freeOpt(allocator, self.minisign);
        freeOpt(allocator, self.verification_policy_json);
    }
};

pub const OwnedResolved = struct {
    tag: ?[]const u8 = null,
    asset: ?[]const u8 = null,
    api_asset_id: ?i64 = null,
    download_url: ?[]const u8 = null,
    digest: ?OwnedDigest = null,

    pub fn deinit(self: *OwnedResolved, allocator: Allocator) void {
        freeOpt(allocator, self.tag);
        freeOpt(allocator, self.asset);
        freeOpt(allocator, self.download_url);
        if (self.digest) |d| {
            allocator.free(d.algorithm);
            allocator.free(d.value);
        }
    }
};

pub const OwnedVerification = struct {
    result: ?[]const u8 = null,
    minisign: ?[]const u8 = null,

    pub fn deinit(self: *OwnedVerification, allocator: Allocator) void {
        freeOpt(allocator, self.result);
        freeOpt(allocator, self.minisign);
    }
};

pub const OwnedCommand = struct {
    /// Final logical name published on the inventory's target platform.
    name: []const u8,
    source_name: ?[]const u8 = null,
    relative_target: []const u8,
    kind: ?[]const u8 = null,

    pub fn deinit(self: *OwnedCommand, allocator: Allocator) void {
        allocator.free(self.name);
        freeOpt(allocator, self.source_name);
        allocator.free(self.relative_target);
        freeOpt(allocator, self.kind);
    }
};

/// One inventory unit. Owns every slice it references. Legacy (v1) records leave
/// v2-only facts null. Defaults are chosen so `deinit` is safe on a partially
/// constructed record (freeing a zero-length slice is a no-op).
pub const InventoryRecord = struct {
    kind: UnitKind,
    status: Status,
    reason: RecordReason,
    /// Tools-relative physical path of the unit (owned).
    path: []const u8,
    /// Canonical ID when it can be reliably determined (owned).
    id: ?[]const u8 = null,
    tag: ?[]const u8 = null,
    asset: ?[]const u8 = null,
    verified: ?[]const u8 = null,
    minisign: ?[]const u8 = null,
    commands: []OwnedCommand = &.{},
    apps: [][]const u8 = &.{},
    source: ?OwnedSource = null,
    config: ?OwnedConfig = null,
    resolved: ?OwnedResolved = null,
    verification: ?OwnedVerification = null,

    pub fn deinit(self: *InventoryRecord, allocator: Allocator) void {
        allocator.free(self.path);
        freeOpt(allocator, self.id);
        freeOpt(allocator, self.tag);
        freeOpt(allocator, self.asset);
        freeOpt(allocator, self.verified);
        freeOpt(allocator, self.minisign);
        for (self.commands) |*c| c.deinit(allocator);
        allocator.free(self.commands);
        for (self.apps) |a| allocator.free(a);
        allocator.free(self.apps);
        if (self.source) |*s| s.deinit(allocator);
        if (self.config) |*c| c.deinit(allocator);
        if (self.resolved) |*r| r.deinit(allocator);
        if (self.verification) |*v| v.deinit(allocator);
    }
};

pub const Inventory = struct {
    records: []InventoryRecord,

    pub fn deinit(self: *Inventory, allocator: Allocator) void {
        for (self.records) |*r| r.deinit(allocator);
        allocator.free(self.records);
    }
};

// ---------------------------------------------------------------------------
// Builder + record construction (single ownership transfer point per record)
// ---------------------------------------------------------------------------

const Builder = struct {
    allocator: Allocator,
    records: std.ArrayListUnmanaged(InventoryRecord) = .empty,
    platform: Platform,

    fn deinit(self: *Builder) void {
        for (self.records.items) |*r| r.deinit(self.allocator);
        self.records.deinit(self.allocator);
    }

    /// Append a diagnostic (corrupt/unsupported) record. `path`/`id_opt` are
    /// borrowed and deep-copied; every allocation here is covered by
    /// `rec.deinit` so a failed append frees the duplicated path and id.
    fn addDiagnostic(
        self: *Builder,
        kind: UnitKind,
        judgment: Judgment,
        path: []const u8,
        id_opt: ?[]const u8,
    ) Allocator.Error!void {
        const path_owned = try self.allocator.dupe(u8, path);
        var rec = InventoryRecord{
            .kind = kind,
            .status = judgment.status,
            .reason = judgment.reason,
            .path = path_owned,
        };
        errdefer rec.deinit(self.allocator);
        rec.id = try dupOpt(self.allocator, id_opt);
        try self.records.append(self.allocator, rec);
    }
};

// ---------------------------------------------------------------------------
// No-follow filesystem helpers (fail closed; never follow symlinks)
// ---------------------------------------------------------------------------

const OpenChild = union(enum) {
    opened: Dir,
    absent,
    symlinked,
    /// The name exists but is not a directory (e.g. a regular file where a
    /// structural directory was expected). Distinguished from `.absent` so
    /// structural nodes fail closed as corrupt rather than being treated as
    /// missing.
    wrong_type,
};

/// Open a child directory relative to `parent` WITHOUT following symlinks. Only
/// an actually-missing entry is `.absent`; a non-directory is `.wrong_type`; a
/// symlink is `.symlinked`; genuine permission/I/O errors propagate.
fn openChildDirNoFollow(io: Io, parent: Dir, name: []const u8) !OpenChild {
    const d = parent.openDir(io, name, .{ .iterate = true, .follow_symlinks = false }) catch |err|
        switch (err) {
            error.FileNotFound => return .absent,
            error.NotDir => return .wrong_type,
            error.SymLinkLoop => return .symlinked,
            else => return err,
        };
    return .{ .opened = d };
}

const ReadMeta = union(enum) {
    body: []u8, // owned
    absent,
    corrupt: RecordReason, // symlinked_path / oversized_metadata / malformed_json
};

/// Read `<dir>/ghr.json` WITHOUT following symlinks. Missing file -> `.absent`;
/// symlink/oversize/non-regular -> `.corrupt` with a precise reason; genuine
/// permission/I/O/read errors propagate; OOM propagates (never conflated with
/// absence).
fn readMetaNoFollow(allocator: Allocator, io: Io, dir: Dir) !ReadMeta {
    var file = dir.openFile(io, metadata_file, .{
        .follow_symlinks = false,
        .allow_directory = false,
    }) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return .absent,
        error.IsDir => return .{ .corrupt = .malformed_json },
        error.SymLinkLoop => return .{ .corrupt = .symlinked_path },
        else => return err,
    };
    defer file.close(io);

    const st = try file.stat(io);
    if (st.kind != .file) return .{ .corrupt = .symlinked_path };

    var buf: [4096]u8 = undefined;
    var fr = file.reader(io, &buf);
    const body = fr.interface.allocRemaining(allocator, Io.Limit.limited(max_metadata_bytes)) catch |err|
        switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.StreamTooLong => return .{ .corrupt = .oversized_metadata },
            error.ReadFailed => return fr.err orelse error.ReadFailed,
        };
    return .{ .body = body };
}

/// Only unambiguous hidden transaction directories are ignored:
/// `.<name>.staging` and `.<name>.old`. Visible `*.old` paths are not skipped
/// because `repo.old` and `module.old` are legal legacy install names.
fn isTransactionDir(name: []const u8) bool {
    return std.mem.startsWith(u8, name, ".") and
        (std.mem.endsWith(u8, name, ".staging") or std.mem.endsWith(u8, name, ".old"));
}

// ---------------------------------------------------------------------------
// Command-name derivation and conflict keys
// ---------------------------------------------------------------------------

/// Return the logical published command name as a slice of `raw` (no copy).
/// Mirrors the legacy publication suffix rules exactly: take the basename
/// (normalizing `/` and `\`); recognize wasm ONLY by the case-sensitive lower
/// `.wasm` rule that `release.isWasmAssetName` uses, and if wasm strip only
/// `.wasm` (never then `.exe`); otherwise, on Windows, strip a trailing `.exe`
/// case-insensitively. Case is otherwise preserved.
fn logicalCommandSlice(raw: []const u8, platform: Platform) []const u8 {
    var base = raw;
    if (std.mem.lastIndexOfScalar(u8, base, '/')) |i| base = base[i + 1 ..];
    if (std.mem.lastIndexOfScalar(u8, base, '\\')) |i| base = base[i + 1 ..];
    if (release.isWasmAssetName(base)) {
        base = base[0 .. base.len - ".wasm".len];
    } else if (platform == .windows and base.len >= 4 and std.ascii.endsWithIgnoreCase(base, ".exe")) {
        base = base[0 .. base.len - 4];
    }
    return base;
}

/// Owned copy of `logicalCommandSlice`. Caller owns the result.
fn logicalCommandName(allocator: Allocator, raw: []const u8, platform: Platform) Allocator.Error![]u8 {
    return allocator.dupe(u8, logicalCommandSlice(raw, platform));
}

/// Case-fold a logical command name into a conflict-comparison key. Windows
/// compares command names ASCII case-insensitively; POSIX is exact.
fn conflictKey(allocator: Allocator, name: []const u8, platform: Platform) Allocator.Error![]u8 {
    const out = try allocator.dupe(u8, name);
    if (platform == .windows) {
        for (out) |*c| c.* = std.ascii.toLower(c.*);
    }
    return out;
}

// ---------------------------------------------------------------------------
// v1 legacy validation + record construction
// ---------------------------------------------------------------------------

/// Validate a legacy v1 body (borrowed wire view). Requires `tag` and `asset`
/// like the current writer, every `bins`/`apps` path to be legacy-safe, and
/// every derived (post-`.wasm`/`.exe`) command name to be a safe portable name.
fn validateV1(wire: WireV1, platform: Platform) Judgment {
    if (wire.tag == null or wire.asset == null) return corrupt(.missing_required_field);
    if (wire.bins) |bins| for (bins) |b| {
        if (!isSafeLegacyRelPath(b, platform)) return corrupt(.unsafe_relative_path);
        // The derived (post-`.wasm`/`.exe`) published name must itself be safe;
        // on Windows it must also be ASCII + bounded for shim companions.
        if (!isSafeDerivedCommandName(logicalCommandSlice(b, platform), platform))
            return corrupt(.unsafe_command_name);
    };
    if (wire.apps) |apps| for (apps) |a| {
        if (!isSafeLegacyRelPath(a, platform)) return corrupt(.unsafe_relative_path);
    };
    return ok();
}

/// Build the owned commands for a v1 record from its (already validated) bins.
fn buildV1Commands(
    allocator: Allocator,
    bins: []const []const u8,
    platform: Platform,
) Allocator.Error![]OwnedCommand {
    const out = try allocator.alloc(OwnedCommand, bins.len);
    var filled: usize = 0;
    errdefer {
        for (out[0..filled]) |*c| c.deinit(allocator);
        allocator.free(out);
    }
    for (bins, 0..) |b, i| {
        const name = try logicalCommandName(allocator, b, platform);
        errdefer allocator.free(name);
        const target = try allocator.dupe(u8, b);
        errdefer allocator.free(target);
        const kind: ?[]const u8 = if (release.isWasmAssetName(b))
            try allocator.dupe(u8, "wasm")
        else
            null;
        out[i] = .{ .name = name, .source_name = null, .relative_target = target, .kind = kind };
        filled = i + 1;
    }
    return out;
}

/// Construct and append an OK v1 record. `path`/`id_opt` are borrowed and
/// deep-copied; a failed transfer frees every duplicated field via rec.deinit.
fn addV1Record(
    b: *Builder,
    kind: UnitKind,
    path: []const u8,
    id_opt: ?[]const u8,
    wire: WireV1,
    platform: Platform,
) Allocator.Error!void {
    const allocator = b.allocator;
    const path_owned = try allocator.dupe(u8, path);
    var rec = InventoryRecord{
        .kind = kind,
        .status = .ok,
        .reason = .none,
        .path = path_owned,
    };
    errdefer rec.deinit(allocator);

    rec.id = try dupOpt(allocator, id_opt);
    rec.tag = try dupOpt(allocator, wire.tag);
    rec.asset = try dupOpt(allocator, wire.asset);
    rec.verified = try dupOpt(allocator, wire.verified);
    rec.minisign = try dupOpt(allocator, wire.minisign);
    if (wire.bins) |bins| rec.commands = try buildV1Commands(allocator, bins, platform);
    if (wire.apps) |apps| rec.apps = try dupStrings(allocator, apps);

    try b.records.append(allocator, rec);
}

// ---------------------------------------------------------------------------
// v2 validation + record construction
// ---------------------------------------------------------------------------

fn parseSourceKind(kind: []const u8) ?SourceKind {
    if (std.mem.eql(u8, kind, "github")) return .github;
    if (std.mem.eql(u8, kind, "generic_url")) return .generic_url;
    return null;
}

/// Validate a v2 body (borrowed wire view) using presence-aware checks. Returns
/// an OK judgment only when every required concept is present and safe; never
/// fabricates missing concepts. A single short-lived arena owns every scratch
/// key/set, so any early corrupt return reclaims all scratch at once and cannot
/// leak. Command validation runs before config so alias/selected correspondence
/// can be checked against the record's actual command set.
fn validateV2(
    allocator: Allocator,
    wire: WireV2,
    platform: Platform,
) Allocator.Error!Judgment {
    // schema/layout
    if (wire.schema == null or wire.schema.? != 2) return corrupt(.missing_required_field);
    if (wire.layout_generation == null) return corrupt(.missing_required_field);
    if (wire.layout_generation.? != 2) return unsupported(.unsupported_layout);

    // canonical id
    const id = wire.id orelse return corrupt(.missing_required_field);
    if (!try isCanonicalIdInline(allocator, id)) return corrupt(.invalid_id);

    // source: kind-specific and mutually exclusive fields.
    const src = wire.source orelse return corrupt(.missing_required_field);
    const kind_str = src.kind orelse return corrupt(.invalid_source);
    const kind = parseSourceKind(kind_str) orelse return corrupt(.invalid_source);
    switch (kind) {
        .github => {
            const owner = src.owner orelse return corrupt(.invalid_source);
            const repo = src.repo orelse return corrupt(.invalid_source);
            if (!isSafeGithubSegment(owner) or !isSafeGithubSegment(repo))
                return corrupt(.invalid_source);
            // github must not also carry a generic url.
            if (src.url != null) return corrupt(.invalid_source);
        },
        .generic_url => {
            const url = src.url orelse return corrupt(.invalid_source);
            if (!isSafeNonCredentialUrl(url)) return corrupt(.credential_url);
            // generic_url must not also carry owner/repo.
            if (src.owner != null or src.repo != null) return corrupt(.invalid_source);
        },
    }
    if (src.tag) |v| if (!isBoundedMetaString(v)) return corrupt(.invalid_source);
    if (src.asset_selector) |v| if (!isBoundedMetaString(v)) return corrupt(.invalid_source);

    // One arena for all scratch sets/keys used below.
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const scratch = arena.allocator();

    // commands (may be empty; every entry safe; no internal duplicate published
    // command). Build the record's published-name set and the available
    // source-or-published-name set so config correspondence can be checked.
    var published: std.StringHashMapUnmanaged(void) = .empty; // logical published keys
    var avail: std.StringHashMapUnmanaged(void) = .empty; // published keys + source_name keys
    const commands = wire.commands orelse return corrupt(.missing_required_field);
    for (commands) |cmd| {
        const name = cmd.name orelse return corrupt(.invalid_command);
        const target = cmd.relative_target orelse return corrupt(.invalid_command);
        // Persisted published/source names are ASCII + bounded (Windows-safe,
        // room for companion suffixes) regardless of the scanning platform.
        if (!isSafeV2CommandName(name)) return corrupt(.unsafe_command_name);
        if (!isSafePortableRelPath(target)) return corrupt(.unsafe_relative_path);
        if (cmd.source_name) |sn| if (!isSafeV2CommandName(sn)) return corrupt(.invalid_command);
        if (cmd.kind) |k| if (!isBoundedMetaString(k)) return corrupt(.invalid_command);
        // The derived (post-suffix) published name must itself be safe.
        const logical = logicalCommandSlice(name, platform);
        if (!isSafeV2CommandName(logical)) return corrupt(.unsafe_command_name);
        const pk = try conflictKey(scratch, logical, platform);
        if ((try published.getOrPut(scratch, pk)).found_existing)
            return corrupt(.duplicate_command_internal);
        try avail.put(scratch, pk, {});
        if (cmd.source_name) |sn| {
            const sk = try conflictKey(scratch, sn, platform);
            try avail.put(scratch, sk, {});
        }
    }

    // config
    const cfg = wire.config orelse return corrupt(.missing_required_field);
    if (cfg.aliases) |aliases| {
        var froms: std.StringHashMapUnmanaged(void) = .empty;
        var tos: std.StringHashMapUnmanaged(void) = .empty;
        for (aliases) |a| {
            const from = a.from orelse return corrupt(.invalid_config);
            const to = a.to orelse return corrupt(.invalid_config);
            if (!isSafeV2CommandName(from) or !isSafeV2CommandName(to))
                return corrupt(.invalid_config);
            const fk = try conflictKey(scratch, from, platform);
            if ((try froms.getOrPut(scratch, fk)).found_existing) return corrupt(.invalid_config);
            const tk = try conflictKey(scratch, to, platform);
            if ((try tos.getOrPut(scratch, tk)).found_existing) return corrupt(.invalid_config);
            // `from` must name an available command (source or published); `to`
            // must be a resulting published command. Dangling => invalid_config.
            if (!avail.contains(fk)) return corrupt(.invalid_config);
            if (!published.contains(tk)) return corrupt(.invalid_config);
        }
    }
    if (cfg.selected_commands) |sc| {
        var seen_sel: std.StringHashMapUnmanaged(void) = .empty;
        for (sc) |c| {
            if (!isSafeV2CommandName(c)) return corrupt(.invalid_config);
            const k = try conflictKey(scratch, c, platform);
            if ((try seen_sel.getOrPut(scratch, k)).found_existing) return corrupt(.invalid_config);
            // A selected command must correspond to an available command.
            if (!avail.contains(k)) return corrupt(.invalid_config);
        }
    }
    if (cfg.minisign) |m| if (!minisign.looksLikePubKey(m)) return corrupt(.invalid_config);
    if (cfg.verification_policy) |vp| {
        if (vp != .object) return corrupt(.invalid_config);
        // Bound nesting depth well below Stringify's internal assertion so a
        // hostile deeply-nested policy is rejected, never crashed on.
        if (!jsonWithinDepth(vp, max_policy_depth)) return corrupt(.invalid_config);
    }

    // resolved (provenance must be non-sensitive). Validate present fields
    // first (so a credential url still reports `credential_url`), then require a
    // conservative minimum of non-sensitive identity for the artifact.
    const res = wire.resolved orelse return corrupt(.missing_required_field);
    if (res.tag) |v| if (!isBoundedMetaString(v)) return corrupt(.invalid_resolved);
    if (res.asset) |v| if (!isBoundedMetaString(v)) return corrupt(.invalid_resolved);
    if (res.api_asset_id) |aid| if (aid <= 0) return corrupt(.invalid_resolved);
    if (res.download_url) |url| {
        if (!isSafeNonCredentialUrl(url)) return corrupt(.credential_url);
    }
    if (res.digest) |d| {
        const alg = d.algorithm orelse return corrupt(.invalid_resolved);
        const val = d.value orelse return corrupt(.invalid_resolved);
        if (alg.len == 0 or alg.len > 32 or val.len == 0 or val.len > 512)
            return corrupt(.invalid_resolved);
    }
    switch (kind) {
        // GitHub: the completed artifact is described by its resolved tag+asset
        // (optionally a positive api id / stable url / digest already checked).
        .github => if (res.tag == null or res.asset == null) return corrupt(.invalid_resolved),
        // Generic URL: a stable download url plus an asset name or a digest.
        .generic_url => {
            if (res.download_url == null) return corrupt(.invalid_resolved);
            if (res.asset == null and res.digest == null) return corrupt(.invalid_resolved);
        },
    }

    // apps
    const apps = wire.apps orelse return corrupt(.missing_required_field);
    for (apps) |a| {
        if (!isSafePortableRelPath(a)) return corrupt(.invalid_apps);
    }

    // verification (concept present; a non-empty bounded result is required).
    const ver = wire.verification orelse return corrupt(.missing_required_field);
    const result = ver.result orelse return corrupt(.invalid_verification);
    if (!isBoundedMetaString(result)) return corrupt(.invalid_verification);
    if (ver.minisign) |m| if (!minisign.looksLikePubKey(m)) return corrupt(.invalid_verification);

    return ok();
}

/// Canonical check that does not leak: canonicalize into a scratch buffer and
/// compare. Returns false on a non-OOM validation failure; OOM propagates so it
/// is never conflated with "non-canonical".
fn isCanonicalIdInline(allocator: Allocator, id: []const u8) Allocator.Error!bool {
    const canon = install_request.canonicalizeId(allocator, id) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return false,
    };
    defer allocator.free(canon);
    return std.mem.eql(u8, canon, id);
}

fn copySource(allocator: Allocator, src: WireSource) Allocator.Error!OwnedSource {
    var out = OwnedSource{ .kind = parseSourceKind(src.kind.?).? };
    errdefer out.deinit(allocator);
    out.owner = try dupOpt(allocator, src.owner);
    out.repo = try dupOpt(allocator, src.repo);
    out.tag = try dupOpt(allocator, src.tag);
    out.asset_selector = try dupOpt(allocator, src.asset_selector);
    out.url = try dupOpt(allocator, src.url);
    return out;
}

fn copyConfig(allocator: Allocator, cfg: WireConfig) Allocator.Error!OwnedConfig {
    var out = OwnedConfig{};
    errdefer out.deinit(allocator);
    if (cfg.aliases) |aliases| {
        const arr = try allocator.alloc(OwnedAlias, aliases.len);
        var filled: usize = 0;
        errdefer {
            for (arr[0..filled]) |a| {
                allocator.free(a.from);
                allocator.free(a.to);
            }
            allocator.free(arr);
        }
        for (aliases, 0..) |a, i| {
            const from = try allocator.dupe(u8, a.from.?);
            errdefer allocator.free(from);
            const to = try allocator.dupe(u8, a.to.?);
            arr[i] = .{ .from = from, .to = to };
            filled = i + 1;
        }
        out.aliases = arr;
    }
    if (cfg.selected_commands) |sc| out.selected_commands = try dupStrings(allocator, sc);
    out.minisign = try dupOpt(allocator, cfg.minisign);
    if (cfg.verification_policy) |vp| {
        out.verification_policy_json = try std.json.Stringify.valueAlloc(allocator, vp, .{});
    }
    return out;
}

fn copyResolved(allocator: Allocator, res: WireResolved) Allocator.Error!OwnedResolved {
    var out = OwnedResolved{ .api_asset_id = res.api_asset_id };
    errdefer out.deinit(allocator);
    out.tag = try dupOpt(allocator, res.tag);
    out.asset = try dupOpt(allocator, res.asset);
    out.download_url = try dupOpt(allocator, res.download_url);
    if (res.digest) |d| {
        const alg = try allocator.dupe(u8, d.algorithm.?);
        errdefer allocator.free(alg);
        const val = try allocator.dupe(u8, d.value.?);
        out.digest = .{ .algorithm = alg, .value = val };
    }
    return out;
}

fn copyVerification(allocator: Allocator, v: WireVerification) Allocator.Error!OwnedVerification {
    var out = OwnedVerification{};
    errdefer out.deinit(allocator);
    out.result = try dupOpt(allocator, v.result);
    out.minisign = try dupOpt(allocator, v.minisign);
    return out;
}

fn copyCommands(
    allocator: Allocator,
    commands: []WireCommand,
    platform: Platform,
) Allocator.Error![]OwnedCommand {
    const out = try allocator.alloc(OwnedCommand, commands.len);
    var filled: usize = 0;
    errdefer {
        for (out[0..filled]) |*c| c.deinit(allocator);
        allocator.free(out);
    }
    for (commands, 0..) |cmd, i| {
        const name = try logicalCommandName(allocator, cmd.name.?, platform);
        errdefer allocator.free(name);
        const source_name = try dupOpt(allocator, cmd.source_name);
        errdefer freeOpt(allocator, source_name);
        const target = try allocator.dupe(u8, cmd.relative_target.?);
        errdefer allocator.free(target);
        const kind = try dupOpt(allocator, cmd.kind);
        out[i] = .{
            .name = name,
            .source_name = source_name,
            .relative_target = target,
            .kind = kind,
        };
        filled = i + 1;
    }
    return out;
}

/// Construct and append an OK v2 record with full owned provenance.
/// `path`/`id` are borrowed and deep-copied; a failed transfer frees every
/// duplicated field via rec.deinit.
fn addV2Record(
    b: *Builder,
    path: []const u8,
    id: []const u8,
    wire: WireV2,
    platform: Platform,
) Allocator.Error!void {
    const allocator = b.allocator;
    const path_owned = try allocator.dupe(u8, path);
    var rec = InventoryRecord{
        .kind = .v2,
        .status = .ok,
        .reason = .none,
        .path = path_owned,
    };
    errdefer rec.deinit(allocator);

    rec.id = try allocator.dupe(u8, id);
    rec.source = try copySource(allocator, wire.source.?);
    rec.config = try copyConfig(allocator, wire.config.?);
    rec.resolved = try copyResolved(allocator, wire.resolved.?);
    rec.verification = try copyVerification(allocator, wire.verification.?);
    rec.commands = try copyCommands(allocator, wire.commands.?, platform);
    if (wire.apps) |apps| rec.apps = try dupStrings(allocator, apps);
    rec.tag = try dupOpt(allocator, wire.tag);
    rec.asset = try dupOpt(allocator, wire.asset);
    rec.verified = try dupOpt(allocator, wire.verified);

    try b.records.append(allocator, rec);
}

// ---------------------------------------------------------------------------
// Metadata classification (schema-aware, fail-closed)
// ---------------------------------------------------------------------------

/// Classify a body found in a LEGACY location (`owner/repo` or nested wasm).
/// A schema:2 manifest here is corrupt (wrong layout), not "unsupported".
fn classifyLegacyBody(
    b: *Builder,
    body: []const u8,
    kind: UnitKind,
    path: []const u8,
    id_opt: ?[]const u8,
) Allocator.Error!void {
    const alloc = b.allocator;
    var parsed = std.json.parseFromSlice(std.json.Value, alloc, body, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return b.addDiagnostic(kind, corrupt(.malformed_json), path, id_opt),
    };
    defer parsed.deinit();

    switch (classifySchema(parsed.value)) {
        .malformed => return b.addDiagnostic(kind, corrupt(.malformed_json), path, id_opt),
        .corrupt_null => return b.addDiagnostic(kind, corrupt(.schema_null), path, id_opt),
        .corrupt_type => return b.addDiagnostic(kind, corrupt(.schema_wrong_type), path, id_opt),
        .unsupported => return b.addDiagnostic(kind, unsupported(.unsupported_schema), path, id_opt),
        .v2 => return b.addDiagnostic(kind, corrupt(.wrong_layout), path, id_opt),
        .v1 => {},
    }

    var pw = std.json.parseFromValue(WireV1, alloc, parsed.value, .{
        .ignore_unknown_fields = true,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return b.addDiagnostic(kind, corrupt(.malformed_json), path, id_opt),
    };
    defer pw.deinit();

    const judg = validateV1(pw.value, b.platform);
    if (judg.status == .ok) {
        try addV1Record(b, kind, path, id_opt, pw.value, b.platform);
    } else {
        try b.addDiagnostic(kind, judg, path, id_opt);
    }
}

/// Classify a body found in a V2 location (`_v2/units/.../_unit`). A v1 or
/// unversioned manifest here is corrupt (wrong layout); an unknown numeric
/// schema is unsupported.
fn classifyV2Body(
    b: *Builder,
    body: []const u8,
    path: []const u8,
    decoded_id: []const u8,
) Allocator.Error!void {
    const alloc = b.allocator;
    var parsed = std.json.parseFromSlice(std.json.Value, alloc, body, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return b.addDiagnostic(.v2, corrupt(.malformed_json), path, decoded_id),
    };
    defer parsed.deinit();

    switch (classifySchema(parsed.value)) {
        .malformed => return b.addDiagnostic(.v2, corrupt(.malformed_json), path, decoded_id),
        .corrupt_null => return b.addDiagnostic(.v2, corrupt(.schema_null), path, decoded_id),
        .corrupt_type => return b.addDiagnostic(.v2, corrupt(.schema_wrong_type), path, decoded_id),
        .unsupported => return b.addDiagnostic(.v2, unsupported(.unsupported_schema), path, decoded_id),
        .v1 => return b.addDiagnostic(.v2, corrupt(.wrong_layout), path, decoded_id),
        .v2 => {},
    }

    // Probe layout_generation from the raw object before typed parsing, so a
    // future layout with an incompatible field shape is still classified by its
    // layout number instead of a misleading malformed_json.
    switch (probeLayout(parsed.value)) {
        .missing => return b.addDiagnostic(.v2, corrupt(.missing_required_field), path, decoded_id),
        .wrong_type => return b.addDiagnostic(.v2, corrupt(.invalid_layout), path, decoded_id),
        .unsupported => return b.addDiagnostic(.v2, unsupported(.unsupported_layout), path, decoded_id),
        .ok => {},
    }

    var pw = std.json.parseFromValue(WireV2, alloc, parsed.value, .{
        .ignore_unknown_fields = true,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return b.addDiagnostic(.v2, corrupt(.malformed_json), path, decoded_id),
    };
    defer pw.deinit();
    const wire = pw.value;

    // The metadata id must match the id encoded in the physical path.
    if (wire.id) |mid| {
        if (!std.mem.eql(u8, mid, decoded_id))
            return b.addDiagnostic(.v2, corrupt(.encoded_path_mismatch), path, decoded_id);
    }

    const judg = try validateV2(alloc, wire, b.platform);
    if (judg.status == .ok) {
        try addV2Record(b, path, decoded_id, wire, b.platform);
    } else {
        try b.addDiagnostic(.v2, judg, path, decoded_id);
    }
}

// ---------------------------------------------------------------------------
// Read-only inventory traversal (never follows symlinks)
// ---------------------------------------------------------------------------

/// Join id parts with `/` and canonicalize. OOM propagates; a non-OOM
/// canonicalization failure yields `null` (the record is still emitted with an
/// unknown id).
fn synthLegacyId(allocator: Allocator, parts: []const []const u8) Allocator.Error!?[]const u8 {
    var joined: std.ArrayListUnmanaged(u8) = .empty;
    defer joined.deinit(allocator);
    for (parts, 0..) |p, i| {
        if (i > 0) try joined.append(allocator, '/');
        try joined.appendSlice(allocator, p);
    }
    const canon = install_request.canonicalizeId(allocator, joined.items) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    };
    return canon;
}

/// Read + classify a legacy unit's metadata. Missing metadata means the dir is
/// simply not a unit (legacy has no marker) and is skipped.
fn processLegacyUnit(
    b: *Builder,
    io: Io,
    unit_dir: Dir,
    kind: UnitKind,
    path: []const u8,
    id_opt: ?[]const u8,
) !void {
    switch (try readMetaNoFollow(b.allocator, io, unit_dir)) {
        .absent => {},
        .corrupt => |reason| try b.addDiagnostic(kind, corrupt(reason), path, id_opt),
        .body => |body| {
            defer b.allocator.free(body);
            try classifyLegacyBody(b, body, kind, path, id_opt);
        },
    }
}

/// Traverse a single `owner` directory: each child is a repo unit (v1_repo) and
/// may contain nested wasm units (v1_wasm).
fn scanOwner(b: *Builder, io: Io, root: Dir, owner: []const u8) !void {
    const alloc = b.allocator;
    switch (try openChildDirNoFollow(io, root, owner)) {
        .absent => return,
        // A symlinked owner is not followed; it is extracted-content-like, not a
        // unit, so no spurious record is produced.
        .symlinked => return,
        // A non-directory named like an owner is not a unit (legacy has no
        // structural guarantee at this level); skip it.
        .wrong_type => return,
        .opened => |owner_dir_| {
            var owner_dir = owner_dir_;
            defer owner_dir.close(io);
            var it = owner_dir.iterate();
            while (try it.next(io)) |entry| {
                const name = entry.name;
                if (isTransactionDir(name)) continue;
                // Ordinary symlink children (extracted archive content) are not
                // units and must not be classified; skip them.
                if (entry.kind == .sym_link) continue;
                if (entry.kind != .directory and entry.kind != .unknown) continue;
                const repo_path = try std.fmt.allocPrint(alloc, "{s}/{s}", .{ owner, name });
                defer alloc.free(repo_path);
                const repo = try alloc.dupe(u8, name);
                defer alloc.free(repo);
                try scanRepo(b, io, owner_dir, owner, repo, repo_path);
            }
        },
    }
}

/// Traverse one `owner/repo` directory: the repo itself is a v1_repo unit; each
/// of its subdirectories that carries `ghr.json` is a nested v1_wasm unit.
fn scanRepo(
    b: *Builder,
    io: Io,
    owner_dir: Dir,
    owner: []const u8,
    repo: []const u8,
    repo_path: []const u8,
) !void {
    const alloc = b.allocator;
    switch (try openChildDirNoFollow(io, owner_dir, repo)) {
        .absent => return,
        // A symlinked repo directory is extracted-content-like; do not follow or
        // classify it. (A symlinked `ghr.json` inside a real dir is still caught
        // by the no-follow metadata open below.)
        .symlinked => return,
        // A non-directory named like a repo is extracted content, not a unit.
        .wrong_type => return,
        .opened => |repo_dir_| {
            var repo_dir = repo_dir_;
            defer repo_dir.close(io);

            {
                const id = try synthLegacyId(alloc, &.{ owner, repo });
                defer freeOpt(alloc, id);
                try processLegacyUnit(b, io, repo_dir, .v1_repo, repo_path, id);
            }

            var it = repo_dir.iterate();
            while (try it.next(io)) |entry| {
                const name = entry.name;
                if (isTransactionDir(name)) continue;
                // Symlinked extracted content is never a nested unit; skip it.
                if (entry.kind == .sym_link) continue;
                if (entry.kind != .directory and entry.kind != .unknown) continue;
                const stem_path = try std.fmt.allocPrint(alloc, "{s}/{s}", .{ repo_path, name });
                defer alloc.free(stem_path);
                switch (try openChildDirNoFollow(io, repo_dir, name)) {
                    .absent => {},
                    .symlinked => {},
                    // A non-directory child is extracted content, not a unit.
                    .wrong_type => {},
                    .opened => |stem_dir_| {
                        var stem_dir = stem_dir_;
                        defer stem_dir.close(io);
                        const id = try synthLegacyId(alloc, &.{ owner, repo, name });
                        defer freeOpt(alloc, id);
                        try processLegacyUnit(b, io, stem_dir, .v1_wasm, stem_path, id);
                    },
                }
            }
        },
    }
}

/// Open the `_v2/units` root (no-follow at each hop) and traverse it.
fn scanV2Root(b: *Builder, io: Io, root: Dir) !void {
    const alloc = b.allocator;
    switch (try openChildDirNoFollow(io, root, v2_namespace)) {
        .absent => return,
        .symlinked => return b.addDiagnostic(.v2, corrupt(.symlinked_path), v2_namespace, null),
        .wrong_type => return b.addDiagnostic(.v2, corrupt(.not_a_directory), v2_namespace, null),
        .opened => |ns_| {
            var ns = ns_;
            defer ns.close(io);
            switch (try openChildDirNoFollow(io, ns, v2_units_dir)) {
                .absent => return,
                .symlinked => return b.addDiagnostic(
                    .v2,
                    corrupt(.symlinked_path),
                    v2_namespace ++ "/" ++ v2_units_dir,
                    null,
                ),
                .wrong_type => return b.addDiagnostic(
                    .v2,
                    corrupt(.not_a_directory),
                    v2_namespace ++ "/" ++ v2_units_dir,
                    null,
                ),
                .opened => |units_| {
                    var units = units_;
                    defer units.close(io);
                    var segs: std.ArrayListUnmanaged([]const u8) = .empty;
                    defer {
                        for (segs.items) |s| alloc.free(s);
                        segs.deinit(alloc);
                    }
                    try scanUnitsNode(b, io, units, v2_namespace ++ "/" ++ v2_units_dir, &segs);
                },
            }
        },
    }
}

/// Recursive traversal of the encoded units tree. `segs` accumulates the
/// encoded directory names (`u-<seg>`) for the current path. Malformed
/// branches/markers become corrupt records rather than being silently skipped.
/// Every `_unit` diagnostic carries the canonical ID decoded from `segs` when
/// reliable, so a structurally-broken v2 unit still participates in duplicate-ID
/// blocking. Non-directory structural nodes fail closed as corrupt.
fn scanUnitsNode(
    b: *Builder,
    io: Io,
    node: Dir,
    prefix: []const u8,
    segs: *std.ArrayListUnmanaged([]const u8),
) !void {
    const alloc = b.allocator;
    var it = node.iterate();
    while (try it.next(io)) |entry| {
        const name = entry.name;
        const child_path = try std.fmt.allocPrint(alloc, "{s}/{s}", .{ prefix, name });
        defer alloc.free(child_path);

        if (std.mem.eql(u8, name, unit_marker)) {
            // Decode the accumulated segments so every `_unit` diagnostic can
            // carry the canonical ID. A non-decodable accumulation (e.g. a
            // stray `_unit` directly under `units`) yields a null id.
            const decoded = decodeSegments(alloc, segs.items) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => null,
            };
            defer if (decoded) |d| alloc.free(d);

            // A symlinked marker is never followed.
            if (entry.kind == .sym_link) {
                try b.addDiagnostic(.v2, corrupt(.symlinked_path), child_path, decoded);
                continue;
            }
            switch (try openChildDirNoFollow(io, node, name)) {
                // Present during iteration but gone/entered a race on open: keep
                // it as a diagnosable record with the decoded id, not absence.
                .absent => try b.addDiagnostic(.v2, corrupt(.missing_metadata), child_path, decoded),
                .symlinked => try b.addDiagnostic(.v2, corrupt(.symlinked_path), child_path, decoded),
                .wrong_type => try b.addDiagnostic(.v2, corrupt(.not_a_directory), child_path, decoded),
                .opened => |unit_dir_| {
                    var unit_dir = unit_dir_;
                    defer unit_dir.close(io);
                    try handleV2Unit(b, io, unit_dir, segs.items, child_path);
                },
            }
            continue;
        }

        // Non-marker children: a symlink is never followed.
        if (entry.kind == .sym_link) {
            try b.addDiagnostic(.v2, corrupt(.symlinked_path), child_path, null);
            continue;
        }

        if (std.mem.startsWith(u8, name, segment_prefix)) {
            const seg = name[segment_prefix.len..];
            if (!isCanonicalIdSegment(seg)) {
                try b.addDiagnostic(.v2, corrupt(.malformed_encoding), child_path, null);
                continue;
            }
            // Bound recursion by both depth (segment count) and the running
            // encoded relative length so a marker-free deep chain cannot recurse
            // unboundedly: emit one corrupt `path_too_long` for this branch and
            // stop descending.
            if (segs.items.len + 1 > max_unit_segments or
                child_path.len + unit_marker.len + 1 > max_encoded_relative_bytes)
            {
                try b.addDiagnostic(.v2, corrupt(.path_too_long), child_path, null);
                continue;
            }
            switch (try openChildDirNoFollow(io, node, name)) {
                .absent => {},
                .symlinked => try b.addDiagnostic(.v2, corrupt(.symlinked_path), child_path, null),
                // A non-directory encoded component is a structural corruption.
                .wrong_type => try b.addDiagnostic(.v2, corrupt(.not_a_directory), child_path, null),
                .opened => |child_dir_| {
                    var child_dir = child_dir_;
                    defer child_dir.close(io);
                    const dup = try alloc.dupe(u8, name);
                    {
                        errdefer alloc.free(dup);
                        try segs.append(alloc, dup);
                    }
                    defer {
                        _ = segs.pop();
                        alloc.free(dup);
                    }
                    try scanUnitsNode(b, io, child_dir, child_path, segs);
                },
            }
            continue;
        }

        try b.addDiagnostic(.v2, corrupt(.malformed_encoding), child_path, null);
    }
}

/// Decode the id for a `_unit` marker and classify its metadata.
fn handleV2Unit(
    b: *Builder,
    io: Io,
    unit_dir: Dir,
    encoded: []const []const u8,
    unit_path: []const u8,
) !void {
    const alloc = b.allocator;
    const decoded = decodeSegments(alloc, encoded) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return b.addDiagnostic(.v2, corrupt(.malformed_encoding), unit_path, null),
    };
    defer alloc.free(decoded);

    switch (try readMetaNoFollow(alloc, io, unit_dir)) {
        .absent => try b.addDiagnostic(.v2, corrupt(.missing_metadata), unit_path, decoded),
        .corrupt => |reason| try b.addDiagnostic(.v2, corrupt(reason), unit_path, decoded),
        .body => |body| {
            defer alloc.free(body);
            try classifyV2Body(b, body, unit_path, decoded);
        },
    }
}

// ---------------------------------------------------------------------------
// Cross-record conflict passes
// ---------------------------------------------------------------------------

fn markConflict(rec: *InventoryRecord, reason: RecordReason) void {
    if (rec.status == .ok) {
        rec.status = .conflict;
        rec.reason = reason;
    }
}

/// Detect canonical-id collisions across ALL records that carry a reliable id
/// (including corrupt/unsupported ones), so no `.ok` record survives for an id
/// that is shared. OK participants become `conflict(duplicate_id)`; damaged
/// (corrupt/unsupported) participants keep their existing status/reason.
fn markDuplicateIds(b: *Builder) Allocator.Error!void {
    const items = b.records.items;
    var counts: std.StringHashMapUnmanaged(usize) = .empty;
    defer counts.deinit(b.allocator);
    for (items) |*rec| {
        const id = rec.id orelse continue;
        const gop = try counts.getOrPut(b.allocator, id);
        if (gop.found_existing) gop.value_ptr.* += 1 else gop.value_ptr.* = 1;
    }
    for (items) |*rec| {
        const id = rec.id orelse continue;
        if (counts.get(id).? > 1) markConflict(rec, .duplicate_id);
    }
}

/// Mark OK records that publish the same logical command (under the selected
/// platform's case/`.exe` semantics) as `conflict(duplicate_command)`.
fn markDuplicateCommands(b: *Builder) Allocator.Error!void {
    var arena = std.heap.ArenaAllocator.init(b.allocator);
    defer arena.deinit();
    const scratch = arena.allocator();
    const items = b.records.items;
    var map: std.StringHashMapUnmanaged(usize) = .empty;
    for (items, 0..) |*rec, i| {
        if (rec.status != .ok) continue;
        for (rec.commands) |cmd| {
            const key = try conflictKey(scratch, cmd.name, b.platform);
            const gop = try map.getOrPut(scratch, key);
            if (gop.found_existing) {
                const first = gop.value_ptr.*;
                if (first != i) {
                    markConflict(&items[first], .duplicate_command);
                    markConflict(&items[i], .duplicate_command);
                }
            } else {
                gop.value_ptr.* = i;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Deterministic ordering + public entry point
// ---------------------------------------------------------------------------

fn recordLessThan(_: void, a: InventoryRecord, b: InventoryRecord) bool {
    const ai = a.id orelse "";
    const bi = b.id orelse "";
    switch (std.mem.order(u8, ai, bi)) {
        .lt => return true,
        .gt => return false,
        .eq => {},
    }
    switch (std.mem.order(u8, a.path, b.path)) {
        .lt => return true,
        .gt => return false,
        .eq => {},
    }
    if (@intFromEnum(a.kind) != @intFromEnum(b.kind))
        return @intFromEnum(a.kind) < @intFromEnum(b.kind);
    return @intFromEnum(a.status) < @intFromEnum(b.status);
}

fn sortRecords(items: []InventoryRecord) void {
    std.mem.sort(InventoryRecord, items, {}, recordLessThan);
}

/// Scan the tools directory at `tools_dir_path` and return a read-only
/// inventory of installed units. The tools root itself may be a symlink (it is
/// the trusted anchor); every child hop is opened WITHOUT following symlinks.
/// A missing tools directory yields an empty inventory; genuine
/// permission/I/O/traversal errors propagate (fail closed). The caller owns the
/// returned `Inventory` and must `deinit` it.
pub fn scan(
    allocator: Allocator,
    io: Io,
    tools_dir_path: []const u8,
    options: ScanOptions,
) !Inventory {
    var b = Builder{ .allocator = allocator, .platform = options.platform };
    errdefer b.deinit();

    var root = Dir.openDirAbsolute(io, tools_dir_path, .{ .iterate = true }) catch |err| switch (err) {
        // Only an actually-missing tools directory is absence. A non-directory
        // (NotDir) or any permission/I/O error fails closed and propagates.
        error.FileNotFound => {
            const recs = try b.records.toOwnedSlice(allocator);
            return .{ .records = recs };
        },
        else => return err,
    };
    defer root.close(io);

    var it = root.iterate();
    while (try it.next(io)) |entry| {
        const name = entry.name;
        if (std.mem.eql(u8, name, v2_namespace)) {
            if (entry.kind == .sym_link) {
                try b.addDiagnostic(.v2, corrupt(.symlinked_path), v2_namespace, null);
                continue;
            }
            try scanV2Root(&b, io, root);
            continue;
        }
        if (entry.kind == .sym_link) continue;
        if (entry.kind != .directory and entry.kind != .unknown) continue;
        if (isTransactionDir(name)) continue;
        const owner = try allocator.dupe(u8, name);
        defer allocator.free(owner);
        try scanOwner(&b, io, root, owner);
    }

    try markDuplicateIds(&b);
    try markDuplicateCommands(&b);
    sortRecords(b.records.items);

    const recs = try b.records.toOwnedSlice(allocator);
    return .{ .records = recs };
}

// ===========================================================================
// Tests (read-only; no runtime behavior is activated by this module)
// ===========================================================================

const testing = std.testing;

const t_v2_ownerrepo =
    \\{
    \\  "schema": 2, "layout_generation": 2, "id": "owner/repo",
    \\  "source": {"kind":"github","owner":"Owner","repo":"Repo","tag":"v1.0","asset_selector":"*.tgz"},
    \\  "config": {"aliases":[{"from":"orig","to":"tool"}],"selected_commands":["tool"],"verification_policy":{"mode":"require","m":1}},
    \\  "resolved": {"tag":"v1.0","asset":"tool.tgz","api_asset_id":7,"download_url":"https://example.com/tool.tgz","digest":{"algorithm":"sha256","value":"deadbeef"}},
    \\  "commands": [{"name":"tool","source_name":"orig","relative_target":"bin/tool","kind":"native"}],
    \\  "apps": ["share/app"],
    \\  "verification": {"result":"verified"}
    \\}
;

fn tWriteUnit(io: Io, dir: Dir, rel_dir: []const u8, json: []const u8) !void {
    try dir.createDirPath(io, rel_dir);
    var buf: [512]u8 = undefined;
    const p = try std.fmt.bufPrint(&buf, "{s}/ghr.json", .{rel_dir});
    try dir.writeFile(io, .{ .sub_path = p, .data = json });
}

fn tScan(allocator: Allocator, io: Io, dir: Dir, platform: Platform) !Inventory {
    var buf: [Dir.max_path_bytes]u8 = undefined;
    const len = try dir.realPath(io, &buf);
    return scan(allocator, io, buf[0..len], .{ .platform = platform });
}

fn tFind(inv: Inventory, path: []const u8) ?*const InventoryRecord {
    for (inv.records) |*r| {
        if (std.mem.eql(u8, r.path, path)) return r;
    }
    return null;
}

fn tCheckV2(allocator: Allocator, body: []const u8) anyerror!void {
    var b = Builder{ .allocator = allocator, .platform = .posix };
    defer b.deinit();
    try classifyV2Body(&b, body, "_v2/units/u-owner/u-repo/_unit", "owner/repo");
    try testing.expectEqual(@as(usize, 1), b.records.items.len);
    try testing.expectEqual(Status.ok, b.records.items[0].status);
}

fn tCheckV1(allocator: Allocator, body: []const u8) anyerror!void {
    var b = Builder{ .allocator = allocator, .platform = .posix };
    defer b.deinit();
    try classifyLegacyBody(&b, body, .v1_repo, "owner/repo", "owner/repo");
    try testing.expectEqual(@as(usize, 1), b.records.items.len);
}

test "encode/decode roundtrip and prefix ids coexist" {
    const a = testing.allocator;
    inline for (.{ "a", "a/b", "owner/repo", "x.y_z/q-1" }) |id| {
        const rel = try encodeRelPath(a, id);
        defer a.free(rel);
        const dec = try decodeRelPath(a, rel);
        defer a.free(dec);
        try testing.expectEqualStrings(id, dec);
    }
    // `a` and `a/b` map to distinct, coexisting paths (marker disambiguates).
    const ra = try encodeRelPath(a, "a");
    defer a.free(ra);
    const rab = try encodeRelPath(a, "a/b");
    defer a.free(rab);
    try testing.expectEqualStrings("_v2/units/u-a/_unit", ra);
    try testing.expectEqualStrings("_v2/units/u-a/u-b/_unit", rab);
}

test "decode rejects uppercase and malformed encodings" {
    const a = testing.allocator;
    try testing.expectError(error.NonCanonicalId, decodeRelPath(a, "_v2/units/u-A/_unit"));
    try testing.expectError(error.InvalidEncoding, decodeRelPath(a, "_v2/units/u-a"));
    try testing.expectError(error.InvalidEncoding, decodeRelPath(a, "_v2/units/x-a/_unit"));
    try testing.expectError(error.InvalidEncoding, decodeRelPath(a, "other/units/u-a/_unit"));
    try testing.expectError(error.InvalidEncoding, decodeRelPath(a, "_v2/units/_unit"));
    try testing.expectError(error.NonCanonicalId, decodeRelPath(a, "_v2/units/u-.hidden/_unit"));
}

test "encodeUnitPath enforces full absolute path budget" {
    const a = testing.allocator;
    const ok_path = try encodeUnitPath(a, "/tools", "owner/repo", .posix);
    a.free(ok_path);
    // A long (but canonical) multi-segment id under a deep Windows root must
    // fail closed with PathTooLong.
    var idbuf: [212]u8 = undefined;
    @memset(&idbuf, 'a');
    idbuf[70] = '/';
    idbuf[141] = '/';
    try testing.expectError(error.PathTooLong, encodeUnitPath(a, "C:\\some\\deep\\tools", &idbuf, .windows));
}

test "credential/userinfo URLs are rejected" {
    try testing.expect(isSafeNonCredentialUrl("https://example.com/a/b.tgz"));
    try testing.expect(!isSafeNonCredentialUrl("https://user:pw@example.com/a"));
    try testing.expect(!isSafeNonCredentialUrl("https://example.com/a?X-Amz-Signature=abc"));
    try testing.expect(!isSafeNonCredentialUrl("https://example.com/a?sig=xyz&sp=r"));
    try testing.expect(!isSafeNonCredentialUrl("https://example.com/a?X-Goog-Credential=k"));
    try testing.expect(!isSafeNonCredentialUrl("ftp://example.com/a"));
    try testing.expect(!isSafeNonCredentialUrl("https://example.com/a?token=t"));
}

test "logical command derivation mirrors legacy suffix rules" {
    const a = testing.allocator;
    const cases = .{
        .{ "bin/tool", Platform.posix, "tool" },
        .{ "bin\\tool.exe", Platform.windows, "tool" },
        .{ "bin/tool.exe", Platform.posix, "tool.exe" },
        .{ "pkg/thing.wasm", Platform.posix, "thing" },
        .{ "pkg/thing.wasm", Platform.windows, "thing" },
        .{ "a/b/App.EXE", Platform.windows, "App" },
        // `.WASM` (uppercase) is NOT wasm under the case-sensitive lower rule;
        // `.WASM` is not a `.exe` suffix either, so it is left intact.
        .{ "x/Foo.WASM", Platform.posix, "Foo.WASM" },
        .{ "x/Foo.WASM", Platform.windows, "Foo.WASM" },
        // wasm strips only `.wasm`; a residual `.exe` is preserved.
        .{ "tool.exe.wasm", Platform.posix, "tool.exe" },
        .{ "tool.exe.wasm", Platform.windows, "tool.exe" },
        // native `.exe`: stripped on Windows, preserved on POSIX.
        .{ "app.exe", Platform.windows, "app" },
        .{ "app.exe", Platform.posix, "app.exe" },
    };
    inline for (cases) |c| {
        const got = try logicalCommandName(a, c[0], c[1]);
        defer a.free(got);
        try testing.expectEqualStrings(c[2], got);
    }
}

test "legacy relative path safety" {
    try testing.expect(isSafeLegacyRelPath("bin/tool", .posix));
    try testing.expect(isSafeLegacyRelPath("bin\\tool", .windows));
    try testing.expect(!isSafeLegacyRelPath("bin\\tool", .posix));
    try testing.expect(!isSafeLegacyRelPath("/abs", .posix));
    try testing.expect(!isSafeLegacyRelPath("C:\\x", .windows));
    try testing.expect(!isSafeLegacyRelPath("../evil", .posix));
    try testing.expect(!isSafeLegacyRelPath("a/../b", .posix));
    try testing.expect(!isSafeLegacyRelPath("", .posix));
}

test "schema classification is presence-aware" {
    const a = testing.allocator;
    const cases = .{
        .{ "{}", SchemaClass.v1 },
        .{ "{\"schema\":2}", SchemaClass.v2 },
        .{ "{\"schema\":1}", SchemaClass.unsupported },
        .{ "{\"schema\":99}", SchemaClass.unsupported },
        .{ "{\"schema\":null}", SchemaClass.corrupt_null },
        .{ "{\"schema\":\"2\"}", SchemaClass.corrupt_type },
        .{ "[]", SchemaClass.malformed },
    };
    inline for (cases) |c| {
        var parsed = try std.json.parseFromSlice(std.json.Value, a, c[0], .{});
        defer parsed.deinit();
        try testing.expectEqual(c[1], classifySchema(parsed.value));
    }
}

test "scan: missing tools directory yields empty inventory" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const a = testing.allocator;
    var inv = try scan(a, testing.io, "/nonexistent/ghr/tools/xyz", .{});
    defer inv.deinit(a);
    try testing.expectEqual(@as(usize, 0), inv.records.len);
}

test "scan: healthy v2 unit retains full provenance" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const a = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tWriteUnit(io, tmp.dir, "_v2/units/u-owner/u-repo/_unit", t_v2_ownerrepo);

    var inv = try tScan(a, io, tmp.dir, .posix);
    defer inv.deinit(a);
    try testing.expectEqual(@as(usize, 1), inv.records.len);
    const rec = &inv.records[0];
    try testing.expectEqual(Status.ok, rec.status);
    try testing.expectEqual(UnitKind.v2, rec.kind);
    try testing.expectEqualStrings("owner/repo", rec.id.?);
    try testing.expect(rec.source != null);
    try testing.expectEqual(SourceKind.github, rec.source.?.kind);
    try testing.expectEqualStrings("Owner", rec.source.?.owner.?);
    try testing.expect(rec.resolved != null);
    try testing.expectEqualStrings("https://example.com/tool.tgz", rec.resolved.?.download_url.?);
    try testing.expectEqual(@as(usize, 1), rec.commands.len);
    try testing.expectEqualStrings("tool", rec.commands[0].name);
    try testing.expectEqualStrings("bin/tool", rec.commands[0].relative_target);
    try testing.expect(rec.verification != null);
    // The verification policy object is retained as canonical JSON.
    try testing.expect(rec.config != null);
    try testing.expect(rec.config.?.verification_policy_json != null);
    try testing.expect(std.mem.indexOf(u8, rec.config.?.verification_policy_json.?, "require") != null);
}

test "scan: v1 archive and nested wasm synthesis" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const a = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tWriteUnit(io, tmp.dir, "owner/repo",
        \\{"tag":"v1.0","asset":"tool.tar.gz","verified":"minisign","minisign":"sig","bins":["bin/tool"],"apps":[]}
    );
    try tWriteUnit(io, tmp.dir, "owner/repo/mod",
        \\{"tag":"v2.0","asset":"mod.wasm","verified":"none","minisign":"","bins":["mod.wasm"],"apps":[]}
    );

    var inv = try tScan(a, io, tmp.dir, .posix);
    defer inv.deinit(a);
    const repo = tFind(inv, "owner/repo").?;
    try testing.expectEqual(Status.ok, repo.status);
    try testing.expectEqual(UnitKind.v1_repo, repo.kind);
    try testing.expectEqualStrings("owner/repo", repo.id.?);
    try testing.expectEqualStrings("v1.0", repo.tag.?);

    const wasm = tFind(inv, "owner/repo/mod").?;
    try testing.expectEqual(UnitKind.v1_wasm, wasm.kind);
    try testing.expectEqualStrings("owner/repo/mod", wasm.id.?);
    try testing.expectEqual(@as(usize, 1), wasm.commands.len);
    try testing.expectEqualStrings("mod", wasm.commands[0].name);
    try testing.expectEqualStrings("wasm", wasm.commands[0].kind.?);
}

test "scan: legacy empty object and unsafe bins are corrupt" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const a = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tWriteUnit(io, tmp.dir, "e/one", "{}");
    try tWriteUnit(io, tmp.dir, "e/two",
        \\{"tag":"v1","asset":"a.tgz","bins":["../evil"],"apps":[]}
    );
    try tWriteUnit(io, tmp.dir, "e/three", "{ not json");

    var inv = try tScan(a, io, tmp.dir, .posix);
    defer inv.deinit(a);
    try testing.expectEqual(RecordReason.missing_required_field, tFind(inv, "e/one").?.reason);
    try testing.expectEqual(RecordReason.unsafe_relative_path, tFind(inv, "e/two").?.reason);
    try testing.expectEqual(RecordReason.malformed_json, tFind(inv, "e/three").?.reason);
}

test "scan: schema variants classified precisely" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const a = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tWriteUnit(io, tmp.dir, "s/unknown", "{\"schema\":99}");
    try tWriteUnit(io, tmp.dir, "s/nullv", "{\"schema\":null}");
    try tWriteUnit(io, tmp.dir, "s/strv", "{\"schema\":\"2\"}");
    // schema:2 in a legacy location is wrong-layout corruption.
    try tWriteUnit(io, tmp.dir, "s/v2here", "{\"schema\":2}");

    var inv = try tScan(a, io, tmp.dir, .posix);
    defer inv.deinit(a);
    const u = tFind(inv, "s/unknown").?;
    try testing.expectEqual(Status.unsupported, u.status);
    try testing.expectEqual(RecordReason.unsupported_schema, u.reason);
    try testing.expectEqual(RecordReason.schema_null, tFind(inv, "s/nullv").?.reason);
    try testing.expectEqual(RecordReason.schema_wrong_type, tFind(inv, "s/strv").?.reason);
    try testing.expectEqual(RecordReason.wrong_layout, tFind(inv, "s/v2here").?.reason);
}

test "scan: v2 layout-generation mismatch is unsupported" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const a = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tWriteUnit(io, tmp.dir, "_v2/units/u-o/u-r/_unit",
        \\{"schema":2,"layout_generation":3,"id":"o/r","source":{"kind":"github","owner":"o","repo":"r"},"config":{},"resolved":{},"commands":[],"apps":[],"verification":{}}
    );
    var inv = try tScan(a, io, tmp.dir, .posix);
    defer inv.deinit(a);
    const rec = tFind(inv, "_v2/units/u-o/u-r/_unit").?;
    try testing.expectEqual(Status.unsupported, rec.status);
    try testing.expectEqual(RecordReason.unsupported_layout, rec.reason);
}

test "scan: v1 manifest in v2 location and id mismatch are corrupt" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const a = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tWriteUnit(io, tmp.dir, "_v2/units/u-o/u-r/_unit",
        \\{"tag":"v1","asset":"a.tgz"}
    );
    try tWriteUnit(io, tmp.dir, "_v2/units/u-x/u-y/_unit",
        \\{"schema":2,"layout_generation":2,"id":"a/b","source":{"kind":"github","owner":"a","repo":"b"},"config":{},"resolved":{},"commands":[],"apps":[],"verification":{}}
    );
    var inv = try tScan(a, io, tmp.dir, .posix);
    defer inv.deinit(a);
    try testing.expectEqual(RecordReason.wrong_layout, tFind(inv, "_v2/units/u-o/u-r/_unit").?.reason);
    try testing.expectEqual(RecordReason.encoded_path_mismatch, tFind(inv, "_v2/units/u-x/u-y/_unit").?.reason);
}

test "scan: visible .old paths are candidates; hidden transactions are ignored" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const a = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    // A repo-level name ending in `.old` is a legal legacy name (a live install
    // or a stale backup) -- surfaced, never omitted.
    try tWriteUnit(io, tmp.dir, "owner/repo.old",
        \\{"tag":"v1","asset":"a.tgz","bins":[],"apps":[]}
    );
    // A stem-level (nested wasm) name ending in `.old` is likewise surfaced.
    try tWriteUnit(io, tmp.dir, "live/repo",
        \\{"tag":"v1","asset":"a.tgz","bins":[],"apps":[]}
    );
    try tWriteUnit(io, tmp.dir, "live/repo/module.old",
        \\{"tag":"v1","asset":"a.tgz","bins":[],"apps":[]}
    );
    // Hidden staging and retained backup directories are transaction artifacts.
    try tWriteUnit(io, tmp.dir, ".mystage.staging/repo",
        \\{"tag":"v1","asset":"a.tgz","bins":[],"apps":[]}
    );
    try tWriteUnit(io, tmp.dir, "live/.repo.old",
        \\{"tag":"v1","asset":"a.tgz","bins":["bin/tool"],"apps":[]}
    );
    try tWriteUnit(io, tmp.dir, "live/repo/.module.old",
        \\{"tag":"v1","asset":"a.tgz","bins":["bin/tool"],"apps":[]}
    );
    var inv = try tScan(a, io, tmp.dir, .posix);
    defer inv.deinit(a);
    try testing.expect(tFind(inv, "owner/repo.old") != null);
    try testing.expect(tFind(inv, "live/repo/module.old") != null);
    try testing.expectEqual(Status.ok, tFind(inv, "live/repo").?.status);
    // Nothing from hidden transaction directories is inventoried.
    for (inv.records) |r| {
        try testing.expect(std.mem.indexOf(u8, r.path, ".mystage.staging") == null);
        try testing.expect(std.mem.indexOf(u8, r.path, ".repo.old") == null);
        try testing.expect(std.mem.indexOf(u8, r.path, ".module.old") == null);
    }
}

test "scan: same-id v1/v2 records conflict; mixed-case legacy collapses" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const a = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    // v1 owner/repo and v2 owner/repo -> duplicate id.
    try tWriteUnit(io, tmp.dir, "owner/repo",
        \\{"tag":"v1","asset":"a.tgz"}
    );
    try tWriteUnit(io, tmp.dir, "_v2/units/u-owner/u-repo/_unit", t_v2_ownerrepo);
    var inv = try tScan(a, io, tmp.dir, .posix);
    defer inv.deinit(a);
    try testing.expectEqual(Status.conflict, tFind(inv, "owner/repo").?.status);
    try testing.expectEqual(RecordReason.duplicate_id, tFind(inv, "owner/repo").?.reason);
    try testing.expectEqual(Status.conflict, tFind(inv, "_v2/units/u-owner/u-repo/_unit").?.status);
}

test "scan: mixed-case legacy owners collapse to one id conflict" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const a = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tWriteUnit(io, tmp.dir, "Foo/Bar",
        \\{"tag":"v1","asset":"a.tgz"}
    );
    try tWriteUnit(io, tmp.dir, "foo/bar",
        \\{"tag":"v1","asset":"a.tgz"}
    );
    var inv = try tScan(a, io, tmp.dir, .posix);
    defer inv.deinit(a);
    try testing.expectEqual(Status.conflict, tFind(inv, "Foo/Bar").?.status);
    try testing.expectEqual(Status.conflict, tFind(inv, "foo/bar").?.status);
}

test "scan: duplicate published command ownership conflicts (windows .exe)" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const a = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tWriteUnit(io, tmp.dir, "_v2/units/u-a/u-one/_unit",
        \\{"schema":2,"layout_generation":2,"id":"a/one","source":{"kind":"github","owner":"a","repo":"one"},"config":{},"resolved":{"tag":"v","asset":"a.tgz"},"commands":[{"name":"tool","relative_target":"bin/tool"}],"apps":[],"verification":{"result":"none"}}
    );
    try tWriteUnit(io, tmp.dir, "_v2/units/u-a/u-two/_unit",
        \\{"schema":2,"layout_generation":2,"id":"a/two","source":{"kind":"github","owner":"a","repo":"two"},"config":{},"resolved":{"tag":"v","asset":"a.tgz"},"commands":[{"name":"tool.exe","relative_target":"bin/tool.exe"}],"apps":[],"verification":{"result":"none"}}
    );
    // POSIX: "tool" != "tool.exe" -> no conflict.
    {
        var inv = try tScan(a, io, tmp.dir, .posix);
        defer inv.deinit(a);
        try testing.expectEqual(Status.ok, tFind(inv, "_v2/units/u-a/u-one/_unit").?.status);
        try testing.expectEqual(Status.ok, tFind(inv, "_v2/units/u-a/u-two/_unit").?.status);
    }
    // Windows: both derive "tool" -> conflict.
    {
        var inv = try tScan(a, io, tmp.dir, .windows);
        defer inv.deinit(a);
        try testing.expectEqual(Status.conflict, tFind(inv, "_v2/units/u-a/u-one/_unit").?.status);
        try testing.expectEqual(RecordReason.duplicate_command, tFind(inv, "_v2/units/u-a/u-two/_unit").?.reason);
    }
}

test "scan: command collision keys do not normalize logical names twice" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const a = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tWriteUnit(io, tmp.dir, "legacy/repo",
        \\{"tag":"v","asset":"a","bins":["bin/tool.exe.wasm"],"apps":[]}
    );
    try tWriteUnit(io, tmp.dir, "_v2/units/u-modern/u-repo/_unit",
        \\{"schema":2,"layout_generation":2,"id":"modern/repo","source":{"kind":"github","owner":"modern","repo":"repo"},"config":{},"resolved":{"tag":"v","asset":"a.tgz"},"commands":[{"name":"tool.exe.wasm","relative_target":"bin/tool.exe.wasm"}],"apps":[],"verification":{"result":"none"}}
    );
    var inv = try tScan(a, io, tmp.dir, .windows);
    defer inv.deinit(a);
    const legacy = tFind(inv, "legacy/repo").?;
    const modern = tFind(inv, "_v2/units/u-modern/u-repo/_unit").?;
    try testing.expectEqualStrings("tool.exe", legacy.commands[0].name);
    try testing.expectEqualStrings("tool.exe", modern.commands[0].name);
    try testing.expectEqual(Status.conflict, legacy.status);
    try testing.expectEqual(RecordReason.duplicate_command, modern.reason);
}

test "scan: internal duplicate command and credential url are corrupt" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const a = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tWriteUnit(io, tmp.dir, "_v2/units/u-a/u-dup/_unit",
        \\{"schema":2,"layout_generation":2,"id":"a/dup","source":{"kind":"github","owner":"a","repo":"dup"},"config":{},"resolved":{},"commands":[{"name":"tool","relative_target":"bin/tool"},{"name":"tool","relative_target":"bin/tool2"}],"apps":[],"verification":{}}
    );
    try tWriteUnit(io, tmp.dir, "_v2/units/u-a/u-cred/_unit",
        \\{"schema":2,"layout_generation":2,"id":"a/cred","source":{"kind":"github","owner":"a","repo":"cred"},"config":{},"resolved":{"download_url":"https://x.com/f?X-Amz-Signature=z"},"commands":[],"apps":[],"verification":{}}
    );
    var inv = try tScan(a, io, tmp.dir, .posix);
    defer inv.deinit(a);
    try testing.expectEqual(RecordReason.duplicate_command_internal, tFind(inv, "_v2/units/u-a/u-dup/_unit").?.reason);
    try testing.expectEqual(RecordReason.credential_url, tFind(inv, "_v2/units/u-a/u-cred/_unit").?.reason);
}

test "scan: generic_url source validation" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const a = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tWriteUnit(io, tmp.dir, "_v2/units/u-g/u-ok/_unit",
        \\{"schema":2,"layout_generation":2,"id":"g/ok","source":{"kind":"generic_url","url":"https://ex.com/a.tgz"},"config":{},"resolved":{"download_url":"https://ex.com/a.tgz","asset":"a.tgz"},"commands":[],"apps":[],"verification":{"result":"none"}}
    );
    try tWriteUnit(io, tmp.dir, "_v2/units/u-g/u-bad/_unit",
        \\{"schema":2,"layout_generation":2,"id":"g/bad","source":{"kind":"generic_url","url":"https://user:pw@ex.com/a"},"config":{},"resolved":{},"commands":[],"apps":[],"verification":{}}
    );
    var inv = try tScan(a, io, tmp.dir, .posix);
    defer inv.deinit(a);
    try testing.expectEqual(Status.ok, tFind(inv, "_v2/units/u-g/u-ok/_unit").?.status);
    try testing.expectEqual(RecordReason.credential_url, tFind(inv, "_v2/units/u-g/u-bad/_unit").?.reason);
}

test "scan: oversized metadata is corrupt" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const a = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const big = try a.alloc(u8, max_metadata_bytes + 16);
    defer a.free(big);
    @memset(big, 'x');
    try tWriteUnit(io, tmp.dir, "big/repo", big);
    var inv = try tScan(a, io, tmp.dir, .posix);
    defer inv.deinit(a);
    try testing.expectEqual(RecordReason.oversized_metadata, tFind(inv, "big/repo").?.reason);
}

test "scan: symlinked metadata and markers are corrupt, never followed" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const a = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    // Legacy unit whose ghr.json is a symlink.
    try tmp.dir.createDirPath(io, "owner/repo");
    try tmp.dir.symLink(io, "/etc/hostname", "owner/repo/ghr.json", .{});
    // v2 marker directory that is a symlink.
    try tmp.dir.createDirPath(io, "_v2/units/u-a");
    try tmp.dir.symLink(io, "/tmp", "_v2/units/u-a/_unit", .{});

    var inv = try tScan(a, io, tmp.dir, .posix);
    defer inv.deinit(a);
    try testing.expectEqual(RecordReason.symlinked_path, tFind(inv, "owner/repo").?.reason);
    try testing.expectEqual(RecordReason.symlinked_path, tFind(inv, "_v2/units/u-a/_unit").?.reason);
}

test "scan: malformed v2 branch names are corrupt records" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const a = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "_v2/units/u-A"); // uppercase segment
    try tmp.dir.createDirPath(io, "_v2/units/bogus"); // no u- prefix
    var inv = try tScan(a, io, tmp.dir, .posix);
    defer inv.deinit(a);
    try testing.expectEqual(RecordReason.malformed_encoding, tFind(inv, "_v2/units/u-A").?.reason);
    try testing.expectEqual(RecordReason.malformed_encoding, tFind(inv, "_v2/units/bogus").?.reason);
}

test "scan: deterministic ordering" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const a = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tWriteUnit(io, tmp.dir, "zeta/repo", "{\"tag\":\"v\",\"asset\":\"a\"}");
    try tWriteUnit(io, tmp.dir, "alpha/repo", "{\"tag\":\"v\",\"asset\":\"a\"}");
    try tWriteUnit(io, tmp.dir, "mid/repo", "{\"tag\":\"v\",\"asset\":\"a\"}");
    var inv = try tScan(a, io, tmp.dir, .posix);
    defer inv.deinit(a);
    try testing.expectEqual(@as(usize, 3), inv.records.len);
    try testing.expectEqualStrings("alpha/repo", inv.records[0].id.?);
    try testing.expectEqualStrings("mid/repo", inv.records[1].id.?);
    try testing.expectEqualStrings("zeta/repo", inv.records[2].id.?);
}

test "v2 build path frees all allocations under induced OOM" {
    try testing.checkAllAllocationFailures(testing.allocator, tCheckV2, .{t_v2_ownerrepo});
}

test "v1 build path frees all allocations under induced OOM" {
    try testing.checkAllAllocationFailures(testing.allocator, tCheckV1, .{
        "{\"tag\":\"v1\",\"asset\":\"a.tgz\",\"bins\":[\"bin/tool\"],\"apps\":[\"share/app\"]}",
    });
}

fn tCountReason(inv: Inventory, reason: RecordReason) usize {
    var n: usize = 0;
    for (inv.records) |r| {
        if (r.reason == reason) n += 1;
    }
    return n;
}

test "url validation resists percent-encoded and userinfo bypasses" {
    // Percent-encoded credential parameter name (%58 == 'X').
    try testing.expect(!isSafeNonCredentialUrl("https://ex.com/a?%58-Amz-Signature=z"));
    // Encoded userinfo separator is still recognized by the parser.
    try testing.expect(!isSafeNonCredentialUrl("https://user%40h:pw@ex.com/a"));
    // Malformed / no host.
    try testing.expect(!isSafeNonCredentialUrl("https://"));
    try testing.expect(!isSafeNonCredentialUrl("http:///nohost"));
    // Fragment smuggling rejected.
    try testing.expect(!isSafeNonCredentialUrl("https://ex.com/a#frag"));
    // A clean URL still passes.
    try testing.expect(isSafeNonCredentialUrl("https://ex.com/a/b.tgz?ref=main"));
}

test "url validation: strict authority regressions" {
    // Whitespace in the authority.
    try testing.expect(!isSafeNonCredentialUrl("https://exa mple.com/a"));
    // Percent-encoded userinfo `@` hidden in the authority.
    try testing.expect(!isSafeNonCredentialUrl("https://user%40example.com/a"));
    // Junk after a bracketed IPv6 literal.
    try testing.expect(!isSafeNonCredentialUrl("https://[::1]junk/a"));
    // Malformed percent escapes anywhere in path/query.
    try testing.expect(!isSafeNonCredentialUrl("https://ex.com/a?x=%"));
    try testing.expect(!isSafeNonCredentialUrl("https://ex.com/a?x=%2"));
    try testing.expect(!isSafeNonCredentialUrl("https://ex.com/a?x=%zz"));
    // Non-numeric / malformed port.
    try testing.expect(!isSafeNonCredentialUrl("https://ex.com:pt/a"));
    // Percent-decoded credential name variant (%78 == 'x').
    try testing.expect(!isSafeNonCredentialUrl("https://ex.com/a?%78-Goog-Credential=k"));
    // Valid DNS host with an optional numeric port.
    try testing.expect(isSafeNonCredentialUrl("https://ex.com:8443/a/b.tgz"));
    // Valid IPv4 host.
    try testing.expect(isSafeNonCredentialUrl("https://192.168.0.1/a"));
    // Valid fully bracketed IPv6 literal, with and without a numeric port.
    try testing.expect(isSafeNonCredentialUrl("https://[::1]/a"));
    try testing.expect(isSafeNonCredentialUrl("https://[2001:db8::1]:8080/a"));
}

test "scan: duplicate id includes unsupported and corrupt participants" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const a = testing.allocator;
    const io = testing.io;
    // OK v1 vs unsupported v2 at the same id.
    {
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        try tWriteUnit(io, tmp.dir, "owner/repo", "{\"tag\":\"v\",\"asset\":\"a\"}");
        try tWriteUnit(io, tmp.dir, "_v2/units/u-owner/u-repo/_unit", "{\"schema\":99}");
        var inv = try tScan(a, io, tmp.dir, .posix);
        defer inv.deinit(a);
        try testing.expectEqual(Status.conflict, tFind(inv, "owner/repo").?.status);
        const v2 = tFind(inv, "_v2/units/u-owner/u-repo/_unit").?;
        try testing.expectEqual(Status.unsupported, v2.status);
        try testing.expectEqual(RecordReason.unsupported_schema, v2.reason);
    }
    // OK v1 vs corrupt v2 (v1 manifest in v2 location) at the same id.
    {
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        try tWriteUnit(io, tmp.dir, "owner/repo", "{\"tag\":\"v\",\"asset\":\"a\"}");
        try tWriteUnit(io, tmp.dir, "_v2/units/u-owner/u-repo/_unit", "{\"tag\":\"v1\",\"asset\":\"a\"}");
        var inv = try tScan(a, io, tmp.dir, .posix);
        defer inv.deinit(a);
        try testing.expectEqual(Status.conflict, tFind(inv, "owner/repo").?.status);
        const v2 = tFind(inv, "_v2/units/u-owner/u-repo/_unit").?;
        try testing.expectEqual(Status.corrupt, v2.status);
        try testing.expectEqual(RecordReason.wrong_layout, v2.reason);
    }
}

test "scan: deep marker-free v2 chain is bounded with path_too_long" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const a = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const seg = "u-" ++ ("a" ** 100);
    var pb: std.ArrayListUnmanaged(u8) = .empty;
    defer pb.deinit(a);
    try pb.appendSlice(a, "_v2/units");
    for (0..12) |_| {
        try pb.append(a, '/');
        try pb.appendSlice(a, seg);
    }
    try tmp.dir.createDirPath(io, pb.items);

    var inv = try tScan(a, io, tmp.dir, .posix);
    defer inv.deinit(a);
    // The branch is cut off with exactly one path_too_long record; the scan
    // completes (no unbounded recursion).
    try testing.expect(tCountReason(inv, .path_too_long) >= 1);
}

test "scan: derived command names validated after normalization" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const a = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    // Empty derived name from a bare ".wasm" command.
    try tWriteUnit(io, tmp.dir, "_v2/units/u-a/u-empty/_unit",
        \\{"schema":2,"layout_generation":2,"id":"a/empty","source":{"kind":"github","owner":"a","repo":"empty"},"config":{},"resolved":{},"commands":[{"name":".wasm","relative_target":"bin/x"}],"apps":[],"verification":{}}
    );
    // A reserved raw command name is rejected.
    try tWriteUnit(io, tmp.dir, "_v2/units/u-a/u-res/_unit",
        \\{"schema":2,"layout_generation":2,"id":"a/res","source":{"kind":"github","owner":"a","repo":"res"},"config":{},"resolved":{},"commands":[{"name":"aux.exe","relative_target":"bin/x"}],"apps":[],"verification":{}}
    );
    // Valid .wasm derivation stays ok.
    try tWriteUnit(io, tmp.dir, "_v2/units/u-a/u-ok/_unit",
        \\{"schema":2,"layout_generation":2,"id":"a/ok","source":{"kind":"github","owner":"a","repo":"ok"},"config":{},"resolved":{"tag":"v","asset":"a.tgz"},"commands":[{"name":"thing.wasm","relative_target":"bin/thing.wasm","kind":"wasm"}],"apps":[],"verification":{"result":"none"}}
    );
    var inv = try tScan(a, io, tmp.dir, .windows);
    defer inv.deinit(a);
    try testing.expectEqual(RecordReason.unsafe_command_name, tFind(inv, "_v2/units/u-a/u-empty/_unit").?.reason);
    try testing.expectEqual(RecordReason.unsafe_command_name, tFind(inv, "_v2/units/u-a/u-res/_unit").?.reason);
    try testing.expectEqual(Status.ok, tFind(inv, "_v2/units/u-a/u-ok/_unit").?.status);
}

test "scan: v1 windows .exe derivation" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const a = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tWriteUnit(io, tmp.dir, "owner/repo",
        \\{"tag":"v","asset":"a","bins":["bin\\app.exe"],"apps":[]}
    );
    var inv = try tScan(a, io, tmp.dir, .windows);
    defer inv.deinit(a);
    const rec = tFind(inv, "owner/repo").?;
    try testing.expectEqual(Status.ok, rec.status);
    try testing.expectEqualStrings("app", rec.commands[0].name);
}

test "scan: legacy archive-content symlink yields no spurious record" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const a = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tWriteUnit(io, tmp.dir, "owner/repo", "{\"tag\":\"v\",\"asset\":\"a\"}");
    // A symlink among the extracted content must not be classified as a unit.
    try tmp.dir.symLink(io, "/etc", "owner/repo/content-link", .{});
    try tmp.dir.symLink(io, "/tmp", "owner/link-repo", .{});

    var inv = try tScan(a, io, tmp.dir, .posix);
    defer inv.deinit(a);
    try testing.expectEqual(@as(usize, 1), inv.records.len);
    try testing.expectEqualStrings("owner/repo", inv.records[0].path);
    try testing.expect(tFind(inv, "owner/repo/content-link") == null);
    try testing.expect(tFind(inv, "owner/link-repo") == null);
}

test "scan: v2 config alias/selected duplicates and minisign validation" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const a = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tWriteUnit(io, tmp.dir, "_v2/units/u-c/u-afrom/_unit",
        \\{"schema":2,"layout_generation":2,"id":"c/afrom","source":{"kind":"github","owner":"c","repo":"afrom"},"config":{"aliases":[{"from":"a","to":"b"},{"from":"a","to":"d"}]},"resolved":{},"commands":[],"apps":[],"verification":{}}
    );
    try tWriteUnit(io, tmp.dir, "_v2/units/u-c/u-sel/_unit",
        \\{"schema":2,"layout_generation":2,"id":"c/sel","source":{"kind":"github","owner":"c","repo":"sel"},"config":{"selected_commands":["x","x"]},"resolved":{},"commands":[],"apps":[],"verification":{}}
    );
    try tWriteUnit(io, tmp.dir, "_v2/units/u-c/u-mini/_unit",
        \\{"schema":2,"layout_generation":2,"id":"c/mini","source":{"kind":"github","owner":"c","repo":"mini"},"config":{"minisign":"notakey"},"resolved":{},"commands":[],"apps":[],"verification":{}}
    );
    try tWriteUnit(io, tmp.dir, "_v2/units/u-c/u-vok/_unit",
        \\{"schema":2,"layout_generation":2,"id":"c/vok","source":{"kind":"github","owner":"c","repo":"vok"},"config":{"minisign":"RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3"},"resolved":{"tag":"v","asset":"a.tgz"},"commands":[],"apps":[],"verification":{"result":"none"}}
    );
    var inv = try tScan(a, io, tmp.dir, .posix);
    defer inv.deinit(a);
    try testing.expectEqual(RecordReason.invalid_config, tFind(inv, "_v2/units/u-c/u-afrom/_unit").?.reason);
    try testing.expectEqual(RecordReason.invalid_config, tFind(inv, "_v2/units/u-c/u-sel/_unit").?.reason);
    try testing.expectEqual(RecordReason.invalid_config, tFind(inv, "_v2/units/u-c/u-mini/_unit").?.reason);
    try testing.expectEqual(Status.ok, tFind(inv, "_v2/units/u-c/u-vok/_unit").?.status);
}

test "scan: v2 source contradictions, api_asset_id and bounded strings" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const a = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    // github with a url is contradictory.
    try tWriteUnit(io, tmp.dir, "_v2/units/u-s/u-ghurl/_unit",
        \\{"schema":2,"layout_generation":2,"id":"s/ghurl","source":{"kind":"github","owner":"o","repo":"r","url":"https://ex.com/a"},"config":{},"resolved":{},"commands":[],"apps":[],"verification":{}}
    );
    // generic_url with owner/repo is contradictory.
    try tWriteUnit(io, tmp.dir, "_v2/units/u-s/u-urlrepo/_unit",
        \\{"schema":2,"layout_generation":2,"id":"s/urlrepo","source":{"kind":"generic_url","url":"https://ex.com/a","owner":"o"},"config":{},"resolved":{},"commands":[],"apps":[],"verification":{}}
    );
    // api_asset_id must be positive.
    try tWriteUnit(io, tmp.dir, "_v2/units/u-s/u-aid/_unit",
        \\{"schema":2,"layout_generation":2,"id":"s/aid","source":{"kind":"github","owner":"o","repo":"r"},"config":{},"resolved":{"api_asset_id":0},"commands":[],"apps":[],"verification":{}}
    );
    var inv = try tScan(a, io, tmp.dir, .posix);
    defer inv.deinit(a);
    try testing.expectEqual(RecordReason.invalid_source, tFind(inv, "_v2/units/u-s/u-ghurl/_unit").?.reason);
    try testing.expectEqual(RecordReason.invalid_source, tFind(inv, "_v2/units/u-s/u-urlrepo/_unit").?.reason);
    try testing.expectEqual(RecordReason.invalid_resolved, tFind(inv, "_v2/units/u-s/u-aid/_unit").?.reason);
}

test "scan: symlinked v2 marker keeps id and blocks legacy duplicate" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const a = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    // A healthy legacy unit at owner/repo.
    try tWriteUnit(io, tmp.dir, "owner/repo", "{\"tag\":\"v\",\"asset\":\"a.tgz\"}");
    // A v2 marker at the SAME id that is a symlink (never followed, but its id
    // must still be recovered so it participates in duplicate-id blocking).
    try tmp.dir.createDirPath(io, "_v2/units/u-owner/u-repo");
    try tmp.dir.symLink(io, "/tmp", "_v2/units/u-owner/u-repo/_unit", .{});

    var inv = try tScan(a, io, tmp.dir, .posix);
    defer inv.deinit(a);
    const legacy = tFind(inv, "owner/repo").?;
    try testing.expectEqual(Status.conflict, legacy.status);
    try testing.expectEqual(RecordReason.duplicate_id, legacy.reason);
    const v2 = tFind(inv, "_v2/units/u-owner/u-repo/_unit").?;
    try testing.expectEqual(Status.corrupt, v2.status);
    try testing.expectEqual(RecordReason.symlinked_path, v2.reason);
    try testing.expectEqualStrings("owner/repo", v2.id.?);
}

test "scan: v2 command names must be ascii and length-bounded" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const a = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    // A non-ASCII (Unicode) command name is rejected.
    try tWriteUnit(io, tmp.dir, "_v2/units/u-u/u-uni/_unit",
        \\{"schema":2,"layout_generation":2,"id":"u/uni","source":{"kind":"github","owner":"u","repo":"uni"},"config":{},"resolved":{"tag":"v","asset":"a.tgz"},"commands":[{"name":"t\u00f3ol","relative_target":"bin/x"}],"apps":[],"verification":{"result":"none"}}
    );
    // An over-length (>240) command name is rejected (companion-suffix headroom).
    var namebuf: [241]u8 = undefined;
    @memset(&namebuf, 'a');
    const body = try std.fmt.allocPrint(a, "{{\"schema\":2,\"layout_generation\":2,\"id\":\"u/long\",\"source\":{{\"kind\":\"github\",\"owner\":\"u\",\"repo\":\"long\"}},\"config\":{{}},\"resolved\":{{\"tag\":\"v\",\"asset\":\"a.tgz\"}},\"commands\":[{{\"name\":\"{s}\",\"relative_target\":\"bin/x\"}}],\"apps\":[],\"verification\":{{\"result\":\"none\"}}}}", .{namebuf});
    defer a.free(body);
    try tWriteUnit(io, tmp.dir, "_v2/units/u-u/u-long/_unit", body);

    var inv = try tScan(a, io, tmp.dir, .posix);
    defer inv.deinit(a);
    try testing.expectEqual(RecordReason.unsafe_command_name, tFind(inv, "_v2/units/u-u/u-uni/_unit").?.reason);
    try testing.expectEqual(RecordReason.unsafe_command_name, tFind(inv, "_v2/units/u-u/u-long/_unit").?.reason);
}

test "scan: v2 resolved minimum provenance and config correspondence" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const a = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    // Empty resolved for a github source is corrupt (no artifact identity).
    try tWriteUnit(io, tmp.dir, "_v2/units/u-r/u-empty/_unit",
        \\{"schema":2,"layout_generation":2,"id":"r/empty","source":{"kind":"github","owner":"r","repo":"empty"},"config":{},"resolved":{},"commands":[],"apps":[],"verification":{"result":"none"}}
    );
    // Alias `from` that does not name an available command is dangling.
    try tWriteUnit(io, tmp.dir, "_v2/units/u-r/u-dfrom/_unit",
        \\{"schema":2,"layout_generation":2,"id":"r/dfrom","source":{"kind":"github","owner":"r","repo":"dfrom"},"config":{"aliases":[{"from":"nope","to":"pub"}]},"resolved":{"tag":"v","asset":"a.tgz"},"commands":[{"name":"pub","relative_target":"bin/pub"}],"apps":[],"verification":{"result":"none"}}
    );
    // Alias `to` that is not a resulting published command is dangling.
    try tWriteUnit(io, tmp.dir, "_v2/units/u-r/u-dto/_unit",
        \\{"schema":2,"layout_generation":2,"id":"r/dto","source":{"kind":"github","owner":"r","repo":"dto"},"config":{"aliases":[{"from":"pub","to":"nope"}]},"resolved":{"tag":"v","asset":"a.tgz"},"commands":[{"name":"pub","source_name":"pub","relative_target":"bin/pub"}],"apps":[],"verification":{"result":"none"}}
    );
    // Selected command that does not correspond to any available command.
    try tWriteUnit(io, tmp.dir, "_v2/units/u-r/u-dsel/_unit",
        \\{"schema":2,"layout_generation":2,"id":"r/dsel","source":{"kind":"github","owner":"r","repo":"dsel"},"config":{"selected_commands":["ghost"]},"resolved":{"tag":"v","asset":"a.tgz"},"commands":[{"name":"pub","relative_target":"bin/pub"}],"apps":[],"verification":{"result":"none"}}
    );
    // Fully consistent aliases + selected + commands is OK.
    try tWriteUnit(io, tmp.dir, "_v2/units/u-r/u-good/_unit",
        \\{"schema":2,"layout_generation":2,"id":"r/good","source":{"kind":"github","owner":"r","repo":"good"},"config":{"aliases":[{"from":"src","to":"pub"}],"selected_commands":["pub"]},"resolved":{"tag":"v","asset":"a.tgz"},"commands":[{"name":"pub","source_name":"src","relative_target":"bin/pub"}],"apps":[],"verification":{"result":"none"}}
    );
    var inv = try tScan(a, io, tmp.dir, .posix);
    defer inv.deinit(a);
    try testing.expectEqual(RecordReason.invalid_resolved, tFind(inv, "_v2/units/u-r/u-empty/_unit").?.reason);
    try testing.expectEqual(RecordReason.invalid_config, tFind(inv, "_v2/units/u-r/u-dfrom/_unit").?.reason);
    try testing.expectEqual(RecordReason.invalid_config, tFind(inv, "_v2/units/u-r/u-dto/_unit").?.reason);
    try testing.expectEqual(RecordReason.invalid_config, tFind(inv, "_v2/units/u-r/u-dsel/_unit").?.reason);
    try testing.expectEqual(Status.ok, tFind(inv, "_v2/units/u-r/u-good/_unit").?.status);
}

test "scan: v2 verification requires a non-empty result" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const a = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    // Missing result entirely.
    try tWriteUnit(io, tmp.dir, "_v2/units/u-v/u-nores/_unit",
        \\{"schema":2,"layout_generation":2,"id":"v/nores","source":{"kind":"github","owner":"v","repo":"nores"},"config":{},"resolved":{"tag":"v","asset":"a.tgz"},"commands":[],"apps":[],"verification":{}}
    );
    // An invalid verification minisign key.
    try tWriteUnit(io, tmp.dir, "_v2/units/u-v/u-badmini/_unit",
        \\{"schema":2,"layout_generation":2,"id":"v/badmini","source":{"kind":"github","owner":"v","repo":"badmini"},"config":{},"resolved":{"tag":"v","asset":"a.tgz"},"commands":[],"apps":[],"verification":{"result":"ok","minisign":"nope"}}
    );
    var inv = try tScan(a, io, tmp.dir, .posix);
    defer inv.deinit(a);
    try testing.expectEqual(RecordReason.invalid_verification, tFind(inv, "_v2/units/u-v/u-nores/_unit").?.reason);
    try testing.expectEqual(RecordReason.invalid_verification, tFind(inv, "_v2/units/u-v/u-badmini/_unit").?.reason);
}

fn tNestedPolicy(a: Allocator, depth: usize) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(a);
    for (0..depth) |_| try buf.appendSlice(a, "{\"a\":");
    try buf.appendSlice(a, "1");
    for (0..depth) |_| try buf.append(a, '}');
    return buf.toOwnedSlice(a);
}

fn tPolicyBody(a: Allocator, id: []const u8, owner: []const u8, repo: []const u8, depth: usize) ![]u8 {
    const policy = try tNestedPolicy(a, depth);
    defer a.free(policy);
    return std.fmt.allocPrint(a, "{{\"schema\":2,\"layout_generation\":2,\"id\":\"{s}\",\"source\":{{\"kind\":\"github\",\"owner\":\"{s}\",\"repo\":\"{s}\"}},\"config\":{{\"verification_policy\":{s}}},\"resolved\":{{\"tag\":\"v\",\"asset\":\"a.tgz\"}},\"commands\":[],\"apps\":[],\"verification\":{{\"result\":\"none\"}}}}", .{ id, owner, repo, policy });
}

test "scan: verification policy nesting depth is bounded" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const a = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    // A policy nested exactly to the bound is accepted and retained.
    const ok_body = try tPolicyBody(a, "p/ok", "p", "ok", max_policy_depth);
    defer a.free(ok_body);
    try tWriteUnit(io, tmp.dir, "_v2/units/u-p/u-ok/_unit", ok_body);
    // A policy nested beyond the bound is corrupt, never crashing the serializer.
    const deep_body = try tPolicyBody(a, "p/deep", "p", "deep", max_policy_depth + 8);
    defer a.free(deep_body);
    try tWriteUnit(io, tmp.dir, "_v2/units/u-p/u-deep/_unit", deep_body);

    var inv = try tScan(a, io, tmp.dir, .posix);
    defer inv.deinit(a);
    try testing.expectEqual(Status.ok, tFind(inv, "_v2/units/u-p/u-ok/_unit").?.status);
    try testing.expectEqual(RecordReason.invalid_config, tFind(inv, "_v2/units/u-p/u-deep/_unit").?.reason);
}

test "scan: future layout with changed field shapes is unsupported" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const a = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    // schema:2 but a future layout number, AND incompatible field shapes that
    // would fail typed WireV2 parsing. The raw-root layout probe must classify
    // it by layout number (unsupported), not as malformed_json.
    try tWriteUnit(io, tmp.dir, "_v2/units/u-f/u-r/_unit",
        \\{"schema":2,"layout_generation":3,"id":"f/r","source":12345,"config":"nope","commands":"bad","resolved":7}
    );
    var inv = try tScan(a, io, tmp.dir, .posix);
    defer inv.deinit(a);
    const rec = tFind(inv, "_v2/units/u-f/u-r/_unit").?;
    try testing.expectEqual(Status.unsupported, rec.status);
    try testing.expectEqual(RecordReason.unsupported_layout, rec.reason);
}

test "scan: non-directory tools root fails closed" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const a = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "notadir", .data = "x" });
    var buf: [Dir.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(io, &buf);
    const path = try std.fmt.allocPrint(a, "{s}/notadir", .{buf[0..len]});
    defer a.free(path);
    try testing.expectError(error.NotDir, scan(a, io, path, .{}));
}

test "scan: non-directory structural nodes are corrupt" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const a = testing.allocator;
    const io = testing.io;
    // A regular file at _v2.
    {
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        try tmp.dir.writeFile(io, .{ .sub_path = "_v2", .data = "x" });
        var inv = try tScan(a, io, tmp.dir, .posix);
        defer inv.deinit(a);
        try testing.expectEqual(RecordReason.not_a_directory, tFind(inv, "_v2").?.reason);
    }
    // A regular file at _v2/units.
    {
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        try tmp.dir.createDirPath(io, "_v2");
        try tmp.dir.writeFile(io, .{ .sub_path = "_v2/units", .data = "x" });
        var inv = try tScan(a, io, tmp.dir, .posix);
        defer inv.deinit(a);
        try testing.expectEqual(RecordReason.not_a_directory, tFind(inv, "_v2/units").?.reason);
    }
    // A regular file at an encoded node.
    {
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        try tmp.dir.createDirPath(io, "_v2/units");
        try tmp.dir.writeFile(io, .{ .sub_path = "_v2/units/u-a", .data = "x" });
        var inv = try tScan(a, io, tmp.dir, .posix);
        defer inv.deinit(a);
        try testing.expectEqual(RecordReason.not_a_directory, tFind(inv, "_v2/units/u-a").?.reason);
    }
    // A regular file at the _unit marker: corrupt, and the id is still recovered.
    {
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        try tmp.dir.createDirPath(io, "_v2/units/u-a");
        try tmp.dir.writeFile(io, .{ .sub_path = "_v2/units/u-a/_unit", .data = "x" });
        var inv = try tScan(a, io, tmp.dir, .posix);
        defer inv.deinit(a);
        const rec = tFind(inv, "_v2/units/u-a/_unit").?;
        try testing.expectEqual(RecordReason.not_a_directory, rec.reason);
        try testing.expectEqualStrings("a", rec.id.?);
    }
}
