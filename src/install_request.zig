//! Pure parsing for the planned ID-based install request grammar.
//!
//! This module deliberately has no command-line integration yet. It accepts
//! positional source/configuration tokens, allocates all normalized IDs and
//! configuration strings, and performs no I/O. Source values borrow from the
//! caller's token storage, which must therefore outlive `ParsedRequests`.

const std = @import("std");
const minisign = @import("minisign.zig");
const release = @import("release.zig");

/// Conservative limits chosen before the eventual filesystem encoding exists.
/// Keeping the whole logical ID below one common component limit leaves room
/// for encoding overhead; the segment bound still accommodates long repository
/// names while preventing unexpectedly large individual components.
pub const max_id_bytes: usize = 240;
pub const max_id_segment_bytes: usize = 100;

pub const ParseError = error{
    MissingSource,
    InvalidSource,
    LoneQueryToken,
    DuplicateQueryToken,
    QueryAfterBareKey,
    EmptyQueryToken,
    EmptyQuerySegment,
    MissingQueryEquals,
    EmptyQueryName,
    EmptyQueryValue,
    InvalidPercentEscape,
    UnknownQueryField,
    DuplicateId,
    DuplicateMinisign,
    InvalidMinisign,
    MalformedAlias,
    DuplicateAliasSource,
    DuplicateAliasPublished,
    LoneBareKey,
    DoubleBareKey,
    GenericUrlRequiresExplicitId,
    InvalidDerivedId,
    InvalidIdEmpty,
    InvalidIdTooLong,
    InvalidIdSegmentTooLong,
    InvalidIdNonAscii,
    InvalidIdEmptySegment,
    InvalidIdDotSegment,
    InvalidIdUnsafeCharacter,
    InvalidIdUnsafeSegmentEdge,
};

pub const Error = ParseError || std.mem.Allocator.Error;

pub const max_diagnostic_field_name_bytes: usize = 32;

pub const BoundedFieldName = struct {
    bytes: [max_diagnostic_field_name_bytes]u8 = [_]u8{0} ** max_diagnostic_field_name_bytes,
    len: u8 = 0,
    truncated: bool = false,

    fn init(name: []const u8) BoundedFieldName {
        var result: BoundedFieldName = .{};
        const len = @min(name.len, result.bytes.len);
        @memcpy(result.bytes[0..len], name[0..len]);
        result.len = @intCast(len);
        result.truncated = name.len > len;
        return result;
    }

    pub fn slice(self: *const BoundedFieldName) []const u8 {
        return self.bytes[0..self.len];
    }
};

/// Sensitive-safe context for a parse failure. It stores token/pair positions
/// and at most a bounded query field name; query values and key material are
/// never retained.
pub const Diagnostic = struct {
    pub const Field = union(enum) {
        none,
        source,
        query,
        id,
        alias,
        minisign,
        unknown: BoundedFieldName,
    };

    token_index: ?usize = null,
    pair_index: ?usize = null,
    field: Field = .none,

    pub fn fieldName(self: *const Diagnostic) ?[]const u8 {
        return switch (self.field) {
            .none => null,
            .source => "source",
            .query => "query",
            .id => "id",
            .alias => "alias",
            .minisign => "minisign",
            .unknown => |*name| name.slice(),
        };
    }
};

pub const IdOrigin = enum {
    explicit,
    derived,
};

pub const Alias = struct {
    source: []u8,
    published: []u8,
};

/// Source details borrow from the caller-owned token strings.
pub const Source = union(enum) {
    github_repo: release.RepoSpec,
    github_file: release.FileSpec,
    github_release_url: []const u8,
    generic_url: []const u8,
};

pub const OriginalTokens = struct {
    source: usize,
    query: ?usize = null,
    bare_minisign: ?usize = null,
};

pub const Config = struct {
    aliases: []Alias,
    minisign: ?[]u8,
};

pub const InstallRequest = struct {
    id: []u8,
    id_origin: IdOrigin,
    source: Source,
    config: Config,
    original_tokens: OriginalTokens,

    pub fn deinit(self: *InstallRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        for (self.config.aliases) |alias| {
            allocator.free(alias.source);
            allocator.free(alias.published);
        }
        allocator.free(self.config.aliases);
        if (self.config.minisign) |key| allocator.free(key);
        self.* = undefined;
    }
};

pub const ParsedRequests = struct {
    items: []InstallRequest,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *ParsedRequests) void {
        for (self.items) |*request| request.deinit(self.allocator);
        self.allocator.free(self.items);
        self.* = undefined;
    }
};

const Builder = struct {
    source: Source,
    source_is_generic: bool,
    derived_id_invalid: bool = false,
    id: ?[]u8 = null,
    id_origin: IdOrigin = .derived,
    aliases: std.ArrayListUnmanaged(Alias) = .empty,
    minisign: ?[]u8 = null,
    query_seen: bool = false,
    bare_key_seen: bool = false,
    original_tokens: OriginalTokens,

    fn deinit(self: *Builder, allocator: std.mem.Allocator) void {
        if (self.id) |id| allocator.free(id);
        for (self.aliases.items) |alias| {
            allocator.free(alias.source);
            allocator.free(alias.published);
        }
        self.aliases.deinit(allocator);
        if (self.minisign) |key| allocator.free(key);
        self.* = undefined;
    }

    fn finish(self: *Builder, allocator: std.mem.Allocator) Error!InstallRequest {
        const id = self.id orelse {
            if (self.source_is_generic) return error.GenericUrlRequiresExplicitId;
            if (self.derived_id_invalid) return error.InvalidDerivedId;
            unreachable;
        };
        const aliases = try self.aliases.toOwnedSlice(allocator);
        const request: InstallRequest = .{
            .id = id,
            .id_origin = self.id_origin,
            .source = self.source,
            .config = .{
                .aliases = aliases,
                .minisign = self.minisign,
            },
            .original_tokens = self.original_tokens,
        };
        self.id = null;
        self.minisign = null;
        self.aliases = .empty;
        return request;
    }
};

/// Parse one or more positional install request tokens.
///
/// The returned IDs, aliases, and minisign values are allocator-owned.
/// Sources borrow from `tokens`; keep those token strings alive until after
/// `ParsedRequests.deinit`.
pub fn parse(allocator: std.mem.Allocator, tokens: []const []const u8) Error!ParsedRequests {
    var diagnostic: Diagnostic = .{};
    return parseWithDiagnostic(allocator, tokens, &diagnostic);
}

/// Parse requests while retaining sensitive-safe context when an error occurs.
pub fn parseWithDiagnostic(
    allocator: std.mem.Allocator,
    tokens: []const []const u8,
    diagnostic: *Diagnostic,
) Error!ParsedRequests {
    diagnostic.* = .{};
    if (tokens.len == 0) {
        setDiagnostic(diagnostic, null, null, .source);
        return error.MissingSource;
    }

    var requests: std.ArrayListUnmanaged(InstallRequest) = .empty;
    errdefer {
        for (requests.items) |*request| request.deinit(allocator);
        requests.deinit(allocator);
    }

    var current: ?Builder = null;
    errdefer if (current) |*builder| builder.deinit(allocator);

    for (tokens, 0..) |token, token_index| {
        if (std.mem.startsWith(u8, token, "?")) {
            const builder = &(current orelse {
                setDiagnostic(diagnostic, token_index, null, .query);
                return error.LoneQueryToken;
            });
            if (builder.bare_key_seen) {
                setDiagnostic(diagnostic, token_index, null, .query);
                return error.QueryAfterBareKey;
            }
            if (builder.query_seen) {
                setDiagnostic(diagnostic, token_index, null, .query);
                return error.DuplicateQueryToken;
            }
            builder.query_seen = true;
            builder.original_tokens.query = token_index;
            try parseQueryToken(allocator, builder, token, token_index, diagnostic);
            continue;
        }

        if (minisign.looksLikePubKey(token)) {
            const builder = &(current orelse {
                setDiagnostic(diagnostic, token_index, null, .minisign);
                return error.LoneBareKey;
            });
            if (builder.bare_key_seen) {
                setDiagnostic(diagnostic, token_index, null, .minisign);
                return error.DoubleBareKey;
            }
            if (builder.minisign != null) {
                setDiagnostic(diagnostic, token_index, null, .minisign);
                return error.DuplicateMinisign;
            }
            builder.minisign = allocator.dupe(u8, token) catch |err| {
                setDiagnostic(diagnostic, token_index, null, .minisign);
                return err;
            };
            builder.bare_key_seen = true;
            builder.original_tokens.bare_minisign = token_index;
            continue;
        }

        if (current) |*builder| {
            var request = try finishBuilder(allocator, builder, diagnostic);
            errdefer request.deinit(allocator);
            requests.append(allocator, request) catch |err| {
                setDiagnostic(diagnostic, request.original_tokens.source, null, .source);
                return err;
            };
            current = null;
        }
        current = try startRequest(allocator, token, token_index, diagnostic);
    }

    if (current) |*builder| {
        var request = try finishBuilder(allocator, builder, diagnostic);
        errdefer request.deinit(allocator);
        requests.append(allocator, request) catch |err| {
            setDiagnostic(diagnostic, request.original_tokens.source, null, .source);
            return err;
        };
        current = null;
    }

    const owned = requests.toOwnedSlice(allocator) catch |err| {
        const source_index = requests.items[requests.items.len - 1].original_tokens.source;
        setDiagnostic(diagnostic, source_index, null, .source);
        return err;
    };
    return .{ .items = owned, .allocator = allocator };
}

fn setDiagnostic(
    diagnostic: *Diagnostic,
    token_index: ?usize,
    pair_index: ?usize,
    field: Diagnostic.Field,
) void {
    diagnostic.* = .{
        .token_index = token_index,
        .pair_index = pair_index,
        .field = field,
    };
}

fn fieldForName(name: []const u8) Diagnostic.Field {
    if (std.mem.eql(u8, name, "id")) return .id;
    if (std.mem.eql(u8, name, "alias")) return .alias;
    if (std.mem.eql(u8, name, "minisign")) return .minisign;
    return .{ .unknown = BoundedFieldName.init(name) };
}

fn finishBuilder(
    allocator: std.mem.Allocator,
    builder: *Builder,
    diagnostic: *Diagnostic,
) Error!InstallRequest {
    return builder.finish(allocator) catch |err| {
        setDiagnostic(diagnostic, builder.original_tokens.source, null, .id);
        return err;
    };
}

fn startRequest(
    allocator: std.mem.Allocator,
    token: []const u8,
    token_index: usize,
    diagnostic: *Diagnostic,
) Error!Builder {
    if (!std.mem.startsWith(u8, token, "http://") and
        !std.mem.startsWith(u8, token, "https://") and
        std.mem.indexOfScalar(u8, token, '?') != null)
    {
        setDiagnostic(diagnostic, token_index, null, .source);
        return error.InvalidSource;
    }

    const classified = release.classifyArg(token) catch {
        setDiagnostic(diagnostic, token_index, null, .source);
        return error.InvalidSource;
    };
    var builder: Builder = undefined;
    switch (classified) {
        .repo_spec => |repo| {
            builder = .{
                .source = .{ .github_repo = repo },
                .source_is_generic = false,
                .original_tokens = .{ .source = token_index },
            };
            builder.id = canonicalGitHubId(allocator, repo.owner, repo.repo) catch |err| switch (err) {
                error.OutOfMemory => {
                    setDiagnostic(diagnostic, token_index, null, .id);
                    return error.OutOfMemory;
                },
                else => blk: {
                    builder.derived_id_invalid = true;
                    break :blk null;
                },
            };
        },
        .file_spec => |file| {
            builder = .{
                .source = .{ .github_file = file },
                .source_is_generic = false,
                .original_tokens = .{ .source = token_index },
            };
            builder.id = canonicalGitHubId(allocator, file.owner, file.repo) catch |err| switch (err) {
                error.OutOfMemory => {
                    setDiagnostic(diagnostic, token_index, null, .id);
                    return error.OutOfMemory;
                },
                else => blk: {
                    builder.derived_id_invalid = true;
                    break :blk null;
                },
            };
        },
        .url => |url| {
            const parsed = release.parseGitHubReleaseUrl(allocator, url) catch |err| {
                setDiagnostic(diagnostic, token_index, null, .source);
                return err;
            };
            if (parsed) |github| {
                defer github.deinit(allocator);
                builder = .{
                    .source = .{ .github_release_url = url },
                    .source_is_generic = false,
                    .original_tokens = .{ .source = token_index },
                };
                builder.id = canonicalGitHubId(allocator, github.owner, github.repo) catch |err| switch (err) {
                    error.OutOfMemory => {
                        setDiagnostic(diagnostic, token_index, null, .id);
                        return error.OutOfMemory;
                    },
                    else => blk: {
                        builder.derived_id_invalid = true;
                        break :blk null;
                    },
                };
            } else {
                builder = .{
                    .source = .{ .generic_url = url },
                    .source_is_generic = true,
                    .original_tokens = .{ .source = token_index },
                };
            }
        },
    }
    return builder;
}

fn parseQueryToken(
    allocator: std.mem.Allocator,
    builder: *Builder,
    token: []const u8,
    token_index: usize,
    diagnostic: *Diagnostic,
) Error!void {
    const query = token[1..];
    if (query.len == 0) {
        setDiagnostic(diagnostic, token_index, 0, .query);
        return error.EmptyQueryToken;
    }

    var pairs = std.mem.splitScalar(u8, query, '&');
    var pair_index: usize = 0;
    while (pairs.next()) |pair| {
        defer pair_index += 1;
        if (pair.len == 0) {
            setDiagnostic(diagnostic, token_index, pair_index, .query);
            return error.EmptyQuerySegment;
        }
        const equals = std.mem.indexOfScalar(u8, pair, '=') orelse {
            setDiagnostic(diagnostic, token_index, pair_index, fieldForName(pair));
            return error.MissingQueryEquals;
        };
        if (equals == 0) {
            setDiagnostic(diagnostic, token_index, pair_index, .query);
            return error.EmptyQueryName;
        }

        const encoded_name = pair[0..equals];
        const name = percentDecode(allocator, encoded_name) catch |err| {
            setDiagnostic(diagnostic, token_index, pair_index, fieldForName(encoded_name));
            return err;
        };
        defer allocator.free(name);
        if (name.len == 0) {
            setDiagnostic(diagnostic, token_index, pair_index, .query);
            return error.EmptyQueryName;
        }
        const field = fieldForName(name);
        if (equals + 1 == pair.len) {
            setDiagnostic(diagnostic, token_index, pair_index, field);
            return error.EmptyQueryValue;
        }

        const value = percentDecode(allocator, pair[equals + 1 ..]) catch |err| {
            setDiagnostic(diagnostic, token_index, pair_index, field);
            return err;
        };
        errdefer allocator.free(value);
        if (value.len == 0) {
            setDiagnostic(diagnostic, token_index, pair_index, field);
            return error.EmptyQueryValue;
        }

        if (std.mem.eql(u8, name, "id")) {
            if (builder.id_origin == .explicit) {
                setDiagnostic(diagnostic, token_index, pair_index, .id);
                return error.DuplicateId;
            }
            const canonical = canonicalizeId(allocator, value) catch |err| switch (err) {
                else => {
                    setDiagnostic(diagnostic, token_index, pair_index, .id);
                    return err;
                },
            };
            allocator.free(value);
            if (builder.id) |old| allocator.free(old);
            builder.id = canonical;
            builder.id_origin = .explicit;
            builder.derived_id_invalid = false;
        } else if (std.mem.eql(u8, name, "alias")) {
            addAlias(allocator, builder, value) catch |err| {
                setDiagnostic(diagnostic, token_index, pair_index, .alias);
                return err;
            };
        } else if (std.mem.eql(u8, name, "minisign")) {
            if (builder.minisign != null) {
                setDiagnostic(diagnostic, token_index, pair_index, .minisign);
                return error.DuplicateMinisign;
            }
            if (!minisign.looksLikePubKey(value)) {
                setDiagnostic(diagnostic, token_index, pair_index, .minisign);
                return error.InvalidMinisign;
            }
            builder.minisign = value;
        } else {
            setDiagnostic(diagnostic, token_index, pair_index, field);
            return error.UnknownQueryField;
        }
    }
}

fn addAlias(
    allocator: std.mem.Allocator,
    builder: *Builder,
    value: []u8,
) Error!void {
    const colon = std.mem.indexOfScalar(u8, value, ':') orelse
        return error.MalformedAlias;
    if (colon == 0 or colon + 1 == value.len) return error.MalformedAlias;
    if (std.mem.indexOfScalarPos(u8, value, colon + 1, ':') != null)
        return error.MalformedAlias;

    const source = try allocator.dupe(u8, value[0..colon]);
    errdefer allocator.free(source);
    const published = try allocator.dupe(u8, value[colon + 1 ..]);
    errdefer allocator.free(published);

    for (builder.aliases.items) |alias| {
        if (std.mem.eql(u8, alias.source, source)) return error.DuplicateAliasSource;
        if (std.mem.eql(u8, alias.published, published)) return error.DuplicateAliasPublished;
    }
    try builder.aliases.append(allocator, .{
        .source = source,
        .published = published,
    });
    allocator.free(value);
}

fn percentDecode(allocator: std.mem.Allocator, encoded: []const u8) Error![]u8 {
    const decoded = try allocator.alloc(u8, encoded.len);
    errdefer allocator.free(decoded);
    var read: usize = 0;
    var write: usize = 0;
    while (read < encoded.len) {
        if (encoded[read] != '%') {
            decoded[write] = encoded[read];
            read += 1;
            write += 1;
            continue;
        }
        if (read + 2 >= encoded.len) return error.InvalidPercentEscape;
        const hi = hexNibble(encoded[read + 1]) orelse return error.InvalidPercentEscape;
        const lo = hexNibble(encoded[read + 2]) orelse return error.InvalidPercentEscape;
        decoded[write] = (hi << 4) | lo;
        read += 3;
        write += 1;
    }
    return allocator.realloc(decoded, write);
}

fn hexNibble(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

fn canonicalGitHubId(
    allocator: std.mem.Allocator,
    owner: []const u8,
    repo: []const u8,
) Error![]u8 {
    if (!isSafeIdSegment(owner) or !isSafeIdSegment(repo))
        return error.InvalidDerivedId;
    if (owner.len > max_id_segment_bytes or repo.len > max_id_segment_bytes)
        return error.InvalidDerivedId;
    const joined = try allocator.alloc(u8, owner.len + 1 + repo.len);
    defer allocator.free(joined);
    @memcpy(joined[0..owner.len], owner);
    joined[owner.len] = '/';
    @memcpy(joined[owner.len + 1 ..], repo);
    return canonicalizeId(allocator, joined) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidDerivedId,
    };
}

/// Validate and lowercase an explicit install ID.
pub fn canonicalizeId(allocator: std.mem.Allocator, value: []const u8) Error![]u8 {
    if (value.len == 0) return error.InvalidIdEmpty;
    if (value.len > max_id_bytes) return error.InvalidIdTooLong;

    var segments = std.mem.splitScalar(u8, value, '/');
    while (segments.next()) |segment| {
        if (segment.len == 0) return error.InvalidIdEmptySegment;
        if (segment.len > max_id_segment_bytes) return error.InvalidIdSegmentTooLong;
        if (std.mem.eql(u8, segment, ".") or std.mem.eql(u8, segment, ".."))
            return error.InvalidIdDotSegment;
        for (segment) |c| {
            if (c > 0x7f) return error.InvalidIdNonAscii;
        }
        if (!std.ascii.isAlphanumeric(segment[0]) or
            !std.ascii.isAlphanumeric(segment[segment.len - 1]))
            return error.InvalidIdUnsafeSegmentEdge;
        for (segment) |c| {
            if (!(std.ascii.isAlphanumeric(c) or c == '.' or c == '_' or c == '-'))
                return error.InvalidIdUnsafeCharacter;
        }
    }

    const canonical = try allocator.alloc(u8, value.len);
    for (value, 0..) |c, i| canonical[i] = std.ascii.toLower(c);
    return canonical;
}

fn isSafeIdSegment(segment: []const u8) bool {
    if (segment.len == 0) return false;
    if (std.mem.eql(u8, segment, ".") or std.mem.eql(u8, segment, "..")) return false;
    if (!std.ascii.isAlphanumeric(segment[0]) or
        !std.ascii.isAlphanumeric(segment[segment.len - 1]))
        return false;
    for (segment) |c| {
        if (c > 0x7f) return false;
        if (!(std.ascii.isAlphanumeric(c) or c == '.' or c == '_' or c == '-'))
            return false;
    }
    return true;
}

const test_key = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";
const plus_key = "RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U";

test "legacy repo and bare minisign key normalize into one request" {
    var parsed = try parse(std.testing.allocator, &.{ "Jedisct1/MiniSign@0.12", test_key });
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 1), parsed.items.len);
    try std.testing.expectEqualStrings("jedisct1/minisign", parsed.items[0].id);
    try std.testing.expectEqual(IdOrigin.derived, parsed.items[0].id_origin);
    try std.testing.expectEqualStrings(test_key, parsed.items[0].config.minisign.?);
    try std.testing.expectEqual(@as(?usize, 1), parsed.items[0].original_tokens.bare_minisign);
}

test "query parses explicit id, ordered aliases, and minisign" {
    var parsed = try parse(std.testing.allocator, &.{
        "cataggar/zig@v1",
        "?id=ZigB&alias=zig:zigb&alias=zls:zlsb&minisign=" ++ test_key,
    });
    defer parsed.deinit();
    const request = &parsed.items[0];
    try std.testing.expectEqualStrings("zigb", request.id);
    try std.testing.expectEqual(IdOrigin.explicit, request.id_origin);
    try std.testing.expectEqual(@as(usize, 2), request.config.aliases.len);
    try std.testing.expectEqualStrings("zig", request.config.aliases[0].source);
    try std.testing.expectEqualStrings("zigb", request.config.aliases[0].published);
    try std.testing.expectEqualStrings("zls", request.config.aliases[1].source);
    try std.testing.expectEqualStrings("zlsb", request.config.aliases[1].published);
    try std.testing.expectEqualStrings(test_key, request.config.minisign.?);
}

test "multiple request boundaries remain unambiguous" {
    var parsed = try parse(std.testing.allocator, &.{
        "Owner/Repo@v1",
        "?id=first",
        test_key,
        "Owner/Repo/file.zip@v2",
        "?id=second&alias=tool:tool2",
        "third/repo",
    });
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 3), parsed.items.len);
    try std.testing.expectEqualStrings("first", parsed.items[0].id);
    try std.testing.expectEqualStrings(test_key, parsed.items[0].config.minisign.?);
    try std.testing.expectEqualStrings("second", parsed.items[1].id);
    try std.testing.expectEqualStrings("third/repo", parsed.items[2].id);
}

test "percent decoding is RFC3986 and alias semantics run after decoding" {
    var parsed = try parse(std.testing.allocator, &.{
        "owner/repo",
        "?id=Tools%2FZig&alias=zig%3Azigb&alias=percent:%25name&minisign=" ++ plus_key,
    });
    defer parsed.deinit();
    try std.testing.expectEqualStrings("tools/zig", parsed.items[0].id);
    try std.testing.expectEqualStrings("zig", parsed.items[0].config.aliases[0].source);
    try std.testing.expectEqualStrings("zigb", parsed.items[0].config.aliases[0].published);
    try std.testing.expectEqualStrings("%name", parsed.items[0].config.aliases[1].published);
    try std.testing.expectEqualStrings(plus_key, parsed.items[0].config.minisign.?);
}

test "query pairs split at first equals" {
    var parsed = try parse(std.testing.allocator, &.{
        "owner/repo",
        "?alias=tool:published=name",
    });
    defer parsed.deinit();
    try std.testing.expectEqualStrings("published=name", parsed.items[0].config.aliases[0].published);
}

test "canonical GitHub release URLs derive lowercase IDs" {
    var parsed = try parse(std.testing.allocator, &.{
        "https://github.com/Owner/Repo/releases/download/v1/tool.tar.gz",
    });
    defer parsed.deinit();
    try std.testing.expectEqualStrings("owner/repo", parsed.items[0].id);
    switch (parsed.items[0].source) {
        .github_release_url => {},
        else => return error.TestUnexpectedResult,
    }
}

test "generic URLs require explicit IDs and explicit IDs override GitHub derivation" {
    try std.testing.expectError(
        error.GenericUrlRequiresExplicitId,
        parse(std.testing.allocator, &.{"https://example.com/tool.tar.gz"}),
    );
    var generic = try parse(std.testing.allocator, &.{
        "https://example.com/tool.tar.gz",
        "?id=Example_Tool",
    });
    defer generic.deinit();
    try std.testing.expectEqualStrings("example_tool", generic.items[0].id);
    try std.testing.expectEqual(@as(usize, 0), generic.items[0].config.aliases.len);

    var github = try parse(std.testing.allocator, &.{
        "Owner/Repo/file.zip",
        "?id=custom",
    });
    defer github.deinit();
    try std.testing.expectEqualStrings("custom", github.items[0].id);
}

test "configuration output owns decoded strings" {
    var query = [_]u8{ '?', 'i', 'd', '=', 'O', 'w', 'n', 'e', 'd', '&', 'a', 'l', 'i', 'a', 's', '=', 'a', ':', 'b' };
    var parsed = try parse(std.testing.allocator, &.{ "owner/repo", query[0..] });
    defer parsed.deinit();
    @memset(&query, 'x');
    try std.testing.expectEqualStrings("owned", parsed.items[0].id);
    try std.testing.expectEqualStrings("a", parsed.items[0].config.aliases[0].source);
    try std.testing.expectEqualStrings("b", parsed.items[0].config.aliases[0].published);
}

test "query token structural errors are typed" {
    try std.testing.expectError(error.MissingSource, parse(std.testing.allocator, &.{}));
    try std.testing.expectError(error.LoneQueryToken, parse(std.testing.allocator, &.{"?id=x"}));
    try std.testing.expectError(error.EmptyQueryToken, parse(std.testing.allocator, &.{ "o/r", "?" }));
    try std.testing.expectError(error.DuplicateQueryToken, parse(std.testing.allocator, &.{ "o/r", "?id=x", "?alias=a:b" }));
    try std.testing.expectError(error.EmptyQuerySegment, parse(std.testing.allocator, &.{ "o/r", "?id=x&&alias=a:b" }));
    try std.testing.expectError(error.MissingQueryEquals, parse(std.testing.allocator, &.{ "o/r", "?id" }));
    try std.testing.expectError(error.EmptyQueryName, parse(std.testing.allocator, &.{ "o/r", "?=x" }));
    try std.testing.expectError(error.EmptyQueryValue, parse(std.testing.allocator, &.{ "o/r", "?id=" }));
    try std.testing.expectError(error.UnknownQueryField, parse(std.testing.allocator, &.{ "o/r", "?typo=x" }));
    try std.testing.expectError(error.DuplicateId, parse(std.testing.allocator, &.{ "o/r", "?id=x&id=y" }));
    try std.testing.expectError(error.DuplicateMinisign, parse(std.testing.allocator, &.{
        "o/r",
        "?minisign=" ++ test_key ++ "&minisign=" ++ plus_key,
    }));
    try std.testing.expectError(error.InvalidSource, parse(std.testing.allocator, &.{ "o/r?id=x", "?id=safe" }));
}

test "invalid percent escapes are rejected and lowercase hex works" {
    try std.testing.expectError(error.InvalidPercentEscape, parse(std.testing.allocator, &.{ "o/r", "?id=x%" }));
    try std.testing.expectError(error.InvalidPercentEscape, parse(std.testing.allocator, &.{ "o/r", "?id=x%2" }));
    try std.testing.expectError(error.InvalidPercentEscape, parse(std.testing.allocator, &.{ "o/r", "?id=x%2g" }));
    var parsed = try parse(std.testing.allocator, &.{ "o/r", "?id=one%2ftwo" });
    defer parsed.deinit();
    try std.testing.expectEqualStrings("one/two", parsed.items[0].id);
}

test "bare key errors and ordering are typed" {
    try std.testing.expectError(error.LoneBareKey, parse(std.testing.allocator, &.{test_key}));
    try std.testing.expectError(error.DoubleBareKey, parse(std.testing.allocator, &.{ "o/r", test_key, plus_key }));
    try std.testing.expectError(error.DuplicateMinisign, parse(std.testing.allocator, &.{ "o/r", "?minisign=" ++ plus_key, test_key }));
    try std.testing.expectError(error.QueryAfterBareKey, parse(std.testing.allocator, &.{ "o/r", test_key, "?id=x" }));
}

test "query minisign uses the bare-key structural policy and preserves plus" {
    var parsed = try parse(std.testing.allocator, &.{
        "o/r",
        "?minisign=" ++ plus_key,
    });
    defer parsed.deinit();
    try std.testing.expectEqualStrings(plus_key, parsed.items[0].config.minisign.?);
    try std.testing.expectError(error.InvalidMinisign, parse(std.testing.allocator, &.{
        "o/r",
        "?minisign=base64+material==",
    }));
}

test "diagnostic identifies a later request query field without retaining its value" {
    const field_name = "future-option-name-that-is-definitely-longer-than-thirty-two-bytes";
    const secret = "credential-like-secret-value";
    var diagnostic: Diagnostic = .{};
    try std.testing.expectError(error.UnknownQueryField, parseWithDiagnostic(
        std.testing.allocator,
        &.{
            "first/repo",
            "?id=first",
            "second/repo",
            "?alias=tool:renamed&" ++ field_name ++ "=" ++ secret,
        },
        &diagnostic,
    ));
    try std.testing.expectEqual(@as(?usize, 3), diagnostic.token_index);
    try std.testing.expectEqual(@as(?usize, 1), diagnostic.pair_index);
    try std.testing.expectEqualStrings(
        field_name[0..max_diagnostic_field_name_bytes],
        diagnostic.fieldName().?,
    );
    switch (diagnostic.field) {
        .unknown => |name| {
            try std.testing.expect(name.truncated);
            try std.testing.expect(std.mem.indexOf(u8, &name.bytes, secret) == null);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "diagnostic classifies invalid minisign without retaining key-like input" {
    var diagnostic: Diagnostic = .{};
    try std.testing.expectError(error.InvalidMinisign, parseWithDiagnostic(
        std.testing.allocator,
        &.{ "o/r", "?id=ok&minisign=not-a-public-key-secret" },
        &diagnostic,
    ));
    try std.testing.expectEqual(@as(?usize, 1), diagnostic.token_index);
    try std.testing.expectEqual(@as(?usize, 1), diagnostic.pair_index);
    try std.testing.expectEqualStrings("minisign", diagnostic.fieldName().?);
    try std.testing.expect(diagnostic.field == .minisign);
}

test "diagnostic identifies malformed percent escape by request pair and field" {
    var diagnostic: Diagnostic = .{};
    try std.testing.expectError(error.InvalidPercentEscape, parseWithDiagnostic(
        std.testing.allocator,
        &.{
            "first/repo",
            "?id=first",
            "second/repo",
            "?alias=tool:renamed&id=private%2Gvalue",
        },
        &diagnostic,
    ));
    try std.testing.expectEqual(@as(?usize, 3), diagnostic.token_index);
    try std.testing.expectEqual(@as(?usize, 1), diagnostic.pair_index);
    try std.testing.expectEqualStrings("id", diagnostic.fieldName().?);
}

test "finish-time diagnostic points to the source requiring an explicit ID" {
    var diagnostic: Diagnostic = .{};
    try std.testing.expectError(error.GenericUrlRequiresExplicitId, parseWithDiagnostic(
        std.testing.allocator,
        &.{ "first/repo", "https://example.com/tool.tar.gz" },
        &diagnostic,
    ));
    try std.testing.expectEqual(@as(?usize, 1), diagnostic.token_index);
    try std.testing.expectEqual(@as(?usize, null), diagnostic.pair_index);
    try std.testing.expectEqualStrings("id", diagnostic.fieldName().?);
}

test "alias validation rejects malformed and duplicate mappings" {
    try std.testing.expectError(error.MalformedAlias, parse(std.testing.allocator, &.{ "o/r", "?alias=ab" }));
    try std.testing.expectError(error.MalformedAlias, parse(std.testing.allocator, &.{ "o/r", "?alias=:b" }));
    try std.testing.expectError(error.MalformedAlias, parse(std.testing.allocator, &.{ "o/r", "?alias=a:" }));
    try std.testing.expectError(error.MalformedAlias, parse(std.testing.allocator, &.{ "o/r", "?alias=a:b:c" }));
    try std.testing.expectError(error.DuplicateAliasSource, parse(std.testing.allocator, &.{ "o/r", "?alias=a:b&alias=a:c" }));
    try std.testing.expectError(error.DuplicateAliasPublished, parse(std.testing.allocator, &.{ "o/r", "?alias=a:c&alias=b:c" }));
}

test "ID validation accepts boundaries and rejects unsafe forms" {
    const segment = "a" ** max_id_segment_bytes;
    const second = "b" ** max_id_segment_bytes;
    var valid = try parse(std.testing.allocator, &.{
        "o/r",
        "?id=" ++ segment ++ "/" ++ second,
    });
    defer valid.deinit();
    try std.testing.expectEqual(@as(usize, max_id_segment_bytes * 2 + 1), valid.items[0].id.len);

    var max_valid = try parse(std.testing.allocator, &.{
        "o/r",
        "?id=" ++ ("a" ** 60) ++ "/" ++
            ("b" ** 60) ++ "/" ++
            ("c" ** 60) ++ "/" ++
            ("d" ** 57),
    });
    defer max_valid.deinit();
    try std.testing.expectEqual(max_id_bytes, max_valid.items[0].id.len);

    try std.testing.expectError(error.InvalidIdSegmentTooLong, parse(std.testing.allocator, &.{
        "o/r",
        "?id=" ++ ("a" ** (max_id_segment_bytes + 1)),
    }));
    try std.testing.expectError(error.InvalidIdTooLong, parse(std.testing.allocator, &.{
        "o/r",
        "?id=" ++ ("a" ** max_id_segment_bytes) ++ "/" ++
            ("b" ** max_id_segment_bytes) ++ "/" ++
            ("c" ** max_id_segment_bytes) ++ "/" ++
            ("d" ** max_id_segment_bytes),
    }));
    try std.testing.expectError(error.InvalidIdEmpty, canonicalizeId(std.testing.allocator, ""));
    try std.testing.expectError(error.InvalidIdEmptySegment, parse(std.testing.allocator, &.{ "o/r", "?id=/a" }));
    try std.testing.expectError(error.InvalidIdEmptySegment, parse(std.testing.allocator, &.{ "o/r", "?id=a/" }));
    try std.testing.expectError(error.InvalidIdEmptySegment, parse(std.testing.allocator, &.{ "o/r", "?id=a//b" }));
    try std.testing.expectError(error.InvalidIdDotSegment, parse(std.testing.allocator, &.{ "o/r", "?id=." }));
    try std.testing.expectError(error.InvalidIdDotSegment, parse(std.testing.allocator, &.{ "o/r", "?id=.." }));
    try std.testing.expectError(error.InvalidIdDotSegment, parse(std.testing.allocator, &.{ "o/r", "?id=a/../b" }));
    try std.testing.expectError(error.InvalidIdUnsafeSegmentEdge, parse(std.testing.allocator, &.{ "o/r", "?id=-a" }));
    try std.testing.expectError(error.InvalidIdUnsafeSegmentEdge, parse(std.testing.allocator, &.{ "o/r", "?id=a-" }));
    try std.testing.expectError(error.InvalidIdUnsafeCharacter, parse(std.testing.allocator, &.{ "o/r", "?id=a\\b" }));
    try std.testing.expectError(error.InvalidIdUnsafeCharacter, parse(std.testing.allocator, &.{ "o/r", "?id=a%25b" }));
    try std.testing.expectError(error.InvalidIdUnsafeCharacter, parse(std.testing.allocator, &.{ "o/r", "?id=a b" }));
    try std.testing.expectError(error.InvalidIdNonAscii, parse(std.testing.allocator, &.{ "o/r", "?id=a%C3%A9" }));
}

test "unsafe derived GitHub ID can be replaced by an explicit safe ID" {
    try std.testing.expectError(error.InvalidDerivedId, parse(std.testing.allocator, &.{"owner/repo."}));
    var parsed = try parse(std.testing.allocator, &.{ "owner/repo.", "?id=safe" });
    defer parsed.deinit();
    try std.testing.expectEqualStrings("safe", parsed.items[0].id);
}
