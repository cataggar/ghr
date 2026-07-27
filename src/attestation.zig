const std = @import("std");
const build_options = @import("build_options");
const snappy = @import("snappy.zig");

const api_base = "https://api.github.com";
const user_agent = std.fmt.comptimePrint("ghr/{s}", .{build_options.version});

const max_api_body = 1024 * 1024;
const max_bundle_wire_body = 4 * 1024 * 1024;
const max_bundle_json = 16 * 1024 * 1024;
const max_total_bundle_json = 64 * 1024 * 1024;
const max_candidates = 100;

pub const Repository = struct {
    owner: []const u8,
    repo: []const u8,
};

pub const ApiAttestation = struct {
    repository_id: ?u64 = null,
    bundle_url: ?[]const u8 = null,
    initiator: ?[]const u8 = null,
    bundle: ?std.json.Value = null,
};

pub const ApiResponse = struct {
    attestations: []const ApiAttestation,
};

pub const BundleSet = struct {
    allocator: std.mem.Allocator,
    items: [][]u8,

    pub fn deinit(self: BundleSet) void {
        for (self.items) |item| self.allocator.free(item);
        self.allocator.free(self.items);
    }
};

pub const LookupResult = union(enum) {
    none,
    found: BundleSet,

    pub fn deinit(self: LookupResult) void {
        switch (self) {
            .none => {},
            .found => |bundles| bundles.deinit(),
        }
    }
};

pub fn lookup(
    client: *std.http.Client,
    allocator: std.mem.Allocator,
    repository: Repository,
    sha256_hex: []const u8,
    auth_header: ?[]const u8,
) !LookupResult {
    const url = try buildApiUrl(allocator, api_base, repository, sha256_hex);
    defer allocator.free(url);

    const raw_api = try fetchApiBody(client, allocator, url, auth_header);
    defer allocator.free(raw_api.body);
    const api_body = try decompressHttpContentAlloc(
        allocator,
        raw_api.body,
        raw_api.content_encoding,
        max_api_body,
    );
    defer allocator.free(api_body);

    var parsed = std.json.parseFromSlice(ApiResponse, allocator, api_body, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch return error.MalformedApiResponse;
    defer parsed.deinit();

    if (parsed.value.attestations.len == 0) return .none;
    if (parsed.value.attestations.len > max_candidates) {
        return error.TooManyAttestations;
    }

    const items = try allocator.alloc([]u8, parsed.value.attestations.len);
    var item_count: usize = 0;
    errdefer {
        for (items[0..item_count]) |item| allocator.free(item);
        allocator.free(items);
    }

    var total_json_size: usize = 0;
    for (parsed.value.attestations) |candidate| {
        const bundle_json = if (candidate.bundle_url) |bundle_url| blk: {
            if (candidate.bundle != null) return error.MalformedApiResponse;
            try validateHttpsUrl(bundle_url);

            const raw_bundle = try fetchBundleBody(client, allocator, bundle_url);
            defer allocator.free(raw_bundle.body);
            const transport_body = try decompressHttpContentAlloc(
                allocator,
                raw_bundle.body,
                raw_bundle.content_encoding,
                max_bundle_json,
            );
            defer allocator.free(transport_body);

            break :blk try decodeBundlePayload(allocator, transport_body);
        } else if (candidate.bundle) |inline_bundle| blk: {
            break :blk try stringifyBundleValue(allocator, inline_bundle);
        } else {
            return error.MalformedApiResponse;
        };

        total_json_size = std.math.add(
            usize,
            total_json_size,
            bundle_json.len,
        ) catch {
            allocator.free(bundle_json);
            return error.ResponseTooLarge;
        };
        if (total_json_size > max_total_bundle_json) {
            allocator.free(bundle_json);
            return error.ResponseTooLarge;
        }

        items[item_count] = bundle_json;
        item_count += 1;
    }

    return .{ .found = .{
        .allocator = allocator,
        .items = items,
    } };
}

const RawResponse = struct {
    body: []u8,
    content_encoding: std.http.ContentEncoding,
};

fn fetchApiBody(
    client: *std.http.Client,
    allocator: std.mem.Allocator,
    url: []const u8,
    auth_header: ?[]const u8,
) !RawResponse {
    var headers: [3]std.http.Header = undefined;
    headers[0] = .{
        .name = "Accept",
        .value = "application/vnd.github+json",
    };
    headers[1] = .{
        .name = "X-GitHub-Api-Version",
        .value = "2026-03-10",
    };
    var header_count: usize = 2;
    if (auth_header) |value| {
        if (value.len != 0) {
            headers[header_count] = .{
                .name = "Authorization",
                .value = value,
            };
            header_count += 1;
        }
    }

    return fetchRaw(client, allocator, .{
        .url = url,
        .identity_limit = max_api_body,
        .encoded_limit = max_api_body,
        .extra_headers = headers[0..header_count],
    });
}

fn fetchBundleBody(
    client: *std.http.Client,
    allocator: std.mem.Allocator,
    url: []const u8,
) !RawResponse {
    return fetchRaw(client, allocator, .{
        .url = url,
        .identity_limit = @max(max_bundle_wire_body, max_bundle_json),
        .encoded_limit = max_bundle_wire_body,
        .require_https = true,
        .follow_redirects = true,
    });
}

const FetchOptions = struct {
    url: []const u8,
    identity_limit: usize,
    encoded_limit: usize,
    require_https: bool = false,
    follow_redirects: bool = false,
    extra_headers: []const std.http.Header = &.{},
};

fn fetchRaw(
    client: *std.http.Client,
    allocator: std.mem.Allocator,
    options: FetchOptions,
) !RawResponse {
    var current_url = options.url;
    var owned_url: ?[]u8 = null;
    defer if (owned_url) |url| allocator.free(url);

    for (0..4) |redirect_count| {
        const step = try fetchOnce(client, allocator, current_url, options);
        switch (step) {
            .response => |response| return response,
            .redirect => |redirect_url| {
                if (!options.follow_redirects) {
                    allocator.free(redirect_url);
                    return error.UnexpectedRedirect;
                }
                if (redirect_count == 3) {
                    allocator.free(redirect_url);
                    return error.TooManyRedirects;
                }
                if (options.require_https) {
                    validateHttpsUrl(redirect_url) catch |err| {
                        allocator.free(redirect_url);
                        return err;
                    };
                }
                if (owned_url) |url| allocator.free(url);
                owned_url = redirect_url;
                current_url = redirect_url;
            },
        }
    }
    unreachable;
}

const FetchStep = union(enum) {
    redirect: []u8,
    response: RawResponse,
};

fn fetchOnce(
    client: *std.http.Client,
    allocator: std.mem.Allocator,
    url: []const u8,
    options: FetchOptions,
) !FetchStep {
    const uri = std.Uri.parse(url) catch return error.InvalidUrl;
    if (options.require_https and
        !std.ascii.eqlIgnoreCase(uri.scheme, "https"))
    {
        return error.InsecureBundleUrl;
    }

    var request = try client.request(.GET, uri, .{
        .redirect_behavior = .unhandled,
        .keep_alive = false,
        .headers = .{
            .user_agent = .{ .override = user_agent },
            .accept_encoding = .{ .override = "gzip, deflate, zstd" },
        },
        .extra_headers = options.extra_headers,
    });
    defer {
        if (request.connection) |connection| connection.closing = true;
        request.deinit();
    }
    request.accept_encoding[@intFromEnum(std.http.ContentEncoding.zstd)] = true;

    try request.sendBodiless();
    var response = try request.receiveHead(&.{});

    if (response.head.status.class() == .redirect) {
        const location = response.head.location orelse
            return error.RedirectLocationMissing;
        return .{
            .redirect = try resolveRedirectAlloc(
                allocator,
                request.uri,
                location,
            ),
        };
    }
    if (response.head.status != .ok) return error.UnexpectedHttpStatus;

    const body_limit = if (response.head.content_encoding == .identity)
        options.identity_limit
    else
        options.encoded_limit;
    if (response.head.content_length) |content_length| {
        if (content_length > body_limit) return error.ResponseTooLarge;
    }

    const buffer_len = std.math.add(usize, body_limit, 1) catch
        return error.ResponseTooLarge;
    const body_buffer = try allocator.alloc(u8, buffer_len);
    errdefer allocator.free(body_buffer);
    var writer = std.Io.Writer.fixed(body_buffer);
    const reader = response.reader(&.{});
    _ = reader.streamRemaining(&writer) catch |err| switch (err) {
        error.ReadFailed => return response.bodyErr().?,
        error.WriteFailed => return error.ResponseTooLarge,
    };

    if (writer.buffered().len > body_limit) return error.ResponseTooLarge;
    const body = try allocator.realloc(body_buffer, writer.buffered().len);
    return .{ .response = .{
        .body = body,
        .content_encoding = response.head.content_encoding,
    } };
}

fn resolveRedirectAlloc(
    allocator: std.mem.Allocator,
    base: std.Uri,
    location: []const u8,
) ![]u8 {
    var buffer: [16 * 1024]u8 = undefined;
    if (location.len > buffer.len) return error.RedirectLocationTooLong;
    @memcpy(buffer[0..location.len], location);
    var auxiliary: []u8 = &buffer;
    const resolved = base.resolveInPlace(location.len, &auxiliary) catch
        return error.InvalidRedirectUrl;
    return std.fmt.allocPrint(allocator, "{f}", .{resolved.fmt(.all)});
}

fn decompressHttpContentAlloc(
    allocator: std.mem.Allocator,
    encoded: []const u8,
    content_encoding: std.http.ContentEncoding,
    max_output: usize,
) ![]u8 {
    if (content_encoding == .identity) {
        if (encoded.len > max_output) return error.ResponseTooLarge;
        return allocator.dupe(u8, encoded);
    }
    if (content_encoding == .compress) {
        return error.UnsupportedContentEncoding;
    }

    var source = std.Io.Reader.fixed(encoded);
    const scratch = try allocator.alloc(u8, content_encoding.minBufferCapacity());
    defer allocator.free(scratch);
    var decompress: std.http.Decompress = undefined;
    const reader = std.http.Decompress.init(
        &decompress,
        &source,
        scratch,
        content_encoding,
    );

    const buffer_len = std.math.add(usize, max_output, 1) catch
        return error.ResponseTooLarge;
    const output_buffer = try allocator.alloc(u8, buffer_len);
    errdefer allocator.free(output_buffer);
    var writer = std.Io.Writer.fixed(output_buffer);
    _ = reader.streamRemaining(&writer) catch |err| switch (err) {
        error.ReadFailed => return error.InvalidCompressedResponse,
        error.WriteFailed => return error.ResponseTooLarge,
    };

    if (writer.buffered().len > max_output) return error.ResponseTooLarge;
    return allocator.realloc(output_buffer, writer.buffered().len);
}

fn decodeBundlePayload(
    allocator: std.mem.Allocator,
    payload: []const u8,
) ![]u8 {
    const first_non_whitespace = std.mem.indexOfNone(
        u8,
        payload,
        " \t\r\n",
    );
    if (first_non_whitespace) |index| {
        if (payload[index] == '{') {
            if (payload.len > max_bundle_json) return error.ResponseTooLarge;
            try validateBundleJson(allocator, payload);
            return allocator.dupe(u8, payload);
        }
    }

    if (payload.len > max_bundle_wire_body) return error.ResponseTooLarge;
    const decompressed = try snappy.decompressAlloc(
        allocator,
        payload,
        max_bundle_json,
    );
    errdefer allocator.free(decompressed);
    try validateBundleJson(allocator, decompressed);
    return decompressed;
}

fn validateBundleJson(allocator: std.mem.Allocator, bundle_json: []const u8) !void {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, bundle_json, .{}) catch
        return error.MalformedBundle;
    defer parsed.deinit();
    if (parsed.value != .object) return error.MalformedBundle;
    const media_type = parsed.value.object.get("mediaType") orelse
        return error.MalformedBundle;
    if (media_type != .string or !std.mem.eql(
        u8,
        media_type.string,
        "application/vnd.dev.sigstore.bundle.v0.3+json",
    )) {
        return error.MalformedBundle;
    }
}

fn stringifyBundleValue(
    allocator: std.mem.Allocator,
    value: std.json.Value,
) ![]u8 {
    if (value != .object) return error.MalformedBundle;

    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    try std.json.Stringify.value(value, .{}, &output.writer);
    if (output.writer.buffered().len > max_bundle_json) {
        return error.ResponseTooLarge;
    }
    const bundle_json = try output.toOwnedSlice();
    errdefer allocator.free(bundle_json);
    try validateBundleJson(allocator, bundle_json);
    return bundle_json;
}

fn validateHttpsUrl(url: []const u8) !void {
    const uri = std.Uri.parse(url) catch return error.InvalidUrl;
    if (!std.ascii.eqlIgnoreCase(uri.scheme, "https")) {
        return error.InsecureBundleUrl;
    }
    if (uri.host == null) return error.InvalidUrl;
}

fn buildApiUrl(
    allocator: std.mem.Allocator,
    base: []const u8,
    repository: Repository,
    sha256_hex: []const u8,
) ![]u8 {
    if (!isLowerSha256(sha256_hex)) return error.InvalidDigest;
    const owner = try encodePathSegment(allocator, repository.owner);
    defer allocator.free(owner);
    const repo = try encodePathSegment(allocator, repository.repo);
    defer allocator.free(repo);

    return std.fmt.allocPrint(
        allocator,
        "{s}/repos/{s}/{s}/attestations/sha256:{s}" ++
            "?predicate_type=provenance&per_page=100",
        .{ base, owner, repo, sha256_hex },
    );
}

fn isLowerSha256(digest: []const u8) bool {
    if (digest.len != 64) return false;
    for (digest) |byte| {
        if (!std.ascii.isDigit(byte) and (byte < 'a' or byte > 'f')) {
            return false;
        }
    }
    return true;
}

fn encodePathSegment(
    allocator: std.mem.Allocator,
    value: []const u8,
) ![]u8 {
    if (value.len == 0) return error.InvalidRepository;

    const hex = "0123456789ABCDEF";
    var output: std.ArrayListUnmanaged(u8) = .empty;
    errdefer output.deinit(allocator);
    for (value) |byte| {
        if (std.ascii.isAlphanumeric(byte) or
            byte == '-' or byte == '.' or byte == '_' or byte == '~')
        {
            try output.append(allocator, byte);
        } else {
            try output.append(allocator, '%');
            try output.append(allocator, hex[byte >> 4]);
            try output.append(allocator, hex[byte & 0x0f]);
        }
    }
    return output.toOwnedSlice(allocator);
}

test "builds the versioned GitHub attestation URL" {
    const allocator = std.testing.allocator;
    const digest = "0123456789abcdef" ** 4;
    const url = try buildApiUrl(
        allocator,
        api_base,
        .{ .owner = "octo org", .repo = "hello-world" },
        digest,
    );
    defer allocator.free(url);
    try std.testing.expectEqualStrings(
        "https://api.github.com/repos/octo%20org/hello-world/" ++
            "attestations/sha256:" ++ digest ++
            "?predicate_type=provenance&per_page=100",
        url,
    );

    try std.testing.expectError(
        error.InvalidDigest,
        buildApiUrl(
            allocator,
            api_base,
            .{ .owner = "octo", .repo = "hello" },
            "ABCDEF",
        ),
    );
}

test "parses current bundle URL and empty API responses" {
    const allocator = std.testing.allocator;
    const current =
        \\{"attestations":[{"repository_id":1209370122,"bundle_url":"https://example.test/bundle.json.sn","initiator":"user"}]}
    ;
    var parsed = try std.json.parseFromSlice(ApiResponse, allocator, current, .{
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 1), parsed.value.attestations.len);
    try std.testing.expectEqual(@as(?u64, 1209370122), parsed.value.attestations[0].repository_id);
    try std.testing.expectEqualStrings(
        "https://example.test/bundle.json.sn",
        parsed.value.attestations[0].bundle_url.?,
    );

    const empty = try std.json.parseFromSlice(
        ApiResponse,
        allocator,
        "{\"attestations\":[]}",
        .{},
    );
    defer empty.deinit();
    try std.testing.expectEqual(@as(usize, 0), empty.value.attestations.len);
}

test "plain JSON and raw Snappy decode to the same bundle" {
    const allocator = std.testing.allocator;
    const bundle_json =
        "{\"mediaType\":\"application/vnd.dev.sigstore.bundle.v0.3+json\"}";

    const plain = try decodeBundlePayload(allocator, bundle_json);
    defer allocator.free(plain);
    try std.testing.expectEqualStrings(bundle_json, plain);

    const compressed = "\x3d\xf0\x3c" ++ bundle_json;
    const decoded = try decodeBundlePayload(allocator, compressed);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings(bundle_json, decoded);
}

test "gzip content reaches the same bundle parser" {
    const allocator = std.testing.allocator;
    const bundle_json =
        "{\"mediaType\":\"application/vnd.dev.sigstore.bundle.v0.3+json\"}";
    const gzip =
        "\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff\xab\x56\xca\x4d\x4d" ++
        "\xc9\x4c\x0c\xa9\x2c\x48\x55\xb2\x52\x4a\x2c\x28\xc8\xc9\x4c" ++
        "\x4e\x2c\xc9\xcc\xcf\xd3\x2f\xcb\x4b\xd1\x4b\x49\x2d\xd3\x2b" ++
        "\xce\x4c\x2f\x2e\xc9\x2f\x4a\xd5\x4b\x2a\xcd\x4b\xc9\x49\xd5" ++
        "\x2b\x33\xd0\x33\xd6\xce\x2a\xce\xcf\x53\xaa\x05\x00\x15\xf4" ++
        "\x11\x41\x3d\x00\x00\x00";

    const transport = try decompressHttpContentAlloc(
        allocator,
        gzip,
        .gzip,
        max_bundle_json,
    );
    defer allocator.free(transport);
    const decoded = try decodeBundlePayload(allocator, transport);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings(bundle_json, decoded);
}

test "rejects insecure URLs and unsupported HTTP compression" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(
        error.InsecureBundleUrl,
        validateHttpsUrl("http://example.test/bundle"),
    );
    try std.testing.expectError(
        error.InvalidUrl,
        validateHttpsUrl("https:///bundle"),
    );
    try std.testing.expectError(
        error.UnsupportedContentEncoding,
        decompressHttpContentAlloc(allocator, "data", .compress, 1024),
    );
}

test "resolves redirects before enforcing HTTPS" {
    const allocator = std.testing.allocator;
    const base = try std.Uri.parse("https://example.test/a/bundle");

    const relative = try resolveRedirectAlloc(allocator, base, "../next");
    defer allocator.free(relative);
    try std.testing.expectEqualStrings(
        "https://example.test/next",
        relative,
    );
    try validateHttpsUrl(relative);

    const downgrade = try resolveRedirectAlloc(
        allocator,
        base,
        "http://example.test/plaintext",
    );
    defer allocator.free(downgrade);
    try std.testing.expectError(
        error.InsecureBundleUrl,
        validateHttpsUrl(downgrade),
    );
}
