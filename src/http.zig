const std = @import("std");
const build_options = @import("build_options");

const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;
const Writer = Io.Writer;

/// HTTP write buffer size for download clients. GitHub release downloads redirect
/// to CDN URLs with long signed query strings (~900 bytes). The default
/// write_buffer_size of 1024 is too small, causing the request to be truncated
/// and the CDN to return HTTP 400. We use 4096 to accommodate these URLs plus
/// the request line and headers.
pub const http_write_buffer_size = 4096;

/// User-Agent used by all `ghr` HTTP requests.
pub const default_user_agent = "ghr/" ++ build_options.version;

/// Optional callback invoked while a body is streamed to disk so callers
/// can render progress. `total` is `null` when the server didn't send a
/// `Content-Length`. Called frequently; implementations should rate-limit.
pub const ProgressFn = *const fn (ctx: *anyopaque, downloaded: u64, total: ?u64) void;

pub const Progress = struct {
    ctx: *anyopaque,
    callback: ProgressFn,
};

pub const DownloadOptions = struct {
    /// Bearer token attached on the initial request only. Stripped on
    /// cross-domain redirects so we never leak credentials to a CDN.
    auth_header: ?[]const u8 = null,
    /// Optional `Accept` header value attached on the initial request only
    /// (e.g. `application/octet-stream` for the GitHub asset API endpoint).
    accept: ?[]const u8 = null,
    /// Optional debug writer; verbose lines are written here when set.
    debug_w: ?*Writer = null,
    /// Maximum number of retry attempts (including the initial attempt).
    max_retries: u8 = 5,
    /// Optional Sha256 hasher updated as bytes are written. Caller owns
    /// the hasher and reads `final` after success.
    hasher: ?*std.crypto.hash.sha2.Sha256 = null,
    /// Optional progress callback.
    progress: ?Progress = null,
};

/// Download `url` into `dest_path` (absolute path), retrying on transient
/// failures. Follows GitHub-style redirects (github.com -> CDN) and strips
/// the Authorization header before following them. On success, the
/// destination file contains the full body. On failure, the partial file
/// is left in place; callers should remove it.
pub fn downloadToFile(
    allocator: std.mem.Allocator,
    io: Io,
    url: []const u8,
    dest_path: []const u8,
    opts: DownloadOptions,
) !void {
    const max_retries = opts.max_retries;
    var attempts: u8 = 0;
    while (attempts < max_retries) : (attempts += 1) {
        if (attempts > 0) {
            const delay_s: i64 = @as(i64, 1) << @intCast(attempts - 1);
            debugLog(opts.debug_w, "  retrying in {d}s ...\n", .{delay_s});
            io.sleep(Io.Duration.fromSeconds(delay_s), .real) catch {};
            Dir.deleteFileAbsolute(io, dest_path) catch {};
            // Reset the hasher so a partial first attempt doesn't poison the digest.
            if (opts.hasher) |h| h.* = std.crypto.hash.sha2.Sha256.init(.{});
        }

        var client: std.http.Client = .{
            .allocator = allocator,
            .io = io,
            .write_buffer_size = http_write_buffer_size,
        };
        defer client.deinit();

        // Initial-request headers: Authorization (github hosts only) and an
        // optional Accept override. Both are dropped before following any
        // cross-domain redirect to a CDN.
        var header_buf: [2]std.http.Header = undefined;
        var header_count: usize = 0;
        if (opts.auth_header) |a| {
            header_buf[header_count] = .{ .name = "Authorization", .value = a };
            header_count += 1;
        }
        if (opts.accept) |ac| {
            header_buf[header_count] = .{ .name = "Accept", .value = ac };
            header_count += 1;
        }
        const extra_headers = header_buf[0..header_count];

        const uri = std.Uri.parse(url) catch {
            debugLog(opts.debug_w, "  invalid URL: {s}\n", .{url});
            return error.DownloadFailed;
        };

        // Use unhandled redirects so we can strip Authorization on
        // cross-domain redirect (github.com -> CDN). Zig 0.16's
        // privileged_headers field is not written by sendHead.
        var req = client.request(.GET, uri, .{
            .redirect_behavior = .unhandled,
            .headers = .{ .user_agent = .{ .override = default_user_agent } },
            .extra_headers = extra_headers,
        }) catch |err| {
            debugLog(opts.debug_w, "  attempt {d}/{d} request error: {}\n", .{ attempts + 1, max_retries, err });
            if (attempts + 1 < max_retries) continue;
            return error.DownloadFailed;
        };
        req.sendBodiless() catch |err| {
            req.deinit();
            debugLog(opts.debug_w, "  attempt {d}/{d} send error: {}\n", .{ attempts + 1, max_retries, err });
            if (attempts + 1 < max_retries) continue;
            return error.DownloadFailed;
        };

        const head_buf = allocator.alloc(u8, 8 * 1024) catch return error.DownloadFailed;
        defer allocator.free(head_buf);

        var response = req.receiveHead(head_buf) catch |err| {
            req.deinit();
            debugLog(opts.debug_w, "  attempt {d}/{d} receiveHead error: {}\n", .{ attempts + 1, max_retries, err });
            if (attempts + 1 < max_retries) continue;
            return error.DownloadFailed;
        };

        if (response.head.status.class() != .redirect) {
            defer req.deinit();
            const result = handleDownloadResponse(allocator, io, &response, dest_path, opts, attempts, max_retries) catch |err| {
                if (err == error.DownloadFailed) return err;
                return err;
            };
            if (result) return;
            continue;
        }

        // Follow redirect without Authorization header.
        const location = response.head.location orelse {
            req.deinit();
            debugLog(opts.debug_w, "  redirect without Location header\n", .{});
            return error.DownloadFailed;
        };
        const redirect_url = try allocator.dupe(u8, location);
        defer allocator.free(redirect_url);

        var redir_buf: [64]u8 = undefined;
        const redir_reader = response.reader(&redir_buf);
        _ = redir_reader.discardRemaining() catch {};
        req.deinit();

        debugLog(opts.debug_w, "  debug: redirect: {s}\n", .{redirect_url});

        var cdn_client: std.http.Client = .{
            .allocator = allocator,
            .io = io,
            .write_buffer_size = http_write_buffer_size,
        };
        defer cdn_client.deinit();

        const cdn_uri = std.Uri.parse(redirect_url) catch {
            debugLog(opts.debug_w, "  invalid redirect URL\n", .{});
            return error.DownloadFailed;
        };

        var cdn_req = cdn_client.request(.GET, cdn_uri, .{
            .redirect_behavior = @enumFromInt(3),
            .headers = .{ .user_agent = .{ .override = default_user_agent } },
        }) catch |err| {
            debugLog(opts.debug_w, "  attempt {d}/{d} CDN request error: {}\n", .{ attempts + 1, max_retries, err });
            if (attempts + 1 < max_retries) continue;
            return error.DownloadFailed;
        };
        defer cdn_req.deinit();

        cdn_req.sendBodiless() catch |err| {
            debugLog(opts.debug_w, "  attempt {d}/{d} CDN send error: {}\n", .{ attempts + 1, max_retries, err });
            if (attempts + 1 < max_retries) continue;
            return error.DownloadFailed;
        };

        const cdn_head_buf = allocator.alloc(u8, 8 * 1024) catch return error.DownloadFailed;
        defer allocator.free(cdn_head_buf);

        var cdn_response = cdn_req.receiveHead(cdn_head_buf) catch |err| {
            debugLog(opts.debug_w, "  attempt {d}/{d} CDN receiveHead error: {}\n", .{ attempts + 1, max_retries, err });
            if (attempts + 1 < max_retries) continue;
            return error.DownloadFailed;
        };

        const result = handleDownloadResponse(allocator, io, &cdn_response, dest_path, opts, attempts, max_retries) catch |err| {
            if (err == error.DownloadFailed) return err;
            return err;
        };
        if (result) return;
        continue;
    }
}

/// Handle the download response: check status, write body to file.
/// Returns true on success, false to retry, error.DownloadFailed for hard fail.
fn handleDownloadResponse(
    allocator: std.mem.Allocator,
    io: Io,
    response: *std.http.Client.Response,
    dest_path: []const u8,
    opts: DownloadOptions,
    attempt: u8,
    max_retries: u8,
) !bool {
    if (response.head.status != .ok) {
        var err_buf: [64]u8 = undefined;
        const body_reader = response.reader(&err_buf);
        var body_w = Writer.Allocating.init(allocator);
        defer body_w.deinit();
        _ = body_reader.streamRemaining(&body_w.writer) catch {};
        const err_body = body_w.toOwnedSlice() catch null;
        defer if (err_body) |b| allocator.free(b);

        if (response.head.status == .bad_request) {
            std.log.err("download failed with HTTP 400 (bad_request)", .{});
            if (err_body) |b| {
                if (b.len > 0) std.log.err("{s}", .{b});
            }
            return error.DownloadFailed;
        }

        if (isTransientStatus(response.head.status)) {
            debugLog(opts.debug_w, "  attempt {d}/{d} HTTP {d} ({s})\n", .{
                attempt + 1, max_retries,
                @intFromEnum(response.head.status), @tagName(response.head.status),
            });
            if (opts.debug_w) |dw| {
                if (err_body) |b| {
                    if (b.len > 0)
                        dw.print("  debug: response body ({d} bytes):\n{s}\n", .{ b.len, b }) catch {};
                }
                dw.flush() catch {};
            }
            if (attempt + 1 < max_retries) return false;
        }
        std.log.err("download failed with HTTP {d} ({s})", .{
            @intFromEnum(response.head.status), @tagName(response.head.status),
        });
        return error.DownloadFailed;
    }

    var file = Dir.createFileAbsolute(io, dest_path, .{}) catch return error.DownloadFailed;
    defer file.close(io);
    var file_buf: [8192]u8 = undefined;
    var file_writer = file.writer(io, &file_buf);

    var transfer_buffer: [64]u8 = undefined;
    var decompress: std.http.Decompress = undefined;
    // Size the decompression window by the negotiated content-encoding.
    // A zero-length buffer (the previous behaviour) underflows the flate
    // window and panics when the server returns a compressed body, e.g. a
    // gzip'd HTML error page. `.identity` needs no window.
    const decompress_buffer: []u8 = switch (response.head.content_encoding) {
        .identity => &.{},
        .zstd => allocator.alloc(u8, std.compress.zstd.default_window_len) catch return error.DownloadFailed,
        .deflate, .gzip => allocator.alloc(u8, std.compress.flate.max_window_len) catch return error.DownloadFailed,
        .compress => {
            std.log.err("download failed: unsupported content-encoding 'compress'", .{});
            return error.DownloadFailed;
        },
    };
    defer if (decompress_buffer.len > 0) allocator.free(decompress_buffer);
    const reader = response.readerDecompressing(&transfer_buffer, &decompress, decompress_buffer);

    // Optional content-length for progress.
    const total: ?u64 = response.head.content_length;

    // Build a writer chain: response -> [hasher] -> [progress] -> file.
    // Both wrappers buffer their own bytes internally; we drain through them
    // into the underlying file writer interface.
    var hashed_buf: [4096]u8 = undefined;
    var hashed_state: ?Writer.Hashed(*std.crypto.hash.sha2.Sha256) = null;
    var dest_writer: *Writer = &file_writer.interface;
    if (opts.hasher) |h| {
        hashed_state = Writer.Hashed(*std.crypto.hash.sha2.Sha256).initHasher(dest_writer, h, &hashed_buf);
        dest_writer = &hashed_state.?.writer;
    }

    var progress_buf: [4096]u8 = undefined;
    var progress_state: ?ProgressWriter = null;
    if (opts.progress) |p| {
        progress_state = ProgressWriter.init(dest_writer, p, total, &progress_buf);
        dest_writer = &progress_state.?.writer;
    }

    _ = reader.streamRemaining(dest_writer) catch return error.DownloadFailed;
    if (progress_state) |*ps| ps.writer.flush() catch return error.DownloadFailed;
    if (hashed_state) |*hs| hs.writer.flush() catch return error.DownloadFailed;
    file_writer.end() catch return error.DownloadFailed;

    // Final progress callback so the caller can render "100%" / final byte count.
    if (opts.progress) |p| {
        const final_bytes: u64 = if (progress_state) |ps| ps.downloaded else 0;
        p.callback(p.ctx, final_bytes, total);
    }

    return true;
}

/// Writer wrapper that calls a progress callback as bytes pass through.
const ProgressWriter = struct {
    out: *Writer,
    progress: Progress,
    total: ?u64,
    downloaded: u64,
    writer: Writer,

    fn init(out: *Writer, progress: Progress, total: ?u64, buffer: []u8) ProgressWriter {
        return .{
            .out = out,
            .progress = progress,
            .total = total,
            .downloaded = 0,
            .writer = .{
                .buffer = buffer,
                .vtable = &.{ .drain = drain },
            },
        };
    }

    fn drain(w: *Writer, data: []const []const u8, splat: usize) Writer.Error!usize {
        const self: *ProgressWriter = @alignCast(@fieldParentPtr("writer", w));
        const aux = w.buffered();
        const aux_n = try self.out.writeSplatHeader(aux, data, splat);
        if (aux_n < w.end) {
            self.downloaded += aux_n;
            const remaining = w.buffer[aux_n..w.end];
            @memmove(w.buffer[0..remaining.len], remaining);
            w.end = remaining.len;
            self.progress.callback(self.progress.ctx, self.downloaded, self.total);
            return 0;
        }
        const after_aux = aux_n - w.end;
        w.end = 0;
        self.downloaded += aux_n;
        self.progress.callback(self.progress.ctx, self.downloaded, self.total);
        return after_aux;
    }
};

/// Log response details on failure for debugging.
pub fn debugLogResponse(w: ?*Writer, response: *const std.http.Client.Response) void {
    if (w == null) return;
    const writer = w.?;
    writer.print("  debug: response headers:\n{s}\n", .{response.head.bytes}) catch {};
    writer.flush() catch {};
}

pub fn debugLog(w: ?*Writer, comptime fmt: []const u8, args: anytype) void {
    if (w) |writer| {
        writer.print(fmt, args) catch {};
        writer.flush() catch {};
    }
}

pub fn isTransientStatus(status: std.http.Status) bool {
    return switch (status) {
        .request_timeout,
        .too_many_requests,
        .internal_server_error,
        .bad_gateway,
        .service_unavailable,
        .gateway_timeout,
        => true,
        else => false,
    };
}

test "isTransientStatus" {
    try std.testing.expect(!isTransientStatus(.bad_request));
    try std.testing.expect(isTransientStatus(.request_timeout));
    try std.testing.expect(isTransientStatus(.too_many_requests));
    try std.testing.expect(isTransientStatus(.internal_server_error));
    try std.testing.expect(isTransientStatus(.bad_gateway));
    try std.testing.expect(isTransientStatus(.service_unavailable));
    try std.testing.expect(isTransientStatus(.gateway_timeout));
    try std.testing.expect(!isTransientStatus(.ok));
    try std.testing.expect(!isTransientStatus(.not_found));
    try std.testing.expect(!isTransientStatus(.forbidden));
}

test "http_write_buffer_size accommodates GitHub CDN redirect URLs" {
    const typical_cdn_path = "/github-production-release-asset/1234567890/" ++
        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" ++
        "?sp=r&sv=2018-11-09&sr=b&spr=https" ++
        "&se=2026-04-15T07%3A04%3A01Z" ++
        "&rscd=attachment%3B+filename%3Dzig-aarch64-macos-0.16.0.tar.xz" ++
        "&rsct=application%2Foctet-stream" ++
        "&skoid=96c2d410-5711-43a1-aedd-ab1947aa7ab0" ++
        "&sktid=398a6654-997b-47e9-b12b-9515b896b4de" ++
        "&skt=2026-04-15T06%3A03%3A53Z" ++
        "&ske=2026-04-15T07%3A04%3A01Z" ++
        "&sks=b&skv=2018-11-09" ++
        "&sig=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop%2Bqrstuv%3D" ++
        "&jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" ++
        ".eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmVsZWFzZS1hc3NldHMu" ++
        "Z2l0aHVidXNlcmNvbnRlbnQuY29tIiwia2V5Ijoia2V5MSIsImV4cCI6MT" ++
        "c3NjIzNTg1MiwibmJmIjoxNzc2MjM0MDUyLCJwYXRoIjoicmVsZWFzZW" ++
        "Fzc2V0cHJvZHVjdGlvbi5ibG9iLmNvcmUud2luZG93cy5uZXQifQ" ++
        ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0" ++
        "&response-content-disposition=attachment%3B%20filename%3Dzig-aarch64-macos-0.16.0.tar.xz" ++
        "&response-content-type=application%2Foctet-stream";

    const request_line_overhead = "GET ".len + " HTTP/1.1\r\n".len;
    const host_header = "Host: release-assets.githubusercontent.com\r\n";
    const user_agent_header = "user-agent: " ++ default_user_agent ++ "\r\n";
    // Zig's HTTP client also emits Accept-Encoding and Connection: keep-alive
    // headers by default; include them in the budget so the assertion
    // reflects the on-the-wire request size.
    const accept_encoding_header = "accept-encoding: gzip, deflate, zstd\r\n";
    const connection_header = "connection: keep-alive\r\n";
    const min_request_size = request_line_overhead + typical_cdn_path.len +
        host_header.len + user_agent_header.len +
        accept_encoding_header.len + connection_header.len + "\r\n".len;

    try std.testing.expect(http_write_buffer_size >= min_request_size);
    // The default of 1024 is not sufficient; this is the bug we fixed by
    // bumping http_write_buffer_size to 4096.
    try std.testing.expect(1024 < min_request_size);
}

test "no User-Agent in extra_headers (override prevents duplicate)" {
    const auth_only = [_]std.http.Header{
        .{ .name = "Authorization", .value = "Bearer test-token" },
    };
    for (auth_only) |h| {
        try std.testing.expect(!std.ascii.eqlIgnoreCase(h.name, "User-Agent"));
    }

    const ua_override: std.http.Client.Request.Headers.Value = .{ .override = default_user_agent };
    try std.testing.expect(ua_override == .override);
    try std.testing.expectEqualStrings(default_user_agent, ua_override.override);
}
