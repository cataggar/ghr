const std = @import("std");

const Io = std.Io;
const EnvironMap = std.process.Environ.Map;

/// Resolved GitHub auth token plus information about how it was obtained.
/// `token` is null if no source produced a token (or `no_auth` was set).
/// `owns_token` is true when the token was allocated by us (e.g. from
/// `gh auth token`); callers must free it with the same allocator.
/// `source` is a static string suitable for debug logs.
pub const Resolved = struct {
    token: ?[]const u8,
    owns_token: bool,
    source: []const u8,

    pub fn deinit(self: Resolved, allocator: std.mem.Allocator) void {
        if (self.owns_token) {
            if (self.token) |t| allocator.free(t);
        }
    }
};

/// Resolve a GitHub auth token from environment variables, falling back to
/// the `gh` CLI. When `no_auth` is true, returns a `Resolved` with no token.
pub fn resolveGithubToken(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    no_auth: bool,
) Resolved {
    if (no_auth) {
        return .{ .token = null, .owns_token = false, .source = "disabled" };
    }
    if (environ.get("GH_TOKEN")) |t| {
        return .{ .token = t, .owns_token = false, .source = "GH_TOKEN" };
    }
    if (environ.get("GITHUB_TOKEN")) |t| {
        return .{ .token = t, .owns_token = false, .source = "GITHUB_TOKEN" };
    }
    if (ghAuthToken(allocator, io)) |t| {
        return .{ .token = t, .owns_token = true, .source = "gh" };
    }
    return .{ .token = null, .owns_token = false, .source = "none" };
}

/// Build a `Bearer <token>` header value from a resolved token.
/// Returns null if the resolved token is null. Caller owns the result.
pub fn bearerHeader(allocator: std.mem.Allocator, resolved: Resolved) !?[]const u8 {
    const token = resolved.token orelse return null;
    return try std.fmt.allocPrint(allocator, "Bearer {s}", .{token});
}

/// Run `gh auth token` to get a GitHub token from the gh CLI.
/// Returns null if gh is not installed or the command fails.
fn ghAuthToken(allocator: std.mem.Allocator, io: Io) ?[]const u8 {
    const result = std.process.run(allocator, io, .{
        .argv = &.{ "gh", "auth", "token" },
        .stdout_limit = Io.Limit.limited(256),
        .stderr_limit = Io.Limit.limited(0),
    }) catch return null;
    defer allocator.free(result.stderr);

    if (result.term != .exited or result.term.exited != 0) {
        allocator.free(result.stdout);
        return null;
    }

    const trimmed = std.mem.trimEnd(u8, result.stdout, &[_]u8{ ' ', '\t', '\r', '\n' });
    if (trimmed.len == 0) {
        allocator.free(result.stdout);
        return null;
    }

    const token = allocator.dupe(u8, trimmed) catch {
        allocator.free(result.stdout);
        return null;
    };
    allocator.free(result.stdout);
    return token;
}

/// Returns true if the URL host is a GitHub-owned host where attaching the
/// user's auth token is acceptable. The set is conservative on purpose:
/// only github.com domains and the release-asset CDN.
pub fn isGithubHost(host: []const u8) bool {
    return std.ascii.eqlIgnoreCase(host, "github.com") or
        std.ascii.eqlIgnoreCase(host, "api.github.com") or
        std.ascii.eqlIgnoreCase(host, "raw.githubusercontent.com") or
        std.ascii.eqlIgnoreCase(host, "objects.githubusercontent.com") or
        std.ascii.eqlIgnoreCase(host, "release-assets.githubusercontent.com");
}

test "ghAuthToken returns token when gh is available" {
    const allocator = std.testing.allocator;
    const token = ghAuthToken(allocator, std.testing.io);
    if (token) |t| {
        defer allocator.free(t);
        try std.testing.expect(t.len > 0);
    }
}

test "isGithubHost matches github-owned domains and not others" {
    try std.testing.expect(isGithubHost("github.com"));
    try std.testing.expect(isGithubHost("api.github.com"));
    try std.testing.expect(isGithubHost("raw.githubusercontent.com"));
    try std.testing.expect(isGithubHost("objects.githubusercontent.com"));
    try std.testing.expect(isGithubHost("release-assets.githubusercontent.com"));
    try std.testing.expect(isGithubHost("GitHub.com"));
    try std.testing.expect(!isGithubHost("evil.com"));
    try std.testing.expect(!isGithubHost("github.com.evil.com"));
    try std.testing.expect(!isGithubHost("notgithub.com"));
    try std.testing.expect(!isGithubHost(""));
}

test "resolveGithubToken honours no_auth" {
    const allocator = std.testing.allocator;
    var env: EnvironMap = .init(allocator);
    defer env.deinit();
    const r = resolveGithubToken(allocator, std.testing.io, &env, true);
    defer r.deinit(allocator);
    try std.testing.expect(r.token == null);
    try std.testing.expectEqualStrings("disabled", r.source);
}

test "resolveGithubToken prefers GH_TOKEN over GITHUB_TOKEN" {
    const allocator = std.testing.allocator;
    var env: EnvironMap = .init(allocator);
    defer env.deinit();
    try env.put("GH_TOKEN", "primary");
    try env.put("GITHUB_TOKEN", "secondary");

    const r = resolveGithubToken(allocator, std.testing.io, &env, false);
    defer r.deinit(allocator);
    try std.testing.expectEqualStrings("primary", r.token.?);
    try std.testing.expectEqualStrings("GH_TOKEN", r.source);
    try std.testing.expect(!r.owns_token);
}

test "bearerHeader formats Bearer prefix" {
    const allocator = std.testing.allocator;
    const r: Resolved = .{ .token = "abc123", .owns_token = false, .source = "test" };
    const h = (try bearerHeader(allocator, r)).?;
    defer allocator.free(h);
    try std.testing.expectEqualStrings("Bearer abc123", h);
}

test "bearerHeader returns null for null token" {
    const allocator = std.testing.allocator;
    const r: Resolved = .{ .token = null, .owns_token = false, .source = "none" };
    try std.testing.expect((try bearerHeader(allocator, r)) == null);
}
