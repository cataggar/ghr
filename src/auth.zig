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

pub const default_github_host = "github.com";

/// True when `host` is the default public GitHub hostname (`github.com`,
/// case-insensitive).
pub fn isDefaultGithubHost(host: []const u8) bool {
    return std.ascii.eqlIgnoreCase(host, default_github_host);
}

/// True when `host` is a valid ASCII DNS hostname (1..253 bytes, dot-separated
/// labels of 1..63 alphanumeric or `-` characters, no leading/trailing `-`).
pub fn isValidGithubHost(host: []const u8) bool {
    if (host.len == 0 or host.len > 253) return false;
    var labels = std.mem.splitScalar(u8, host, '.');
    while (labels.next()) |label| {
        if (label.len == 0 or label.len > 63 or label[0] == '-' or label[label.len - 1] == '-') return false;
        for (label) |c| if (!std.ascii.isAlphanumeric(c) and c != '-') return false;
    }
    return true;
}

/// Resolve the target GitHub hostname with precedence:
///   1. Explicit CLI `--hostname` / `-h` flag (`cli_host`)
///   2. `GH_HOST` environment variable (when non-empty after whitespace trim)
///   3. `"github.com"`
/// Returns `error.InvalidGithubHost` if the chosen host is not a valid DNS name.
pub fn resolveGithubHost(
    cli_host: ?[]const u8,
    environ: *const EnvironMap,
) error{InvalidGithubHost}![]const u8 {
    if (cli_host) |h| {
        if (!isValidGithubHost(h)) return error.InvalidGithubHost;
        return h;
    }
    if (environ.get("GH_HOST")) |env_h| {
        const trimmed = std.mem.trim(u8, env_h, " \t\r\n");
        if (trimmed.len > 0) {
            if (!isValidGithubHost(trimmed)) return error.InvalidGithubHost;
            return trimmed;
        }
    }
    return default_github_host;
}

/// True when `host` is a GitHub Enterprise Cloud with Data Residency subdomain
/// (`*.ghe.com`, e.g. `example.ghe.com`).
pub fn isGheComHost(host: []const u8) bool {
    const suffix = ".ghe.com";
    return host.len > suffix.len and std.ascii.endsWithIgnoreCase(host, suffix);
}

/// Build the REST API base URL (without trailing slash) for `host`:
///   * `github.com`  -> `https://api.github.com`
///   * `*.ghe.com`   -> `https://api.<host>`
///   * other hosts   -> `https://<host>/api/v3`
pub fn githubApiBaseUrl(allocator: std.mem.Allocator, host: []const u8) ![]u8 {
    if (isDefaultGithubHost(host)) {
        return allocator.dupe(u8, "https://api.github.com");
    }
    if (isGheComHost(host)) {
        return allocator.print("https://api.{s}", .{host});
    }
    return allocator.print("https://{s}/api/v3", .{host});
}

/// Resolve a GitHub auth token from environment variables, falling back to
/// the `gh` CLI. When `no_auth` is true, returns a `Resolved` with no token.
pub fn resolveGithubToken(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    no_auth: bool,
) Resolved {
    return resolveGithubTokenForHost(allocator, io, environ, no_auth, default_github_host);
}

/// Resolve a GitHub auth token for `host` from environment variables, falling
/// back to `gh auth token --hostname <host>`. For non-`github.com` hosts,
/// `GH_ENTERPRISE_TOKEN` and `GITHUB_ENTERPRISE_TOKEN` are checked before
/// `GH_TOKEN` and `GITHUB_TOKEN`, matching `gh` CLI precedence.
pub fn resolveGithubTokenForHost(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    no_auth: bool,
    host: []const u8,
) Resolved {
    if (no_auth) {
        return .{ .token = null, .owns_token = false, .source = "disabled" };
    }
    if (!isDefaultGithubHost(host)) {
        if (environ.get("GH_ENTERPRISE_TOKEN")) |t| {
            if (t.len > 0) return .{ .token = t, .owns_token = false, .source = "GH_ENTERPRISE_TOKEN" };
        }
        if (environ.get("GITHUB_ENTERPRISE_TOKEN")) |t| {
            if (t.len > 0) return .{ .token = t, .owns_token = false, .source = "GITHUB_ENTERPRISE_TOKEN" };
        }
    }
    if (environ.get("GH_TOKEN")) |t| {
        return .{ .token = t, .owns_token = false, .source = "GH_TOKEN" };
    }
    if (environ.get("GITHUB_TOKEN")) |t| {
        return .{ .token = t, .owns_token = false, .source = "GITHUB_TOKEN" };
    }
    if (ghAuthTokenForHost(allocator, io, host)) |t| {
        return .{ .token = t, .owns_token = true, .source = "gh" };
    }
    return .{ .token = null, .owns_token = false, .source = "none" };
}

/// Build a `Bearer <token>` header value from a resolved token.
/// Returns null if the resolved token is null. Caller owns the result.
pub fn bearerHeader(allocator: std.mem.Allocator, resolved: Resolved) !?[]const u8 {
    const token = resolved.token orelse return null;
    return try allocator.print("Bearer {s}", .{token});
}

/// Run `gh auth token` to get a GitHub token from the gh CLI.
/// Returns null if gh is not installed or the command fails.
fn ghAuthToken(allocator: std.mem.Allocator, io: Io) ?[]const u8 {
    return ghAuthTokenForHost(allocator, io, default_github_host);
}

fn ghAuthTokenForHost(allocator: std.mem.Allocator, io: Io, host: []const u8) ?[]const u8 {
    if (!isValidGithubHost(host)) return null;
    const argv: []const []const u8 = if (isDefaultGithubHost(host))
        &.{ "gh", "auth", "token", "--hostname", default_github_host }
    else
        &.{ "gh", "auth", "token", "--hostname", host };
    const result = std.process.run(allocator, io, .{
        .argv = argv,
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

/// Returns true if `host` is a trusted endpoint for `configured_host` where
/// attaching the token resolved for `configured_host` is safe.
/// When `configured_host` is `github.com`, delegates to `isGithubHost`.
/// For any other `configured_host`, matches `<configured_host>` and known
/// GitHub service subdomains (`api.`, `raw.`, `objects.`, `release-assets.`,
/// `codeload.`) of `<configured_host>` only — never `github.com`.
pub fn isGithubHostFor(host: []const u8, configured_host: []const u8) bool {
    if (!isValidGithubHost(configured_host)) return false;
    if (isDefaultGithubHost(configured_host)) return isGithubHost(host);
    if (std.ascii.eqlIgnoreCase(host, configured_host)) return true;

    const prefixes = [_][]const u8{
        "api.",
        "raw.",
        "objects.",
        "release-assets.",
        "codeload.",
    };
    for (prefixes) |prefix| {
        if (host.len == prefix.len + configured_host.len and
            std.ascii.startsWithIgnoreCase(host, prefix) and
            std.ascii.eqlIgnoreCase(host[prefix.len..], configured_host))
        {
            return true;
        }
    }
    return false;
}

/// Decode and validate the URI host before deciding whether auth is safe.
pub fn isGithubUri(uri: std.Uri) bool {
    return isGithubUriFor(uri, default_github_host);
}

/// Decode and validate the URI host before deciding whether auth is safe for
/// `configured_host`.
pub fn isGithubUriFor(uri: std.Uri, configured_host: []const u8) bool {
    var buffer: [Io.net.HostName.max_len]u8 = undefined;
    const host = Io.net.HostName.fromUri(uri, &buffer) catch return false;
    return isGithubHostFor(host.bytes, configured_host);
}

test "isGithubUri validates decoded hosts and fails closed" {
    const cases = [_]struct { url: []const u8, trusted: bool }{
        .{ .url = "https://GitHub.com/asset", .trusted = true },
        .{ .url = "https://api%2egithub.com/asset", .trusted = true },
        .{ .url = "https://github.com@evil.example/asset", .trusted = false },
        .{ .url = "https://github.com.evil.example/asset", .trusted = false },
        .{ .url = "https://github.com%00.evil.example/asset", .trusted = false },
        .{ .url = "https://github.com%2f.evil.example/asset", .trusted = false },
        .{ .url = "https://github.com./asset", .trusted = false },
        .{ .url = "https://[::1]/asset", .trusted = false },
        .{ .url = "https:///asset", .trusted = false },
        .{ .url = "https:asset", .trusted = false },
        .{ .url = "https://" ++ @as([254]u8, @splat('a')) ++ "/asset", .trusted = false },
    };
    for (cases) |case| {
        try std.testing.expectEqual(case.trusted, isGithubUri(try std.Uri.parse(case.url)));
    }
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

test "resolveGithubHost respects CLI flag, GH_HOST, and default" {
    const allocator = std.testing.allocator;
    var env: EnvironMap = .init(allocator);
    defer env.deinit();

    try std.testing.expectEqualStrings("github.com", try resolveGithubHost(null, &env));

    try env.put("GH_HOST", "  example.ghe.com \n");
    try std.testing.expectEqualStrings("example.ghe.com", try resolveGithubHost(null, &env));

    try std.testing.expectEqualStrings("cli.ghe.com", try resolveGithubHost("cli.ghe.com", &env));

    try env.put("GH_HOST", "   ");
    try std.testing.expectEqualStrings("github.com", try resolveGithubHost(null, &env));

    try std.testing.expectError(error.InvalidGithubHost, resolveGithubHost("-bad.host", &env));
    try env.put("GH_HOST", "bad/host");
    try std.testing.expectError(error.InvalidGithubHost, resolveGithubHost(null, &env));
}

test "githubApiBaseUrl formats github.com, *.ghe.com, and GHES hosts" {
    const allocator = std.testing.allocator;

    const gh = try githubApiBaseUrl(allocator, "github.com");
    defer allocator.free(gh);
    try std.testing.expectEqualStrings("https://api.github.com", gh);

    const ghe = try githubApiBaseUrl(allocator, "example.ghe.com");
    defer allocator.free(ghe);
    try std.testing.expectEqualStrings("https://api.example.ghe.com", ghe);

    const ghes = try githubApiBaseUrl(allocator, "github.example.com");
    defer allocator.free(ghes);
    try std.testing.expectEqualStrings("https://github.example.com/api/v3", ghes);
}

test "resolveGithubTokenForHost prefers enterprise token env vars on custom hosts" {
    const allocator = std.testing.allocator;
    var env: EnvironMap = .init(allocator);
    defer env.deinit();
    try env.put("GH_ENTERPRISE_TOKEN", "ent-token");
    try env.put("GH_TOKEN", "pub-token");

    const custom = resolveGithubTokenForHost(allocator, std.testing.io, &env, false, "example.ghe.com");
    defer custom.deinit(allocator);
    try std.testing.expectEqualStrings("ent-token", custom.token.?);
    try std.testing.expectEqualStrings("GH_ENTERPRISE_TOKEN", custom.source);

    const pub_gh = resolveGithubTokenForHost(allocator, std.testing.io, &env, false, "github.com");
    defer pub_gh.deinit(allocator);
    try std.testing.expectEqualStrings("pub-token", pub_gh.token.?);
    try std.testing.expectEqualStrings("GH_TOKEN", pub_gh.source);
}

test "isGithubHostFor scopes auth to configured host and its service subdomains" {
    try std.testing.expect(isGithubHostFor("example.ghe.com", "example.ghe.com"));
    try std.testing.expect(isGithubHostFor("api.example.ghe.com", "example.ghe.com"));
    try std.testing.expect(isGithubHostFor("release-assets.example.ghe.com", "example.ghe.com"));
    try std.testing.expect(isGithubHostFor("objects.example.ghe.com", "example.ghe.com"));
    try std.testing.expect(isGithubHostFor("raw.example.ghe.com", "example.ghe.com"));
    try std.testing.expect(isGithubHostFor("codeload.example.ghe.com", "example.ghe.com"));
    try std.testing.expect(!isGithubHostFor("github.com", "example.ghe.com"));
    try std.testing.expect(!isGithubHostFor("other.ghe.com", "example.ghe.com"));
    try std.testing.expect(!isGithubHostFor("evilexample.ghe.com", "example.ghe.com"));
}
