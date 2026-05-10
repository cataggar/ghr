//! Shared GitHub-release plumbing used by both `install` and `download`:
//!
//!   - spec parsing (`owner/repo[@tag]` and `owner/repo/file[@tag]`)
//!   - GitHub Releases API lookup
//!   - asset selection (platform-keyword scoring + by-name matching)
//!   - SHA256 + sigstore verification of a downloaded asset
//!
//! `install.zig` keeps everything that's actually about installing a
//! tool (shims, app bundles, tool dir layout, `ghr.json`); `download.zig`
//! reuses the helpers below.

const std = @import("std");
const builtin = @import("builtin");
const http = @import("http.zig");
const sigstore = @import("sigstore.zig");
const version = @import("build_options").version;

const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;
const Writer = Io.Writer;

const debugLog = http.debugLog;

// ---------------------------------------------------------------------------
// Spec types and parsing.
// ---------------------------------------------------------------------------

/// A parsed `owner/repo[@tag]` spec.
pub const RepoSpec = struct {
    owner: []const u8,
    repo: []const u8,
    tag: ?[]const u8,
};

/// Parse `owner/repo[@tag]`. Slices reference the input string.
pub fn parseRepoSpec(s: []const u8) !RepoSpec {
    const slash = std.mem.indexOfScalar(u8, s, '/') orelse return error.InvalidSpec;
    const owner = s[0..slash];
    const rest = s[slash + 1 ..];
    if (owner.len == 0 or rest.len == 0) return error.InvalidSpec;

    if (std.mem.indexOfScalar(u8, rest, '@')) |at| {
        const repo = rest[0..at];
        const tag = rest[at + 1 ..];
        if (repo.len == 0 or tag.len == 0) return error.InvalidSpec;
        // A second '/' inside `rest` (before '@') would mean this is actually
        // a file-spec; the caller should try `parseFileSpec` instead.
        if (std.mem.indexOfScalar(u8, repo, '/') != null) return error.InvalidSpec;
        return .{ .owner = owner, .repo = repo, .tag = tag };
    }
    if (std.mem.indexOfScalar(u8, rest, '/') != null) return error.InvalidSpec;
    return .{ .owner = owner, .repo = rest, .tag = null };
}

/// A parsed `owner/repo/file[@tag]` spec. `file` is the asset name (or a
/// case-insensitive substring of it) that the caller wants downloaded.
pub const FileSpec = struct {
    owner: []const u8,
    repo: []const u8,
    file: []const u8,
    tag: ?[]const u8,
};

/// Parse `owner/repo/file[@tag]`. Slices reference the input string.
///
/// The `@tag` separator is the **first** `@` in the string, so asset names
/// containing `@` are not supported (matching `parseRepoSpec`'s convention).
/// `file` must not contain `/`, `\`, and may not be `.` or `..`.
pub fn parseFileSpec(s: []const u8) !FileSpec {
    const at = std.mem.indexOfScalar(u8, s, '@');
    const head = if (at) |a| s[0..a] else s;
    const tag: ?[]const u8 = if (at) |a| blk: {
        const t = s[a + 1 ..];
        if (t.len == 0) return error.InvalidSpec;
        break :blk t;
    } else null;

    const slash1 = std.mem.indexOfScalar(u8, head, '/') orelse return error.InvalidSpec;
    const after_owner = head[slash1 + 1 ..];
    const slash2_rel = std.mem.indexOfScalar(u8, after_owner, '/') orelse return error.InvalidSpec;
    const owner = head[0..slash1];
    const repo = after_owner[0..slash2_rel];
    const file = after_owner[slash2_rel + 1 ..];

    if (owner.len == 0 or repo.len == 0 or file.len == 0) return error.InvalidSpec;
    if (std.mem.indexOfAny(u8, file, "/\\") != null) return error.InvalidSpec;
    if (std.mem.eql(u8, file, ".") or std.mem.eql(u8, file, "..")) return error.InvalidSpec;

    return .{ .owner = owner, .repo = repo, .file = file, .tag = tag };
}

/// URL-decode percent-escapes (`%XX`) and `+` (treat as space is **not**
/// applied — release-download paths use `%20` for spaces). Returns an
/// allocated buffer the caller must free.
fn urlDecode(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    var i: usize = 0;
    while (i < s.len) {
        const c = s[i];
        if (c == '%' and i + 2 < s.len) {
            const hi = hexNibble(s[i + 1]);
            const lo = hexNibble(s[i + 2]);
            if (hi != null and lo != null) {
                try buf.append(allocator, (hi.? << 4) | lo.?);
                i += 3;
                continue;
            }
        }
        try buf.append(allocator, c);
        i += 1;
    }
    return buf.toOwnedSlice(allocator);
}

/// Decompose a github.com release-download URL into a `FileSpec`. Returns
/// `null` for any URL that doesn't match the canonical
/// `https://github.com/<owner>/<repo>/releases/download/<tag>/<file>` shape
/// — the caller can then decide whether to error out (install) or fall back
/// to a generic URL download (download).
///
/// The returned `tag` and `file` are URL-decoded copies allocated from
/// `allocator`. The caller owns them.
pub const ParsedReleaseUrl = struct {
    owner: []u8,
    repo: []u8,
    tag: []u8,
    file: []u8,

    pub fn deinit(self: *const ParsedReleaseUrl, allocator: std.mem.Allocator) void {
        allocator.free(self.owner);
        allocator.free(self.repo);
        allocator.free(self.tag);
        allocator.free(self.file);
    }
};

pub fn parseGitHubReleaseUrl(allocator: std.mem.Allocator, url: []const u8) !?ParsedReleaseUrl {
    const uri = std.Uri.parse(url) catch return null;
    if (!std.ascii.eqlIgnoreCase(uri.scheme, "https") and
        !std.ascii.eqlIgnoreCase(uri.scheme, "http")) return null;
    const host = switch (uri.host orelse return null) {
        .raw => |h| h,
        .percent_encoded => |h| h,
    };
    if (!std.ascii.eqlIgnoreCase(host, "github.com")) return null;
    const path = switch (uri.path) {
        .raw => |p| p,
        .percent_encoded => |p| p,
    };

    // Expect /<owner>/<repo>/releases/download/<tag>/<file>
    var it = std.mem.splitScalar(u8, path, '/');
    // Leading empty segment from leading '/'.
    if (it.next()) |first| {
        if (first.len != 0) return null;
    } else return null;
    const owner = it.next() orelse return null;
    const repo = it.next() orelse return null;
    const releases = it.next() orelse return null;
    const download = it.next() orelse return null;
    const tag = it.next() orelse return null;
    const file = it.next() orelse return null;
    if (it.next() != null) return null; // trailing segments not allowed
    if (owner.len == 0 or repo.len == 0 or tag.len == 0 or file.len == 0) return null;
    if (!std.mem.eql(u8, releases, "releases")) return null;
    if (!std.mem.eql(u8, download, "download")) return null;

    const owner_dec = try urlDecode(allocator, owner);
    errdefer allocator.free(owner_dec);
    const repo_dec = try urlDecode(allocator, repo);
    errdefer allocator.free(repo_dec);
    const tag_dec = try urlDecode(allocator, tag);
    errdefer allocator.free(tag_dec);
    const file_dec = try urlDecode(allocator, file);
    errdefer allocator.free(file_dec);

    return .{ .owner = owner_dec, .repo = repo_dec, .tag = tag_dec, .file = file_dec };
}

/// Classification of a positional argument to `install` / `download`.
pub const Classified = union(enum) {
    /// `http://...` or `https://...`
    url: []const u8,
    /// `owner/repo/file[@tag]`
    file_spec: FileSpec,
    /// `owner/repo[@tag]`
    repo_spec: RepoSpec,
};

/// Classify a positional argument. Tries (in order):
///   1. URL with `http`/`https` scheme.
///   2. `parseFileSpec` (three `/`-separated segments).
///   3. `parseRepoSpec` (two `/`-separated segments).
/// Returns `error.InvalidSpec` if none match.
pub fn classifyArg(arg: []const u8) !Classified {
    if (std.mem.startsWith(u8, arg, "http://") or std.mem.startsWith(u8, arg, "https://")) {
        return .{ .url = arg };
    }
    if (parseFileSpec(arg)) |fs| {
        return .{ .file_spec = fs };
    } else |_| {}
    const rs = try parseRepoSpec(arg);
    return .{ .repo_spec = rs };
}

// ---------------------------------------------------------------------------
// GitHub release API types and lookup.
// ---------------------------------------------------------------------------

/// GitHub release asset from the API response.
pub const Asset = struct {
    name: []const u8,
    browser_download_url: []const u8,
};

/// Parsed release info.
pub const Release = struct {
    tag_name: []const u8,
    assets: []const Asset,
};

/// URL-encode a tag for use in the GitHub API path.
/// Handles '+' -> '%2B' and other special characters.
pub fn urlEncode(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    for (s) |c| {
        switch (c) {
            '+' => try buf.appendSlice(allocator, "%2B"),
            ' ' => try buf.appendSlice(allocator, "%20"),
            '#' => try buf.appendSlice(allocator, "%23"),
            '?' => try buf.appendSlice(allocator, "%3F"),
            '&' => try buf.appendSlice(allocator, "%26"),
            '%' => try buf.appendSlice(allocator, "%25"),
            else => try buf.append(allocator, c),
        }
    }
    return buf.toOwnedSlice(allocator);
}

pub const ParsedRelease = struct {
    parsed: std.json.Parsed(Release),
    body: []u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *ParsedRelease) void {
        self.parsed.deinit();
        self.allocator.free(self.body);
    }
};

pub fn getRelease(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    owner: []const u8,
    repo: []const u8,
    tag: ?[]const u8,
    auth_header: ?[]const u8,
) !ParsedRelease {
    const url = if (tag) |t| blk: {
        const encoded_tag = try urlEncode(allocator, t);
        defer allocator.free(encoded_tag);
        break :blk try std.fmt.allocPrint(allocator, "https://api.github.com/repos/{s}/{s}/releases/tags/{s}", .{ owner, repo, encoded_tag });
    } else try std.fmt.allocPrint(allocator, "https://api.github.com/repos/{s}/{s}/releases/latest", .{ owner, repo });
    defer allocator.free(url);

    var body_writer = std.Io.Writer.Allocating.init(allocator);
    errdefer body_writer.deinit();

    const headers_with_auth = [_]std.http.Header{
        .{ .name = "Accept", .value = "application/vnd.github+json" },
        .{ .name = "Authorization", .value = auth_header orelse "" },
    };
    const headers_without_auth = [_]std.http.Header{
        .{ .name = "Accept", .value = "application/vnd.github+json" },
    };
    const headers: []const std.http.Header = if (auth_header != null)
        &headers_with_auth
    else
        &headers_without_auth;

    const result = try client.fetch(.{
        .location = .{ .url = url },
        .headers = .{ .user_agent = .{ .override = "ghr/" ++ version } },
        .extra_headers = headers,
        .response_writer = &body_writer.writer,
    });

    if (result.status != .ok) {
        const err_body = body_writer.toOwnedSlice() catch null;
        defer if (err_body) |b| allocator.free(b);

        if (err_body) |b| {
            if (std.json.parseFromSlice(
                struct { message: []const u8, documentation_url: []const u8 = "" },
                allocator,
                b,
                .{ .ignore_unknown_fields = true },
            )) |parsed| {
                defer parsed.deinit();
                const msg = parsed.value.message;
                if (result.status == .forbidden or result.status == .too_many_requests) {
                    std.log.err("GitHub API: {s}", .{msg});
                    if (auth_header == null) {
                        std.log.err("hint: set GH_TOKEN for higher rate limits (5000/hr vs 60/hr)", .{});
                    }
                } else {
                    std.log.err("GitHub API HTTP {d}: {s}", .{ @intFromEnum(result.status), msg });
                }
            } else |_| {}
        }
        return error.GitHubApiError;
    }

    const body = try body_writer.toOwnedSlice();
    if (body.len == 0) {
        allocator.free(body);
        return error.EmptyResponse;
    }
    const parsed = try std.json.parseFromSlice(Release, allocator, body, .{ .ignore_unknown_fields = true });
    return .{ .parsed = parsed, .body = body, .allocator = allocator };
}

// ---------------------------------------------------------------------------
// Asset selection: platform-keyword scoring (`findBestAsset`).
// ---------------------------------------------------------------------------

pub const PlatformKeywords = struct {
    os: []const []const u8,
    arch: []const []const u8,
};

pub fn currentPlatformKeywords() PlatformKeywords {
    const os_keywords: []const []const u8 = switch (builtin.os.tag) {
        .windows => &.{ "windows", "win" },
        .linux => &.{"linux"},
        .macos => &.{ "macos", "darwin", "osx" },
        else => &.{},
    };
    const arch_keywords: []const []const u8 = switch (builtin.cpu.arch) {
        .x86_64 => &.{ "x86_64", "x64", "amd64" },
        .aarch64 => &.{ "aarch64", "arm64" },
        .x86 => &.{ "x86", "i686", "i386" },
        else => &.{},
    };
    return .{ .os = os_keywords, .arch = arch_keywords };
}

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        var match = true;
        for (0..needle.len) |j| {
            if (std.ascii.toLower(haystack[i + j]) != std.ascii.toLower(needle[j])) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

/// Like containsIgnoreCase, but requires a left word-boundary: the character
/// preceding the match (if any) must not be an ASCII letter. This prevents
/// short keywords like "win" from matching inside unrelated words like
/// "darwin" (where the 'r' precedes 'win').
fn containsIgnoreCaseBounded(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0 or needle.len > haystack.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (i > 0 and std.ascii.isAlphabetic(haystack[i - 1])) continue;
        var match = true;
        for (0..needle.len) |j| {
            if (std.ascii.toLower(haystack[i + j]) != std.ascii.toLower(needle[j])) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

/// Returns true if the asset looks installable: archives, Windows .exe, or
/// bare binaries (extensionless files common in Go/Rust releases).
fn isInstallableAsset(name: []const u8) bool {
    if (std.mem.endsWith(u8, name, ".zip")) return true;
    if (std.mem.endsWith(u8, name, ".tar.gz")) return true;
    if (std.mem.endsWith(u8, name, ".tgz")) return true;
    if (std.mem.endsWith(u8, name, ".tar.xz")) return true;
    if (std.mem.endsWith(u8, name, ".exe")) return true;
    const non_installable = [_][]const u8{
        ".json", ".txt", ".pub", ".sig", ".asc", ".pem", ".md",
        ".sha256", ".sha512", ".md5", ".minisig",
        ".rpm",  ".deb",  ".apk", ".msi", ".pkg", ".dmg",
        ".yml",  ".yaml",
    };
    for (non_installable) |ext| {
        if (std.mem.endsWith(u8, name, ext)) return false;
    }
    return true;
}

/// Markers in asset names that indicate non-primary variants (libraries,
/// source tarballs, minimal/debug builds, plugins, distro-specific static
/// bundles) which should be deprioritized when a plain binary archive is
/// also available.
fn nonPrimaryPenalty(name: []const u8) u32 {
    const strong = [_][]const u8{
        "c-api",    "capi",      "headers",   "sdk",
        "dev",      "lib-only",  "src",       "source",
        "sources",  "sbom",      "checksum",  "checksums",
        "debug",    "dbg",       "symbols",
    };
    const medium = [_][]const u8{
        "plugin",   "plugins",   "wasi_nn",   "wasi-nn",
        "ffmpeg",   "tensorflow", "image",    "opencvmini",
    };
    const soft = [_][]const u8{
        "static",   "min",       "minimal",
    };
    var penalty: u32 = 0;
    for (strong) |m| if (containsIgnoreCaseBounded(name, m)) { penalty += 5; };
    for (medium) |m| if (containsIgnoreCaseBounded(name, m)) { penalty += 3; };
    for (soft) |m| if (containsIgnoreCaseBounded(name, m)) { penalty += 1; };
    return penalty;
}

/// Returns true if the asset name targets a platform that is clearly not
/// the host. Used to filter out obviously-wrong candidates (e.g.
/// `linux-android`, `wasm32-wasi`, or `darwin` on a Linux host) before
/// ranking. If filtering removes everything, the caller falls back to the
/// unfiltered set.
fn isWrongPlatform(name: []const u8, plat_os: []const []const u8) bool {
    const always_wrong = [_][]const u8{
        "linux-android", "android",
        "ios", "tvos", "watchos",
        "wasi",  "wasm32", "wasm64", "emscripten",
    };
    for (always_wrong) |t| {
        if (containsIgnoreCaseBounded(name, t)) return true;
    }
    for (plat_os) |k| {
        if (containsIgnoreCaseBounded(name, k)) return false;
    }
    const foreign = [_][]const u8{
        "windows", "win32", "win64", "mingw",
        "linux",
        "darwin",  "macos", "osx",
        "freebsd", "netbsd", "openbsd", "solaris", "illumos",
    };
    for (foreign) |t| {
        var is_host = false;
        for (plat_os) |k| {
            if (std.ascii.eqlIgnoreCase(k, t)) { is_host = true; break; }
        }
        if (is_host) continue;
        if (containsIgnoreCaseBounded(name, t)) return true;
    }
    return false;
}

/// Returns true if the asset name targets a CPU architecture that is
/// clearly not the host. Used to reject `linux-amd64` on aarch64 hosts
/// (and vice versa) so that a foreign-arch asset doesn't win on the
/// strength of an OS keyword match alone.
///
/// The check is deliberately conservative: it only rejects when the
/// name contains a foreign-arch token AND no host-arch token. That
/// preserves names that mention both arches (e.g. cross-arch bundles)
/// and is a no-op on hosts whose arch isn't in the supported set
/// (`plat_arch` empty).
fn isForeignArch(name: []const u8, plat_arch: []const []const u8) bool {
    if (plat_arch.len == 0) return false;
    const all_arch = [_][]const u8{
        "x86_64", "x64",   "amd64",
        "aarch64", "arm64",
        "armv7l", "armv7", "armv6",
        "i386",   "i686",  "x86",
    };
    for (plat_arch) |k| {
        if (containsIgnoreCaseBounded(name, k)) return false;
    }
    for (all_arch) |t| {
        var is_host = false;
        for (plat_arch) |k| {
            if (std.ascii.eqlIgnoreCase(k, t)) { is_host = true; break; }
        }
        if (is_host) continue;
        if (containsIgnoreCaseBounded(name, t)) return true;
    }
    return false;
}

/// On Linux hosts, prefer portable glibc/musl triples over distro-tagged
/// variants. Returns a signed bonus to fold into the score.
fn linuxPortabilityBonus(name: []const u8, plat_os: []const []const u8) i32 {
    var is_linux_host = false;
    for (plat_os) |k| {
        if (std.ascii.eqlIgnoreCase(k, "linux")) { is_linux_host = true; break; }
    }
    if (!is_linux_host) return 0;
    var s: i32 = 0;
    const generic = [_][]const u8{
        "manylinux",
        "unknown-linux-gnu", "unknown-linux-musl",
        "linux-gnu", "linux-musl",
    };
    for (generic) |t| {
        if (containsIgnoreCaseBounded(name, t)) { s += 2; break; }
    }
    const distros = [_][]const u8{
        "ubuntu", "debian", "alpine", "fedora", "centos", "rhel", "suse",
    };
    for (distros) |t| {
        if (containsIgnoreCaseBounded(name, t)) { s -= 1; break; }
    }
    return s;
}

/// Bonus for archive formats (portable, pre-packaged) over bare binaries.
fn archiveFormatBonus(name: []const u8) i32 {
    if (std.mem.endsWith(u8, name, ".tar.gz") or
        std.mem.endsWith(u8, name, ".tgz") or
        std.mem.endsWith(u8, name, ".tar.xz") or
        std.mem.endsWith(u8, name, ".zip")) return 1;
    return 0;
}

/// Tie-break: prefer shorter, then lexicographically smaller. Returns true
/// if `a` should beat `b`.
fn tieBreakPrefers(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return a.len < b.len;
    return std.mem.order(u8, a, b) == .lt;
}

fn scoreAsset(name: []const u8, plat: PlatformKeywords) i32 {
    var score: i32 = 0;
    for (plat.os) |kw| {
        if (containsIgnoreCaseBounded(name, kw)) { score += 10; break; }
    }
    for (plat.arch) |kw| {
        if (containsIgnoreCaseBounded(name, kw)) { score += 5; break; }
    }
    score -= @as(i32, @intCast(nonPrimaryPenalty(name)));
    score += linuxPortabilityBonus(name, plat.os);
    score += archiveFormatBonus(name);
    return score;
}

fn selectBestByScore(assets: []const Asset, plat: PlatformKeywords) ?Asset {
    var best: ?Asset = null;
    var best_score: i32 = std.math.minInt(i32);
    for (assets) |asset| {
        if (!isInstallableAsset(asset.name)) continue;
        if (isWrongPlatform(asset.name, plat.os)) continue;
        if (isForeignArch(asset.name, plat.arch)) continue;
        const score = scoreAsset(asset.name, plat);
        if (best == null or score > best_score or
            (score == best_score and tieBreakPrefers(asset.name, best.?.name)))
        {
            best_score = score;
            best = asset;
        }
    }
    return best;
}

pub fn findBestAssetForKeywords(assets: []const Asset, plat: PlatformKeywords) !Asset {
    if (selectBestByScore(assets, plat)) |b| {
        if (scoreAsset(b.name, plat) > 0) return b;
    }
    var count: u32 = 0;
    var single: ?Asset = null;
    for (assets) |asset| {
        if (!isInstallableAsset(asset.name)) continue;
        if (isWrongPlatform(asset.name, plat.os)) continue;
        if (isForeignArch(asset.name, plat.arch)) continue;
        count += 1;
        single = asset;
    }
    if (count == 1) return single.?;
    return error.NoMatchingAsset;
}

pub fn findBestAsset(assets: []const Asset) !Asset {
    return findBestAssetForKeywords(assets, currentPlatformKeywords());
}

/// Re-exported so install.zig can keep listing only installable assets in
/// its "no executables" / "no matching asset" diagnostics.
pub fn isInstallableAssetName(name: []const u8) bool {
    return isInstallableAsset(name);
}

// ---------------------------------------------------------------------------
// SHA256 download verification (Phase 1 of issue #50).
// ---------------------------------------------------------------------------

const Sha256 = std.crypto.hash.sha2.Sha256;

/// Outcome of running the verification step for a downloaded asset.
pub const VerifyOutcome = enum {
    /// A SHA256 checksum file was found and its hash matched the download.
    sha256_verified,
    /// A sigstore bundle was found and verification (chain, signature, Rekor
    /// SET) succeeded. This implies SHA256 verification too — the bundle's
    /// `messageDigest` is checked against the cached file.
    sigstore_verified,
    /// No verification material was published for this release.
    no_verification,
    /// User passed --skip-verify.
    skipped,
};

/// Decode a single ASCII hex character into 0..15. Returns null on invalid input.
fn hexNibble(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

/// Returns true if `s` is exactly 64 ASCII hex characters.
fn isHex64(s: []const u8) bool {
    if (s.len != 64) return false;
    for (s) |c| {
        if (hexNibble(c) == null) return false;
    }
    return true;
}

/// Lowercase ASCII-hex equality. Both sides must already be 64 chars.
fn hexEqIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (std.ascii.toLower(x) != std.ascii.toLower(y)) return false;
    }
    return true;
}

/// Format a 32-byte digest as 64 lowercase hex characters into `out`.
fn sha256ToHex(digest: [32]u8, out: *[64]u8) void {
    const hex = "0123456789abcdef";
    for (digest, 0..) |b, i| {
        out[i * 2] = hex[b >> 4];
        out[i * 2 + 1] = hex[b & 0x0f];
    }
}

const Sha256Entry = struct {
    hex: []const u8,
    name: []const u8,
};

/// Parse a single line from a SHA256 checksum file. Supports:
///   GNU coreutils: `<hex>  <name>` or `<hex> *<name>` (binary-mode marker)
///   BSD shasum:    `SHA256 (<name>) = <hex>`
/// Strips a leading `./` from the filename. Returns null for blank lines,
/// `#` comment lines, or anything we can't recognize.
fn parseSha256Line(raw: []const u8) ?Sha256Entry {
    var line = raw;
    while (line.len > 0 and (line[line.len - 1] == '\r' or line[line.len - 1] == '\n' or
        line[line.len - 1] == ' ' or line[line.len - 1] == '\t'))
    {
        line = line[0 .. line.len - 1];
    }
    while (line.len > 0 and (line[0] == ' ' or line[0] == '\t')) line = line[1..];
    if (line.len == 0) return null;
    if (line[0] == '#') return null;

    const bsd_prefix = "SHA256 (";
    if (line.len > bsd_prefix.len and std.mem.startsWith(u8, line, bsd_prefix)) {
        const rest = line[bsd_prefix.len..];
        const close = std.mem.indexOfScalar(u8, rest, ')') orelse return null;
        const name = rest[0..close];
        const after = rest[close + 1 ..];
        if (after.len < 4) return null;
        if (!std.mem.startsWith(u8, after, " = ")) return null;
        const hex = after[3..];
        if (!isHex64(hex)) return null;
        return .{ .hex = hex, .name = stripDotSlash(name) };
    }

    if (line.len < 64 + 1 + 1) return null;
    const hex = line[0..64];
    if (!isHex64(hex)) return null;
    if (line[64] != ' ' and line[64] != '\t') return null;
    var name_start: usize = 65;
    while (name_start < line.len and (line[name_start] == ' ' or line[name_start] == '\t')) {
        name_start += 1;
    }
    if (name_start < line.len and line[name_start] == '*') name_start += 1;
    if (name_start >= line.len) return null;
    return .{ .hex = hex, .name = stripDotSlash(line[name_start..]) };
}

fn stripDotSlash(name: []const u8) []const u8 {
    if (name.len >= 2 and name[0] == '.' and name[1] == '/') return name[2..];
    return name;
}

/// Filename equality used when matching a checksum-file entry to a target
/// asset basename. Case-insensitive (Windows + Unix asset names mix), and
/// matches by basename so `./foo` and `foo` both work after `stripDotSlash`.
fn checksumNameMatches(entry_name: []const u8, target: []const u8) bool {
    const last_slash = std.mem.lastIndexOfAny(u8, entry_name, "/\\");
    const basename = if (last_slash) |i| entry_name[i + 1 ..] else entry_name;
    return std.ascii.eqlIgnoreCase(basename, target);
}

/// Search a SHA256 checksum-file body for the entry matching `target_name`
/// and return its 64-char hex hash. Returns null if no entry matches.
fn lookupSha256(content: []const u8, target_name: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, content, '\n');
    while (it.next()) |line| {
        const entry = parseSha256Line(line) orelse continue;
        if (checksumNameMatches(entry.name, target_name)) return entry.hex;
    }
    return null;
}

/// Returns true if `name` looks like a SHA256 checksum file rather than a
/// signature, key, or unrelated checksum (sha512/md5).
fn isSha256ChecksumFile(name: []const u8) bool {
    const reject_suffixes = [_][]const u8{
        ".sig", ".asc", ".pem", ".pub", ".gpg", ".minisig",
        ".sha512", ".sha512sum", ".sha512sums",
        ".md5", ".md5sum", ".md5sums",
        ".sha1", ".sha1sum",
    };
    for (reject_suffixes) |s| {
        if (std.ascii.endsWithIgnoreCase(name, s)) return false;
    }
    if (std.ascii.endsWithIgnoreCase(name, ".sha256")) return true;
    if (std.ascii.endsWithIgnoreCase(name, ".sha256sum")) return true;
    if (std.ascii.endsWithIgnoreCase(name, ".sha256sums")) return true;
    if (std.ascii.endsWithIgnoreCase(name, ".sha256sum.txt")) return true;
    if (std.ascii.endsWithIgnoreCase(name, ".sha256sums.txt")) return true;
    if (containsIgnoreCase(name, "checksum")) return true;
    if (containsIgnoreCase(name, "sha256sums")) return true;
    if (std.ascii.eqlIgnoreCase(name, "SHA256SUMS")) return true;
    return false;
}

/// Locate the best SHA256 checksum asset for `asset_name` in the release's
/// asset list. Prefers a sidecar (`<asset>.sha256`) when present, otherwise
/// falls back to an aggregate checksum file. Returns null when none is
/// available.
fn findChecksumAsset(assets: []const Asset, asset_name: []const u8) ?Asset {
    for (assets) |a| {
        if (std.mem.eql(u8, a.name, asset_name)) continue;
        if (std.ascii.endsWithIgnoreCase(a.name, ".sha256") or
            std.ascii.endsWithIgnoreCase(a.name, ".sha256sum"))
        {
            const dot = std.mem.lastIndexOfScalar(u8, a.name, '.').?;
            const stem = a.name[0..dot];
            const final_stem = if (std.ascii.endsWithIgnoreCase(stem, ".sha256"))
                stem[0 .. stem.len - ".sha256".len]
            else
                stem;
            if (std.ascii.eqlIgnoreCase(final_stem, asset_name)) return a;
        }
    }
    for (assets) |a| {
        if (std.mem.eql(u8, a.name, asset_name)) continue;
        if (isSha256ChecksumFile(a.name)) return a;
    }
    return null;
}

/// Stream the file at `path` through SHA-256 and return the 32-byte digest.
fn computeFileSha256(io: Io, path: []const u8) ![32]u8 {
    var file = try Dir.openFileAbsolute(io, path, .{});
    defer file.close(io);
    var read_buf: [64 * 1024]u8 = undefined;
    var file_reader = file.reader(io, &read_buf);
    var hasher = Sha256.init(.{});
    var chunk: [64 * 1024]u8 = undefined;
    while (true) {
        const n = try file_reader.interface.readSliceShort(&chunk);
        if (n == 0) break;
        hasher.update(chunk[0..n]);
        if (n < chunk.len) break;
    }
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

/// Run Phase 1 verification on `download_path`. On `mismatch` this function
/// prints the diagnostic and returns `error.ChecksumMismatch`; the caller is
/// responsible for deleting the cached file and exiting.
pub fn verifyDownloadedAssetSha256(
    allocator: std.mem.Allocator,
    io: Io,
    cache_dir: []const u8,
    assets: []const Asset,
    asset_name: []const u8,
    download_path: []const u8,
    debug_w: ?*Writer,
    auth_header: ?[]const u8,
    w: *Writer,
    err_w: *Writer,
) !VerifyOutcome {
    const checksum_asset = findChecksumAsset(assets, asset_name) orelse {
        return .no_verification;
    };

    debugLog(debug_w, "debug: checksum asset: {s}\n", .{checksum_asset.name});

    const checksum_path = try std.fmt.allocPrint(allocator, "{s}{c}{s}", .{
        cache_dir, std.fs.path.sep, checksum_asset.name,
    });
    defer allocator.free(checksum_path);
    defer Dir.deleteFileAbsolute(io, checksum_path) catch {};

    http.downloadToFile(allocator, io, checksum_asset.browser_download_url, checksum_path, .{
        .auth_header = auth_header,
        .debug_w = debug_w,
    }) catch |err| {
        try err_w.print("error: failed to download checksum file '{s}': {}\n", .{ checksum_asset.name, err });
        try err_w.flush();
        return error.ChecksumDownloadFailed;
    };

    const checksum_bytes = blk: {
        var dir = try Dir.openDirAbsolute(io, cache_dir, .{});
        defer dir.close(io);
        break :blk try dir.readFileAlloc(io, checksum_asset.name, allocator, Io.Limit.limited(16 * 1024 * 1024));
    };
    defer allocator.free(checksum_bytes);

    const expected_hex = lookupSha256(checksum_bytes, asset_name) orelse {
        try err_w.print("error: checksum file '{s}' has no entry for '{s}'\n", .{ checksum_asset.name, asset_name });
        try err_w.flush();
        return error.ChecksumEntryMissing;
    };

    const digest = computeFileSha256(io, download_path) catch |err| {
        try err_w.print("error: failed to hash '{s}': {}\n", .{ download_path, err });
        try err_w.flush();
        return err;
    };
    var actual_hex: [64]u8 = undefined;
    sha256ToHex(digest, &actual_hex);

    if (!hexEqIgnoreCase(expected_hex, &actual_hex)) {
        try err_w.print(
            "error: SHA256 mismatch for {s}\n  expected: {s}\n  actual:   {s}\n  source:   {s}\n",
            .{ asset_name, expected_hex, &actual_hex, checksum_asset.name },
        );
        try err_w.flush();
        return error.ChecksumMismatch;
    }

    try w.print("verified sha256 {s}… ({s})\n", .{ actual_hex[0..12], checksum_asset.name });
    try w.flush();
    return .sha256_verified;
}

/// Run Phase 2 verification (sigstore bundle) on `download_path`. Verifies
/// the X.509 chain to the embedded Fulcio root, the artifact ECDSA
/// signature, and the Rekor SET. Returns `.no_verification` when no bundle
/// asset is published. On any verification failure, prints a diagnostic and
/// returns an error; the caller deletes the cached file and exits.
pub fn verifyDownloadedAssetSigstore(
    allocator: std.mem.Allocator,
    io: Io,
    cache_dir: []const u8,
    assets: []const Asset,
    asset_name: []const u8,
    download_path: []const u8,
    debug_w: ?*Writer,
    auth_header: ?[]const u8,
    w: *Writer,
    err_w: *Writer,
) !VerifyOutcome {
    const views = try allocator.alloc(sigstore.AssetView, assets.len);
    defer allocator.free(views);
    for (assets, 0..) |a, i| {
        views[i] = .{ .name = a.name, .browser_download_url = a.browser_download_url };
    }

    const bundle_asset = sigstore.findBundleAsset(views, asset_name) orelse {
        return .no_verification;
    };

    debugLog(debug_w, "debug: sigstore bundle asset: {s}\n", .{bundle_asset.name});

    const bundle_path = try std.fmt.allocPrint(allocator, "{s}{c}{s}", .{
        cache_dir, std.fs.path.sep, bundle_asset.name,
    });
    defer allocator.free(bundle_path);
    defer Dir.deleteFileAbsolute(io, bundle_path) catch {};

    http.downloadToFile(allocator, io, bundle_asset.browser_download_url, bundle_path, .{
        .auth_header = auth_header,
        .debug_w = debug_w,
    }) catch |err| {
        try err_w.print("error: failed to download sigstore bundle '{s}': {}\n", .{ bundle_asset.name, err });
        try err_w.flush();
        return error.SigstoreDownloadFailed;
    };

    const bundle_bytes = blk: {
        var dir = try Dir.openDirAbsolute(io, cache_dir, .{});
        defer dir.close(io);
        break :blk try dir.readFileAlloc(io, bundle_asset.name, allocator, Io.Limit.limited(8 * 1024 * 1024));
    };
    defer allocator.free(bundle_bytes);

    var bundle = sigstore.parseBundle(allocator, bundle_bytes) catch |err| {
        try err_w.print("error: failed to parse sigstore bundle '{s}': {s}\n", .{ bundle_asset.name, @errorName(err) });
        try err_w.flush();
        return error.SigstoreParseFailed;
    };
    defer bundle.deinit();

    const rekor = sigstore.embeddedRekorKey(allocator) catch |err| {
        try err_w.print("error: failed to load embedded Rekor key: {s}\n", .{@errorName(err)});
        try err_w.flush();
        return err;
    };

    var file = try Dir.openFileAbsolute(io, download_path, .{});
    defer file.close(io);

    const identity = sigstore.verifyBundle(allocator, io, bundle, rekor, file) catch |err| {
        try err_w.print("error: sigstore verification failed for '{s}': {s}\n", .{ asset_name, @errorName(err) });
        try err_w.flush();
        return error.SigstoreVerificationFailed;
    };

    var digest_hex: [64]u8 = undefined;
    sha256ToHex(bundle.artifact_digest, &digest_hex);
    try w.print(
        "verified sigstore: sha256 {s}… (rekor t={d}, log {d})\n",
        .{ digest_hex[0..12], identity.integrated_time, bundle.rekor_log_index },
    );
    if (identity.identity.primarySubject()) |subject| {
        try w.print("  identity: {s}\n", .{subject});
    }
    if (identity.identity.oidc_issuer) |issuer| {
        try w.print("  issuer:   {s}\n", .{issuer});
    }
    if (identity.inclusion_verified) {
        const cp_note: []const u8 = if (identity.checkpoint_verified) " + checkpoint" else "";
        if (bundle.inclusion) |inc| {
            try w.print("  inclusion: tree size {d}{s}\n", .{ inc.tree_size, cp_note });
        }
    }
    try w.flush();
    return .sigstore_verified;
}

// ---------------------------------------------------------------------------
// Asset matching by name and unified verification wrapper.
// ---------------------------------------------------------------------------

/// Result of `findAssetByName`. The `ambiguous` slice references entries in
/// the input `assets` array (so they live as long as the assets do), but the
/// slice itself is allocator-owned and the caller must free it.
pub const AssetMatch = union(enum) {
    /// Exactly one asset matched (exact-name or unique substring).
    one: Asset,
    /// No assets matched.
    none,
    /// Multiple assets substring-matched. Caller frees the slice.
    ambiguous: []const Asset,
};

/// Find a single asset by `name` using a two-stage match:
///   1. Case-sensitive exact name match — one match wins.
///   2. Otherwise case-insensitive substring match — one match wins,
///      multiple → `.ambiguous`, zero → `.none`.
pub fn findAssetByName(
    allocator: std.mem.Allocator,
    assets: []const Asset,
    name: []const u8,
) !AssetMatch {
    for (assets) |a| {
        if (std.mem.eql(u8, a.name, name)) return .{ .one = a };
    }

    var matches: std.ArrayListUnmanaged(Asset) = .empty;
    errdefer matches.deinit(allocator);
    for (assets) |a| {
        if (containsIgnoreCase(a.name, name)) try matches.append(allocator, a);
    }
    if (matches.items.len == 0) {
        matches.deinit(allocator);
        return .none;
    }
    if (matches.items.len == 1) {
        const only = matches.items[0];
        matches.deinit(allocator);
        return .{ .one = only };
    }
    return .{ .ambiguous = try matches.toOwnedSlice(allocator) };
}

/// Run SHA256 + sigstore verification on `download_path` and return the
/// strongest outcome. Mirrors the existing `cmdInstall` flow:
///
///   - `skip_verify=true` → prints a `note:` line and returns `.skipped`
///     without touching the file.
///   - Otherwise runs SHA256 first, then sigstore. Sigstore success
///     upgrades the outcome (`.sigstore_verified` implies SHA256).
///   - If neither material is published, prints a `note:` saying the
///     download is unverified and returns `.no_verification`.
///
/// Errors propagate to the caller, which is responsible for deleting the
/// cached file and aborting (`install` exits, `download` reports and
/// removes the partial file).
pub fn verifyAssetOnDisk(
    allocator: std.mem.Allocator,
    io: Io,
    cache_dir: []const u8,
    assets: []const Asset,
    asset_name: []const u8,
    download_path: []const u8,
    debug_w: ?*Writer,
    auth_header: ?[]const u8,
    skip_verify: bool,
    w: *Writer,
    err_w: *Writer,
) !VerifyOutcome {
    if (skip_verify) {
        try w.print("note: verification skipped (--skip-verify)\n", .{});
        try w.flush();
        return .skipped;
    }

    const sha_outcome = try verifyDownloadedAssetSha256(
        allocator,
        io,
        cache_dir,
        assets,
        asset_name,
        download_path,
        debug_w,
        auth_header,
        w,
        err_w,
    );

    const sig_outcome = try verifyDownloadedAssetSigstore(
        allocator,
        io,
        cache_dir,
        assets,
        asset_name,
        download_path,
        debug_w,
        auth_header,
        w,
        err_w,
    );

    if (sig_outcome == .sigstore_verified) return .sigstore_verified;
    if (sha_outcome == .sha256_verified) return .sha256_verified;

    try w.print("note: download is unverified (no SHA256 checksum or sigstore bundle published)\n", .{});
    try w.flush();
    return .no_verification;
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

test {
    _ = @import("sigstore.zig");
}

test "parseRepoSpec with tag" {
    const spec = try parseRepoSpec("ctaggart/pencil2d@v0.8.0-dev.1");
    try std.testing.expectEqualStrings("ctaggart", spec.owner);
    try std.testing.expectEqualStrings("pencil2d", spec.repo);
    try std.testing.expectEqualStrings("v0.8.0-dev.1", spec.tag.?);
}

test "parseRepoSpec without tag" {
    const spec = try parseRepoSpec("ctaggart/pencil2d");
    try std.testing.expectEqualStrings("ctaggart", spec.owner);
    try std.testing.expectEqualStrings("pencil2d", spec.repo);
    try std.testing.expect(spec.tag == null);
}

test "parseRepoSpec invalid" {
    try std.testing.expectError(error.InvalidSpec, parseRepoSpec("noslash"));
    try std.testing.expectError(error.InvalidSpec, parseRepoSpec("/repo"));
    try std.testing.expectError(error.InvalidSpec, parseRepoSpec("owner/"));
}

test "parseFileSpec with tag" {
    const fs = try parseFileSpec("owner/repo/asset.tar.gz@v1.2.3");
    try std.testing.expectEqualStrings("owner", fs.owner);
    try std.testing.expectEqualStrings("repo", fs.repo);
    try std.testing.expectEqualStrings("asset.tar.gz", fs.file);
    try std.testing.expectEqualStrings("v1.2.3", fs.tag.?);
}

test "parseFileSpec without tag" {
    const fs = try parseFileSpec("owner/repo/file.zip");
    try std.testing.expectEqualStrings("owner", fs.owner);
    try std.testing.expectEqualStrings("repo", fs.repo);
    try std.testing.expectEqualStrings("file.zip", fs.file);
    try std.testing.expect(fs.tag == null);
}

test "parseFileSpec with refs/tags style tag" {
    const fs = try parseFileSpec("owner/repo/asset@refs/tags/v1.0");
    try std.testing.expectEqualStrings("asset", fs.file);
    try std.testing.expectEqualStrings("refs/tags/v1.0", fs.tag.?);
}

test "parseFileSpec invalid" {
    try std.testing.expectError(error.InvalidSpec, parseFileSpec("owner/repo"));
    try std.testing.expectError(error.InvalidSpec, parseFileSpec("/repo/file"));
    try std.testing.expectError(error.InvalidSpec, parseFileSpec("owner//file"));
    try std.testing.expectError(error.InvalidSpec, parseFileSpec("owner/repo/"));
    try std.testing.expectError(error.InvalidSpec, parseFileSpec("owner/repo/file@"));
    try std.testing.expectError(error.InvalidSpec, parseFileSpec("owner/repo/."));
    try std.testing.expectError(error.InvalidSpec, parseFileSpec("owner/repo/.."));
    try std.testing.expectError(error.InvalidSpec, parseFileSpec("owner/repo/dir/file"));
}

test "parseGitHubReleaseUrl matches canonical download URL" {
    const a = std.testing.allocator;
    const parsed = (try parseGitHubReleaseUrl(a, "https://github.com/cli/cli/releases/download/v2.40.0/gh_2.40.0_linux_amd64.tar.gz")).?;
    defer parsed.deinit(a);
    try std.testing.expectEqualStrings("cli", parsed.owner);
    try std.testing.expectEqualStrings("cli", parsed.repo);
    try std.testing.expectEqualStrings("v2.40.0", parsed.tag);
    try std.testing.expectEqualStrings("gh_2.40.0_linux_amd64.tar.gz", parsed.file);
}

test "parseGitHubReleaseUrl decodes percent-escaped tag" {
    const a = std.testing.allocator;
    const parsed = (try parseGitHubReleaseUrl(a, "https://github.com/o/r/releases/download/v1.2%2Bbeta/asset.tgz")).?;
    defer parsed.deinit(a);
    try std.testing.expectEqualStrings("v1.2+beta", parsed.tag);
    try std.testing.expectEqualStrings("asset.tgz", parsed.file);
}

test "parseGitHubReleaseUrl preserves wasi-sdk style tag" {
    const a = std.testing.allocator;
    const parsed = (try parseGitHubReleaseUrl(a, "https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-25/wasi-sdk-25.0-x86_64-linux.tar.gz")).?;
    defer parsed.deinit(a);
    try std.testing.expectEqualStrings("wasi-sdk-25", parsed.tag);
}

test "parseGitHubReleaseUrl rejects non-download URLs" {
    const a = std.testing.allocator;
    try std.testing.expect((try parseGitHubReleaseUrl(a, "https://github.com/o/r/releases/tag/v1.0")) == null);
    try std.testing.expect((try parseGitHubReleaseUrl(a, "https://github.com/o/r/archive/refs/tags/v1.0.tar.gz")) == null);
    try std.testing.expect((try parseGitHubReleaseUrl(a, "https://raw.githubusercontent.com/o/r/main/file")) == null);
    try std.testing.expect((try parseGitHubReleaseUrl(a, "https://example.com/file.tar.gz")) == null);
    try std.testing.expect((try parseGitHubReleaseUrl(a, "not a url")) == null);
    try std.testing.expect((try parseGitHubReleaseUrl(a, "https://github.com/o/r/releases/download/v1.0/file/extra")) == null);
}

test "classifyArg recognises url, file_spec, repo_spec" {
    switch (try classifyArg("https://example.com/x.tgz")) {
        .url => |u| try std.testing.expectEqualStrings("https://example.com/x.tgz", u),
        else => try std.testing.expect(false),
    }
    switch (try classifyArg("owner/repo/file.tar.gz@v1")) {
        .file_spec => |fs| {
            try std.testing.expectEqualStrings("owner", fs.owner);
            try std.testing.expectEqualStrings("file.tar.gz", fs.file);
            try std.testing.expectEqualStrings("v1", fs.tag.?);
        },
        else => try std.testing.expect(false),
    }
    switch (try classifyArg("owner/repo@v1")) {
        .repo_spec => |rs| {
            try std.testing.expectEqualStrings("owner", rs.owner);
            try std.testing.expectEqualStrings("repo", rs.repo);
            try std.testing.expectEqualStrings("v1", rs.tag.?);
        },
        else => try std.testing.expect(false),
    }
    switch (try classifyArg("owner/repo")) {
        .repo_spec => |rs| try std.testing.expectEqualStrings("repo", rs.repo),
        else => try std.testing.expect(false),
    }
    try std.testing.expectError(error.InvalidSpec, classifyArg("noslash"));
    try std.testing.expectError(error.InvalidSpec, classifyArg(""));
}

test "containsIgnoreCase" {
    try std.testing.expect(containsIgnoreCase("pencil2d-Windows.zip", "windows"));
    try std.testing.expect(containsIgnoreCase("pencil2d-LINUX.tar.gz", "linux"));
    try std.testing.expect(!containsIgnoreCase("pencil2d-macos.zip", "windows"));
}

test "containsIgnoreCaseBounded enforces left word boundary" {
    try std.testing.expect(containsIgnoreCaseBounded("tool-win64.zip", "win"));
    try std.testing.expect(containsIgnoreCaseBounded("Win32.zip", "win"));
    try std.testing.expect(containsIgnoreCaseBounded("pc-windows-msvc.zip", "windows"));
    try std.testing.expect(!containsIgnoreCaseBounded("x86_64-apple-darwin.tar.gz", "win"));
    try std.testing.expect(!containsIgnoreCaseBounded("darwin.zip", "win"));
}

test "findBestAsset prefers windows over darwin" {
    const assets = [_]Asset{
        .{ .name = "ripgrep-15.1.0-x86_64-apple-darwin.tar.gz", .browser_download_url = "" },
        .{ .name = "ripgrep-15.1.0-x86_64-pc-windows-gnu.zip", .browser_download_url = "" },
        .{ .name = "ripgrep-15.1.0-x86_64-pc-windows-msvc.zip", .browser_download_url = "" },
    };
    const best = try findBestAssetForKeywords(&assets, .{
        .os = &.{ "windows", "win" },
        .arch = &.{ "x86_64", "x64", "amd64" },
    });
    try std.testing.expect(std.mem.indexOf(u8, best.name, "windows") != null);
}

test "isInstallableAsset" {
    try std.testing.expect(isInstallableAsset("foo.zip"));
    try std.testing.expect(isInstallableAsset("foo.tar.gz"));
    try std.testing.expect(isInstallableAsset("foo.tgz"));
    try std.testing.expect(isInstallableAsset("foo.tar.xz"));
    try std.testing.expect(isInstallableAsset("cosign-windows-amd64.exe"));
    try std.testing.expect(isInstallableAsset("tool.exe"));
    try std.testing.expect(isInstallableAsset("cosign-linux-amd64"));
    try std.testing.expect(isInstallableAsset("cosign-darwin-arm64"));
    try std.testing.expect(!isInstallableAsset("checksums.txt"));
    try std.testing.expect(!isInstallableAsset("foo.sha256"));
    try std.testing.expect(!isInstallableAsset("cosign-linux-amd64.sigstore.json"));
    try std.testing.expect(!isInstallableAsset("cosign-3.0.6-1.x86_64.rpm"));
    try std.testing.expect(!isInstallableAsset("cosign_3.0.6_amd64.deb"));
    try std.testing.expect(!isInstallableAsset("cosign_3.0.6_aarch64.apk"));
    try std.testing.expect(!isInstallableAsset("release-cosign.pub"));
}

test "findBestAsset selects cosign exe for Windows" {
    const assets = [_]Asset{
        .{ .name = "cosign-darwin-amd64", .browser_download_url = "" },
        .{ .name = "cosign-darwin-amd64.sigstore.json", .browser_download_url = "" },
        .{ .name = "cosign-linux-amd64", .browser_download_url = "" },
        .{ .name = "cosign-linux-amd64.sigstore.json", .browser_download_url = "" },
        .{ .name = "cosign-windows-amd64.exe", .browser_download_url = "" },
        .{ .name = "cosign-windows-amd64.exe.sigstore.json", .browser_download_url = "" },
        .{ .name = "cosign_checksums.txt", .browser_download_url = "" },
        .{ .name = "release-cosign.pub", .browser_download_url = "" },
    };
    const best = try findBestAssetForKeywords(&assets, .{
        .os = &.{ "windows", "win" },
        .arch = &.{ "x86_64", "x64", "amd64" },
    });
    try std.testing.expectEqualStrings("cosign-windows-amd64.exe", best.name);
}

test "findBestAsset prefers plain archive over c-api variant" {
    const assets = [_]Asset{
        .{ .name = "wasmtime-v44.0.0-aarch64-linux-c-api.tar.xz", .browser_download_url = "" },
        .{ .name = "wasmtime-v44.0.0-aarch64-linux-min.tar.xz", .browser_download_url = "" },
        .{ .name = "wasmtime-v44.0.0-aarch64-linux.tar.xz", .browser_download_url = "" },
        .{ .name = "wasmtime-v44.0.0-x86_64-linux.tar.xz", .browser_download_url = "" },
    };
    const best = try findBestAssetForKeywords(&assets, .{
        .os = &.{"linux"},
        .arch = &.{ "aarch64", "arm64" },
    });
    try std.testing.expectEqualStrings("wasmtime-v44.0.0-aarch64-linux.tar.xz", best.name);
}

test "findBestAsset picks manylinux over distro-tagged and static WasmEdge variants" {
    const assets = [_]Asset{
        .{ .name = "WasmEdge-0.16.2-manylinux_2_28_aarch64.tar.gz", .browser_download_url = "" },
        .{ .name = "WasmEdge-0.16.2-alpine3.23_aarch64_static.tar.gz", .browser_download_url = "" },
        .{ .name = "WasmEdge-0.16.2-debian11_aarch64_static.tar.gz", .browser_download_url = "" },
        .{ .name = "WasmEdge-0.16.2-ubuntu20.04_aarch64.tar.gz", .browser_download_url = "" },
        .{ .name = "WasmEdge-plugin-wasi_nn-ggml-0.16.2-manylinux_2_28_aarch64.tar.gz", .browser_download_url = "" },
        .{ .name = "WasmEdge-0.16.2-aarch64.rpm", .browser_download_url = "" },
    };
    const best = try findBestAssetForKeywords(&assets, .{
        .os = &.{"linux"},
        .arch = &.{ "aarch64", "arm64" },
    });
    try std.testing.expectEqualStrings("WasmEdge-0.16.2-manylinux_2_28_aarch64.tar.gz", best.name);
}

test "findBestAsset rejects linux-android on Linux host" {
    const assets = [_]Asset{
        .{ .name = "wash-aarch64-linux-android", .browser_download_url = "" },
        .{ .name = "wash-aarch64-unknown-linux-musl", .browser_download_url = "" },
        .{ .name = "wash-x86_64-unknown-linux-musl", .browser_download_url = "" },
        .{ .name = "wash-aarch64-apple-darwin", .browser_download_url = "" },
    };
    const best = try findBestAssetForKeywords(&assets, .{
        .os = &.{"linux"},
        .arch = &.{ "aarch64", "arm64" },
    });
    try std.testing.expectEqualStrings("wash-aarch64-unknown-linux-musl", best.name);
}

test "findBestAsset tie-break prefers shorter name" {
    const assets = [_]Asset{
        .{ .name = "tool-x86_64-linux-extra.tar.gz", .browser_download_url = "" },
        .{ .name = "tool-x86_64-linux.tar.gz", .browser_download_url = "" },
    };
    const best = try findBestAssetForKeywords(&assets, .{
        .os = &.{"linux"},
        .arch = &.{ "x86_64", "x64", "amd64" },
    });
    try std.testing.expectEqualStrings("tool-x86_64-linux.tar.gz", best.name);
}

test "isWrongPlatform basics" {
    const linux_os: []const []const u8 = &.{"linux"};
    try std.testing.expect(isWrongPlatform("wash-aarch64-linux-android", linux_os));
    try std.testing.expect(isWrongPlatform("tool-wasm32-wasi.tar.gz", linux_os));
    try std.testing.expect(isWrongPlatform("tool-x86_64-apple-darwin.tar.gz", linux_os));
    try std.testing.expect(!isWrongPlatform("tool-x86_64-unknown-linux-gnu.tar.gz", linux_os));
    try std.testing.expect(!isWrongPlatform("tool-aarch64-linux.tar.xz", linux_os));

    const win_os: []const []const u8 = &.{ "windows", "win" };
    try std.testing.expect(isWrongPlatform("tool-x86_64-apple-darwin.tar.gz", win_os));
    try std.testing.expect(isWrongPlatform("tool-x86_64-unknown-linux-gnu.tar.gz", win_os));
    try std.testing.expect(!isWrongPlatform("tool-x86_64-pc-windows-msvc.zip", win_os));
}

test "isForeignArch basics" {
    const aarch64_arch: []const []const u8 = &.{ "aarch64", "arm64" };
    try std.testing.expect(isForeignArch("lunatic-linux-amd64.tar.gz", aarch64_arch));
    try std.testing.expect(isForeignArch("wavm-nightly-linux-x64.tar.gz", aarch64_arch));
    try std.testing.expect(isForeignArch("tool-x86_64-unknown-linux-gnu.tar.gz", aarch64_arch));
    try std.testing.expect(isForeignArch("tool-i686-linux.tar.gz", aarch64_arch));
    try std.testing.expect(!isForeignArch("tool-aarch64-linux.tar.xz", aarch64_arch));
    try std.testing.expect(!isForeignArch("wash-aarch64-unknown-linux-musl", aarch64_arch));
    try std.testing.expect(!isForeignArch("lunatic-macos-universal.tar.gz", aarch64_arch));
    try std.testing.expect(!isForeignArch("tool.tar.gz", aarch64_arch));
    try std.testing.expect(!isForeignArch("tool-x86_64-and-aarch64.tar.gz", aarch64_arch));

    const x86_64_arch: []const []const u8 = &.{ "x86_64", "x64", "amd64" };
    try std.testing.expect(isForeignArch("tool-aarch64-linux.tar.xz", x86_64_arch));
    try std.testing.expect(isForeignArch("tool-arm64-linux.tar.gz", x86_64_arch));
    try std.testing.expect(isForeignArch("tool-armv7l.tar.gz", x86_64_arch));
    try std.testing.expect(!isForeignArch("tool-x86_64-linux.tar.gz", x86_64_arch));
    try std.testing.expect(!isForeignArch("lunatic-linux-amd64.tar.gz", x86_64_arch));

    try std.testing.expect(!isForeignArch("tool-linux64.tar.gz", aarch64_arch));

    const empty: []const []const u8 = &.{};
    try std.testing.expect(!isForeignArch("tool-x86_64-linux.tar.gz", empty));
}

test "findBestAsset errors on aarch64 when only amd64 Linux assets exist (issue #55 lunatic)" {
    const assets = [_]Asset{
        .{ .name = "lunatic-linux-amd64.tar.gz", .browser_download_url = "" },
        .{ .name = "lunatic-macos-universal.tar.gz", .browser_download_url = "" },
        .{ .name = "lunatic-windows-amd64.zip", .browser_download_url = "" },
    };
    const result = findBestAssetForKeywords(&assets, .{
        .os = &.{"linux"},
        .arch = &.{ "aarch64", "arm64" },
    });
    try std.testing.expectError(error.NoMatchingAsset, result);
}

test "findBestAsset errors on aarch64 when only x64 Linux assets exist (issue #55 WAVM)" {
    const assets = [_]Asset{
        .{ .name = "wavm-nightly-2026-04-05-linux-x64.tar.gz", .browser_download_url = "" },
        .{ .name = "wavm-nightly-2026-04-05-macos-arm64.tar.gz", .browser_download_url = "" },
        .{ .name = "wavm-nightly-2026-04-05-macos-x64.tar.gz", .browser_download_url = "" },
        .{ .name = "wavm-nightly-2026-04-05-windows-arm64.zip", .browser_download_url = "" },
        .{ .name = "wavm-nightly-2026-04-05-windows-x64.zip", .browser_download_url = "" },
    };
    const result = findBestAssetForKeywords(&assets, .{
        .os = &.{"linux"},
        .arch = &.{ "aarch64", "arm64" },
    });
    try std.testing.expectError(error.NoMatchingAsset, result);
}

test "findBestAsset errors on x86_64 when only aarch64 Linux assets exist" {
    const assets = [_]Asset{
        .{ .name = "tool-aarch64-linux.tar.gz", .browser_download_url = "" },
        .{ .name = "tool-aarch64-apple-darwin.tar.gz", .browser_download_url = "" },
        .{ .name = "tool-aarch64-windows.zip", .browser_download_url = "" },
    };
    const result = findBestAssetForKeywords(&assets, .{
        .os = &.{"linux"},
        .arch = &.{ "x86_64", "x64", "amd64" },
    });
    try std.testing.expectError(error.NoMatchingAsset, result);
}

test "findBestAsset selects host-arch Linux asset when both arches present" {
    const assets = [_]Asset{
        .{ .name = "tool-x86_64-linux.tar.gz", .browser_download_url = "" },
        .{ .name = "tool-aarch64-linux.tar.gz", .browser_download_url = "" },
    };
    const best = try findBestAssetForKeywords(&assets, .{
        .os = &.{"linux"},
        .arch = &.{ "aarch64", "arm64" },
    });
    try std.testing.expectEqualStrings("tool-aarch64-linux.tar.gz", best.name);
}

test "findBestAsset selects cosign bare binary for Linux" {
    const assets = [_]Asset{
        .{ .name = "cosign-darwin-amd64", .browser_download_url = "" },
        .{ .name = "cosign-linux-amd64", .browser_download_url = "" },
        .{ .name = "cosign-linux-amd64.sigstore.json", .browser_download_url = "" },
        .{ .name = "cosign-windows-amd64.exe", .browser_download_url = "" },
        .{ .name = "cosign_checksums.txt", .browser_download_url = "" },
    };
    const best = try findBestAssetForKeywords(&assets, .{
        .os = &.{"linux"},
        .arch = &.{ "x86_64", "x64", "amd64" },
    });
    try std.testing.expectEqualStrings("cosign-linux-amd64", best.name);
}

test "ParsedRelease deinit frees all memory" {
    const allocator = std.testing.allocator;

    const json_body = try allocator.dupe(u8,
        \\{"tag_name":"v1.0.0","assets":[{"name":"app.tar.gz","browser_download_url":"https://example.com/app.tar.gz"}]}
    );

    const parsed = try std.json.parseFromSlice(Release, allocator, json_body, .{ .ignore_unknown_fields = true });

    var pr: ParsedRelease = .{ .parsed = parsed, .body = json_body, .allocator = allocator };

    try std.testing.expectEqualStrings("v1.0.0", pr.parsed.value.tag_name);
    try std.testing.expectEqual(@as(usize, 1), pr.parsed.value.assets.len);
    try std.testing.expectEqualStrings("app.tar.gz", pr.parsed.value.assets[0].name);

    pr.deinit();
}

test "urlEncode handles special characters" {
    const allocator = std.testing.allocator;

    const plain = try urlEncode(allocator, "v1.0.0");
    defer allocator.free(plain);
    try std.testing.expectEqualStrings("v1.0.0", plain);

    const plus = try urlEncode(allocator, "v1.0.0+build");
    defer allocator.free(plus);
    try std.testing.expectEqualStrings("v1.0.0%2Bbuild", plus);

    const space = try urlEncode(allocator, "my tag");
    defer allocator.free(space);
    try std.testing.expectEqualStrings("my%20tag", space);

    const multi = try urlEncode(allocator, "a+b&c#d");
    defer allocator.free(multi);
    try std.testing.expectEqualStrings("a%2Bb%26c%23d", multi);

    const percent = try urlEncode(allocator, "100%done");
    defer allocator.free(percent);
    try std.testing.expectEqualStrings("100%25done", percent);
}

test "isHex64 accepts and rejects" {
    try std.testing.expect(isHex64("0123456789abcdefABCDEF000000000000000000000000000000000000000000"));
    try std.testing.expect(!isHex64("0123"));
    try std.testing.expect(!isHex64("zzzz" ++ ("0" ** 60)));
    try std.testing.expect(!isHex64("g" ++ ("0" ** 63)));
}

test "parseSha256Line GNU two-space form" {
    const line = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789  app.tar.gz";
    const e = parseSha256Line(line) orelse return error.TestUnexpectedNull;
    try std.testing.expectEqualStrings("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", e.hex);
    try std.testing.expectEqualStrings("app.tar.gz", e.name);
}

test "parseSha256Line GNU binary-mode asterisk" {
    const line = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff *bin.exe";
    const e = parseSha256Line(line) orelse return error.TestUnexpectedNull;
    try std.testing.expectEqualStrings("bin.exe", e.name);
}

test "parseSha256Line strips leading ./" {
    const line = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff  ./foo";
    const e = parseSha256Line(line) orelse return error.TestUnexpectedNull;
    try std.testing.expectEqualStrings("foo", e.name);
}

test "parseSha256Line BSD form" {
    const line = "SHA256 (app.tar.gz) = abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    const e = parseSha256Line(line) orelse return error.TestUnexpectedNull;
    try std.testing.expectEqualStrings("app.tar.gz", e.name);
    try std.testing.expectEqualStrings("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", e.hex);
}

test "parseSha256Line skips comments and blanks" {
    try std.testing.expect(parseSha256Line("") == null);
    try std.testing.expect(parseSha256Line("   \r\n") == null);
    try std.testing.expect(parseSha256Line("# header line") == null);
    try std.testing.expect(parseSha256Line("not a real line") == null);
    try std.testing.expect(parseSha256Line("dead  short") == null);
}

test "lookupSha256 finds entry across formats" {
    const body =
        "# generated by something\n" ++
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef  other.bin\n" ++
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789  app.tar.gz\n" ++
        "SHA256 (alt.zip) = 1111111111111111111111111111111111111111111111111111111111111111\n";
    const got = lookupSha256(body, "app.tar.gz") orelse return error.TestUnexpectedNull;
    try std.testing.expectEqualStrings("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", got);
    const got2 = lookupSha256(body, "alt.zip") orelse return error.TestUnexpectedNull;
    try std.testing.expectEqualStrings("1111111111111111111111111111111111111111111111111111111111111111", got2);
    try std.testing.expect(lookupSha256(body, "missing") == null);
}

test "checksumNameMatches strips path and ignores case" {
    try std.testing.expect(checksumNameMatches("./Foo.TGZ", "foo.tgz"));
    try std.testing.expect(checksumNameMatches("dist/foo.tgz", "foo.tgz"));
    try std.testing.expect(!checksumNameMatches("bar.tgz", "foo.tgz"));
}

test "isSha256ChecksumFile accepts sha256 forms, rejects sigs and sha512" {
    try std.testing.expect(isSha256ChecksumFile("app.tar.gz.sha256"));
    try std.testing.expect(isSha256ChecksumFile("checksums.txt"));
    try std.testing.expect(isSha256ChecksumFile("SHA256SUMS"));
    try std.testing.expect(isSha256ChecksumFile("project_checksums_v1.0.txt"));
    try std.testing.expect(!isSha256ChecksumFile("app.tar.gz"));
    try std.testing.expect(!isSha256ChecksumFile("app.tar.gz.sig"));
    try std.testing.expect(!isSha256ChecksumFile("app.tar.gz.sha512"));
    try std.testing.expect(!isSha256ChecksumFile("checksums.txt.sig"));
    try std.testing.expect(!isSha256ChecksumFile("release.pub"));
}

test "findChecksumAsset prefers sidecar over aggregate" {
    const assets = [_]Asset{
        .{ .name = "app-linux.tar.gz", .browser_download_url = "" },
        .{ .name = "checksums.txt", .browser_download_url = "" },
        .{ .name = "app-linux.tar.gz.sha256", .browser_download_url = "" },
    };
    const got = findChecksumAsset(&assets, "app-linux.tar.gz") orelse return error.TestUnexpectedNull;
    try std.testing.expectEqualStrings("app-linux.tar.gz.sha256", got.name);
}

test "findChecksumAsset falls back to aggregate" {
    const assets = [_]Asset{
        .{ .name = "app-linux.tar.gz", .browser_download_url = "" },
        .{ .name = "SHA256SUMS", .browser_download_url = "" },
    };
    const got = findChecksumAsset(&assets, "app-linux.tar.gz") orelse return error.TestUnexpectedNull;
    try std.testing.expectEqualStrings("SHA256SUMS", got.name);
}

test "findChecksumAsset returns null when only sha512 is present" {
    const assets = [_]Asset{
        .{ .name = "app-linux.tar.gz", .browser_download_url = "" },
        .{ .name = "app-linux.tar.gz.sha512", .browser_download_url = "" },
        .{ .name = "release.sig", .browser_download_url = "" },
    };
    try std.testing.expect(findChecksumAsset(&assets, "app-linux.tar.gz") == null);
}

test "computeFileSha256 streams a synthetic file" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const payload = "the quick brown fox jumps over the lazy dog\n";
    var f = try tmp.dir.createFile(std.testing.io, "blob", .{});
    try f.writeStreamingAll(std.testing.io, payload);
    f.close(std.testing.io);

    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPathFile(std.testing.io, "blob", &path_buf);
    const full_path = path_buf[0..n];

    const digest = try computeFileSha256(std.testing.io, full_path);
    var expected: [32]u8 = undefined;
    Sha256.hash(payload, &expected, .{});
    try std.testing.expectEqualSlices(u8, &expected, &digest);
}

test "hexEqIgnoreCase mixed case" {
    try std.testing.expect(hexEqIgnoreCase(
        "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789",
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    ));
    try std.testing.expect(!hexEqIgnoreCase(
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456788",
    ));
}

test "findAssetByName exact match wins over ambiguous substring" {
    const a = std.testing.allocator;
    const assets = [_]Asset{
        .{ .name = "tool-linux-amd64.tar.gz", .browser_download_url = "" },
        .{ .name = "tool-linux-amd64", .browser_download_url = "" },
        .{ .name = "tool-windows-amd64.exe", .browser_download_url = "" },
    };
    switch (try findAssetByName(a, &assets, "tool-linux-amd64")) {
        .one => |asset| try std.testing.expectEqualStrings("tool-linux-amd64", asset.name),
        else => try std.testing.expect(false),
    }
}

test "findAssetByName unique substring match" {
    const a = std.testing.allocator;
    const assets = [_]Asset{
        .{ .name = "tool-linux-amd64.tar.gz", .browser_download_url = "" },
        .{ .name = "tool-windows-amd64.exe", .browser_download_url = "" },
    };
    switch (try findAssetByName(a, &assets, "LINUX")) {
        .one => |asset| try std.testing.expectEqualStrings("tool-linux-amd64.tar.gz", asset.name),
        else => try std.testing.expect(false),
    }
}

test "findAssetByName ambiguous substring returns candidates" {
    const a = std.testing.allocator;
    const assets = [_]Asset{
        .{ .name = "tool-linux-amd64.tar.gz", .browser_download_url = "" },
        .{ .name = "tool-linux-arm64.tar.gz", .browser_download_url = "" },
        .{ .name = "tool-windows-amd64.exe", .browser_download_url = "" },
    };
    switch (try findAssetByName(a, &assets, "linux")) {
        .ambiguous => |list| {
            defer a.free(list);
            try std.testing.expectEqual(@as(usize, 2), list.len);
        },
        else => try std.testing.expect(false),
    }
}

test "findAssetByName none when nothing matches" {
    const a = std.testing.allocator;
    const assets = [_]Asset{
        .{ .name = "tool-linux-amd64.tar.gz", .browser_download_url = "" },
    };
    try std.testing.expectEqual(AssetMatch.none, try findAssetByName(a, &assets, "macos"));
}
