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
const minisign = @import("minisign.zig");
const authenticode = @import("authenticode.zig");
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

/// A single positional argument from the install/download CLI: a spec
/// string plus an optional inline minisign public key that immediately
/// followed the spec on the command line. Both slices borrow from argv.
///
/// When `key` is non-null, it has already passed `minisign.looksLikePubKey`
/// (length 56, `RW`/`RV` prefix, decodes to a known algo). The downstream
/// verifier re-parses it with `minisign.parsePublicKey` and surfaces a
/// pointed error if it doesn't decode (covers the rare structural
/// false-positive).
pub const SpecWithKey = struct {
    spec: []const u8,
    key: ?[]const u8 = null,
};

/// Bundle of per-invocation verification skip flags. `skip_verify` is the
/// umbrella (disables every check); the four narrow flags suppress one
/// path apiece.
pub const VerifyGates = struct {
    skip_verify: bool = false,
    skip_checksum: bool = false,
    skip_minisign: bool = false,
    skip_sigstore: bool = false,
    skip_authenticode: bool = false,
};

/// CLI positional classifier outcome for one bare argument.
pub const SpecOrKey = union(enum) {
    /// A regular spec — caller should push a new `SpecWithKey` onto its
    /// list.
    spec: []const u8,
    /// A minisign pubkey that follows a prior spec — caller should attach
    /// it to the most recent entry's `key` field.
    key: []const u8,
    /// First positional was a pubkey-shaped token. Caller emits a "lone
    /// key" diagnostic and aborts.
    lone_key,
    /// Pubkey-shaped token, but the previous spec already has one.
    /// Caller emits a "double key" diagnostic and aborts.
    double_key,
};

/// Classify one positional argument from the install/download CLI given
/// the current accumulated entries. Pure: no allocation, no I/O.
///
/// The caller decides how to act on each variant:
///   * `.spec`      — append a new `SpecWithKey` to its list.
///   * `.key`       — set the last entry's `.key` field.
///   * `.lone_key`  — print "key must follow a spec" and exit.
///   * `.double_key`— print "spec already has a key" and exit.
pub fn classifySpecOrKey(arg: []const u8, prior: []const SpecWithKey) SpecOrKey {
    if (!minisign.looksLikePubKey(arg)) return .{ .spec = arg };
    if (prior.len == 0) return .lone_key;
    if (prior[prior.len - 1].key != null) return .double_key;
    return .{ .key = arg };
}

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

/// A `RepoSpec` whose `owner`/`repo`/`tag` strings are heap-owned. Used when
/// the caller needs to construct on-disk paths that must be canonical
/// lowercase regardless of the casing the user typed (GitHub is
/// case-insensitive on slugs; Linux filesystems are not).
pub const OwnedRepoSpec = struct {
    owner: []u8,
    repo: []u8,
    tag: ?[]u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: OwnedRepoSpec) void {
        self.allocator.free(self.owner);
        self.allocator.free(self.repo);
        if (self.tag) |t| self.allocator.free(t);
    }
};

/// Like `parseRepoSpec` but ASCII-lowercases `owner` and `repo` and copies
/// every field onto `allocator`. `tag` is preserved verbatim (tags are
/// case-sensitive; only the slug halves are canonicalized). Use when
/// building on-disk paths (`<tools>/<owner>/<repo>`); use `parseRepoSpec`
/// for transient borrowing reads.
pub fn parseRepoSpecOwned(allocator: std.mem.Allocator, s: []const u8) !OwnedRepoSpec {
    const sp = try parseRepoSpec(s);
    const owner = try asciiLowerDup(allocator, sp.owner);
    errdefer allocator.free(owner);
    const repo = try asciiLowerDup(allocator, sp.repo);
    errdefer allocator.free(repo);
    const tag: ?[]u8 = if (sp.tag) |t| try allocator.dupe(u8, t) else null;
    return .{ .owner = owner, .repo = repo, .tag = tag, .allocator = allocator };
}

fn asciiLowerDup(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, s.len);
    for (s, 0..) |c, i| out[i] = std.ascii.toLower(c);
    return out;
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
    /// The `api.github.com/repos/<owner>/<repo>/releases/assets/<id>` URL.
    /// Unlike `browser_download_url`, this endpoint honors `Authorization`
    /// (with `Accept: application/octet-stream`) for private and
    /// SSO-protected enterprise releases, where `browser_download_url`
    /// redirects unauthenticated requests to an SSO/login page. Empty when
    /// the field is absent from the release JSON.
    url: []const u8 = "",
    /// SHA-256 digest GitHub computes for every release asset at upload
    /// time and exposes inline in the release JSON as `"sha256:<hex>"`
    /// (added 2025-06-03). `null` for assets uploaded before that rollout.
    digest: ?[]const u8 = null,
};

/// `Accept` header value for the GitHub release-asset API endpoint, which
/// makes it return a redirect to the signed download URL instead of asset
/// JSON metadata.
pub const asset_octet_accept = "application/octet-stream";

/// Resolved download URL plus the `Accept` header to send with it.
pub const AssetDownload = struct {
    url: []const u8,
    accept: ?[]const u8,
};

/// Choose how to download `asset`. When an auth token is available and the
/// API asset URL is known, prefer it: the `api.github.com` asset endpoint
/// honors `Authorization` for private and SSO-protected enterprise releases,
/// whereas `browser_download_url` redirects unauthenticated callers to an
/// SSO/login page. Anonymous downloads keep using `browser_download_url` to
/// avoid the stricter unauthenticated `api.github.com` rate limit.
pub fn assetDownload(asset: Asset, have_auth: bool) AssetDownload {
    if (have_auth and asset.url.len > 0) {
        return .{ .url = asset.url, .accept = asset_octet_accept };
    }
    return .{ .url = asset.browser_download_url, .accept = null };
}

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

/// Host C library family on Linux. Rust target triples encode this as the
/// `-gnu` / `-musl` suffix, and a glibc binary will not run on a musl host
/// (or vice versa). `null` means "don't let libc influence scoring".
pub const Libc = enum { gnu, musl };

pub const PlatformKeywords = struct {
    os: []const []const u8,
    arch: []const []const u8,
    /// Host libc on Linux; `null` on other platforms (and in tests that don't
    /// care), where it leaves scoring untouched.
    libc: ?Libc = null,
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
        .riscv64 => &.{ "riscv64gc", "riscv64" },
        else => &.{},
    };
    // ghr ships a separate glibc and musl binary for each Linux arch, and every
    // install path places the libc-matched build on the host: install.sh probes
    // for musl, and the PyPI wheels carry musllinux/manylinux platform tags that
    // pip resolves per host. So our own compiled ABI is a reliable, zero-I/O
    // proxy for the host's libc.
    const libc: ?Libc = switch (builtin.os.tag) {
        .linux => if (std.mem.startsWith(u8, @tagName(builtin.abi), "musl")) .musl else .gnu,
        else => null,
    };
    return .{ .os = os_keywords, .arch = arch_keywords, .libc = libc };
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

/// Returns true if the asset looks installable: archives, Windows .exe, wasm
/// modules, or bare binaries (extensionless files common in Go/Rust releases).
fn isInstallableAsset(name: []const u8) bool {
    if (std.mem.endsWith(u8, name, ".zip")) return true;
    if (std.mem.endsWith(u8, name, ".tar.gz")) return true;
    if (std.mem.endsWith(u8, name, ".tgz")) return true;
    if (std.mem.endsWith(u8, name, ".tar.xz")) return true;
    if (std.mem.endsWith(u8, name, ".exe")) return true;
    if (std.mem.endsWith(u8, name, ".wasm")) return true;
    const non_installable = [_][]const u8{
        ".json",   ".txt",    ".pub", ".sig",     ".asc", ".pem", ".md",
        ".sha256", ".sha512", ".md5", ".minisig", ".rpm", ".apk", ".msi",
        ".pkg",    ".dmg",    ".yml", ".yaml",    ".ghr",
    };
    for (non_installable) |ext| {
        if (std.mem.endsWith(u8, name, ext)) return false;
    }
    return true;
}

/// Returns true if `name` is a WebAssembly module installable by ghr.
pub fn isWasmAssetName(name: []const u8) bool {
    return std.mem.endsWith(u8, name, ".wasm");
}

/// Find the companion `<wasm_name>.ghr` manifest asset for a wasm asset.
/// Returns `null` when the release does not publish one.
pub fn findGhrManifestAsset(assets: []const Asset, wasm_name: []const u8) ?Asset {
    var buf: [512]u8 = undefined;
    const want = std.fmt.bufPrint(&buf, "{s}.ghr", .{wasm_name}) catch return null;
    for (assets) |a| {
        if (std.mem.eql(u8, a.name, want)) return a;
    }
    return null;
}

/// Markers in asset names that indicate non-primary variants (libraries,
/// source tarballs, minimal/debug builds, plugins, distro-specific static
/// bundles) which should be deprioritized when a plain binary archive is
/// also available.
fn nonPrimaryPenalty(name: []const u8) u32 {
    const strong = [_][]const u8{
        "c-api",   "capi",     "headers",  "sdk",
        "dev",     "lib-only", "src",      "source",
        "sources", "sbom",     "checksum", "checksums",
        "debug",   "dbg",      "symbols",
    };
    const medium = [_][]const u8{
        "plugin", "plugins",    "wasi_nn", "wasi-nn",
        "ffmpeg", "tensorflow", "image",   "opencvmini",
    };
    const soft = [_][]const u8{
        "static", "min", "minimal",
    };
    var penalty: u32 = 0;
    for (strong) |m| if (containsIgnoreCaseBounded(name, m)) {
        penalty += 5;
    };
    for (medium) |m| if (containsIgnoreCaseBounded(name, m)) {
        penalty += 3;
    };
    for (soft) |m| if (containsIgnoreCaseBounded(name, m)) {
        penalty += 1;
    };
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
        "ios",           "tvos",
        "watchos",       "wasi",
        "wasm32",        "wasm64",
        "emscripten",
    };
    for (always_wrong) |t| {
        if (containsIgnoreCaseBounded(name, t)) return true;
    }
    for (plat_os) |k| {
        if (containsIgnoreCaseBounded(name, k)) return false;
    }
    const foreign = [_][]const u8{
        "windows", "win",     "win32",   "win64",   "mingw",
        "linux",   "darwin",  "macos",   "osx",     "freebsd",
        "netbsd",  "openbsd", "solaris", "illumos",
    };
    for (foreign) |t| {
        var is_host = false;
        for (plat_os) |k| {
            if (std.ascii.eqlIgnoreCase(k, t)) {
                is_host = true;
                break;
            }
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
pub fn isForeignArch(name: []const u8, plat_arch: []const []const u8) bool {
    if (plat_arch.len == 0) return false;
    const all_arch = [_][]const u8{
        "x86_64",  "x64",   "amd64",
        "aarch64", "arm64", "armv7l",
        "armv7",   "armv6", "i386",
        "i686",    "x86",   "riscv64",
    };
    for (plat_arch) |k| {
        if (containsIgnoreCaseBounded(name, k)) return false;
    }
    for (all_arch) |t| {
        var is_host = false;
        for (plat_arch) |k| {
            if (std.ascii.eqlIgnoreCase(k, t)) {
                is_host = true;
                break;
            }
        }
        if (is_host) continue;
        if (containsIgnoreCaseBounded(name, t)) return true;
    }
    return false;
}

/// Returns true if `name` contains a token for the host architecture. Used
/// alongside `isForeignArch` to resolve duplicate-executable collisions that
/// arise when an archive bundles the same binary for several architectures
/// under arch-named directories (see install.zig).
pub fn hasHostArch(name: []const u8, plat_arch: []const []const u8) bool {
    for (plat_arch) |k| {
        if (containsIgnoreCaseBounded(name, k)) return true;
    }
    return false;
}

/// On Linux hosts, prefer portable glibc/musl triples over distro-tagged
/// variants. Returns a signed bonus to fold into the score.
fn linuxPortabilityBonus(name: []const u8, plat_os: []const []const u8) i32 {
    var is_linux_host = false;
    for (plat_os) |k| {
        if (std.ascii.eqlIgnoreCase(k, "linux")) {
            is_linux_host = true;
            break;
        }
    }
    if (!is_linux_host) return 0;
    var s: i32 = 0;
    const generic = [_][]const u8{
        "manylinux",
        "unknown-linux-gnu",
        "unknown-linux-musl",
        "linux-gnu",
        "linux-musl",
    };
    for (generic) |t| {
        if (containsIgnoreCaseBounded(name, t)) {
            s += 2;
            break;
        }
    }
    const distros = [_][]const u8{
        "ubuntu", "debian", "alpine", "fedora", "centos", "rhel", "suse",
    };
    for (distros) |t| {
        if (containsIgnoreCaseBounded(name, t)) {
            s -= 1;
            break;
        }
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

/// On Linux, reward the asset built for the host's C library. Rust target
/// triples encode this as `-gnu` vs `-musl`. The bonus is intentionally
/// positive-only: it breaks a gnu-vs-musl tie in favour of the host libc but
/// never penalizes an asset, so a release that only ships the "wrong" libc (or
/// names assets without a libc marker) is unaffected and still installable.
fn libcBonus(name: []const u8, libc: ?Libc) i32 {
    const want = libc orelse return 0;
    const has_musl = containsIgnoreCaseBounded(name, "musl");
    const has_gnu = containsIgnoreCaseBounded(name, "gnu");
    if (has_musl == has_gnu) return 0; // neither marker, or (ambiguously) both
    return switch (want) {
        .musl => if (has_musl) 3 else 0,
        .gnu => if (has_gnu) 3 else 0,
    };
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
        if (containsIgnoreCaseBounded(name, kw)) {
            score += 10;
            break;
        }
    }
    for (plat.arch) |kw| {
        if (containsIgnoreCaseBounded(name, kw)) {
            score += 5;
            break;
        }
    }
    score -= @as(i32, @intCast(nonPrimaryPenalty(name)));
    score += linuxPortabilityBonus(name, plat.os);
    score += libcBonus(name, plat.libc);
    score += archiveFormatBonus(name);
    // wasm modules are platform-independent; give them a positive score so a
    // release that ships only a `.wasm` (plus sidecars) selects it.
    if (isWasmAssetName(name)) score += 5;
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
    /// The asset's GitHub-published `digest` field (a SHA-256 GitHub
    /// computes at upload time, added 2025-06-03) matched the download.
    /// No extra network request — the digest arrives inline in the
    /// release JSON. Same trust root as a CI-generated `.sha256` sidecar:
    /// it attests integrity, not independent provenance.
    github_digest_verified,
    /// A `<asset>.minisig` sidecar was found and the caller-supplied
    /// minisign public key verified both the artifact and trusted-comment
    /// signatures.
    minisign_verified,
    /// An embedded Authenticode signature on the downloaded PE (or on a
    /// PE inside a downloaded `.zip`) verified against an embedded MS /
    /// commercial CA trust root, with a valid RFC 3161 timestamp.
    authenticode_verified,
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
///
/// Recognised formats:
///   - GNU coreutils: `<hex>  <name>` or `<hex> *<name>`
///   - BSD shasum:    `SHA256 (<name>) = <hex>`
///   - Windows `certutil -hashfile <name> SHA256`, which BurntSushi/ripgrep
///     and friends publish as Windows `.sha256` sidecars:
///         SHA256 hash of <name>:
///         <hex>
///         CertUtil: -hashfile command completed successfully.
fn lookupSha256(content: []const u8, target_name: []const u8) ?[]const u8 {
    const certutil_prefix = "SHA256 hash of ";
    var pending_certutil_name: ?[]const u8 = null;
    var it = std.mem.splitScalar(u8, content, '\n');
    while (it.next()) |raw_line| {
        // Trim trailing whitespace/CR so we can recognise certutil's CRLF
        // output without dragging the trim logic into every branch below.
        var line = raw_line;
        while (line.len > 0 and (line[line.len - 1] == '\r' or
            line[line.len - 1] == ' ' or line[line.len - 1] == '\t'))
        {
            line = line[0 .. line.len - 1];
        }

        // certutil header line: capture the asset name; the next bare 64-hex
        // line is its digest.
        if (std.mem.startsWith(u8, line, certutil_prefix) and
            std.mem.endsWith(u8, line, ":"))
        {
            pending_certutil_name = line[certutil_prefix.len .. line.len - 1];
            continue;
        }

        // certutil digest line: a bare 64-hex line immediately following a
        // header. Any other non-empty line terminates the certutil block.
        if (pending_certutil_name) |name| {
            if (line.len == 64 and isHex64(line)) {
                if (checksumNameMatches(name, target_name)) return line;
                pending_certutil_name = null;
                continue;
            }
            if (line.len > 0) pending_certutil_name = null;
        }

        const entry = parseSha256Line(line) orelse continue;
        if (checksumNameMatches(entry.name, target_name)) return entry.hex;
    }
    return null;
}

/// Returns true if `name` looks like a SHA256 checksum file rather than a
/// signature, key, or unrelated checksum (sha512/md5).
fn isSha256ChecksumFile(name: []const u8) bool {
    const reject_suffixes = [_][]const u8{
        ".sig",    ".asc",       ".pem",        ".pub", ".gpg",    ".minisig",
        ".sha512", ".sha512sum", ".sha512sums", ".md5", ".md5sum", ".md5sums",
        ".sha1",   ".sha1sum",
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

    const checksum_dl = assetDownload(checksum_asset, auth_header != null);
    http.downloadToFile(allocator, io, checksum_dl.url, checksum_path, .{
        .auth_header = auth_header,
        .accept = checksum_dl.accept,
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

    try w.print("verified sha256 {s}... ({s})\n", .{ actual_hex[0..12], checksum_asset.name });
    try w.flush();
    return .sha256_verified;
}

/// Extract the 64-hex SHA-256 from an asset's GitHub `digest` field
/// (`"sha256:<hex>"`). Returns null when the matching asset has no digest
/// (uploaded before 2025-06-03), the algorithm isn't sha256, or the hex is
/// malformed.
fn lookupAssetDigest(assets: []const Asset, asset_name: []const u8) ?[]const u8 {
    const prefix = "sha256:";
    for (assets) |a| {
        if (!std.mem.eql(u8, a.name, asset_name)) continue;
        const d = a.digest orelse return null;
        if (d.len <= prefix.len) return null;
        if (!std.ascii.eqlIgnoreCase(d[0..prefix.len], prefix)) return null;
        const hex = d[prefix.len..];
        if (!isHex64(hex)) return null;
        return hex;
    }
    return null;
}

/// Verify `download_path` against the SHA-256 `digest` GitHub publishes
/// inline on the release asset (added 2025-06-03). Costs no extra network
/// request — the digest already arrived in the release JSON. The trust root
/// is GitHub itself (identical to a CI-generated `.sha256` sidecar): it
/// attests integrity, not independent provenance. Returns `.no_verification`
/// when the asset carries no usable digest. On mismatch, prints a diagnostic
/// and returns `error.ChecksumMismatch`; the caller deletes the cached file.
pub fn verifyDownloadedAssetGithubDigest(
    io: Io,
    assets: []const Asset,
    asset_name: []const u8,
    download_path: []const u8,
    debug_w: ?*Writer,
    w: *Writer,
    err_w: *Writer,
) !VerifyOutcome {
    const expected_hex = lookupAssetDigest(assets, asset_name) orelse {
        return .no_verification;
    };

    debugLog(debug_w, "debug: github asset digest: sha256:{s}\n", .{expected_hex});

    const digest = computeFileSha256(io, download_path) catch |err| {
        try err_w.print("error: failed to hash '{s}': {}\n", .{ download_path, err });
        try err_w.flush();
        return err;
    };
    var actual_hex: [64]u8 = undefined;
    sha256ToHex(digest, &actual_hex);

    if (!hexEqIgnoreCase(expected_hex, &actual_hex)) {
        try err_w.print(
            "error: SHA256 mismatch for {s}\n  expected: {s}\n  actual:   {s}\n  source:   GitHub release asset digest\n",
            .{ asset_name, expected_hex, &actual_hex },
        );
        try err_w.flush();
        return error.ChecksumMismatch;
    }

    try w.print("verified github sha256 {s}... (release asset digest)\n", .{actual_hex[0..12]});
    try w.flush();
    return .github_digest_verified;
}
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
    const have_auth = auth_header != null;
    for (assets, 0..) |a, i| {
        views[i] = .{ .name = a.name, .browser_download_url = assetDownload(a, have_auth).url };
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
        .accept = if (have_auth) asset_octet_accept else null,
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

    const identity = sigstore.verifyBundle(allocator, io, bundle, rekor, file, asset_name) catch |err| {
        try err_w.print("error: sigstore verification failed for '{s}': {s}\n", .{ asset_name, @errorName(err) });
        try err_w.flush();
        return error.SigstoreVerificationFailed;
    };

    var digest_hex: [64]u8 = undefined;
    sha256ToHex(identity.artifact_digest, &digest_hex);
    var rekor_time_buf: [20]u8 = undefined;
    const rekor_time_iso = authenticode.formatUnixTimeIso(identity.integrated_time, &rekor_time_buf);
    try w.print(
        "verified sigstore: sha256 {s}... (rekor t={s}, log {d})\n",
        .{ digest_hex[0..12], rekor_time_iso, bundle.rekor_log_index },
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

/// Run Authenticode verification on `download_path`. Auto-detects the
/// file shape:
///
///   * MZ-prefixed → treat as a single PE, verify its embedded
///     PKCS#7 SignedData.
///   * `PK\x03\x04`-prefixed → walk the zip in memory, find any
///     `.exe` / `.dll` / `.sys` entries, and verify each PE that
///     carries an Authenticode signature.
///   * Anything else → return `.no_verification`.
///
/// Fail-closed when a PE carries an Authenticode signature but it
/// doesn't verify. Fail-open (return `.no_verification`) when no PE
/// in the file carries any Authenticode signature — same model as
/// the sigstore / sha256 verifiers.
pub fn verifyDownloadedAssetAuthenticode(
    allocator: std.mem.Allocator,
    io: Io,
    download_path: []const u8,
    debug_w: ?*Writer,
    w: *Writer,
    err_w: *Writer,
) !VerifyOutcome {
    var file = try Dir.openFileAbsolute(io, download_path, .{});
    defer file.close(io);

    // Peek at the first 4 bytes to short-circuit on non-PE/non-zip
    // downloads before slurping the whole file into memory.
    var magic: [4]u8 = undefined;
    {
        var peek_buf: [4]u8 = undefined;
        var fr = file.reader(io, &peek_buf);
        const n = fr.interface.readSliceShort(&magic) catch 0;
        if (n < 4) return .no_verification;
    }
    const is_pe = magic[0] == 'M' and magic[1] == 'Z';
    const is_zip = std.mem.eql(u8, &magic, &[_]u8{ 'P', 'K', 0x03, 0x04 });
    if (!is_pe and !is_zip) return .no_verification;

    const stat = try file.stat(io);
    if (stat.size > authenticode.max_entry_size) {
        debugLog(debug_w, "debug: authenticode: skipping (file > {d} bytes)\n", .{authenticode.max_entry_size});
        return .no_verification;
    }

    // Read the whole file with a fresh reader (the peek above consumed
    // some bytes from the first one).
    var file2 = try Dir.openFileAbsolute(io, download_path, .{});
    defer file2.close(io);
    var read_buf: [64 * 1024]u8 = undefined;
    var fr2 = file2.reader(io, &read_buf);
    const bytes = try allocator.alloc(u8, @intCast(stat.size));
    defer allocator.free(bytes);
    try fr2.interface.readSliceAll(bytes);

    var trust = try authenticode.buildTrustBundle(allocator, Io.Clock.now(.real, io).toSeconds());
    defer trust.deinit(allocator);

    const now = Io.Clock.now(.real, io).toSeconds();

    if (is_pe) {
        return verifySinglePe(allocator, bytes, trust, now, "asset", debug_w, w, err_w);
    }
    return verifyZipPes(allocator, bytes, trust, now, debug_w, w, err_w);
}

fn verifySinglePe(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    trust: std.crypto.Certificate.Bundle,
    now: i64,
    display_name: []const u8,
    debug_w: ?*Writer,
    w: *Writer,
    err_w: *Writer,
) !VerifyOutcome {
    _ = debug_w;
    const image = authenticode.parsePe(bytes) catch return .no_verification;
    const cert_entry = (authenticode.findFirstPkcs7Entry(image) catch null) orelse
        return .no_verification;
    _ = cert_entry;

    const outcome = authenticode.verifyPe(allocator, bytes, trust, trust, now) catch |err| {
        try err_w.print("error: authenticode verification failed for '{s}': {s}\n", .{ display_name, @errorName(err) });
        try err_w.flush();
        return error.AuthenticodeVerificationFailed;
    };

    var digest_hex: [64]u8 = undefined;
    sha256ToHex(outcome.digest, &digest_hex);
    var gen_time_buf: [20]u8 = undefined;
    const gen_time_iso = authenticode.formatUnixTimeIso(outcome.gen_time, &gen_time_buf);
    try w.print("verified authenticode: sha256 {s}... (genTime {s})\n", .{ digest_hex[0..12], gen_time_iso });
    if (outcome.subject_cn.len > 0) {
        try w.print("  subject: {s}\n", .{outcome.subject_cn});
    }
    if (outcome.organization.len > 0) {
        try w.print("  org:     {s}\n", .{outcome.organization});
    }
    try w.flush();
    return .authenticode_verified;
}

fn verifyZipPes(
    allocator: std.mem.Allocator,
    zip_bytes: []const u8,
    trust: std.crypto.Certificate.Bundle,
    now: i64,
    debug_w: ?*Writer,
    w: *Writer,
    err_w: *Writer,
) !VerifyOutcome {
    var results: std.array_list.Managed(authenticode.PeEntryResult) = .init(allocator);
    defer {
        for (results.items) |r| allocator.free(r.bytes);
        results.deinit();
    }
    authenticode.walkZipPes(allocator, zip_bytes, &results) catch |err| {
        debugLog(debug_w, "debug: authenticode zip walk failed: {s}\n", .{@errorName(err)});
        return .no_verification;
    };

    var any_signed = false;
    var verified_count: usize = 0;
    var min_gen_time: i64 = std.math.maxInt(i64);
    var max_gen_time: i64 = std.math.minInt(i64);
    var first_outcome: ?authenticode.Outcome = null;
    for (results.items) |entry| {
        const image = authenticode.parsePe(entry.bytes) catch continue;
        const cert_entry = (authenticode.findFirstPkcs7Entry(image) catch null) orelse continue;
        _ = cert_entry;
        any_signed = true;
        const outcome = authenticode.verifyPe(allocator, entry.bytes, trust, trust, now) catch |err| {
            try err_w.print("error: authenticode verification failed for '{s}': {s}\n", .{ entry.name, @errorName(err) });
            try err_w.flush();
            return error.AuthenticodeVerificationFailed;
        };
        verified_count += 1;
        if (outcome.gen_time < min_gen_time) min_gen_time = outcome.gen_time;
        if (outcome.gen_time > max_gen_time) max_gen_time = outcome.gen_time;
        if (first_outcome == null) first_outcome = outcome;
    }
    if (!any_signed) return .no_verification;
    if (verified_count == 0) return .no_verification;

    if (first_outcome) |s| {
        var min_buf: [20]u8 = undefined;
        var max_buf: [20]u8 = undefined;
        const min_iso = authenticode.formatUnixTimeIso(min_gen_time, &min_buf);
        const max_iso = authenticode.formatUnixTimeIso(max_gen_time, &max_buf);
        if (min_gen_time == max_gen_time) {
            try w.print("verified authenticode: {d} PEs (genTime {s})\n", .{ verified_count, min_iso });
        } else {
            try w.print("verified authenticode: {d} PEs (genTime {s}..{s})\n", .{ verified_count, min_iso, max_iso });
        }
        if (s.subject_cn.len > 0) {
            try w.print("  subject: {s}\n", .{s.subject_cn});
        }
        if (s.organization.len > 0) {
            try w.print("  org:     {s}\n", .{s.organization});
        }
        try w.flush();
    }
    return .authenticode_verified;
}

// ---------------------------------------------------------------------------
// Asset matching by name and unified verification wrapper.
// ---------------------------------------------------------------------------

/// Run minisign verification on `download_path` using a caller-supplied
/// public key. Pure plumbing — the protocol lives in `src/minisign.zig`.
///
///   - `pubkey_b64 == null` AND no `<asset>.minisig` sidecar is published
///     → return `.no_verification` silently.
///   - `pubkey_b64 == null` AND a `<asset>.minisig` sidecar IS published
///     → fail-closed with `error.MinisignSidecarPresentButNoKey`. The
///     release explicitly published a minisign signature, so consuming
///     the asset without a trust anchor would silently skip a real
///     verification opportunity. Caller must pass `--minisign <pubkey>`
///     or `--skip-verify`.
///   - `pubkey_b64 != null` but no `<asset>.minisig` sidecar is published
///     → fail-closed with `error.MinisignSidecarMissing`. The user
///     explicitly required minisign verification.
///   - Otherwise: download the sidecar to `cache_dir`, parse the user's
///     pubkey, parse the sidecar, check key-id, verify the artifact
///     signature (streams the file for the `ED` Blake2b-prehash variant),
///     verify the trusted-comment global signature, and print a one-line
///     summary on success.
pub fn verifyDownloadedAssetMinisign(
    allocator: std.mem.Allocator,
    io: Io,
    cache_dir: []const u8,
    assets: []const Asset,
    asset_name: []const u8,
    download_path: []const u8,
    debug_w: ?*Writer,
    auth_header: ?[]const u8,
    pubkey_b64: ?[]const u8,
    w: *Writer,
    err_w: *Writer,
) !VerifyOutcome {
    const views = try allocator.alloc(minisign.AssetView, assets.len);
    defer allocator.free(views);
    const have_auth = auth_header != null;
    for (assets, 0..) |a, i| {
        views[i] = .{ .name = a.name, .browser_download_url = assetDownload(a, have_auth).url };
    }

    const sidecar_opt = minisign.findMinisigAsset(views, asset_name);

    const key_b64 = pubkey_b64 orelse {
        // Caller didn't opt in.
        if (sidecar_opt) |sidecar| {
            try err_w.print(
                "error: '{s}' is published with a minisign signature ('{s}') but --minisign was not provided\n",
                .{ asset_name, sidecar.name },
            );
            try err_w.print(
                "  hint: pass --minisign <base64-pubkey> to verify, or --skip-verify to bypass\n",
                .{},
            );
            try err_w.flush();
            return error.MinisignSidecarPresentButNoKey;
        }
        return .no_verification;
    };

    // Parse the pubkey first — if it's malformed there's no point in
    // touching the network.
    const pk = minisign.parsePublicKey(key_b64) catch |err| {
        try err_w.print("error: --minisign value is not a valid minisign public key ({s})\n", .{@errorName(err)});
        try err_w.flush();
        return error.MinisignPubKeyParseError;
    };

    const sidecar = sidecar_opt orelse {
        try err_w.print(
            "error: --minisign was supplied but no '{s}.minisig' sidecar is published in this release\n",
            .{asset_name},
        );
        try err_w.flush();
        return error.MinisignSidecarMissing;
    };

    debugLog(debug_w, "debug: minisign sidecar: {s}\n", .{sidecar.name});

    const sidecar_path = try std.fmt.allocPrint(allocator, "{s}{c}{s}", .{
        cache_dir, std.fs.path.sep, sidecar.name,
    });
    defer allocator.free(sidecar_path);
    defer Dir.deleteFileAbsolute(io, sidecar_path) catch {};

    http.downloadToFile(allocator, io, sidecar.browser_download_url, sidecar_path, .{
        .auth_header = auth_header,
        .accept = if (have_auth) asset_octet_accept else null,
        .debug_w = debug_w,
    }) catch |err| {
        try err_w.print("error: failed to download minisign sidecar '{s}': {}\n", .{ sidecar.name, err });
        try err_w.flush();
        return error.MinisignDownloadFailed;
    };

    const sidecar_bytes = blk: {
        var dir = try Dir.openDirAbsolute(io, cache_dir, .{});
        defer dir.close(io);
        // A `.minisig` is ~280 bytes; 64 KiB is generous and bounded.
        break :blk try dir.readFileAlloc(io, sidecar.name, allocator, Io.Limit.limited(64 * 1024));
    };
    defer allocator.free(sidecar_bytes);

    const sig = minisign.parseSignature(sidecar_bytes) catch |err| {
        try err_w.print("error: failed to parse minisign sidecar '{s}': {s}\n", .{ sidecar.name, @errorName(err) });
        try err_w.flush();
        return error.MinisignParseError;
    };

    minisign.verifyKeyId(pk, sig) catch {
        var sig_id_hex: [16]u8 = undefined;
        var pk_id_hex: [16]u8 = undefined;
        minisign.keyIdToHex(sig.key_id, &sig_id_hex);
        minisign.keyIdToHex(pk.key_id, &pk_id_hex);
        try err_w.print(
            "error: minisign key id mismatch for '{s}'\n  sidecar key: {s}\n  --minisign:  {s}\n",
            .{ asset_name, &sig_id_hex, &pk_id_hex },
        );
        try err_w.flush();
        return error.MinisignKeyIdMismatch;
    };

    var file = try Dir.openFileAbsolute(io, download_path, .{});
    defer file.close(io);
    minisign.verifyArtifact(io, file, pk, sig) catch |err| {
        try err_w.print(
            "error: minisign artifact signature does not verify for '{s}': {s}\n",
            .{ asset_name, @errorName(err) },
        );
        try err_w.flush();
        return error.MinisignSignatureMismatch;
    };

    minisign.verifyGlobal(pk, sig) catch |err| {
        try err_w.print(
            "error: minisign trusted-comment signature does not verify for '{s}': {s}\n",
            .{ asset_name, @errorName(err) },
        );
        try err_w.flush();
        return error.MinisignGlobalSigMismatch;
    };

    var key_hex: [16]u8 = undefined;
    minisign.keyIdToHex(pk.key_id, &key_hex);
    try w.print("verified minisign: key {s} (", .{&key_hex});
    try writeTrustedCommentFormatted(w, sig.trusted_comment);
    try w.writeAll(")\n");
    try w.flush();
    return .minisign_verified;
}

/// Print a minisign trusted comment, rewriting the leading `timestamp:<unix>`
/// field as an ISO-8601 datetime so humans can read it. Everything else is
/// emitted verbatim. If no `timestamp:` prefix is found, or the digits don't
/// parse, the comment is written unchanged.
fn writeTrustedCommentFormatted(w: *Writer, comment: []const u8) !void {
    const prefix = "timestamp:";
    const idx = std.mem.indexOf(u8, comment, prefix) orelse {
        try w.writeAll(comment);
        return;
    };
    const after = comment[idx + prefix.len ..];
    var end: usize = 0;
    while (end < after.len and after[end] >= '0' and after[end] <= '9') : (end += 1) {}
    if (end == 0) {
        try w.writeAll(comment);
        return;
    }
    const ts = std.fmt.parseInt(i64, after[0..end], 10) catch {
        try w.writeAll(comment);
        return;
    };
    var iso_buf: [20]u8 = undefined;
    const iso = authenticode.formatUnixTimeIso(ts, &iso_buf);
    try w.writeAll(comment[0..idx]);
    try w.writeAll(prefix);
    try w.writeAll(iso);
    try w.writeAll(after[end..]);
}

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

/// Returns true if `name` is a verification/metadata sidecar (signature,
/// checksum, manifest, certificate, etc.) that accompanies a primary asset
/// rather than being a downloadable artifact itself. Used to exclude such
/// companions from substring name matching so that, e.g., `petstore-test`
/// resolves to `petstore-test.wasm` and not its `.ghr` / `.minisig` /
/// `.sigstore` siblings.
pub fn isSidecarAsset(name: []const u8) bool {
    const sidecar_suffixes = [_][]const u8{
        ".ghr",        ".minisig",    ".sig",        ".asc",
        ".pem",        ".pub",        ".gpg",        ".cert",
        ".crt",        ".bundle",     ".sigstore",   ".sigstore.json",
        ".sha256",     ".sha256sum",  ".sha256sums", ".sha512",
        ".sha512sum",  ".sha512sums", ".md5",        ".md5sum",
        ".md5sums",    ".sha1",       ".sha1sum",
    };
    for (sidecar_suffixes) |s| {
        if (std.ascii.endsWithIgnoreCase(name, s)) return true;
    }
    return false;
}

/// Find a single asset by `name` using a two-stage match:
///   1. Case-sensitive exact name match — one match wins (sidecars included,
///      so a fully-qualified sidecar name still resolves).
///   2. Otherwise case-insensitive substring match over non-sidecar assets
///      only — one match wins, multiple → `.ambiguous`, zero → `.none`.
///      Verification/metadata sidecars (`.ghr`, `.minisig`, `.sigstore`, …)
///      are skipped so they never make an otherwise-unique match ambiguous.
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
        if (isSidecarAsset(a.name)) continue;
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

/// Run SHA256 + minisign + sigstore verification on `download_path` and
/// return the strongest outcome. Mirrors the existing `cmdInstall` flow:
///
///   - `skip_verify=true` → prints a `note:` line and returns `.skipped`
///     without touching the file.
///   - Otherwise runs SHA256, then minisign (only when `minisign_pubkey_b64`
///     is non-null), then sigstore. Each verifier is independent; the
///     strongest success drives the returned outcome.
///   - Outcome precedence: `.sigstore_verified` > `.minisign_verified` >
///     `.sha256_verified` > `.no_verification`.
///   - If neither material is published, prints a `note:` saying the
///     download is unverified and returns `.no_verification`.
///
/// Lightweight pre-flight that inspects only the release's asset list
/// (no network, no disk) to decide whether the download is allowed to
/// proceed:
///
///   - `--skip-verify` always short-circuits to ok.
///   - If a `<asset_name>.minisig` sidecar is present but the caller did
///     not pass `--minisign`, fail-closed with a hint pointing to both
///     `--minisign` and `--skip-verify`. This aborts BEFORE the (often
///     large) download begins.
///   - If `--minisign` was supplied but no sidecar is published, fail
///     immediately for the same reason.
///   - Otherwise (no sidecar, no key, or sidecar+key both present) the
///     check passes and the caller proceeds. Full cryptographic
///     verification happens later in `verifyAssetOnDisk`.
///
/// Emits the same error messages as the post-download path so users see
/// consistent diagnostics regardless of when the check fires.
pub fn preflightVerification(
    assets: []const Asset,
    asset_name: []const u8,
    gates: VerifyGates,
    minisign_pubkey_b64: ?[]const u8,
    err_w: *Writer,
) !void {
    if (gates.skip_verify or gates.skip_minisign) return;

    var views_buf: [256]minisign.AssetView = undefined;
    if (assets.len > views_buf.len) {
        // Releases with more than 256 assets are vanishingly rare; if we
        // ever hit one the caller can still rely on the post-download
        // check.
        return;
    }
    for (assets, 0..) |a, i| {
        views_buf[i] = .{ .name = a.name, .browser_download_url = a.browser_download_url };
    }
    const views = views_buf[0..assets.len];

    const sidecar_opt = minisign.findMinisigAsset(views, asset_name);

    if (minisign_pubkey_b64) |key_b64| {
        _ = minisign.parsePublicKey(key_b64) catch |err| {
            try err_w.print(
                "error: minisign value is not a valid minisign public key ({s})\n",
                .{@errorName(err)},
            );
            try err_w.flush();
            return error.MinisignPubKeyParseError;
        };

        if (sidecar_opt == null) {
            try err_w.print(
                "error: a minisign key was supplied but no '{s}.minisig' sidecar is published in this release\n",
                .{asset_name},
            );
            try err_w.flush();
            return error.MinisignSidecarMissing;
        }
        return;
    }

    if (sidecar_opt) |sidecar| {
        try err_w.print(
            "error: '{s}' is published with a minisign signature ('{s}') but no minisign key was provided\n",
            .{ asset_name, sidecar.name },
        );
        try err_w.print(
            "  hint: pass a minisign key (positional after the spec, or --minisign <base64-pubkey>),\n",
            .{},
        );
        try err_w.print(
            "        or --skip-minisign / --skip-verify to bypass\n",
            .{},
        );
        try err_w.flush();
        return error.MinisignSidecarPresentButNoKey;
    }
}

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
    gates: VerifyGates,
    minisign_pubkey_b64: ?[]const u8,
    w: *Writer,
    err_w: *Writer,
) !VerifyOutcome {
    if (gates.skip_verify) {
        try w.print("note: verification skipped (--skip-verify)\n", .{});
        try w.flush();
        return .skipped;
    }

    const sha_outcome: VerifyOutcome = if (gates.skip_checksum) blk: {
        try w.print("note: checksum verification skipped (--skip-checksum)\n", .{});
        break :blk .no_verification;
    } else blk: {
        // Verify GitHub's built-in asset digest (inline in the release
        // JSON, no extra network request). Independently, if the release
        // also publishes a `.sha256` / `SHA256SUMS` sidecar, validate that
        // too — a published sidecar is never silently ignored. Both must
        // pass; the sidecar drives the reported outcome when present.
        const gh_outcome = try verifyDownloadedAssetGithubDigest(
            io,
            assets,
            asset_name,
            download_path,
            debug_w,
            w,
            err_w,
        );
        const sidecar_outcome = try verifyDownloadedAssetSha256(
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
        break :blk if (sidecar_outcome == .sha256_verified) sidecar_outcome else gh_outcome;
    };

    const mini_outcome: VerifyOutcome = if (gates.skip_minisign) blk: {
        if (minisign_pubkey_b64 != null) {
            try w.print("note: minisign verification skipped (--skip-minisign)\n", .{});
        }
        break :blk .no_verification;
    } else try verifyDownloadedAssetMinisign(
        allocator,
        io,
        cache_dir,
        assets,
        asset_name,
        download_path,
        debug_w,
        auth_header,
        minisign_pubkey_b64,
        w,
        err_w,
    );

    const sig_outcome: VerifyOutcome = if (gates.skip_sigstore) blk: {
        try w.print("note: sigstore verification skipped (--skip-sigstore)\n", .{});
        break :blk .no_verification;
    } else try verifyDownloadedAssetSigstore(
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

    const ac_outcome: VerifyOutcome = if (gates.skip_authenticode) blk: {
        try w.print("note: authenticode verification skipped (--skip-authenticode)\n", .{});
        break :blk .no_verification;
    } else try verifyDownloadedAssetAuthenticode(
        allocator,
        io,
        download_path,
        debug_w,
        w,
        err_w,
    );

    if (sig_outcome == .sigstore_verified) return .sigstore_verified;
    if (mini_outcome == .minisign_verified) return .minisign_verified;
    if (ac_outcome == .authenticode_verified) return .authenticode_verified;
    if (sha_outcome == .sha256_verified) return .sha256_verified;
    if (sha_outcome == .github_digest_verified) return .github_digest_verified;

    try w.print("note: download is unverified (no checksum, minisign, sigstore, or authenticode)\n", .{});
    try w.flush();
    return .no_verification;
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

test {
    _ = @import("sigstore.zig");
    _ = @import("minisign.zig");
    _ = @import("authenticode.zig");
}

test "writeTrustedCommentFormatted rewrites unix timestamp as ISO" {
    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer aw.deinit();
    try writeTrustedCommentFormatted(
        &aw.writer,
        "timestamp:1780495437\tfile:ghr-0.5.0-dev.1-windows-x64.zip\tcommit:abc\ttag:v0.5.0-dev.1",
    );
    try std.testing.expectEqualStrings(
        "timestamp:2026-06-03T14:03:57Z\tfile:ghr-0.5.0-dev.1-windows-x64.zip\tcommit:abc\ttag:v0.5.0-dev.1",
        aw.written(),
    );
}

test "writeTrustedCommentFormatted passes through when timestamp is missing" {
    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer aw.deinit();
    const input = "file:msg.bin\thashed";
    try writeTrustedCommentFormatted(&aw.writer, input);
    try std.testing.expectEqualStrings(input, aw.written());
}

test "assetDownload prefers API url with octet-stream when authenticated" {
    const asset: Asset = .{
        .name = "tool-linux.tar.xz",
        .browser_download_url = "https://github.com/o/r/releases/download/v1/tool-linux.tar.xz",
        .url = "https://api.github.com/repos/o/r/releases/assets/123",
    };
    const auth = assetDownload(asset, true);
    try std.testing.expectEqualStrings("https://api.github.com/repos/o/r/releases/assets/123", auth.url);
    try std.testing.expectEqualStrings(asset_octet_accept, auth.accept.?);

    const anon = assetDownload(asset, false);
    try std.testing.expectEqualStrings(asset.browser_download_url, anon.url);
    try std.testing.expect(anon.accept == null);
}

test "assetDownload falls back to browser url when API url is absent" {
    const asset: Asset = .{
        .name = "tool-linux.tar.xz",
        .browser_download_url = "https://github.com/o/r/releases/download/v1/tool-linux.tar.xz",
    };
    const r = assetDownload(asset, true);
    try std.testing.expectEqualStrings(asset.browser_download_url, r.url);
    try std.testing.expect(r.accept == null);
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

test "parseRepoSpecOwned: lowercases owner and repo, preserves tag case" {
    const sp = try parseRepoSpecOwned(std.testing.allocator, "AzureAD/Microsoft-Authentication-CLI@v0.9.6");
    defer sp.deinit();
    try std.testing.expectEqualStrings("azuread", sp.owner);
    try std.testing.expectEqualStrings("microsoft-authentication-cli", sp.repo);
    try std.testing.expectEqualStrings("v0.9.6", sp.tag.?);
}

test "parseRepoSpecOwned: already-lowercase passes through" {
    const sp = try parseRepoSpecOwned(std.testing.allocator, "ctaggart/ghr");
    defer sp.deinit();
    try std.testing.expectEqualStrings("ctaggart", sp.owner);
    try std.testing.expectEqualStrings("ghr", sp.repo);
    try std.testing.expect(sp.tag == null);
}

test "parseRepoSpecOwned: invalid spec error propagates" {
    try std.testing.expectError(error.InvalidSpec, parseRepoSpecOwned(std.testing.allocator, "noslash"));
}

test "classifySpecOrKey: plain spec without key" {
    const result = classifySpecOrKey("BurntSushi/ripgrep@14.1.1", &.{});
    try std.testing.expect(result == .spec);
    try std.testing.expectEqualStrings("BurntSushi/ripgrep@14.1.1", result.spec);
}

test "classifySpecOrKey: pubkey-shaped token after unkeyed spec" {
    const prior = [_]SpecWithKey{.{ .spec = "jedisct1/minisign@0.12" }};
    const key = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";
    const result = classifySpecOrKey(key, &prior);
    try std.testing.expect(result == .key);
    try std.testing.expectEqualStrings(key, result.key);
}

test "classifySpecOrKey: pubkey with no prior spec is a lone key" {
    const key = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";
    try std.testing.expect(classifySpecOrKey(key, &.{}) == .lone_key);
}

test "classifySpecOrKey: pubkey after already-keyed spec is a double key" {
    const prior = [_]SpecWithKey{.{
        .spec = "jedisct1/minisign@0.12",
        .key = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3",
    }};
    const second_key = "RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U";
    try std.testing.expect(classifySpecOrKey(second_key, &prior) == .double_key);
}

test "classifySpecOrKey: plain spec after keyed spec is still a spec" {
    const prior = [_]SpecWithKey{.{
        .spec = "jedisct1/minisign@0.12",
        .key = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3",
    }};
    const result = classifySpecOrKey("BurntSushi/ripgrep@14.1.1", &prior);
    try std.testing.expect(result == .spec);
    try std.testing.expectEqualStrings("BurntSushi/ripgrep@14.1.1", result.spec);
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
    try std.testing.expect(isInstallableAsset("foo.deb"));
    try std.testing.expect(isInstallableAsset("cosign-windows-amd64.exe"));
    try std.testing.expect(isInstallableAsset("tool.exe"));
    try std.testing.expect(isInstallableAsset("cosign-linux-amd64"));
    try std.testing.expect(isInstallableAsset("cosign-darwin-arm64"));
    try std.testing.expect(!isInstallableAsset("checksums.txt"));
    try std.testing.expect(!isInstallableAsset("foo.sha256"));
    try std.testing.expect(!isInstallableAsset("cosign-linux-amd64.sigstore.json"));
    try std.testing.expect(!isInstallableAsset("cosign-3.0.6-1.x86_64.rpm"));
    try std.testing.expect(!isInstallableAsset("cosign_3.0.6_aarch64.apk"));
    try std.testing.expect(!isInstallableAsset("release-cosign.pub"));
    // wasm modules are installable; the companion `.ghr` manifest is not.
    try std.testing.expect(isInstallableAsset("hello.wasm"));
    try std.testing.expect(!isInstallableAsset("hello.wasm.ghr"));
}

test "isWasmAssetName and findGhrManifestAsset" {
    try std.testing.expect(isWasmAssetName("hello.wasm"));
    try std.testing.expect(!isWasmAssetName("hello.wasm.ghr"));
    try std.testing.expect(!isWasmAssetName("tool.tar.gz"));

    const assets = [_]Asset{
        .{ .name = "hello.wasm", .browser_download_url = "u1" },
        .{ .name = "hello.wasm.ghr", .browser_download_url = "u2" },
        .{ .name = "hello.wasm.minisig", .browser_download_url = "u3" },
    };
    const found = findGhrManifestAsset(&assets, "hello.wasm") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("hello.wasm.ghr", found.name);
    try std.testing.expect(findGhrManifestAsset(&assets, "missing.wasm") == null);
}

test "findBestAsset selects the lone wasm module over its sidecars" {
    const assets = [_]Asset{
        .{ .name = "hello.wasm", .browser_download_url = "" },
        .{ .name = "hello.wasm.ghr", .browser_download_url = "" },
        .{ .name = "hello.wasm.minisig", .browser_download_url = "" },
    };
    const best = try findBestAssetForKeywords(&assets, .{
        .os = &.{"linux"},
        .arch = &.{ "x86_64", "x64", "amd64" },
    });
    try std.testing.expectEqualStrings("hello.wasm", best.name);
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
    try std.testing.expect(isWrongPlatform("azureauth-0.9.6-win-arm64.zip", linux_os));
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

test "isForeignArch handles riscv64 (issue #116)" {
    const x86_64_arch: []const []const u8 = &.{ "x86_64", "x64", "amd64" };
    const riscv64_arch: []const []const u8 = &.{ "riscv64gc", "riscv64" };
    // A riscv64 asset is foreign on an x86_64 host (riscv64gc matches riscv64).
    try std.testing.expect(isForeignArch("rustup-riscv64gc-unknown-linux-gnu.tar.gz", x86_64_arch));
    // An x86_64 / aarch64 asset is foreign on a riscv64 host.
    try std.testing.expect(isForeignArch("rustup-x86_64-unknown-linux-gnu.tar.gz", riscv64_arch));
    try std.testing.expect(isForeignArch("rustup-aarch64-unknown-linux-gnu.tar.gz", riscv64_arch));
    // The native riscv64 asset is not foreign on a riscv64 host.
    try std.testing.expect(!isForeignArch("rustup-riscv64gc-unknown-linux-gnu.tar.gz", riscv64_arch));
}

test "findBestAsset selects riscv64 build on riscv64 host (issue #116)" {
    const assets = [_]Asset{
        .{ .name = "rustup-1.29.0-x86_64-unknown-linux-gnu.tar.gz", .browser_download_url = "" },
        .{ .name = "rustup-1.29.0-aarch64-unknown-linux-gnu.tar.gz", .browser_download_url = "" },
        .{ .name = "rustup-1.29.0-riscv64gc-unknown-linux-gnu.tar.gz", .browser_download_url = "" },
    };
    const best = try findBestAssetForKeywords(&assets, .{
        .os = &.{"linux"},
        .arch = &.{ "riscv64gc", "riscv64" },
        .libc = .gnu,
    });
    try std.testing.expectEqualStrings("rustup-1.29.0-riscv64gc-unknown-linux-gnu.tar.gz", best.name);
}

test "libcBonus rewards the matching libc and is otherwise neutral (issue #116)" {
    // No host libc, or no libc marker in the name: neutral.
    try std.testing.expectEqual(@as(i32, 0), libcBonus("tool-x86_64-unknown-linux-gnu.tar.gz", null));
    try std.testing.expectEqual(@as(i32, 0), libcBonus("tool-linux-x64.tar.gz", .gnu));
    // Matching libc is rewarded; the mismatching one is never penalized.
    try std.testing.expectEqual(@as(i32, 3), libcBonus("tool-x86_64-unknown-linux-gnu.tar.gz", .gnu));
    try std.testing.expectEqual(@as(i32, 0), libcBonus("tool-x86_64-unknown-linux-gnu.tar.gz", .musl));
    try std.testing.expectEqual(@as(i32, 3), libcBonus("tool-x86_64-unknown-linux-musl.tar.gz", .musl));
    try std.testing.expectEqual(@as(i32, 0), libcBonus("tool-x86_64-unknown-linux-musl.tar.gz", .gnu));
}

test "findBestAsset picks gnu on glibc host and musl on musl host (issue #116)" {
    const assets = [_]Asset{
        .{ .name = "rustup-1.29.0-x86_64-unknown-linux-gnu.tar.gz", .browser_download_url = "" },
        .{ .name = "rustup-1.29.0-x86_64-unknown-linux-musl.tar.gz", .browser_download_url = "" },
    };
    const x86_64_arch: []const []const u8 = &.{ "x86_64", "x64", "amd64" };
    const gnu_best = try findBestAssetForKeywords(&assets, .{
        .os = &.{"linux"},
        .arch = x86_64_arch,
        .libc = .gnu,
    });
    try std.testing.expectEqualStrings("rustup-1.29.0-x86_64-unknown-linux-gnu.tar.gz", gnu_best.name);
    const musl_best = try findBestAssetForKeywords(&assets, .{
        .os = &.{"linux"},
        .arch = x86_64_arch,
        .libc = .musl,
    });
    try std.testing.expectEqualStrings("rustup-1.29.0-x86_64-unknown-linux-musl.tar.gz", musl_best.name);
}

test "musl-only release still installs on a glibc host (issue #116)" {
    const assets = [_]Asset{
        .{ .name = "tool-x86_64-unknown-linux-musl.tar.gz", .browser_download_url = "" },
    };
    const best = try findBestAssetForKeywords(&assets, .{
        .os = &.{"linux"},
        .arch = &.{ "x86_64", "x64", "amd64" },
        .libc = .gnu,
    });
    try std.testing.expectEqualStrings("tool-x86_64-unknown-linux-musl.tar.gz", best.name);
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

test "findBestAsset selects .deb on Linux arm64 when no tarball exists" {
    const assets = [_]Asset{
        .{ .name = "azureauth-0.9.6-win-arm64.zip", .browser_download_url = "" },
        .{ .name = "azureauth-0.9.6-osx-arm64.tar.gz", .browser_download_url = "" },
        .{ .name = "azureauth-0.9.6-linux-arm64.deb", .browser_download_url = "" },
    };
    const best = try findBestAssetForKeywords(&assets, .{
        .os = &.{"linux"},
        .arch = &.{ "aarch64", "arm64" },
    });
    try std.testing.expectEqualStrings("azureauth-0.9.6-linux-arm64.deb", best.name);
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

test "lookupSha256 parses certutil format (Windows .sha256 sidecars)" {
    // Verbatim shape of `certutil -hashfile <name> SHA256` output, which
    // BurntSushi/ripgrep publishes as its Windows `.sha256` sidecars (CRLF
    // line endings, three lines: header, bare digest, trailing status).
    const body =
        "SHA256 hash of ripgrep-14.1.1-x86_64-pc-windows-gnu.zip:\r\n" ++
        "01469c43c3fffdb4baff80469a75a7bf1dc3d0bf4ef63cda72a22f885f27465a\r\n" ++
        "CertUtil: -hashfile command completed successfully.\r\n";
    const got = lookupSha256(body, "ripgrep-14.1.1-x86_64-pc-windows-gnu.zip") orelse
        return error.TestUnexpectedNull;
    try std.testing.expectEqualStrings(
        "01469c43c3fffdb4baff80469a75a7bf1dc3d0bf4ef63cda72a22f885f27465a",
        got,
    );
    try std.testing.expect(lookupSha256(body, "wrong-name.zip") == null);
}

test "lookupSha256 mixes certutil and gnu entries in one file" {
    const body =
        "SHA256 hash of asset-a.zip:\r\n" ++
        ("a" ** 64) ++ "\r\n" ++
        "CertUtil: -hashfile command completed successfully.\r\n" ++
        ("b" ** 64) ++ "  asset-b.zip\n";
    const a = lookupSha256(body, "asset-a.zip") orelse return error.TestUnexpectedNull;
    try std.testing.expectEqualStrings("a" ** 64, a);
    const b = lookupSha256(body, "asset-b.zip") orelse return error.TestUnexpectedNull;
    try std.testing.expectEqualStrings("b" ** 64, b);
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

test "lookupAssetDigest extracts the GitHub sha256 digest" {
    const hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const assets = [_]Asset{
        .{ .name = "other.zip", .browser_download_url = "", .digest = "sha256:" ++ ("11" ** 32) },
        .{ .name = "app.tar.gz", .browser_download_url = "", .digest = "sha256:" ++ hex },
    };
    const got = lookupAssetDigest(&assets, "app.tar.gz") orelse return error.TestUnexpectedNull;
    try std.testing.expectEqualStrings(hex, got);
    // Case-insensitive on the algorithm prefix.
    const upper = [_]Asset{
        .{ .name = "app.tar.gz", .browser_download_url = "", .digest = "SHA256:" ++ hex },
    };
    const got2 = lookupAssetDigest(&upper, "app.tar.gz") orelse return error.TestUnexpectedNull;
    try std.testing.expectEqualStrings(hex, got2);
}

test "lookupAssetDigest rejects missing, malformed, and non-sha256 digests" {
    const hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    // No digest (pre-2025-06-03 asset).
    const none = [_]Asset{.{ .name = "app.tar.gz", .browser_download_url = "" }};
    try std.testing.expect(lookupAssetDigest(&none, "app.tar.gz") == null);
    // Wrong algorithm.
    const sha512 = [_]Asset{.{ .name = "app.tar.gz", .browser_download_url = "", .digest = "sha512:" ++ hex }};
    try std.testing.expect(lookupAssetDigest(&sha512, "app.tar.gz") == null);
    // Truncated hex.
    const short = [_]Asset{.{ .name = "app.tar.gz", .browser_download_url = "", .digest = "sha256:dead" }};
    try std.testing.expect(lookupAssetDigest(&short, "app.tar.gz") == null);
    // No matching asset name.
    const ok = [_]Asset{.{ .name = "app.tar.gz", .browser_download_url = "", .digest = "sha256:" ++ hex }};
    try std.testing.expect(lookupAssetDigest(&ok, "missing.tar.gz") == null);
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

test "findAssetByName ignores sidecars so primary asset is unique" {
    const a = std.testing.allocator;
    const assets = [_]Asset{
        .{ .name = "petstore-test.wasm", .browser_download_url = "" },
        .{ .name = "petstore-test.wasm.ghr", .browser_download_url = "" },
        .{ .name = "petstore-test.wasm.minisig", .browser_download_url = "" },
        .{ .name = "petstore-test.wasm.sigstore.json", .browser_download_url = "" },
        .{ .name = "petstore-test.wasm.sha256", .browser_download_url = "" },
    };
    switch (try findAssetByName(a, &assets, "petstore-test")) {
        .one => |asset| try std.testing.expectEqualStrings("petstore-test.wasm", asset.name),
        else => try std.testing.expect(false),
    }
}

test "findAssetByName exact sidecar name still resolves" {
    const a = std.testing.allocator;
    const assets = [_]Asset{
        .{ .name = "petstore-test.wasm", .browser_download_url = "" },
        .{ .name = "petstore-test.wasm.ghr", .browser_download_url = "" },
    };
    switch (try findAssetByName(a, &assets, "petstore-test.wasm.ghr")) {
        .one => |asset| try std.testing.expectEqualStrings("petstore-test.wasm.ghr", asset.name),
        else => try std.testing.expect(false),
    }
}

test "isSidecarAsset classifies sidecars and primaries" {
    try std.testing.expect(isSidecarAsset("petstore-test.wasm.ghr"));
    try std.testing.expect(isSidecarAsset("petstore-test.wasm.minisig"));
    try std.testing.expect(isSidecarAsset("tool.tar.gz.sigstore.json"));
    try std.testing.expect(isSidecarAsset("tool.tar.gz.sha256"));
    try std.testing.expect(!isSidecarAsset("petstore-test.wasm"));
    try std.testing.expect(!isSidecarAsset("tool-linux-amd64.tar.gz"));
}

test "verifyDownloadedAssetMinisign fails closed when no sidecar is published" {
    const a = std.testing.allocator;
    // No --minisign value AND no sidecar → silent .no_verification.
    var out_buf: [256]u8 = undefined;
    var out_writer = std.Io.Writer.Discarding.init(&out_buf);
    var err_buf: [256]u8 = undefined;
    var err_writer = std.Io.Writer.Discarding.init(&err_buf);

    const assets = [_]Asset{
        .{ .name = "tool.tar.xz", .browser_download_url = "https://example.invalid/a" },
        .{ .name = "tool.tar.xz.sha256", .browser_download_url = "https://example.invalid/b" },
    };

    const none_outcome = try verifyDownloadedAssetMinisign(
        a,
        std.testing.io,
        "/tmp/should/not/be/used",
        &assets,
        "tool.tar.xz",
        "/tmp/should/not/exist",
        null,
        null,
        null,
        &out_writer.writer,
        &err_writer.writer,
    );
    try std.testing.expectEqual(VerifyOutcome.no_verification, none_outcome);

    // --minisign set but no sidecar in the asset list → fail-closed.
    // Use a valid pubkey so we get past parsePublicKey.
    const valid_pubkey = "RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U";
    try std.testing.expectError(error.MinisignSidecarMissing, verifyDownloadedAssetMinisign(
        a,
        std.testing.io,
        "/tmp/should/not/be/used",
        &assets,
        "tool.tar.xz",
        "/tmp/should/not/exist",
        null,
        null,
        valid_pubkey,
        &out_writer.writer,
        &err_writer.writer,
    ));

    // --minisign set with a garbage value → parse error fast-path, also
    // no network or disk touched.
    try std.testing.expectError(error.MinisignPubKeyParseError, verifyDownloadedAssetMinisign(
        a,
        std.testing.io,
        "/tmp/should/not/be/used",
        &assets,
        "tool.tar.xz",
        "/tmp/should/not/exist",
        null,
        null,
        "not a real minisign pubkey",
        &out_writer.writer,
        &err_writer.writer,
    ));
}

test "verifyDownloadedAssetMinisign fails closed when sidecar is present but no key given" {
    const a = std.testing.allocator;
    var out_buf: [256]u8 = undefined;
    var out_writer = std.Io.Writer.Discarding.init(&out_buf);
    var err_buf: [256]u8 = undefined;
    var err_writer = std.Io.Writer.Discarding.init(&err_buf);

    const assets = [_]Asset{
        .{ .name = "tool.tar.xz", .browser_download_url = "https://example.invalid/a" },
        .{ .name = "tool.tar.xz.minisig", .browser_download_url = "https://example.invalid/b" },
    };

    // No --minisign value but sidecar exists → fail-closed without
    // touching the network or disk.
    try std.testing.expectError(error.MinisignSidecarPresentButNoKey, verifyDownloadedAssetMinisign(
        a,
        std.testing.io,
        "/tmp/should/not/be/used",
        &assets,
        "tool.tar.xz",
        "/tmp/should/not/exist",
        null,
        null,
        null,
        &out_writer.writer,
        &err_writer.writer,
    ));
}
