const std = @import("std");
const builtin = @import("builtin");
const Dirs = @import("dirs.zig").Dirs;
const http = @import("http.zig");
const archive = @import("archive.zig");
const auth = @import("auth.zig");
const sigstore = @import("sigstore.zig");
const version = @import("build_options").version;

const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;
const Writer = Io.Writer;
const Environ = std.process.Environ;
const EnvironMap = Environ.Map;

const http_write_buffer_size = http.http_write_buffer_size;
const debugLog = http.debugLog;
const isTransientStatus = http.isTransientStatus;

/// Delete an absolute path's directory tree. Zig 0.16 removed Dir.deleteTreeAbsolute,
/// so we open the parent dir and call deleteTree on the basename.
fn deleteTreeAbsolute(io: Io, abs_path: []const u8) !void {
    const parent = std.fs.path.dirname(abs_path) orelse return error.InvalidPath;
    const basename = std.fs.path.basename(abs_path);
    var dir = try Dir.openDirAbsolute(io, parent, .{});
    defer dir.close(io);
    try dir.deleteTree(io, basename);
}
const Spec = struct {
    owner: []const u8,
    repo: []const u8,
    tag: ?[]const u8,
};

fn parseSpec(s: []const u8) !Spec {
    // Split on '/' to get owner and repo[@tag]
    const slash = std.mem.indexOfScalar(u8, s, '/') orelse return error.InvalidSpec;
    const owner = s[0..slash];
    const rest = s[slash + 1 ..];
    if (owner.len == 0 or rest.len == 0) return error.InvalidSpec;

    // Split repo[@tag]
    if (std.mem.indexOfScalar(u8, rest, '@')) |at| {
        const repo = rest[0..at];
        const tag = rest[at + 1 ..];
        if (repo.len == 0 or tag.len == 0) return error.InvalidSpec;
        return .{ .owner = owner, .repo = repo, .tag = tag };
    }
    return .{ .owner = owner, .repo = rest, .tag = null };
}

/// GitHub release asset from the API response.
const Asset = struct {
    name: []const u8,
    browser_download_url: []const u8,
};

/// Parsed release info.
const Release = struct {
    tag_name: []const u8,
    assets: []const Asset,
};

/// URL-encode a tag for use in the GitHub API path.
/// Handles '+' -> '%2B' and other special characters.
fn urlEncode(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
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

const ParsedRelease = struct {
    parsed: std.json.Parsed(Release),
    body: []u8,
    allocator: std.mem.Allocator,

    fn deinit(self: *ParsedRelease) void {
        self.parsed.deinit();
        self.allocator.free(self.body);
    }
};

fn getRelease(
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
        // Try to extract error message from response body
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
                // GitHub returns "API rate limit exceeded" for 403 when rate limited
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

fn currentPlatformKeywords() struct { os: []const []const u8, arch: []const []const u8 } {
    const os_keywords: []const []const u8 = switch (builtin.os.tag) {
        .windows => &.{ "windows", "win" },
        .linux => &.{ "linux" },
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
    // Archives
    if (std.mem.endsWith(u8, name, ".zip")) return true;
    if (std.mem.endsWith(u8, name, ".tar.gz")) return true;
    if (std.mem.endsWith(u8, name, ".tgz")) return true;
    if (std.mem.endsWith(u8, name, ".tar.xz")) return true;
    // Windows executables
    if (std.mem.endsWith(u8, name, ".exe")) return true;
    // Reject known non-installable extensions
    const non_installable = [_][]const u8{
        ".json", ".txt", ".pub", ".sig", ".asc", ".pem", ".md",
        ".sha256", ".sha512", ".md5", ".minisig",
        ".rpm",  ".deb",  ".apk", ".msi", ".pkg", ".dmg",
        ".yml",  ".yaml",
    };
    for (non_installable) |ext| {
        if (std.mem.endsWith(u8, name, ext)) return false;
    }
    // Accept as potential bare binary
    return true;
}

/// Returns true if the file is a shared library (not a program executable).
fn isSharedLibrary(name: []const u8) bool {
    if (std.mem.endsWith(u8, name, ".dylib")) return true;
    if (std.mem.endsWith(u8, name, ".dll")) return true;
    // Check for .so or .so.N.N.N patterns
    if (std.mem.endsWith(u8, name, ".so")) return true;
    if (std.mem.indexOf(u8, name, ".so.") != null) return true;
    return false;
}

/// Returns true if the directory contains shared libraries rather than executables.
fn isLibraryDir(name: []const u8) bool {
    if (std.mem.endsWith(u8, name, ".framework")) return true;
    if (std.mem.eql(u8, name, "lib")) return true;
    if (std.mem.eql(u8, name, "Frameworks")) return true;
    if (std.mem.eql(u8, name, "PlugIns")) return true;
    return false;
}

const PlatformKeywords = struct {
    os: []const []const u8,
    arch: []const []const u8,
};

/// Markers in asset names that indicate non-primary variants (libraries,
/// source tarballs, minimal/debug builds, plugins, distro-specific static
/// bundles) which should be deprioritized when a plain binary archive is
/// also available.
fn nonPrimaryPenalty(name: []const u8) u32 {
    // Strong penalty: non-runtime variants (C API headers, SDKs, sources,
    // checksums, debug symbols). These almost never contain an executable
    // the user would want to run.
    const strong = [_][]const u8{
        "c-api",    "capi",      "headers",   "sdk",
        "dev",      "lib-only",  "src",       "source",
        "sources",  "sbom",      "checksum",  "checksums",
        "debug",    "dbg",       "symbols",
    };
    // Medium penalty: plugins/addons that ship separately from the main
    // runtime archive.
    const medium = [_][]const u8{
        "plugin",   "plugins",   "wasi_nn",   "wasi-nn",
        "ffmpeg",   "tensorflow", "image",    "opencvmini",
    };
    // Soft penalty: minimal/static/distro-coupled variants. Still allowed
    // if nothing better exists.
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
    // Tokens that are never the host for a normal desktop/server install.
    const always_wrong = [_][]const u8{
        "linux-android", "android",
        "ios", "tvos", "watchos",
        "wasi",  "wasm32", "wasm64", "emscripten",
    };
    for (always_wrong) |t| {
        if (containsIgnoreCaseBounded(name, t)) return true;
    }
    // If the asset contains any host OS keyword, accept it.
    for (plat_os) |k| {
        if (containsIgnoreCaseBounded(name, k)) return false;
    }
    // Otherwise, if it contains a known foreign OS token, it's wrong.
    const foreign = [_][]const u8{
        "windows", "win32", "win64", "mingw",
        "linux",
        "darwin",  "macos", "osx",
        "freebsd", "netbsd", "openbsd", "solaris", "illumos",
    };
    for (foreign) |t| {
        // Skip tokens that are in plat_os (case-insensitive match).
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
    // Universe of arch tokens recognized across supported hosts. Any of
    // these that aren't host-arch keywords are "foreign".
    const all_arch = [_][]const u8{
        "x86_64", "x64",   "amd64",
        "aarch64", "arm64",
        "armv7l", "armv7", "armv6",
        "i386",   "i686",  "x86",
    };
    // If the name contains any host-arch keyword, accept it.
    for (plat_arch) |k| {
        if (containsIgnoreCaseBounded(name, k)) return false;
    }
    // Otherwise, if it contains a known foreign-arch token, it's wrong.
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

fn findBestAssetForKeywords(assets: []const Asset, plat: PlatformKeywords) !Asset {
    // Filter out wrong-OS and wrong-arch assets, and require a positive
    // platform score. A wrong-platform asset must never win, even when
    // it is the only candidate the upstream ships, so we deliberately
    // do not relax this filter as a fallback.
    if (selectBestByScore(assets, plat)) |b| {
        if (scoreAsset(b.name, plat) > 0) return b;
    }

    // Last resort: exactly one installable asset means it's unambiguous.
    // Still gate on platform correctness so a single foreign-arch /
    // foreign-OS asset doesn't slip through.
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

fn findBestAsset(assets: []const Asset) !Asset {
    const plat = currentPlatformKeywords();
    return findBestAssetForKeywords(assets, .{ .os = plat.os, .arch = plat.arch });
}

// ---------------------------------------------------------------------------
// SHA256 download verification (Phase 1 of issue #50).
// ---------------------------------------------------------------------------

const Sha256 = std.crypto.hash.sha2.Sha256;

/// Outcome of running the verification step for a downloaded asset.
const VerifyOutcome = enum {
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

test {
    _ = @import("sigstore.zig");
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
    // Trim trailing CR/LF and surrounding spaces/tabs.
    var line = raw;
    while (line.len > 0 and (line[line.len - 1] == '\r' or line[line.len - 1] == '\n' or
        line[line.len - 1] == ' ' or line[line.len - 1] == '\t'))
    {
        line = line[0 .. line.len - 1];
    }
    while (line.len > 0 and (line[0] == ' ' or line[0] == '\t')) line = line[1..];
    if (line.len == 0) return null;
    if (line[0] == '#') return null;

    // BSD form: "SHA256 (<name>) = <hex>"
    const bsd_prefix = "SHA256 (";
    if (line.len > bsd_prefix.len and std.mem.startsWith(u8, line, bsd_prefix)) {
        const rest = line[bsd_prefix.len..];
        const close = std.mem.indexOfScalar(u8, rest, ')') orelse return null;
        const name = rest[0..close];
        const after = rest[close + 1 ..];
        const eq_marker = ") = ";
        // We've already consumed the ')'; expect " = <hex>"
        if (after.len < 4) return null;
        if (!std.mem.startsWith(u8, after, " = ")) return null;
        _ = eq_marker;
        const hex = after[3..];
        if (!isHex64(hex)) return null;
        return .{ .hex = hex, .name = stripDotSlash(name) };
    }

    // GNU form: "<hex>  <name>" or "<hex> *<name>"
    if (line.len < 64 + 1 + 1) return null;
    const hex = line[0..64];
    if (!isHex64(hex)) return null;
    if (line[64] != ' ' and line[64] != '\t') return null;
    var name_start: usize = 65;
    // Skip extra whitespace, optional `*` binary-mode marker.
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
    // Reject signature/key/non-sha256 sidecars first.
    const reject_suffixes = [_][]const u8{
        ".sig", ".asc", ".pem", ".pub", ".gpg", ".minisig",
        ".sha512", ".sha512sum", ".sha512sums",
        ".md5", ".md5sum", ".md5sums",
        ".sha1", ".sha1sum",
    };
    for (reject_suffixes) |s| {
        if (std.ascii.endsWithIgnoreCase(name, s)) return false;
    }
    // Sidecar SHA256 files.
    if (std.ascii.endsWithIgnoreCase(name, ".sha256")) return true;
    if (std.ascii.endsWithIgnoreCase(name, ".sha256sum")) return true;
    if (std.ascii.endsWithIgnoreCase(name, ".sha256sums")) return true;
    if (std.ascii.endsWithIgnoreCase(name, ".sha256sum.txt")) return true;
    if (std.ascii.endsWithIgnoreCase(name, ".sha256sums.txt")) return true;
    // Aggregate checksum files. Use a bounded substring match to avoid
    // false positives like `notchecksums.zip` (which would still contain
    // "checksum"); aggregate names are conventionally `*checksums*` or
    // `SHA256SUMS*`, so we accept either pattern.
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
    // Pass 1: exact sidecar match.
    for (assets) |a| {
        if (std.mem.eql(u8, a.name, asset_name)) continue;
        if (std.ascii.endsWithIgnoreCase(a.name, ".sha256") or
            std.ascii.endsWithIgnoreCase(a.name, ".sha256sum"))
        {
            // The sidecar's stem (everything before the trailing `.sha256[sum]`)
            // must equal the asset name.
            const dot = std.mem.lastIndexOfScalar(u8, a.name, '.').?;
            const stem = a.name[0..dot];
            // Handle the `.sha256sum` two-extension case.
            const final_stem = if (std.ascii.endsWithIgnoreCase(stem, ".sha256"))
                stem[0 .. stem.len - ".sha256".len]
            else
                stem;
            if (std.ascii.eqlIgnoreCase(final_stem, asset_name)) return a;
        }
    }
    // Pass 2: aggregate checksum file.
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
fn verifyDownloadedAssetSha256(
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

    // Download the checksum file into the cache, alongside the asset.
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
        // Cap the checksum file at 16 MiB; real-world files are << 1 MiB.
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
fn verifyDownloadedAssetSigstore(
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
    // Build a view of the asset list using the sigstore module's public
    // adapter shape (avoids exposing the install-internal `Asset` type).
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
        // Cap at 8 MiB; cosign bundles are < 16 KiB but allow generous slack.
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

/// For bare-binary assets whose name follows the `<name>-<arch>-<triple>...`
/// convention (e.g. `wash-aarch64-unknown-linux-musl`), extract `<name>` so
/// the resulting link in `~/.ghr/bin/` is the natural command the user
/// expects to run. Falls back to `repo` if the pattern doesn't match (e.g.
/// `cosign-linux-amd64`, where the arch is not directly after the stem).
fn deriveBareBinaryName(
    allocator: std.mem.Allocator,
    asset_name: []const u8,
    repo: []const u8,
    is_windows: bool,
) ![]u8 {
    var name = asset_name;
    if (std.mem.endsWith(u8, name, ".exe")) name = name[0 .. name.len - 4];

    // Find the first '-' or '_' separator.
    var sep_idx: ?usize = null;
    for (name, 0..) |c, i| {
        if (c == '-' or c == '_') { sep_idx = i; break; }
    }

    if (sep_idx) |si| {
        if (si > 0 and si + 1 < name.len) {
            const stem = name[0..si];
            const after = name[si + 1 ..];
            const archs = [_][]const u8{
                "x86_64", "x64",    "amd64",
                "aarch64", "arm64",
                "armv7l", "armv7",  "armv6",
                "x86",    "i686",   "i386",
                "ppc64le", "ppc64", "s390x", "riscv64",
            };
            for (archs) |a| {
                if (after.len < a.len) continue;
                if (!std.ascii.eqlIgnoreCase(after[0..a.len], a)) continue;
                if (after.len > a.len) {
                    const nc = after[a.len];
                    if (nc != '-' and nc != '_' and nc != '.') continue;
                }
                if (is_windows) {
                    return std.fmt.allocPrint(allocator, "{s}.exe", .{stem});
                }
                return allocator.dupe(u8, stem);
            }
        }
    }

    if (is_windows) return std.fmt.allocPrint(allocator, "{s}.exe", .{repo});
    return allocator.dupe(u8, repo);
}


/// Copy a bare executable from the cache into the staging directory,
/// renaming it to `dest_name` and setting executable permissions.
fn stageBareExecutable(
    allocator: std.mem.Allocator,
    io: Io,
    cache_path: []const u8,
    asset_name: []const u8,
    staging_dir: Dir,
    dest_name: []const u8,
) !void {
    var cache_dir = try Dir.openDirAbsolute(io, cache_path, .{});
    defer cache_dir.close(io);
    const content = try cache_dir.readFileAlloc(io, asset_name, allocator, Io.Limit.limited(256 * 1024 * 1024));
    defer allocator.free(content);

    var dest = try staging_dir.createFile(io, dest_name, .{ .permissions = .executable_file });
    defer dest.close(io);
    try dest.writeStreamingAll(io, content);
}

/// Scan directory recursively for executable files and return their relative paths.
fn findExecutables(allocator: std.mem.Allocator, io: Io, dir: Dir) !std.ArrayListUnmanaged([]const u8) {
    var result: std.ArrayListUnmanaged([]const u8) = .empty;
    try scanForExecutables(allocator, io, dir, &result, "");
    return result;
}

fn scanForExecutables(
    allocator: std.mem.Allocator,
    io: Io,
    dir: Dir,
    result: *std.ArrayListUnmanaged([]const u8),
    prefix: []const u8,
) !void {
    var iter = dir.iterate();
    while (try iter.next(io)) |entry| {
        const rel_name = if (prefix.len > 0)
            try std.fmt.allocPrint(allocator, "{s}{c}{s}", .{ prefix, std.fs.path.sep, entry.name })
        else
            try allocator.dupe(u8, entry.name);

        if (entry.kind == .directory) {
            if (isMacAppBundle(io, dir, entry.name)) {
                // Only scan Contents/MacOS/ inside .app bundles
                try scanAppBundle(allocator, io, dir, entry.name, result, rel_name);
                allocator.free(rel_name);
            } else if (isLibraryDir(entry.name)) {
                // Skip directories that contain shared libraries, not executables
                allocator.free(rel_name);
            } else {
                var sub = dir.openDir(io, entry.name, .{ .iterate = true }) catch {
                    allocator.free(rel_name);
                    continue;
                };
                defer sub.close(io);
                try scanForExecutables(allocator, io, sub, result, rel_name);
                allocator.free(rel_name);
            }
        } else if (entry.kind == .file) {
            if (isSharedLibrary(entry.name)) {
                allocator.free(rel_name);
                continue;
            }
            const is_exe = if (builtin.os.tag == .windows)
                std.mem.endsWith(u8, entry.name, ".exe")
            else blk: {
                const stat = dir.statFile(io, entry.name, .{}) catch {
                    allocator.free(rel_name);
                    continue;
                };
                break :blk (@as(u32, @intFromEnum(stat.permissions)) & 0o111) != 0;
            };
            if (is_exe) {
                try result.append(allocator, rel_name);
            } else {
                allocator.free(rel_name);
            }
        } else {
            allocator.free(rel_name);
        }
    }
}

/// Check if a directory is a macOS .app bundle (has Contents/MacOS/ inside).
fn isMacAppBundle(io: Io, parent: Dir, name: []const u8) bool {
    if (!std.mem.endsWith(u8, name, ".app")) return false;
    // Verify it has the expected bundle structure
    var app_dir = parent.openDir(io, name, .{}) catch return false;
    defer app_dir.close(io);
    app_dir.access(io, "Contents/MacOS", .{}) catch return false;
    return true;
}

/// Scan only the Contents/MacOS/ directory inside a .app bundle for executables.
fn scanAppBundle(
    allocator: std.mem.Allocator,
    io: Io,
    parent: Dir,
    app_name: []const u8,
    result: *std.ArrayListUnmanaged([]const u8),
    app_prefix: []const u8,
) !void {
    const macos_rel = try std.fmt.allocPrint(allocator, "{s}/Contents/MacOS", .{app_name});
    defer allocator.free(macos_rel);
    var macos_dir = parent.openDir(io, macos_rel, .{ .iterate = true }) catch return;
    defer macos_dir.close(io);

    const prefix = try std.fmt.allocPrint(allocator, "{s}/Contents/MacOS", .{app_prefix});
    defer allocator.free(prefix);

    var iter = macos_dir.iterate();
    while (try iter.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (isSharedLibrary(entry.name)) continue;
        const is_exe = if (builtin.os.tag == .windows)
            std.mem.endsWith(u8, entry.name, ".exe")
        else blk: {
            const stat = macos_dir.statFile(io, entry.name, .{}) catch continue;
            break :blk (@as(u32, @intFromEnum(stat.permissions)) & 0o111) != 0;
        };
        if (is_exe) {
            const rel_name = try std.fmt.allocPrint(allocator, "{s}{c}{s}", .{ prefix, std.fs.path.sep, entry.name });
            try result.append(allocator, rel_name);
        }
    }
}

/// Link or copy an executable to the bin directory.
fn linkToBin(
    allocator: std.mem.Allocator,
    io: Io,
    tool_dir_path: []const u8,
    bin_dir: Dir,
    exe_rel_path: []const u8,
    w: *Writer,
) !void {
    _ = allocator;
    const exe_name = std.fs.path.basename(exe_rel_path);
    var src_path_buf: [Dir.max_path_bytes]u8 = undefined;
    const src_path = std.fmt.bufPrint(&src_path_buf, "{s}{c}{s}", .{
        tool_dir_path,
        std.fs.path.sep,
        exe_rel_path,
    }) catch return error.PathTooLong;

    if (builtin.os.tag == .windows) {
        // Use a shim .exe + .shim file instead of a .cmd wrapper.
        // The shim is embedded in ghr at build time so it's always available,
        // regardless of how ghr is installed (PyPI, GitHub release, etc.).
        // This is the same technique used by npm and Scoop on Windows.
        const shim_exe_bytes = @import("shim_exe").bytes;

        const stem = if (std.mem.endsWith(u8, exe_name, ".exe"))
            exe_name[0 .. exe_name.len - 4]
        else
            exe_name;

        // Write the .shim file with the target path
        var shim_name_buf: [Dir.max_path_bytes]u8 = undefined;
        const shim_name = std.fmt.bufPrint(&shim_name_buf, "{s}.shim", .{stem}) catch return error.PathTooLong;
        bin_dir.deleteFile(io, shim_name) catch {};
        var shim_file = bin_dir.createFile(io, shim_name, .{}) catch return error.CreateFailed;
        defer shim_file.close(io);
        var shim_buf: [4096]u8 = undefined;
        var shim_w = shim_file.writer(io, &shim_buf);
        shim_w.interface.print("{s}", .{src_path}) catch return error.WriteFailed;
        shim_w.end() catch return error.WriteFailed;

        // Write the embedded shim exe as <name>.exe
        const shim_exe_name = if (std.mem.endsWith(u8, exe_name, ".exe"))
            exe_name
        else blk: {
            var name_buf: [Dir.max_path_bytes]u8 = undefined;
            break :blk std.fmt.bufPrint(&name_buf, "{s}.exe", .{stem}) catch return error.PathTooLong;
        };
        bin_dir.deleteFile(io, shim_exe_name) catch {
            // On Windows a running shim exe cannot be deleted; rename it out of the way.
            var old_name_buf: [Dir.max_path_bytes]u8 = undefined;
            const old_name = std.fmt.bufPrint(&old_name_buf, "{s}.old", .{shim_exe_name}) catch return error.PathTooLong;
            bin_dir.deleteFile(io, old_name) catch {};
            bin_dir.rename(shim_exe_name, bin_dir, old_name, io) catch {};
        };
        if (bin_dir.createFile(io, shim_exe_name, .{})) |*exe_file| {
            defer exe_file.close(io);
            exe_file.writeStreamingAll(io, shim_exe_bytes) catch return error.WriteFailed;
        } else |_| {
            // The shim exe is locked (self-update). The .shim file has already
            // been updated with the new target path, so the existing shim exe
            // will work correctly on the next invocation. Skip replacing it.
        }

        // Clean up any legacy .cmd wrapper from previous installs
        var cmd_name_buf: [Dir.max_path_bytes]u8 = undefined;
        const cmd_name = std.fmt.bufPrint(&cmd_name_buf, "{s}.cmd", .{stem}) catch return error.PathTooLong;
        bin_dir.deleteFile(io, cmd_name) catch {};
    } else {
        // Unix: symlink
        bin_dir.deleteFile(io, exe_name) catch {};
        try bin_dir.symLink(io, src_path, exe_name, .{});
    }
    try w.print("  linked {s}\n", .{exe_name});
}

/// Find .app bundles recursively in a directory. Returns relative paths from the root.
fn findAppBundles(allocator: std.mem.Allocator, io: Io, dir: Dir) !std.ArrayListUnmanaged([]const u8) {
    var result: std.ArrayListUnmanaged([]const u8) = .empty;
    try scanForAppBundles(allocator, io, dir, &result, "");
    return result;
}

fn scanForAppBundles(
    allocator: std.mem.Allocator,
    io: Io,
    dir: Dir,
    result: *std.ArrayListUnmanaged([]const u8),
    prefix: []const u8,
) !void {
    var iter = dir.iterate();
    while (try iter.next(io)) |entry| {
        if (entry.kind != .directory) continue;
        const rel_name = if (prefix.len > 0)
            try std.fmt.allocPrint(allocator, "{s}/{s}", .{ prefix, entry.name })
        else
            try allocator.dupe(u8, entry.name);

        if (isMacAppBundle(io, dir, entry.name)) {
            try result.append(allocator, rel_name);
            // Don't recurse into .app bundles
        } else {
            var sub = dir.openDir(io, entry.name, .{ .iterate = true }) catch {
                allocator.free(rel_name);
                continue;
            };
            defer sub.close(io);
            try scanForAppBundles(allocator, io, sub, result, rel_name);
            allocator.free(rel_name);
        }
    }
}

/// Marker file placed inside copied .app bundles to track ghr ownership.
const ghr_marker = "Contents/.ghr-source";

/// On macOS, copy .app bundles into ~/Applications for Spotlight and Launchpad discovery.
/// Symlinks are not indexed by Spotlight, so a real copy is required.
fn installAppBundles(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    app_paths: []const []const u8,
    tool_dir_path: []const u8,
    w: *Writer,
) !void {
    if (app_paths.len == 0) return;

    const home = environ.get("HOME") orelse return;
    const apps_dir_path = try std.fmt.allocPrint(allocator, "{s}/Applications", .{home});
    defer allocator.free(apps_dir_path);
    Dir.createDirAbsolute(io, apps_dir_path, .default_dir) catch {};

    var apps_dir = Dir.openDirAbsolute(io, apps_dir_path, .{}) catch return;
    defer apps_dir.close(io);

    for (app_paths) |rel_path| {
        const app_name = std.fs.path.basename(rel_path);
        const app_src = std.fmt.allocPrint(allocator, "{s}/{s}", .{ tool_dir_path, rel_path }) catch continue;
        defer allocator.free(app_src);

        // If an existing app is present, only replace it if we own it (has our marker or is a legacy symlink)
        const existing = apps_dir.statFile(io, app_name, .{}) catch null;
        if (existing) |_| {
            if (isLegacyAppSymlink(allocator, io, apps_dir, app_name, tool_dir_path, rel_path)) {
                apps_dir.deleteFile(io, app_name) catch continue;
            } else if (isOwnedAppBundle(io, apps_dir, app_name, tool_dir_path)) {
                apps_dir.deleteTree(io, app_name) catch continue;
            } else {
                w.print("  skipped ~/Applications/{s} (not owned by ghr)\n", .{app_name}) catch {};
                continue;
            }
        }

        // Copy to a staging name, then rename for atomicity
        const staging_name = std.fmt.allocPrint(allocator, ".ghr-staging-{s}", .{app_name}) catch continue;
        defer allocator.free(staging_name);
        apps_dir.deleteTree(io, staging_name) catch {};

        // Open source .app directory
        var src_dir = Dir.openDirAbsolute(io, app_src, .{ .iterate = true }) catch continue;
        defer src_dir.close(io);

        // Create staging directory and copy
        apps_dir.createDir(io, staging_name, .default_dir) catch continue;
        var staging_dir = apps_dir.openDir(io, staging_name, .{}) catch continue;
        defer staging_dir.close(io);

        copyDirRecursive(io, src_dir, staging_dir) catch {
            apps_dir.deleteTree(io, staging_name) catch {};
            continue;
        };

        // Write ownership marker (remove first in case archive contained one as a symlink)
        staging_dir.deleteFile(io, ghr_marker) catch {};
        writeMarkerFile(io, staging_dir, tool_dir_path) catch {
            apps_dir.deleteTree(io, staging_name) catch {};
            continue;
        };

        // Atomic rename into place
        apps_dir.rename(staging_name, apps_dir, app_name, io) catch {
            apps_dir.deleteTree(io, staging_name) catch {};
            continue;
        };

        try w.print("  installed ~/Applications/{s}\n", .{app_name});
    }
}

/// Remove ~/Applications .app bundles owned by this tool.
fn uninstallAppBundles(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    app_paths: []const []const u8,
    tool_dir_path: []const u8,
    w: *Writer,
) void {
    if (app_paths.len == 0) return;

    const home = environ.get("HOME") orelse return;
    const apps_dir_path = std.fmt.allocPrint(allocator, "{s}/Applications", .{home}) catch return;
    defer allocator.free(apps_dir_path);

    var apps_dir = Dir.openDirAbsolute(io, apps_dir_path, .{}) catch return;
    defer apps_dir.close(io);

    for (app_paths) |rel_path| {
        const app_name = std.fs.path.basename(rel_path);

        // Handle legacy symlinks from older ghr versions
        if (isLegacyAppSymlink(allocator, io, apps_dir, app_name, tool_dir_path, rel_path)) {
            apps_dir.deleteFile(io, app_name) catch continue;
            w.print("  uninstalled ~/Applications/{s}\n", .{app_name}) catch {};
            continue;
        }

        if (!isOwnedAppBundle(io, apps_dir, app_name, tool_dir_path)) continue;

        apps_dir.deleteTree(io, app_name) catch continue;
        w.print("  uninstalled ~/Applications/{s}\n", .{app_name}) catch {};
    }
}

/// Check if an .app bundle in ~/Applications is owned by ghr for the given tool path.
fn isOwnedAppBundle(io: Io, apps_dir: Dir, app_name: []const u8, tool_dir_path: []const u8) bool {
    // Build path to marker: <app_name>/Contents/.ghr-source
    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const marker_path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ app_name, ghr_marker }) catch return false;

    // Verify marker is a regular file, not a symlink
    const stat = apps_dir.statFile(io, marker_path, .{}) catch return false;
    if (stat.kind == .sym_link) return false;

    // Read and compare source path
    var content_buf: [Dir.max_path_bytes]u8 = undefined;
    const file = apps_dir.openFile(io, marker_path, .{}) catch return false;
    defer file.close(io);
    const len = file.readPositionalAll(io, &content_buf, 0) catch return false;
    return std.mem.eql(u8, content_buf[0..len], tool_dir_path);
}

/// Check if an entry is a legacy symlink (from older ghr versions) pointing to our tool.
fn isLegacyAppSymlink(
    allocator: std.mem.Allocator,
    io: Io,
    apps_dir: Dir,
    app_name: []const u8,
    tool_dir_path: []const u8,
    rel_path: []const u8,
) bool {
    var link_buf: [Dir.max_path_bytes]u8 = undefined;
    const len = apps_dir.readLink(io, app_name, &link_buf) catch return false;
    const link_target = link_buf[0..len];
    const expected = std.fmt.allocPrint(allocator, "{s}/{s}", .{ tool_dir_path, rel_path }) catch return false;
    defer allocator.free(expected);
    return std.mem.eql(u8, link_target, expected);
}

/// Write the ghr ownership marker file.
fn writeMarkerFile(io: Io, dir: Dir, tool_dir_path: []const u8) !void {
    var file = try dir.createFile(io, ghr_marker, .{});
    defer file.close(io);
    try file.writeStreamingAll(io, tool_dir_path);
}

/// Recursively copy a directory tree, preserving symlinks without following them.
fn copyDirRecursive(io: Io, src_dir: Dir, dest_dir: Dir) !void {
    var iter = src_dir.iterate();
    while (try iter.next(io)) |entry| {
        switch (entry.kind) {
            .file => {
                try src_dir.copyFile(entry.name, dest_dir, entry.name, io, .{});
            },
            .directory => {
                dest_dir.createDir(io, entry.name, .default_dir) catch |err| switch (err) {
                    error.PathAlreadyExists => {},
                    else => return err,
                };
                var child_src = try src_dir.openDir(io, entry.name, .{ .iterate = true });
                defer child_src.close(io);
                var child_dest = try dest_dir.openDir(io, entry.name, .{});
                defer child_dest.close(io);
                try copyDirRecursive(io, child_src, child_dest);
            },
            .sym_link => {
                var buf: [Dir.max_path_bytes]u8 = undefined;
                const len = try src_dir.readLink(io, entry.name, &buf);
                dest_dir.symLink(io, buf[0..len], entry.name, .{}) catch {};
            },
            else => {},
        }
    }
}

/// Write ghr.json metadata.
fn writeMetadata(
    allocator: std.mem.Allocator,
    io: Io,
    tool_dir: Dir,
    tag: []const u8,
    asset_name: []const u8,
    bins: []const []const u8,
    apps: []const []const u8,
    verified: []const u8,
) !void {
    _ = allocator;
    var file = try tool_dir.createFile(io, "ghr.json", .{});
    defer file.close(io);
    var buf: [4096]u8 = undefined;
    var fw = file.writer(io, &buf);
    const w = &fw.interface;
    try w.print("{{\"tag\":\"{s}\",\"asset\":\"{s}\",\"verified\":\"{s}\",\"bins\":[", .{ tag, asset_name, verified });
    for (bins, 0..) |bin, i| {
        if (i > 0) try w.print(",", .{});
        try w.print("\"", .{});
        try writeJsonEscaped(w, bin);
        try w.print("\"", .{});
    }
    try w.print("],\"apps\":[", .{});
    for (apps, 0..) |app, i| {
        if (i > 0) try w.print(",", .{});
        try w.print("\"", .{});
        try writeJsonEscaped(w, app);
        try w.print("\"", .{});
    }
    try w.print("]}}\n", .{});
    try fw.end();
}

/// Write a string with JSON escaping (backslashes and quotes).
fn writeJsonEscaped(w: *Writer, s: []const u8) !void {
    for (s) |c| {
        switch (c) {
            '\\' => try w.print("\\\\", .{}),
            '"' => try w.print("\\\"", .{}),
            else => try w.print("{c}", .{c}),
        }
    }
}

/// Metadata stored in ghr.json.
const Metadata = struct {
    tag: []const u8,
    asset: []const u8,
    verified: []const u8 = "none",
    bins: []const []const u8 = &.{},
    apps: []const []const u8 = &.{},
};

/// Read ghr.json metadata from a tool directory.
fn readMetadata(allocator: std.mem.Allocator, io: Io, tool_dir_path: []const u8) ?struct {
    parsed: std.json.Parsed(Metadata),
    body: []const u8,
} {
    var dir = Dir.openDirAbsolute(io, tool_dir_path, .{}) catch return null;
    defer dir.close(io);
    const body = dir.readFileAlloc(io, "ghr.json", allocator, Io.Limit.limited(65536)) catch return null;
    const parsed = std.json.parseFromSlice(Metadata, allocator, body, .{ .ignore_unknown_fields = true }) catch {
        allocator.free(body);
        return null;
    };
    return .{ .parsed = parsed, .body = body };
}

/// Clean up old install's bin symlinks and app bundles before replacing.
fn cleanupOldInstall(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    tool_path: []const u8,
    bin_path: []const u8,
    w: *Writer,
) void {
    const meta = readMetadata(allocator, io, tool_path) orelse return;
    defer meta.parsed.deinit();
    defer allocator.free(meta.body);

    var bin_dir = Dir.openDirAbsolute(io, bin_path, .{}) catch return;
    defer bin_dir.close(io);
    for (meta.parsed.value.bins) |exe_rel| {
        const exe_name = std.fs.path.basename(exe_rel);
        if (builtin.os.tag == .windows) {
            cleanupWindowsBinEntry(io, bin_dir, exe_name, tool_path);
        } else {
            // Verify the symlink points to our tool dir before removing
            var link_buf: [Dir.max_path_bytes]u8 = undefined;
            const len = bin_dir.readLink(io, exe_name, &link_buf) catch continue;
            const link_target = link_buf[0..len];
            if (std.mem.startsWith(u8, link_target, tool_path) and
                (link_target.len == tool_path.len or link_target[tool_path.len] == '/'))
            {
                bin_dir.deleteFile(io, exe_name) catch {};
            }
        }
    }

    // Remove old app bundle copies (macOS)
    if (comptime builtin.os.tag.isDarwin()) {
        uninstallAppBundles(allocator, io, environ, meta.parsed.value.apps, tool_path, w);
    }
}

/// Remove shim .exe + .shim files or legacy .cmd for a single bin entry on Windows.
fn cleanupWindowsBinEntry(io: Io, bin_dir: Dir, exe_name: []const u8, tool_path: []const u8) void {
    const stem = if (std.mem.endsWith(u8, exe_name, ".exe"))
        exe_name[0 .. exe_name.len - 4]
    else
        exe_name;

    // Remove .shim file if it points to our tool dir
    var shim_name_buf: [Dir.max_path_bytes]u8 = undefined;
    const shim_name = std.fmt.bufPrint(&shim_name_buf, "{s}.shim", .{stem}) catch return;
    if (shimPointsToToolDir(io, bin_dir, shim_name, tool_path)) {
        bin_dir.deleteFile(io, shim_name) catch {};
        // Remove the companion shim .exe
        const shim_exe_name = if (std.mem.endsWith(u8, exe_name, ".exe")) exe_name else blk: {
            var name_buf: [Dir.max_path_bytes]u8 = undefined;
            break :blk std.fmt.bufPrint(&name_buf, "{s}.exe", .{stem}) catch return;
        };
        bin_dir.deleteFile(io, shim_exe_name) catch {};
    }

    // Also remove legacy .cmd wrapper if present
    var cmd_name_buf: [Dir.max_path_bytes]u8 = undefined;
    const cmd_name = std.fmt.bufPrint(&cmd_name_buf, "{s}.cmd", .{stem}) catch return;
    bin_dir.deleteFile(io, cmd_name) catch {};
}

/// Check if a .shim file's target path starts with tool_path.
fn shimPointsToToolDir(io: Io, bin_dir: Dir, shim_name: []const u8, tool_path: []const u8) bool {
    var content_buf: [Dir.max_path_bytes]u8 = undefined;
    const file = bin_dir.openFile(io, shim_name, .{}) catch return false;
    defer file.close(io);
    const len = file.readPositionalAll(io, &content_buf, 0) catch return false;
    const content = std.mem.trim(u8, content_buf[0..len], &[_]u8{ ' ', '\t', '\r', '\n' });
    return std.mem.startsWith(u8, content, tool_path) and
        (content.len == tool_path.len or content[tool_path.len] == '\\' or content[tool_path.len] == '/');
}

/// Remove bin entries from a previous install that are NOT present in the new install.
/// Called after new bins are already linked so the active install is never broken.
fn cleanupStaleBinEntries(
    io: Io,
    bin_dir: Dir,
    old_bins: []const []const u8,
    new_bins: []const []const u8,
    old_tool_path: []const u8,
) void {
    for (old_bins) |old_exe_rel| {
        const old_name = std.fs.path.basename(old_exe_rel);
        // Skip if this bin is also in the new install (already overwritten by linkToBin)
        var dominated = false;
        for (new_bins) |new_exe_rel| {
            if (std.mem.eql(u8, std.fs.path.basename(new_exe_rel), old_name)) {
                dominated = true;
                break;
            }
        }
        if (dominated) continue;
        if (builtin.os.tag == .windows) {
            cleanupWindowsBinEntry(io, bin_dir, old_name, old_tool_path);
        } else {
            var link_buf: [Dir.max_path_bytes]u8 = undefined;
            const len = bin_dir.readLink(io, old_name, &link_buf) catch continue;
            const link_target = link_buf[0..len];
            if (std.mem.startsWith(u8, link_target, old_tool_path) and
                (link_target.len == old_tool_path.len or link_target[old_tool_path.len] == '/'))
            {
                bin_dir.deleteFile(io, old_name) catch {};
            }
        }
    }
}

pub fn cmdUninstall(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    spec_str: []const u8,
    w: *Writer,
    err_w: *Writer,
) !void {
    const spec = parseSpec(spec_str) catch {
        try err_w.print("error: invalid spec '{s}', expected owner/repo\n", .{spec_str});
        try err_w.flush();
        std.process.exit(1);
    };

    const d = try Dirs.detect(allocator, environ);
    defer d.deinit();

    const tool_path = try std.fmt.allocPrint(allocator, "{s}{c}{s}{c}{s}", .{
        d.tools, std.fs.path.sep, spec.owner, std.fs.path.sep, spec.repo,
    });
    defer allocator.free(tool_path);

    // Check the tool exists
    Dir.accessAbsolute(io, tool_path, .{}) catch {
        try err_w.print("error: {s}/{s} is not installed\n", .{ spec.owner, spec.repo });
        try err_w.flush();
        std.process.exit(1);
    };

    // Read metadata to know what to clean up
    const meta = readMetadata(allocator, io, tool_path);
    defer if (meta) |m| {
        m.parsed.deinit();
        allocator.free(m.body);
    };

    // Remove bin symlinks
    var bin_dir = Dir.openDirAbsolute(io, d.bin, .{}) catch null;
    defer if (bin_dir) |*bd| bd.close(io);

    if (meta) |m| {
        for (m.parsed.value.bins) |exe_rel| {
            const exe_name = std.fs.path.basename(exe_rel);
            if (bin_dir) |bd| {
                if (builtin.os.tag == .windows) {
                    cleanupWindowsBinEntry(io, bd, exe_name, tool_path);
                    try w.print("  unlinked {s}\n", .{exe_name});
                } else {
                    var link_buf: [Dir.max_path_bytes]u8 = undefined;
                    const len = bd.readLink(io, exe_name, &link_buf) catch continue;
                    const link_target = link_buf[0..len];
                    if (std.mem.startsWith(u8, link_target, tool_path) and
                        (link_target.len == tool_path.len or link_target[tool_path.len] == '/'))
                    {
                        bd.deleteFile(io, exe_name) catch continue;
                        try w.print("  unlinked {s}\n", .{exe_name});
                    }
                }
            }
        }

        // Remove app bundle copies (macOS)
        if (comptime builtin.os.tag.isDarwin()) {
            uninstallAppBundles(allocator, io, environ, m.parsed.value.apps, tool_path, w);
        }
    }

    // Delete the tool directory
    deleteTreeAbsolute(io, tool_path) catch {
        try err_w.print("error: failed to remove {s}\n", .{tool_path});
        try err_w.flush();
        std.process.exit(1);
    };

    try w.print("uninstalled {s}/{s}\n", .{ spec.owner, spec.repo });
}

pub fn cmdInstall(
    allocator: std.mem.Allocator,
    io: Io,
    environ: *const EnvironMap,
    spec_str: []const u8,
    w: *Writer,
    err_w: *Writer,
    debug: bool,
    no_auth: bool,
    skip_verify: bool,
) !void {
    const spec = parseSpec(spec_str) catch {
        try err_w.print("error: invalid spec '{s}', expected owner/repo[@tag]\n", .{spec_str});
        try err_w.flush();
        std.process.exit(1);
    };

    const d = try Dirs.detect(allocator, environ);
    defer d.deinit();

    // Resolve auth token: env vars first, then `gh auth token` as fallback
    const auth_resolved = auth.resolveGithubToken(allocator, io, environ, no_auth);
    defer auth_resolved.deinit(allocator);
    const auth_header = try auth.bearerHeader(allocator, auth_resolved);
    defer if (auth_header) |h| allocator.free(h);

    try w.print("resolving {s}/{s}", .{ spec.owner, spec.repo });
    if (spec.tag) |t| try w.print("@{s}", .{t});
    try w.print(" ...\n", .{});
    try w.flush();

    // Set up HTTP client
    var client: std.http.Client = .{
        .allocator = allocator,
        .io = io,
        .write_buffer_size = http_write_buffer_size,
    };
    defer client.deinit();

    // Get release info
    var release = getRelease(allocator, &client, spec.owner, spec.repo, spec.tag, auth_header) catch |err| {
        switch (err) {
            error.GitHubApiError => {
                try err_w.print("error: release not found for {s}/{s}", .{ spec.owner, spec.repo });
                if (spec.tag) |t| try err_w.print("@{s}", .{t});
                try err_w.print("\n", .{});
            },
            else => try err_w.print("error: failed to fetch release: {}\n", .{err}),
        }
        try err_w.flush();
        std.process.exit(1);
    };
    defer release.deinit();

    const tag_name = release.parsed.value.tag_name;
    try w.print("found release {s}\n", .{tag_name});

    // Find matching asset
    const asset = findBestAsset(release.parsed.value.assets) catch {
        try err_w.print("error: no matching asset for this platform\n", .{});
        try err_w.print("available assets:\n", .{});
        for (release.parsed.value.assets) |a| {
            try err_w.print("  {s}\n", .{a.name});
        }
        try err_w.flush();
        std.process.exit(1);
    };

    try w.print("downloading {s} ...\n", .{asset.name});
    try w.flush();

    // Ensure cache directory tree exists
    if (std.fs.path.dirname(d.cache)) |parent| {
        Dir.createDirAbsolute(io, parent, .default_dir) catch {};
    }
    Dir.createDirAbsolute(io, d.cache, .default_dir) catch {};

    // Download to cache file
    const download_path = try std.fmt.allocPrint(allocator, "{s}{c}{s}", .{
        d.cache, std.fs.path.sep, asset.name,
    });
    defer allocator.free(download_path);

    const debug_w: ?*Writer = if (debug) err_w else null;

    debugLog(debug_w, "debug: ghr {s}\n", .{version});
    debugLog(debug_w, "debug: auth: {s}\n", .{auth_resolved.source});
    debugLog(debug_w, "debug: url: {s}\n", .{asset.browser_download_url});
    debugLog(debug_w, "debug: cache: {s}\n", .{download_path});

    http.downloadToFile(allocator, io, asset.browser_download_url, download_path, .{
        .auth_header = auth_header,
        .debug_w = debug_w,
    }) catch |err| {
        try err_w.print("error: download failed: {}\n", .{err});
        try err_w.print("  url: {s}\n", .{asset.browser_download_url});
        try err_w.flush();
        std.process.exit(1);
    };
    defer Dir.deleteFileAbsolute(io, download_path) catch {};

    // Get file size for display
    {
        const stat = Dir.openFileAbsolute(io, download_path, .{}) catch null;
        if (stat) |f| {
            defer f.close(io);
            const size = f.length(io) catch 0;
            if (size > 0) {
                try w.print("downloaded {d:.1} MB\n", .{@as(f64, @floatFromInt(size)) / 1024.0 / 1024.0});
            }
        }
    }

    // Verification (issue #50). Runs after the asset is on disk, before we
    // extract or move anything. SHA256 (Phase 1) and sigstore bundle
    // (Phase 2) are independent — both run when material is published.
    // Sigstore is the stronger signal and overrides the metadata label.
    var verified_label: []const u8 = "none";
    if (skip_verify) {
        verified_label = "skipped";
        try w.print("note: verification skipped (--skip-verify)\n", .{});
    } else {
        const sha_outcome = verifyDownloadedAssetSha256(
            allocator,
            io,
            d.cache,
            release.parsed.value.assets,
            asset.name,
            download_path,
            debug_w,
            auth_header,
            w,
            err_w,
        ) catch |verr| {
            switch (verr) {
                error.ChecksumMismatch,
                error.ChecksumDownloadFailed,
                error.ChecksumEntryMissing,
                => {
                    Dir.deleteFileAbsolute(io, download_path) catch {};
                    std.process.exit(1);
                },
                else => {
                    try err_w.print("error: SHA256 verification failed: {}\n", .{verr});
                    try err_w.flush();
                    Dir.deleteFileAbsolute(io, download_path) catch {};
                    std.process.exit(1);
                },
            }
        };
        if (sha_outcome == .sha256_verified) verified_label = "sha256";

        const sig_outcome = verifyDownloadedAssetSigstore(
            allocator,
            io,
            d.cache,
            release.parsed.value.assets,
            asset.name,
            download_path,
            debug_w,
            auth_header,
            w,
            err_w,
        ) catch |verr| {
            try err_w.print("error: sigstore verification failed: {s}\n", .{@errorName(verr)});
            try err_w.flush();
            Dir.deleteFileAbsolute(io, download_path) catch {};
            std.process.exit(1);
        };
        if (sig_outcome == .sigstore_verified) verified_label = "sigstore";

        if (sha_outcome == .no_verification and sig_outcome == .no_verification) {
            try w.print("note: download is unverified (no SHA256 checksum or sigstore bundle published)\n", .{});
        }
        try w.flush();
    }

    // Stage extraction
    const staging_path = try std.fmt.allocPrint(allocator, "{s}{c}staging-{s}-{s}", .{
        d.cache, std.fs.path.sep, spec.owner, spec.repo,
    });
    defer allocator.free(staging_path);

    // Clean up any leftover staging dir
    deleteTreeAbsolute(io, staging_path) catch {};
    try Dir.createDirAbsolute(io, staging_path, .default_dir);

    var staging_dir = try Dir.openDirAbsolute(io, staging_path, .{ .iterate = true });
    defer staging_dir.close(io);

    // Extract
    try w.print("extracting ...\n", .{});
    try w.flush();

    switch (archive.detectFormat(asset.name)) {
        .zip, .tar_gz, .tar_xz => {
            archive.extractAuto(allocator, io, staging_dir, download_path, 0) catch |err| {
                try err_w.print("error: extraction failed: {}\n", .{err});
                try err_w.flush();
                std.process.exit(1);
            };
        },
        .unknown => {
            // Bare executable (e.g., cosign-windows-amd64.exe or cosign-linux-amd64).
            // Derive the command name from the asset (e.g. `wash` from
            // `wash-aarch64-unknown-linux-musl`) so the linked command is the
            // natural tool name. Falls back to repo when the pattern doesn't
            // fit (e.g. `cosign-linux-amd64` -> `cosign`).
            const exe_name = try deriveBareBinaryName(
                allocator,
                asset.name,
                spec.repo,
                builtin.os.tag == .windows,
            );
            defer allocator.free(exe_name);

            try stageBareExecutable(allocator, io, d.cache, asset.name, staging_dir, exe_name);
        },
    }

    // Find executables
    var exes = try findExecutables(allocator, io, staging_dir);
    defer {
        for (exes.items) |e| allocator.free(e);
        exes.deinit(allocator);
    }

    if (exes.items.len == 0) {
        try err_w.print("error: no executables found in archive\n", .{});
        try err_w.print("  selected asset: {s}\n", .{asset.name});
        try err_w.print("  other installable assets in this release:\n", .{});
        var listed: u32 = 0;
        for (release.parsed.value.assets) |a| {
            if (std.mem.eql(u8, a.name, asset.name)) continue;
            if (!isInstallableAsset(a.name)) continue;
            try err_w.print("    {s}\n", .{a.name});
            listed += 1;
        }
        if (listed == 0) {
            try err_w.print("    (none)\n", .{});
        }
        try err_w.flush();
        std.process.exit(1);
    }

    // Find .app bundles (macOS)
    var apps: std.ArrayListUnmanaged([]const u8) = .empty;
    if (comptime builtin.os.tag.isDarwin()) {
        apps = try findAppBundles(allocator, io, staging_dir);
    }
    defer {
        for (apps.items) |a| allocator.free(a);
        apps.deinit(allocator);
    }

    // Move staging to final tool dir
    const tool_path = try std.fmt.allocPrint(allocator, "{s}{c}{s}{c}{s}", .{
        d.tools, std.fs.path.sep, spec.owner, std.fs.path.sep, spec.repo,
    });
    defer allocator.free(tool_path);

    // Clean up tombstone from a previous self-update (Windows)
    if (comptime builtin.os.tag == .windows) {
        var tb: [Dir.max_path_bytes]u8 = undefined;
        if (std.fmt.bufPrint(&tb, "{s}.old", .{tool_path})) |t| {
            deleteTreeAbsolute(io, t) catch {};
        } else |_| {}
    }

    // Save old metadata before touching anything (for stale bin cleanup after install)
    const old_meta = readMetadata(allocator, io, tool_path);
    defer if (old_meta) |m| {
        m.parsed.deinit();
        allocator.free(m.body);
    };

    // Remove old tool directory. On Windows, running executables can be renamed
    // but not deleted, so fall back to renaming the old dir as a tombstone.
    deleteTreeAbsolute(io, tool_path) catch {
        if (comptime builtin.os.tag == .windows) {
            var tombstone_buf: [Dir.max_path_bytes]u8 = undefined;
            const tombstone = std.fmt.bufPrint(&tombstone_buf, "{s}.old", .{tool_path}) catch {
                try err_w.print("error: tool path too long\n", .{});
                try err_w.flush();
                std.process.exit(1);
            };
            deleteTreeAbsolute(io, tombstone) catch {};
            Dir.renameAbsolute(tool_path, tombstone, io) catch {
                try err_w.print("error: cannot replace tool directory (files may be locked by a running process)\n", .{});
                try err_w.flush();
                std.process.exit(1);
            };
        }
    };

    // Ensure tools and owner dirs exist (create full path)
    const owner_path = try std.fmt.allocPrint(allocator, "{s}{c}{s}", .{
        d.tools, std.fs.path.sep, spec.owner,
    });
    defer allocator.free(owner_path);
    // Create all parent directories
    var dir = Dir.openDirAbsolute(io, std.fs.path.dirname(d.tools) orelse ".", .{}) catch blk: {
        // Create parents manually
        if (std.fs.path.dirname(d.tools)) |parent| {
            if (std.fs.path.dirname(parent)) |grandparent| {
                Dir.createDirAbsolute(io, grandparent, .default_dir) catch {};
            }
            Dir.createDirAbsolute(io, parent, .default_dir) catch {};
        }
        Dir.createDirAbsolute(io, d.tools, .default_dir) catch {};
        break :blk try Dir.openDirAbsolute(io, d.tools, .{});
    };
    dir.close(io);
    Dir.createDirAbsolute(io, d.tools, .default_dir) catch {};
    Dir.createDirAbsolute(io, owner_path, .default_dir) catch {};

    // Rename staging to final
    Dir.renameAbsolute(staging_path, tool_path, io) catch {
        try err_w.print("error: failed to move staging directory to tool directory\n", .{});
        try err_w.flush();
        std.process.exit(1);
    };

    // Re-open the tool dir for metadata and linking
    var tool_dir = try Dir.openDirAbsolute(io, tool_path, .{});
    defer tool_dir.close(io);

    // Write metadata
    const bins_slice = exes.items;
    const apps_slice = apps.items;
    writeMetadata(allocator, io, tool_dir, tag_name, asset.name, bins_slice, apps_slice, verified_label) catch |err| {
        try err_w.print("warning: failed to write metadata: {}\n", .{err});
    };

    // Create bin dir and link executables
    Dir.createDirAbsolute(io, d.bin, .default_dir) catch {};
    var bin_dir = try Dir.openDirAbsolute(io, d.bin, .{});
    defer bin_dir.close(io);

    try w.print("linking executables:\n", .{});
    for (exes.items) |exe_name| {
        linkToBin(allocator, io, tool_path, bin_dir, exe_name, w) catch |err| {
            try err_w.print("warning: failed to link {s}: {}\n", .{ exe_name, err });
        };
    }

    // Clean up stale bin entries from old install that aren't in the new one
    if (old_meta) |m| {
        cleanupStaleBinEntries(io, bin_dir, m.parsed.value.bins, exes.items, tool_path);
    }

    // On macOS, copy .app bundles into ~/Applications for Spotlight discovery
    if (comptime builtin.os.tag.isDarwin()) {
        installAppBundles(allocator, io, environ, apps_slice, tool_path, w) catch |err| {
            try err_w.print("warning: failed to install .app bundle: {}\n", .{err});
        };
    }

    try w.print("installed {s}/{s}@{s}\n", .{ spec.owner, spec.repo, tag_name });
}

test "parseSpec with tag" {
    const spec = try parseSpec("ctaggart/pencil2d@v0.8.0-dev.1");
    try std.testing.expectEqualStrings("ctaggart", spec.owner);
    try std.testing.expectEqualStrings("pencil2d", spec.repo);
    try std.testing.expectEqualStrings("v0.8.0-dev.1", spec.tag.?);
}

test "parseSpec without tag" {
    const spec = try parseSpec("ctaggart/pencil2d");
    try std.testing.expectEqualStrings("ctaggart", spec.owner);
    try std.testing.expectEqualStrings("pencil2d", spec.repo);
    try std.testing.expect(spec.tag == null);
}

test "parseSpec invalid" {
    try std.testing.expectError(error.InvalidSpec, parseSpec("noslash"));
    try std.testing.expectError(error.InvalidSpec, parseSpec("/repo"));
    try std.testing.expectError(error.InvalidSpec, parseSpec("owner/"));
}

test "containsIgnoreCase" {
    try std.testing.expect(containsIgnoreCase("pencil2d-Windows.zip", "windows"));
    try std.testing.expect(containsIgnoreCase("pencil2d-LINUX.tar.gz", "linux"));
    try std.testing.expect(!containsIgnoreCase("pencil2d-macos.zip", "windows"));
}

test "containsIgnoreCaseBounded enforces left word boundary" {
    // "win" should match at a boundary (start or non-letter prefix)
    try std.testing.expect(containsIgnoreCaseBounded("tool-win64.zip", "win"));
    try std.testing.expect(containsIgnoreCaseBounded("Win32.zip", "win"));
    try std.testing.expect(containsIgnoreCaseBounded("pc-windows-msvc.zip", "windows"));
    // but NOT inside a larger word like "darwin"
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
    // Archives
    try std.testing.expect(isInstallableAsset("foo.zip"));
    try std.testing.expect(isInstallableAsset("foo.tar.gz"));
    try std.testing.expect(isInstallableAsset("foo.tgz"));
    try std.testing.expect(isInstallableAsset("foo.tar.xz"));
    // Windows executables
    try std.testing.expect(isInstallableAsset("cosign-windows-amd64.exe"));
    try std.testing.expect(isInstallableAsset("tool.exe"));
    // Bare binaries (no extension)
    try std.testing.expect(isInstallableAsset("cosign-linux-amd64"));
    try std.testing.expect(isInstallableAsset("cosign-darwin-arm64"));
    // Non-installable
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
    // aarch64 host: amd64/x86_64/x64/i386/i686/x86 are foreign.
    const aarch64_arch: []const []const u8 = &.{ "aarch64", "arm64" };
    try std.testing.expect(isForeignArch("lunatic-linux-amd64.tar.gz", aarch64_arch));
    try std.testing.expect(isForeignArch("wavm-nightly-linux-x64.tar.gz", aarch64_arch));
    try std.testing.expect(isForeignArch("tool-x86_64-unknown-linux-gnu.tar.gz", aarch64_arch));
    try std.testing.expect(isForeignArch("tool-i686-linux.tar.gz", aarch64_arch));
    try std.testing.expect(!isForeignArch("tool-aarch64-linux.tar.xz", aarch64_arch));
    try std.testing.expect(!isForeignArch("wash-aarch64-unknown-linux-musl", aarch64_arch));
    // Names with no arch tokens are not rejected.
    try std.testing.expect(!isForeignArch("lunatic-macos-universal.tar.gz", aarch64_arch));
    try std.testing.expect(!isForeignArch("tool.tar.gz", aarch64_arch));
    // Mixed names that include a host-arch token are not rejected even
    // if a foreign-arch token is also present (e.g. cross-arch bundles).
    try std.testing.expect(!isForeignArch("tool-x86_64-and-aarch64.tar.gz", aarch64_arch));

    // x86_64 host: aarch64/arm64/armv7*/armv6 are foreign.
    const x86_64_arch: []const []const u8 = &.{ "x86_64", "x64", "amd64" };
    try std.testing.expect(isForeignArch("tool-aarch64-linux.tar.xz", x86_64_arch));
    try std.testing.expect(isForeignArch("tool-arm64-linux.tar.gz", x86_64_arch));
    try std.testing.expect(isForeignArch("tool-armv7l.tar.gz", x86_64_arch));
    try std.testing.expect(!isForeignArch("tool-x86_64-linux.tar.gz", x86_64_arch));
    try std.testing.expect(!isForeignArch("lunatic-linux-amd64.tar.gz", x86_64_arch));

    // Word boundary: x64 must not match inside linux64 etc.
    try std.testing.expect(!isForeignArch("tool-linux64.tar.gz", aarch64_arch));

    // Unknown host (empty arch list) -> never reject.
    const empty: []const []const u8 = &.{};
    try std.testing.expect(!isForeignArch("tool-x86_64-linux.tar.gz", empty));
}

test "findBestAsset errors on aarch64 when only amd64 Linux assets exist (issue #55 lunatic)" {
    // Repro 1 from issue #55: lunatic-solutions/lunatic@v0.13.2 ships only
    // x86_64 binaries; on aarch64 Linux ghr must error rather than install
    // the wrong-arch x86_64 ELF.
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
    // Repro 2 from issue #55: WAVM nightly ships only linux-x64 for Linux.
    // The release also has macos-arm64, which would falsely match the host
    // arch if foreign-OS rejection were ever bypassed; this test guards
    // that the OS filter is never relaxed.
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
    // Symmetric of issue #55: an upstream that ships only aarch64 Linux
    // binaries must error on an x86_64 Linux host.
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
    // On aarch64 Linux, when both aarch64 and x86_64 Linux assets exist,
    // the aarch64 one must win.
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

test "deriveBareBinaryName strips arch-triple from stem" {
    const a = std.testing.allocator;

    {
        const n = try deriveBareBinaryName(a, "wash-aarch64-unknown-linux-musl", "wasmCloud", false);
        defer a.free(n);
        try std.testing.expectEqualStrings("wash", n);
    }
    {
        const n = try deriveBareBinaryName(a, "wash-x86_64-pc-windows-msvc.exe", "wasmCloud", true);
        defer a.free(n);
        try std.testing.expectEqualStrings("wash.exe", n);
    }
    {
        // arch is not directly after stem -> fall back to repo.
        const n = try deriveBareBinaryName(a, "cosign-linux-amd64", "cosign", false);
        defer a.free(n);
        try std.testing.expectEqualStrings("cosign", n);
    }
    {
        const n = try deriveBareBinaryName(a, "cosign-windows-amd64.exe", "cosign", true);
        defer a.free(n);
        try std.testing.expectEqualStrings("cosign.exe", n);
    }
    {
        // Underscore separator.
        const n = try deriveBareBinaryName(a, "foo_aarch64-unknown-linux-gnu", "repo", false);
        defer a.free(n);
        try std.testing.expectEqualStrings("foo", n);
    }
    {
        // No separator at all -> fall back.
        const n = try deriveBareBinaryName(a, "singleword", "repo", false);
        defer a.free(n);
        try std.testing.expectEqualStrings("repo", n);
    }
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

test "stageBareExecutable copies file with executable permissions" {
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Create a fake "cache" subdir with a downloaded bare executable
    tmp.dir.createDirPath(tio, "cache") catch {};
    var cache_dir = try tmp.dir.openDir(tio, "cache", .{});
    defer cache_dir.close(tio);
    var src = try cache_dir.createFile(tio, "tool-windows-amd64.exe", .{});
    try src.writeStreamingAll(tio, "FAKE_EXE_CONTENT");
    src.close(tio);

    // Create a staging dir
    tmp.dir.createDirPath(tio, "staging") catch {};
    var staging = try tmp.dir.openDir(tio, "staging", .{ .iterate = true });
    defer staging.close(tio);

    // Stage the bare executable
    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const cache_path_len = try tmp.dir.realPathFile(tio, "cache", &path_buf);
    const cache_path = path_buf[0..cache_path_len];
    try stageBareExecutable(
        std.testing.allocator,
        tio,
        cache_path,
        "tool-windows-amd64.exe",
        staging,
        "tool.exe",
    );

    // Verify the staged file exists and has the right content
    const content = try staging.readFileAlloc(tio, "tool.exe", std.testing.allocator, Io.Limit.limited(4096));
    defer std.testing.allocator.free(content);
    try std.testing.expectEqualStrings("FAKE_EXE_CONTENT", content);

    // Verify findExecutables discovers it
    var exes = try findExecutables(std.testing.allocator, tio, staging);
    defer {
        for (exes.items) |e| std.testing.allocator.free(e);
        exes.deinit(std.testing.allocator);
    }
    try std.testing.expectEqual(@as(usize, 1), exes.items.len);
    try std.testing.expectEqualStrings("tool.exe", exes.items[0]);
}


test "findExecutables discovers executable files" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    // Create an executable file
    const exe_file = try tmp.dir.createFile(std.testing.io, "myapp", .{ .permissions = .executable_file });
    exe_file.close(std.testing.io);

    // Create a non-executable file
    const txt_file = try tmp.dir.createFile(std.testing.io, "readme.txt", .{});
    txt_file.close(std.testing.io);

    const allocator = std.testing.allocator;
    var exes = try findExecutables(allocator, std.testing.io, tmp.dir);
    defer {
        for (exes.items) |e| allocator.free(e);
        exes.deinit(allocator);
    }

    // Should find the executable but not the text file
    try std.testing.expectEqual(@as(usize, 1), exes.items.len);
    try std.testing.expectEqualStrings("myapp", exes.items[0]);
}

test "findExecutables discovers nested executables" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    // Create nested structure
    try tmp.dir.createDirPath(std.testing.io, "bin");
    const exe_file = try tmp.dir.createFile(std.testing.io, "bin/tool", .{ .permissions = .executable_file });
    exe_file.close(std.testing.io);

    const allocator = std.testing.allocator;
    var exes = try findExecutables(allocator, std.testing.io, tmp.dir);
    defer {
        for (exes.items) |e| allocator.free(e);
        exes.deinit(allocator);
    }

    try std.testing.expectEqual(@as(usize, 1), exes.items.len);
    try std.testing.expectEqualStrings("bin/tool", exes.items[0]);
}

test "findExecutables returns empty for no executables" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    const txt_file = try tmp.dir.createFile(std.testing.io, "readme.txt", .{});
    txt_file.close(std.testing.io);

    const allocator = std.testing.allocator;
    var exes = try findExecutables(allocator, std.testing.io, tmp.dir);
    defer {
        for (exes.items) |e| allocator.free(e);
        exes.deinit(allocator);
    }

    try std.testing.expectEqual(@as(usize, 0), exes.items.len);
}

test "ParsedRelease deinit frees all memory" {
    const allocator = std.testing.allocator;

    // Simulate what getRelease does: parse JSON from a body buffer
    const json_body = try allocator.dupe(u8,
        \\{"tag_name":"v1.0.0","assets":[{"name":"app.tar.gz","browser_download_url":"https://example.com/app.tar.gz"}]}
    );

    const parsed = try std.json.parseFromSlice(Release, allocator, json_body, .{ .ignore_unknown_fields = true });

    var pr: ParsedRelease = .{ .parsed = parsed, .body = json_body, .allocator = allocator };

    // Verify parsed data is accessible
    try std.testing.expectEqualStrings("v1.0.0", pr.parsed.value.tag_name);
    try std.testing.expectEqual(@as(usize, 1), pr.parsed.value.assets.len);
    try std.testing.expectEqualStrings("app.tar.gz", pr.parsed.value.assets[0].name);

    // deinit should free everything with no leaks (testing.allocator will catch leaks)
    pr.deinit();
}

test "isMacAppBundle detects valid .app bundles" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Valid .app bundle
    try tmp.dir.createDirPath(std.testing.io, "MyApp.app/Contents/MacOS");
    try std.testing.expect(isMacAppBundle(std.testing.io, tmp.dir, "MyApp.app"));

    // Not a .app (wrong extension)
    try tmp.dir.createDirPath(std.testing.io, "notapp/Contents/MacOS");
    try std.testing.expect(!isMacAppBundle(std.testing.io, tmp.dir, "notapp"));

    // .app without Contents/MacOS
    try tmp.dir.createDirPath(std.testing.io, "Broken.app/Contents");
    try std.testing.expect(!isMacAppBundle(std.testing.io, tmp.dir, "Broken.app"));
}

test "findExecutables only scans Contents/MacOS in .app bundles" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    const allocator = std.testing.allocator;

    // Create a .app bundle with main executable and framework binaries
    try tmp.dir.createDirPath(std.testing.io, "MyApp.app/Contents/MacOS");
    try tmp.dir.createDirPath(std.testing.io, "MyApp.app/Contents/Frameworks/QtCore.framework/Versions/A");
    try tmp.dir.createDirPath(std.testing.io, "MyApp.app/Contents/PlugIns/platforms");

    // Main executable
    const main_exe = try tmp.dir.createFile(std.testing.io, "MyApp.app/Contents/MacOS/myapp", .{ .permissions = .executable_file });
    main_exe.close(std.testing.io);

    // Framework binary (should NOT be found)
    const fw_exe = try tmp.dir.createFile(std.testing.io, "MyApp.app/Contents/Frameworks/QtCore.framework/Versions/A/QtCore", .{ .permissions = .executable_file });
    fw_exe.close(std.testing.io);

    // Plugin binary (should NOT be found)
    const plugin_exe = try tmp.dir.createFile(std.testing.io, "MyApp.app/Contents/PlugIns/platforms/libqcocoa.dylib", .{ .permissions = .executable_file });
    plugin_exe.close(std.testing.io);

    var exes = try findExecutables(allocator, std.testing.io, tmp.dir);
    defer {
        for (exes.items) |e| allocator.free(e);
        exes.deinit(allocator);
    }

    // Should only find the main executable, not framework/plugin binaries
    try std.testing.expectEqual(@as(usize, 1), exes.items.len);
    try std.testing.expectEqualStrings("MyApp.app/Contents/MacOS/myapp", exes.items[0]);
}

test "findExecutables handles .app bundle alongside regular executables" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    const allocator = std.testing.allocator;

    // A .app bundle
    try tmp.dir.createDirPath(std.testing.io, "MyApp.app/Contents/MacOS");
    const app_exe = try tmp.dir.createFile(std.testing.io, "MyApp.app/Contents/MacOS/myapp", .{ .permissions = .executable_file });
    app_exe.close(std.testing.io);

    // A regular executable next to the .app
    const cli_exe = try tmp.dir.createFile(std.testing.io, "mytool", .{ .permissions = .executable_file });
    cli_exe.close(std.testing.io);

    var exes = try findExecutables(allocator, std.testing.io, tmp.dir);
    defer {
        for (exes.items) |e| allocator.free(e);
        exes.deinit(allocator);
    }

    // Should find both
    try std.testing.expectEqual(@as(usize, 2), exes.items.len);

    // Sort for deterministic comparison
    std.mem.sort([]const u8, exes.items, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lt);
    try std.testing.expectEqualStrings("MyApp.app/Contents/MacOS/myapp", exes.items[0]);
    try std.testing.expectEqualStrings("mytool", exes.items[1]);
}

test "isSharedLibrary identifies shared libraries" {
    try std.testing.expect(isSharedLibrary("libfoo.dylib"));
    try std.testing.expect(isSharedLibrary("Qt6Core.dll"));
    try std.testing.expect(isSharedLibrary("libfoo.so"));
    try std.testing.expect(isSharedLibrary("libfoo.so.1"));
    try std.testing.expect(isSharedLibrary("libfoo.so.1.2.3"));
    try std.testing.expect(!isSharedLibrary("myapp"));
    try std.testing.expect(!isSharedLibrary("myapp.exe"));
    try std.testing.expect(!isSharedLibrary("README.md"));
}

test "isLibraryDir identifies library directories" {
    try std.testing.expect(isLibraryDir("QtCore.framework"));
    try std.testing.expect(isLibraryDir("lib"));
    try std.testing.expect(isLibraryDir("Frameworks"));
    try std.testing.expect(isLibraryDir("PlugIns"));
    try std.testing.expect(!isLibraryDir("bin"));
    try std.testing.expect(!isLibraryDir("Contents"));
    try std.testing.expect(!isLibraryDir("MacOS"));
}

test "findExecutables skips shared libraries" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    const allocator = std.testing.allocator;

    // Real executable
    const exe = try tmp.dir.createFile(std.testing.io, "pencil2d", .{ .permissions = .executable_file });
    exe.close(std.testing.io);

    // Shared libraries (should be skipped)
    try tmp.dir.createDirPath(std.testing.io, "lib");
    const dylib = try tmp.dir.createFile(std.testing.io, "lib/libfoo.dylib", .{ .permissions = .executable_file });
    dylib.close(std.testing.io);
    const so = try tmp.dir.createFile(std.testing.io, "lib/libbar.so", .{ .permissions = .executable_file });
    so.close(std.testing.io);

    var exes = try findExecutables(allocator, std.testing.io, tmp.dir);
    defer {
        for (exes.items) |e| allocator.free(e);
        exes.deinit(allocator);
    }

    try std.testing.expectEqual(@as(usize, 1), exes.items.len);
    try std.testing.expectEqualStrings("pencil2d", exes.items[0]);
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


test "writeJsonEscaped escapes backslashes and quotes" {
    const allocator = std.testing.allocator;
    var collected = std.Io.Writer.Allocating.init(allocator);
    defer collected.deinit();

    try writeJsonEscaped(&collected.writer, "no special chars");
    const plain = try collected.toOwnedSlice();
    defer allocator.free(plain);
    try std.testing.expectEqualStrings("no special chars", plain);

    var collected2 = std.Io.Writer.Allocating.init(allocator);
    defer collected2.deinit();
    try writeJsonEscaped(&collected2.writer, "path\\to\\file");
    const escaped = try collected2.toOwnedSlice();
    defer allocator.free(escaped);
    try std.testing.expectEqualStrings("path\\\\to\\\\file", escaped);

    var collected3 = std.Io.Writer.Allocating.init(allocator);
    defer collected3.deinit();
    try writeJsonEscaped(&collected3.writer, "say \"hello\"");
    const quoted = try collected3.toOwnedSlice();
    defer allocator.free(quoted);
    try std.testing.expectEqualStrings("say \\\"hello\\\"", quoted);
}

test "writeMetadata and readMetadata round-trip" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const bins = [_][]const u8{ "sub\\dir\\tool.exe", "other.exe" };
    const apps = [_][]const u8{};
    try writeMetadata(allocator, std.testing.io, tmp.dir, "v1.0.0", "tool-windows.zip", &bins, &apps, "sha256");

    // Verify it's valid JSON by reading it back
    const body = try tmp.dir.readFileAlloc(std.testing.io, "ghr.json", allocator, Io.Limit.limited(8192));
    defer allocator.free(body);

    // Backslashes must be escaped in JSON
    try std.testing.expect(std.mem.indexOf(u8, body, "sub\\\\dir\\\\tool.exe") != null);

    // Parse it back
    const parsed = try std.json.parseFromSlice(Metadata, allocator, body, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    try std.testing.expectEqualStrings("v1.0.0", parsed.value.tag);
    try std.testing.expectEqualStrings("tool-windows.zip", parsed.value.asset);
    try std.testing.expectEqualStrings("sha256", parsed.value.verified);
    try std.testing.expectEqual(@as(usize, 2), parsed.value.bins.len);
    try std.testing.expectEqualStrings("sub\\dir\\tool.exe", parsed.value.bins[0]);
    try std.testing.expectEqualStrings("other.exe", parsed.value.bins[1]);
}

test "readMetadata returns null for missing file" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Get absolute path for the tmp dir
    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const tmp_path_len = tmp.dir.realPath(std.testing.io, &path_buf) catch return;
    const tmp_path = path_buf[0..tmp_path_len];
    const result = readMetadata(allocator, std.testing.io, tmp_path);
    try std.testing.expect(result == null);
}

test "shimPointsToToolDir validates path boundaries" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Create a .shim file pointing to a tool path
    var f = try tmp.dir.createFile(std.testing.io, "tool.shim", .{});
    var buf: [256]u8 = undefined;
    var fw = f.writer(std.testing.io, &buf);
    try fw.interface.print("C:\\tools\\owner\\repo\\bin\\tool.exe", .{});
    try fw.end();
    f.close(std.testing.io);

    // Exact tool path prefix should match
    try std.testing.expect(shimPointsToToolDir(
        std.testing.io,
        tmp.dir,
        "tool.shim",
        "C:\\tools\\owner\\repo",
    ));

    // Partial prefix that doesn't end at path boundary should NOT match
    try std.testing.expect(!shimPointsToToolDir(
        std.testing.io,
        tmp.dir,
        "tool.shim",
        "C:\\tools\\owner\\rep",
    ));

    // Non-matching prefix
    try std.testing.expect(!shimPointsToToolDir(
        std.testing.io,
        tmp.dir,
        "tool.shim",
        "C:\\other\\path",
    ));

    // Missing .shim file
    try std.testing.expect(!shimPointsToToolDir(
        std.testing.io,
        tmp.dir,
        "nonexistent.shim",
        "C:\\tools\\owner\\repo",
    ));
}

// ---------------------------------------------------------------------------
// SHA256 verification tests (Phase 1 of issue #50).
// ---------------------------------------------------------------------------

test "isHex64 accepts and rejects" {
    try std.testing.expect(isHex64("0123456789abcdefABCDEF000000000000000000000000000000000000000000"));
    try std.testing.expect(!isHex64("0123")); // too short
    try std.testing.expect(!isHex64("zzzz" ++ ("0" ** 60))); // bad chars
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
    // Bad hex length
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
