//! Native minisign verification (issue #65).
//!
//! Coverage:
//!   * Parse a minisign v2 public key — single-token base64 of
//!     `<sig_alg:2><key_id:8><pubkey:32>`. Tolerates a leading
//!     `untrusted comment: ...\n` line so a copy-pasted `.pub` file body
//!     also parses cleanly.
//!   * Parse a v2 `.minisig` 4-line file (`Ed` pure or `ED` Blake2b-512
//!     prehashed Ed25519, plus the trailing trusted-comment global
//!     signature).
//!   * Verify the artifact signature, streaming the asset from disk in
//!     64 KiB chunks for the `ED` prehash variant.
//!   * Verify the global signature over `signature_bytes || trusted_comment`.
//!   * Locate the `<asset>.minisig` sidecar in a release's asset list.
//!
//! No allocation: parser results borrow slices from the caller-owned
//! input. Crypto uses `std.crypto.sign.Ed25519` and
//! `std.crypto.hash.blake2.Blake2b512` — no new C deps.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;

const Ed25519 = std.crypto.sign.Ed25519;
const Blake2b512 = std.crypto.hash.blake2.Blake2b512;

// ---------------------------------------------------------------------------
// Wire format constants.
// ---------------------------------------------------------------------------

/// Pure Ed25519 (signs the artifact bytes directly).
pub const algo_pure: [2]u8 = .{ 'E', 'd' };
/// Blake2b-512 prehashed Ed25519 (signs Blake2b-512 of the artifact).
pub const algo_prehashed: [2]u8 = .{ 'E', 'D' };

/// 8-byte key identifier.
pub const KeyId = [8]u8;

/// Decoded length of a minisign public key: `<algo:2><key_id:8><pubkey:32>`.
const pubkey_decoded_len = 2 + 8 + 32;
/// Decoded length of a minisign signature line: `<algo:2><key_id:8><sig:64>`.
const sig_decoded_len = 2 + 8 + Ed25519.Signature.encoded_length;
/// Decoded length of the trailing global signature line (raw Ed25519 sig).
const global_sig_decoded_len = Ed25519.Signature.encoded_length;

const untrusted_prefix = "untrusted comment:";
const trusted_prefix = "trusted comment:";

// ---------------------------------------------------------------------------
// Parsed structures.
// ---------------------------------------------------------------------------

pub const PublicKey = struct {
    algo: [2]u8,
    key_id: KeyId,
    key: [Ed25519.PublicKey.encoded_length]u8,
};

pub const Signature = struct {
    /// Algorithm tag from the signature line. `Ed` or `ED`.
    algo: [2]u8,
    /// Key id from the signature line. Must equal the public key's `key_id`
    /// before any crypto runs — caller checks via `verifyKeyId`.
    key_id: KeyId,
    /// Raw 64-byte Ed25519 signature over the artifact (or its prehash).
    sig: [Ed25519.Signature.encoded_length]u8,
    /// Trusted-comment value (everything after `trusted comment: ` on
    /// line 3, no trailing CR/LF). Slice into caller-owned input.
    trusted_comment: []const u8,
    /// Raw 64-byte Ed25519 signature over `sig || trusted_comment`,
    /// signed with the same key.
    global_sig: [Ed25519.Signature.encoded_length]u8,
};

// ---------------------------------------------------------------------------
// Errors.
// ---------------------------------------------------------------------------

pub const ParseError = error{
    MinisignParseError,
    MinisignPubKeyParseError,
    MinisignUnknownAlgorithm,
};

pub const VerifyError = error{
    MinisignKeyIdMismatch,
    MinisignSignatureMismatch,
    MinisignGlobalSigMismatch,
};

// ---------------------------------------------------------------------------
// Parsing helpers.
// ---------------------------------------------------------------------------

/// Strip ASCII whitespace (space, tab, CR, LF) from both ends of `s`.
fn trimAsciiSpace(s: []const u8) []const u8 {
    var start: usize = 0;
    var end: usize = s.len;
    while (start < end) : (start += 1) {
        switch (s[start]) {
            ' ', '\t', '\r', '\n' => continue,
            else => break,
        }
    }
    while (end > start) {
        switch (s[end - 1]) {
            ' ', '\t', '\r', '\n' => end -= 1,
            else => break,
        }
    }
    return s[start..end];
}

/// Decode a base64-standard token into `out`. Returns ParseError on any
/// padding or character problem, or if the decoded length doesn't match.
fn decodeBase64Exact(token: []const u8, out: []u8) ParseError!void {
    const decoder = std.base64.standard.Decoder;
    const decoded_len = decoder.calcSizeForSlice(token) catch return ParseError.MinisignParseError;
    if (decoded_len != out.len) return ParseError.MinisignParseError;
    decoder.decode(out, token) catch return ParseError.MinisignParseError;
}

fn isKnownAlgo(algo: [2]u8) bool {
    return std.mem.eql(u8, &algo, &algo_pure) or std.mem.eql(u8, &algo, &algo_prehashed);
}

// ---------------------------------------------------------------------------
// Public-key parsing.
// ---------------------------------------------------------------------------

/// Parse a minisign public key. Accepts:
///   * a single base64 token (the second line of a `.pub` file), or
///   * the entire 2-line `.pub` body (`untrusted comment:` on line 1 and
///     the base64 token on line 2).
/// Whitespace at either end is tolerated.
pub fn parsePublicKey(input: []const u8) ParseError!PublicKey {
    const trimmed = trimAsciiSpace(input);
    if (trimmed.len == 0) return ParseError.MinisignPubKeyParseError;

    // If the user pasted the whole .pub file, skip the untrusted-comment
    // line. Single-token form has no leading "untrusted comment:".
    var token = trimmed;
    if (std.mem.startsWith(u8, token, untrusted_prefix)) {
        const nl = std.mem.indexOfScalar(u8, token, '\n') orelse
            return ParseError.MinisignPubKeyParseError;
        token = trimAsciiSpace(token[nl + 1 ..]);
    }

    // Reject anything still containing whitespace — a valid minisign
    // pubkey is a single base64 token.
    for (token) |c| {
        if (c == ' ' or c == '\t' or c == '\r' or c == '\n') {
            return ParseError.MinisignPubKeyParseError;
        }
    }

    var raw: [pubkey_decoded_len]u8 = undefined;
    decodeBase64Exact(token, &raw) catch return ParseError.MinisignPubKeyParseError;

    const algo: [2]u8 = .{ raw[0], raw[1] };
    if (!isKnownAlgo(algo)) return ParseError.MinisignUnknownAlgorithm;

    var pk: PublicKey = .{
        .algo = algo,
        .key_id = undefined,
        .key = undefined,
    };
    @memcpy(&pk.key_id, raw[2..10]);
    @memcpy(&pk.key, raw[10..]);
    return pk;
}

/// Cheap structural check: is `token` shaped like a minisign v2 public key?
/// Used by the install/download CLI parsers to disambiguate a positional
/// `<owner/repo[@tag]>` spec from an inline minisign pubkey token that
/// follows a spec.
///
/// A minisign v2 public key is always:
///   * exactly 56 base64 characters (decodes to 42 bytes: `algo:2 | key_id:8 | pubkey:32`),
///   * starts with `RW` (algo `Ed` = 0x45 0x64, pure Ed25519) or
///     `RU` (algo `ED` = 0x45 0x44, Blake2b-512 prehashed Ed25519),
///   * base64-decodes cleanly with a known algo tag.
///
/// A real GitHub `owner/repo[@tag]` cannot satisfy all three: it contains
/// `/` (not a base64 char) and almost certainly is not 56 chars long with
/// an `RW`/`RU` prefix.
pub fn looksLikePubKey(token: []const u8) bool {
    if (token.len != 56) return false;
    if (!(std.mem.startsWith(u8, token, "RW") or std.mem.startsWith(u8, token, "RU"))) return false;
    _ = parsePublicKey(token) catch return false;
    return true;
}

// ---------------------------------------------------------------------------
// `.minisig` parsing.
// ---------------------------------------------------------------------------

/// Parse a v2 minisign signature file. Returns slices that borrow from
/// `body`; the caller must keep `body` alive while using the result.
pub fn parseSignature(body: []const u8) ParseError!Signature {
    var lines: [4][]const u8 = .{ "", "", "", "" };
    var i: usize = 0;
    var rest = body;
    while (i < 4) : (i += 1) {
        if (std.mem.indexOfScalar(u8, rest, '\n')) |nl| {
            lines[i] = rest[0..nl];
            rest = rest[nl + 1 ..];
        } else {
            // Last line may legitimately have no trailing newline.
            lines[i] = rest;
            rest = rest[rest.len..];
        }
        // Strip a single trailing CR (CRLF tolerance).
        var line = lines[i];
        if (line.len > 0 and line[line.len - 1] == '\r') line = line[0 .. line.len - 1];
        lines[i] = line;
    }

    // Reject extra non-empty trailing content. A trailing newline (empty
    // string) is fine.
    if (rest.len > 0) {
        const tail = trimAsciiSpace(rest);
        if (tail.len > 0) return ParseError.MinisignParseError;
    }

    if (!std.mem.startsWith(u8, lines[0], untrusted_prefix)) {
        return ParseError.MinisignParseError;
    }
    if (!std.mem.startsWith(u8, lines[2], trusted_prefix)) {
        return ParseError.MinisignParseError;
    }

    // Line 2: signature line.
    var sig_raw: [sig_decoded_len]u8 = undefined;
    const sig_token = trimAsciiSpace(lines[1]);
    try decodeBase64Exact(sig_token, &sig_raw);
    const sig_algo: [2]u8 = .{ sig_raw[0], sig_raw[1] };
    if (!isKnownAlgo(sig_algo)) return ParseError.MinisignUnknownAlgorithm;

    // Line 3: trusted comment. Strip `trusted comment:` plus an optional
    // single space, then keep the rest verbatim — that's the exact byte
    // sequence covered by the global signature.
    var trusted = lines[2][trusted_prefix.len..];
    if (trusted.len > 0 and trusted[0] == ' ') trusted = trusted[1..];

    // Line 4: global signature.
    var gsig_raw: [global_sig_decoded_len]u8 = undefined;
    const gsig_token = trimAsciiSpace(lines[3]);
    try decodeBase64Exact(gsig_token, &gsig_raw);

    var out: Signature = .{
        .algo = sig_algo,
        .key_id = undefined,
        .sig = undefined,
        .trusted_comment = trusted,
        .global_sig = gsig_raw,
    };
    @memcpy(&out.key_id, sig_raw[2..10]);
    @memcpy(&out.sig, sig_raw[10..]);
    return out;
}

// ---------------------------------------------------------------------------
// Verification.
// ---------------------------------------------------------------------------

/// Returns an error if the signature's `key_id` doesn't match the public
/// key's `key_id`. Cheap fast-path before any crypto runs.
pub fn verifyKeyId(pk: PublicKey, sig: Signature) VerifyError!void {
    if (!std.mem.eql(u8, &pk.key_id, &sig.key_id)) {
        return VerifyError.MinisignKeyIdMismatch;
    }
}

/// Verify the artifact signature against `file`. For the `ED` (prehashed)
/// variant the file is streamed through Blake2b-512 in 64 KiB chunks; for
/// `Ed` (pure) the whole file is hashed inline (this is how minisign defines
/// pure mode — Ed25519 already SHA-512s the message internally).
pub fn verifyArtifact(io: Io, file: File, pk: PublicKey, sig: Signature) !void {
    const ed_sig = Ed25519.Signature.fromBytes(sig.sig);
    const ed_pk = Ed25519.PublicKey.fromBytes(pk.key) catch
        return VerifyError.MinisignSignatureMismatch;

    if (std.mem.eql(u8, &sig.algo, &algo_prehashed)) {
        var read_buf: [64 * 1024]u8 = undefined;
        var fr = file.reader(io, &read_buf);
        var hasher = Blake2b512.init(.{});
        var chunk: [64 * 1024]u8 = undefined;
        while (true) {
            const n = try fr.interface.readSliceShort(&chunk);
            if (n == 0) break;
            hasher.update(chunk[0..n]);
            if (n < chunk.len) break;
        }
        var digest: [Blake2b512.digest_length]u8 = undefined;
        hasher.final(&digest);
        ed_sig.verify(&digest, ed_pk) catch return VerifyError.MinisignSignatureMismatch;
        return;
    }

    if (std.mem.eql(u8, &sig.algo, &algo_pure)) {
        // Pure Ed25519 over the whole file. minisign expects `verify(file_bytes)`.
        // Use an incremental verifier so we don't need the file in RAM.
        var verifier = ed_sig.verifier(ed_pk) catch
            return VerifyError.MinisignSignatureMismatch;
        var read_buf: [64 * 1024]u8 = undefined;
        var fr = file.reader(io, &read_buf);
        var chunk: [64 * 1024]u8 = undefined;
        while (true) {
            const n = try fr.interface.readSliceShort(&chunk);
            if (n == 0) break;
            verifier.update(chunk[0..n]);
            if (n < chunk.len) break;
        }
        verifier.verify() catch return VerifyError.MinisignSignatureMismatch;
        return;
    }

    return ParseError.MinisignUnknownAlgorithm;
}

/// Verify the global signature over `signature_bytes || trusted_comment`
/// using the same public key. minisign always uses pure Ed25519 here,
/// regardless of the artifact algorithm.
pub fn verifyGlobal(pk: PublicKey, sig: Signature) !void {
    const ed_sig = Ed25519.Signature.fromBytes(sig.global_sig);
    const ed_pk = Ed25519.PublicKey.fromBytes(pk.key) catch
        return VerifyError.MinisignGlobalSigMismatch;

    var verifier = ed_sig.verifier(ed_pk) catch
        return VerifyError.MinisignGlobalSigMismatch;
    verifier.update(&sig.sig);
    verifier.update(sig.trusted_comment);
    verifier.verify() catch return VerifyError.MinisignGlobalSigMismatch;
}

// ---------------------------------------------------------------------------
// Asset-list helpers.
// ---------------------------------------------------------------------------

/// Asset shape used by `findMinisigAsset`. Mirrors `release.Asset` so the
/// caller doesn't need to import this module's release plumbing.
pub const AssetView = struct {
    name: []const u8,
    browser_download_url: []const u8,
};

/// Find the `<asset>.minisig` sidecar for `asset_name` in a release's
/// asset list. Case-insensitive on the `.minisig` suffix and the stem so
/// we tolerate releases that uppercase the OS or arch tokens.
pub fn findMinisigAsset(assets: []const AssetView, asset_name: []const u8) ?AssetView {
    for (assets) |a| {
        if (std.mem.eql(u8, a.name, asset_name)) continue;
        if (!std.ascii.endsWithIgnoreCase(a.name, ".minisig")) continue;
        const stem = a.name[0 .. a.name.len - ".minisig".len];
        if (std.ascii.eqlIgnoreCase(stem, asset_name)) return a;
    }
    return null;
}

/// Format a `KeyId` as 16 lowercase hex characters into `out`.
pub fn keyIdToHex(id: KeyId, out: *[16]u8) void {
    const hex = "0123456789abcdef";
    for (id, 0..) |b, i| {
        out[i * 2] = hex[b >> 4];
        out[i * 2 + 1] = hex[b & 0x0f];
    }
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

const testing = std.testing;

// Issue-supplied parse-only fixtures (no matching artifact published).
const issue_pubkey_b64 = "RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U";
const issue_minisig_body =
    "untrusted comment: signature from minisign secret key\n" ++
    "RUSGOq2NVecA2Wyfno8LdBVh6Sz9MTMDDFFWqcSGNMy3Va1PiE0D45oaPz7cPiH/IoVFTHmxbGgTKTBuA5b6bYU9pQiXKhNwMgA=\n" ++
    "trusted comment: timestamp:1776106316\tfile:zig-0.16.0.tar.xz\thashed\n" ++
    "o3OnTQ1gGpZRPN85+y5pIazpHgi4nr657NQq352ioM+Xzu0b6+v6dH8K0bpbUDVmcAQupnkeRhT1RAbQ/iLbAQ==\n";

test "parsePublicKey: single-token issue example" {
    const pk = try parsePublicKey(issue_pubkey_b64);
    try testing.expectEqualSlices(u8, &algo_pure, &pk.algo);
    // Key id 0x863AAD8D55E700D9 in little-endian byte order — that's how
    // minisign serializes it after the algo bytes.
    const expected_id = [_]u8{ 0x86, 0x3A, 0xAD, 0x8D, 0x55, 0xE7, 0x00, 0xD9 };
    try testing.expectEqualSlices(u8, &expected_id, &pk.key_id);
    try testing.expectEqual(@as(usize, 32), pk.key.len);
}

test "parsePublicKey: full 2-line .pub body" {
    const body = "untrusted comment: minisign public key 863AAD8D55E700D9\n" ++ issue_pubkey_b64 ++ "\n";
    const pk = try parsePublicKey(body);
    try testing.expectEqualSlices(u8, &algo_pure, &pk.algo);
}

test "parsePublicKey: rejects garbage" {
    try testing.expectError(ParseError.MinisignPubKeyParseError, parsePublicKey(""));
    try testing.expectError(ParseError.MinisignPubKeyParseError, parsePublicKey("not base64 at all !!!"));
    // Wrong decoded length.
    try testing.expectError(ParseError.MinisignPubKeyParseError, parsePublicKey("AAAA"));
}

test "looksLikePubKey: classifies real keys, rejects specs" {
    // Real minisign pubkey from jedisct1/minisign 0.12 release notes (algo `Ed`).
    try testing.expect(looksLikePubKey("RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3"));
    // Upstream test fixture pubkey (also algo `Ed`).
    try testing.expect(looksLikePubKey("RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U"));
    // Synthetic prehashed-mode pubkey (algo `ED`, encoded `RU…`).
    try testing.expect(looksLikePubKey("RUQLMFV6n8TpDjNYfaLH7BE2W4Clyu8UOV6DqM3yFzxhhqvQ9Ro/ZImu"));

    // Plausible-looking owner/repo strings — always have '/', so always rejected.
    try testing.expect(!looksLikePubKey("owner/repo"));
    try testing.expect(!looksLikePubKey("BurntSushi/ripgrep@14.1.1"));
    try testing.expect(!looksLikePubKey("very/long/owner/repo/file/name/with/many/slashes@1.0.0"));

    // Wrong length.
    try testing.expect(!looksLikePubKey("RW"));
    try testing.expect(!looksLikePubKey("RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7"));
    try testing.expect(!looksLikePubKey("RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3X"));

    // Right length but wrong prefix (RV is not a valid algo encoding).
    try testing.expect(!looksLikePubKey("RVQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3"));
    try testing.expect(!looksLikePubKey("XYQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3"));
}

test "parseSignature: issue example" {
    const sig = try parseSignature(issue_minisig_body);
    try testing.expectEqualSlices(u8, &algo_prehashed, &sig.algo);
    const expected_id = [_]u8{ 0x86, 0x3A, 0xAD, 0x8D, 0x55, 0xE7, 0x00, 0xD9 };
    try testing.expectEqualSlices(u8, &expected_id, &sig.key_id);
    try testing.expectEqualStrings(
        "timestamp:1776106316\tfile:zig-0.16.0.tar.xz\thashed",
        sig.trusted_comment,
    );

    // Key-id check binds the issue pubkey + sig.
    const pk = try parsePublicKey(issue_pubkey_b64);
    try verifyKeyId(pk, sig);
}

test "parseSignature: rejects bad prefix" {
    const bad =
        "untrusted comment: ok\n" ++
        "RUSGOq2NVecA2Wyfno8LdBVh6Sz9MTMDDFFWqcSGNMy3Va1PiE0D45oaPz7cPiH/IoVFTHmxbGgTKTBuA5b6bYU9pQiXKhNwMgA=\n" ++
        "TRUSTED COMMENT: capitalized\n" ++
        "o3OnTQ1gGpZRPN85+y5pIazpHgi4nr657NQq352ioM+Xzu0b6+v6dH8K0bpbUDVmcAQupnkeRhT1RAbQ/iLbAQ==\n";
    try testing.expectError(ParseError.MinisignParseError, parseSignature(bad));
}

test "verifyKeyId: mismatch" {
    const pk = try parsePublicKey(issue_pubkey_b64);
    var sig = try parseSignature(issue_minisig_body);
    sig.key_id[0] ^= 0xFF;
    try testing.expectError(VerifyError.MinisignKeyIdMismatch, verifyKeyId(pk, sig));
}

test "findMinisigAsset: matches sidecar" {
    const assets = [_]AssetView{
        .{ .name = "tool-1.0.0-linux.tar.xz", .browser_download_url = "u1" },
        .{ .name = "tool-1.0.0-linux.tar.xz.minisig", .browser_download_url = "u2" },
        .{ .name = "tool-1.0.0-darwin.tar.xz", .browser_download_url = "u3" },
    };
    const found = findMinisigAsset(&assets, "tool-1.0.0-linux.tar.xz") orelse
        return error.NotFound;
    try testing.expectEqualStrings("tool-1.0.0-linux.tar.xz.minisig", found.name);
    try testing.expect(findMinisigAsset(&assets, "tool-1.0.0-darwin.tar.xz") == null);
}

test "findMinisigAsset: case-insensitive" {
    const assets = [_]AssetView{
        .{ .name = "Tool.exe.MINISIG", .browser_download_url = "u" },
    };
    const found = findMinisigAsset(&assets, "Tool.exe") orelse return error.NotFound;
    try testing.expectEqualStrings("Tool.exe.MINISIG", found.name);
}

test "keyIdToHex" {
    var hex: [16]u8 = undefined;
    const id: KeyId = .{ 0x86, 0x3A, 0xAD, 0x8D, 0x55, 0xE7, 0x00, 0xD9 };
    keyIdToHex(id, &hex);
    try testing.expectEqualStrings("863aad8d55e700d9", &hex);
}

// ---------------------------------------------------------------------------
// Round-trip tests against fixtures generated by the upstream `rsign` /
// `minisign` CLI. Embedded so the tests run hermetically.
// ---------------------------------------------------------------------------

const fixture_pubkey = @embedFile("minisign/testdata/pubkey.txt");
const fixture_artifact = @embedFile("minisign/testdata/hello.txt");
const fixture_minisig = @embedFile("minisign/testdata/hello.txt.minisig");

fn realPathOf(io: Io, dir: Dir, name: []const u8, out: *[Dir.max_path_bytes]u8) ![]u8 {
    const n = try dir.realPathFile(io, name, out);
    return out[0..n];
}

test "verifyArtifact + verifyGlobal: ED-mode upstream fixture" {
    const pk = try parsePublicKey(fixture_pubkey);
    const sig = try parseSignature(fixture_minisig);
    try testing.expectEqualSlices(u8, &algo_prehashed, &sig.algo);

    try verifyKeyId(pk, sig);

    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var f = try tmp.dir.createFile(io, "hello.txt", .{});
        try f.writeStreamingAll(io, fixture_artifact);
        f.close(io);
    }
    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const path = try realPathOf(io, tmp.dir, "hello.txt", &path_buf);

    var f = try Dir.openFileAbsolute(io, path, .{});
    defer f.close(io);
    try verifyArtifact(io, f, pk, sig);
    try verifyGlobal(pk, sig);
}

test "verifyArtifact: tampered file fails" {
    const pk = try parsePublicKey(fixture_pubkey);
    const sig = try parseSignature(fixture_minisig);

    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var f = try tmp.dir.createFile(io, "tampered.bin", .{});
        var bytes: [fixture_artifact.len]u8 = fixture_artifact.*;
        bytes[0] ^= 0x01;
        try f.writeStreamingAll(io, &bytes);
        f.close(io);
    }
    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const path = try realPathOf(io, tmp.dir, "tampered.bin", &path_buf);

    var f = try Dir.openFileAbsolute(io, path, .{});
    defer f.close(io);
    try testing.expectError(VerifyError.MinisignSignatureMismatch, verifyArtifact(io, f, pk, sig));
}

test "verifyGlobal: tampered trusted comment fails" {
    const pk = try parsePublicKey(fixture_pubkey);
    var sig = try parseSignature(fixture_minisig);
    // Forge a bogus trusted comment — global sig must reject it.
    sig.trusted_comment = "tampered trusted comment";
    try testing.expectError(VerifyError.MinisignGlobalSigMismatch, verifyGlobal(pk, sig));
}

// Synthetic Ed-mode (pure) fixture, signed by Zig itself so we can prove
// the pure path round-trips without depending on an external tool that
// only emits ED today.
test "verifyArtifact + verifyGlobal: synthetic Ed (pure) round-trip" {
    var seed: [Ed25519.KeyPair.seed_length]u8 = undefined;
    @memset(&seed, 0x42);
    const kp = try Ed25519.KeyPair.generateDeterministic(seed);

    const message = "ghr pure-Ed minisign round-trip";
    const trusted_comment_str = "timestamp:1700000000\tfile:msg.bin";

    // Sign artifact (pure Ed25519 over the message bytes).
    const artifact_sig = try kp.sign(message, null);
    // Sign global (sig || trusted_comment).
    var global_input: [Ed25519.Signature.encoded_length + trusted_comment_str.len]u8 = undefined;
    @memcpy(global_input[0..Ed25519.Signature.encoded_length], &artifact_sig.toBytes());
    @memcpy(global_input[Ed25519.Signature.encoded_length..], trusted_comment_str);
    const global_signer_sig = try kp.sign(&global_input, null);

    // Build a key id (any 8 bytes are fine — verifyKeyId only checks
    // sig.key_id == pk.key_id).
    const key_id: KeyId = .{ 1, 2, 3, 4, 5, 6, 7, 8 };

    const pk: PublicKey = .{
        .algo = algo_pure,
        .key_id = key_id,
        .key = kp.public_key.toBytes(),
    };
    const sig: Signature = .{
        .algo = algo_pure,
        .key_id = key_id,
        .sig = artifact_sig.toBytes(),
        .trusted_comment = trusted_comment_str,
        .global_sig = global_signer_sig.toBytes(),
    };

    try verifyKeyId(pk, sig);
    try verifyGlobal(pk, sig);

    // Stream the message from disk and verify.
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var f = try tmp.dir.createFile(io, "pure.bin", .{});
        try f.writeStreamingAll(io, message);
        f.close(io);
    }
    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const path = try realPathOf(io, tmp.dir, "pure.bin", &path_buf);

    var f = try Dir.openFileAbsolute(io, path, .{});
    defer f.close(io);
    try verifyArtifact(io, f, pk, sig);
}
