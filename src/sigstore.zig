//! Native Sigstore Bundle (v0.3) verification, Phase 2 of issue #50.
//!
//! Today this module covers the foundation pieces:
//!   * Embedded production Fulcio root + intermediate (Sigstore public good
//!     instance) and the Rekor public key, pulled from
//!     https://github.com/sigstore/root-signing.
//!   * Asset-list helper to find the `<asset>.sigstore.json` sidecar.
//!   * JSON parser for the fields of the bundle we actually consume.
//!   * X.509 chain walk against the embedded trust roots, using
//!     `std.crypto.Certificate` and the `Bundle.verify` pattern from
//!     `std/crypto/tls/Client.zig`. The verification clock is the Rekor
//!     `integratedTime` from the bundle, since cosign's leaf certs only
//!     live for ~10 minutes.
//!
//! Subsequent commits will add: artifact signature verification, Rekor SET
//! verification (anchors `integratedTime`), and identity reporting.

const std = @import("std");
const Io = std.Io;
const Certificate = std.crypto.Certificate;

/// Embedded Sigstore production trust roots. Updating these requires a new
/// ghr release; see `docs/sigstore.md` (TODO) for rotation notes.
pub const fulcio_root_pem = @embedFile("sigstore/trust/fulcio_v1.crt.pem");
pub const fulcio_intermediate_pem = @embedFile("sigstore/trust/fulcio_intermediate_v1.crt.pem");
pub const rekor_pubkey_pem = @embedFile("sigstore/trust/rekor.pub");

// ---------------------------------------------------------------------------
// Asset-list helpers.
// ---------------------------------------------------------------------------

/// Asset shape used by `findBundleAsset`. Mirrors `install.Asset` so the
/// caller doesn't need to import this module.
pub const AssetView = struct {
    name: []const u8,
    browser_download_url: []const u8,
};

/// Find the sigstore bundle asset for `asset_name` in a release's asset
/// list. Prefers `<asset>.sigstore.json` over the legacy `.sigstore` form.
/// Returns null when neither is present.
pub fn findBundleAsset(assets: []const AssetView, asset_name: []const u8) ?AssetView {
    // Pass 1: exact `<asset>.sigstore.json`.
    for (assets) |a| {
        if (std.mem.eql(u8, a.name, asset_name)) continue;
        if (!std.ascii.endsWithIgnoreCase(a.name, ".sigstore.json")) continue;
        const stem = a.name[0 .. a.name.len - ".sigstore.json".len];
        if (std.ascii.eqlIgnoreCase(stem, asset_name)) return a;
    }
    // Pass 2: `<asset>.sigstore`.
    for (assets) |a| {
        if (std.mem.eql(u8, a.name, asset_name)) continue;
        if (std.ascii.endsWithIgnoreCase(a.name, ".sigstore.json")) continue;
        if (!std.ascii.endsWithIgnoreCase(a.name, ".sigstore")) continue;
        const stem = a.name[0 .. a.name.len - ".sigstore".len];
        if (std.ascii.eqlIgnoreCase(stem, asset_name)) return a;
    }
    return null;
}

// ---------------------------------------------------------------------------
// Bundle JSON parsing.
// ---------------------------------------------------------------------------

/// Subset of the Sigstore Bundle v0.3 JSON shape we consume. Anything we
/// don't need is ignored. The schema is documented at
/// https://github.com/sigstore/protobuf-specs.
pub const RawBundle = struct {
    mediaType: []const u8 = "",
    verificationMaterial: VerificationMaterial,
    messageSignature: MessageSignature,

    pub const VerificationMaterial = struct {
        certificate: ?CertEntry = null,
        x509CertificateChain: ?CertChain = null,
        tlogEntries: []const TlogEntry,
    };

    pub const CertEntry = struct {
        rawBytes: []const u8,
    };

    pub const CertChain = struct {
        certificates: []const CertEntry,
    };

    pub const TlogEntry = struct {
        logIndex: []const u8,
        logId: LogId,
        kindVersion: KindVersion,
        integratedTime: []const u8,
        canonicalizedBody: []const u8 = "",
        inclusionPromise: ?InclusionPromise = null,
        inclusionProof: ?InclusionProof = null,
    };

    pub const LogId = struct {
        keyId: []const u8,
    };

    pub const KindVersion = struct {
        kind: []const u8,
        version: []const u8,
    };

    pub const InclusionPromise = struct {
        signedEntryTimestamp: []const u8,
    };

    pub const InclusionProof = struct {
        logIndex: []const u8 = "",
        rootHash: []const u8 = "",
        treeSize: []const u8 = "",
        hashes: []const []const u8 = &.{},
        checkpoint: ?Checkpoint = null,
    };

    pub const Checkpoint = struct {
        envelope: []const u8 = "",
    };

    pub const MessageSignature = struct {
        messageDigest: MessageDigest,
        signature: []const u8,
    };

    pub const MessageDigest = struct {
        algorithm: []const u8,
        digest: []const u8,
    };
};

pub const BundleParseError = std.json.ParseFromValueError ||
    std.json.Scanner.NextError ||
    std.mem.Allocator.Error ||
    error{
        UnsupportedBundleMediaType,
        BundleHasNoCertificate,
        BundleHasNoTlogEntry,
        UnsupportedDigestAlgorithm,
        UnsupportedRekorEntryKind,
    };

/// Parsed bundle, owned by the caller. Call `deinit` to release.
pub const Bundle = struct {
    parsed: std.json.Parsed(RawBundle),
    leaf_der: []const u8, // DER-decoded leaf cert (sub-slice of `arena_bytes`)
    artifact_digest: [32]u8,
    artifact_signature: []const u8, // raw (DER ECDSA) signature, owned via arena
    rekor_integrated_time: i64,
    rekor_log_index: u64,
    rekor_log_key_id: []const u8, // raw bytes (binary keyId), owned via arena
    rekor_canonical_body: []const u8, // base64-decoded canonical Rekor entry body
    rekor_set: ?[]const u8, // base64-decoded SET bytes, when inclusionPromise is present
    arena: *std.heap.ArenaAllocator,

    pub fn deinit(self: *Bundle) void {
        const child = self.arena.child_allocator;
        self.parsed.deinit();
        self.arena.deinit();
        child.destroy(self.arena);
    }
};

/// Parse a Sigstore Bundle JSON blob and decode the base64-encoded fields we
/// need. The returned `Bundle` owns its decoded buffers via an arena.
pub fn parseBundle(allocator: std.mem.Allocator, json_bytes: []const u8) BundleParseError!Bundle {
    var parsed = try std.json.parseFromSlice(RawBundle, allocator, json_bytes, .{
        .ignore_unknown_fields = true,
    });
    errdefer parsed.deinit();

    const raw = parsed.value;

    if (!std.mem.startsWith(u8, raw.mediaType, "application/vnd.dev.sigstore.bundle"))
        return error.UnsupportedBundleMediaType;

    if (raw.verificationMaterial.tlogEntries.len == 0)
        return error.BundleHasNoTlogEntry;

    const tlog = raw.verificationMaterial.tlogEntries[0];
    if (!std.mem.eql(u8, tlog.kindVersion.kind, "hashedrekord"))
        return error.UnsupportedRekorEntryKind;

    if (!std.ascii.eqlIgnoreCase(raw.messageSignature.messageDigest.algorithm, "SHA2_256"))
        return error.UnsupportedDigestAlgorithm;

    // Locate the leaf cert: prefer singular `certificate`, fall back to the
    // first entry of `x509CertificateChain`.
    const leaf_b64 = blk: {
        if (raw.verificationMaterial.certificate) |c| break :blk c.rawBytes;
        if (raw.verificationMaterial.x509CertificateChain) |chain| {
            if (chain.certificates.len == 0) return error.BundleHasNoCertificate;
            break :blk chain.certificates[0].rawBytes;
        }
        return error.BundleHasNoCertificate;
    };

    const arena = try allocator.create(std.heap.ArenaAllocator);
    arena.* = std.heap.ArenaAllocator.init(allocator);
    errdefer {
        arena.deinit();
        allocator.destroy(arena);
    }
    const aalloc = arena.allocator();

    const leaf_der = try base64Decode(aalloc, leaf_b64);
    const sig_bytes = try base64Decode(aalloc, raw.messageSignature.signature);
    const digest_bytes = try base64Decode(aalloc, raw.messageSignature.messageDigest.digest);
    if (digest_bytes.len != 32) return error.UnsupportedDigestAlgorithm;
    var digest_arr: [32]u8 = undefined;
    @memcpy(&digest_arr, digest_bytes);

    const canonical_body = try base64Decode(aalloc, tlog.canonicalizedBody);
    const log_key_id = try base64Decode(aalloc, tlog.logId.keyId);

    const set_bytes: ?[]const u8 = if (tlog.inclusionPromise) |ip|
        try base64Decode(aalloc, ip.signedEntryTimestamp)
    else
        null;

    const integrated_time = std.fmt.parseInt(i64, tlog.integratedTime, 10) catch
        return error.BundleHasNoTlogEntry;
    const log_index = std.fmt.parseInt(u64, tlog.logIndex, 10) catch
        return error.BundleHasNoTlogEntry;

    return .{
        .parsed = parsed,
        .leaf_der = leaf_der,
        .artifact_digest = digest_arr,
        .artifact_signature = sig_bytes,
        .rekor_integrated_time = integrated_time,
        .rekor_log_index = log_index,
        .rekor_log_key_id = log_key_id,
        .rekor_canonical_body = canonical_body,
        .rekor_set = set_bytes,
        .arena = arena,
    };
}

fn base64Decode(allocator: std.mem.Allocator, b64: []const u8) ![]u8 {
    const decoder = std.base64.standard.Decoder;
    const decoded_len = try decoder.calcSizeForSlice(b64);
    const buf = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(buf);
    try decoder.decode(buf, b64);
    return buf;
}

// ---------------------------------------------------------------------------
// X.509 chain verification against the embedded Fulcio trust bundle.
// ---------------------------------------------------------------------------

pub const ChainError = error{
    LeafCertParseFailed,
    TrustBundleBuildFailed,
    IssuerNotInTrustBundle,
} || Certificate.Parsed.VerifyError || Certificate.ParseError || std.mem.Allocator.Error;

/// Build a `Certificate.Bundle` containing the embedded Fulcio root +
/// intermediate. Caller owns the returned bundle and must call
/// `bundle.deinit(allocator)`.
///
/// `now_sec` is used by `parseCert` to skip already-expired certs. The
/// embedded roots are valid until 2031, so passing the current wall-clock
/// time is fine. Certificate-validity-window enforcement during chain
/// verification uses a separate `verify_at` parameter.
pub fn buildTrustBundle(allocator: std.mem.Allocator, now_sec: i64) ChainError!Certificate.Bundle {
    var bundle: Certificate.Bundle = .empty;
    errdefer bundle.deinit(allocator);
    try addPemCertsToBundle(&bundle, allocator, fulcio_root_pem, now_sec);
    try addPemCertsToBundle(&bundle, allocator, fulcio_intermediate_pem, now_sec);
    return bundle;
}

/// Add every PEM-encoded `CERTIFICATE` block in `pem_bytes` to `cb`.
/// This mirrors `Certificate.Bundle.addCertsFromFile` but works with an
/// in-memory `@embedFile`'d slice (no `Io.File.Reader` involved).
fn addPemCertsToBundle(
    cb: *Certificate.Bundle,
    gpa: std.mem.Allocator,
    pem_bytes: []const u8,
    now_sec: i64,
) ChainError!void {
    const begin_marker = "-----BEGIN CERTIFICATE-----";
    const end_marker = "-----END CERTIFICATE-----";

    // Each base64-decoded cert is at most (3/4) * encoded_len.
    const decoded_upper = pem_bytes.len; // generous, certs decode shorter than encoded
    try cb.bytes.ensureUnusedCapacity(gpa, @intCast(decoded_upper));

    var start_index: usize = 0;
    while (std.mem.indexOfPos(u8, pem_bytes, start_index, begin_marker)) |begin_off| {
        const cert_start = begin_off + begin_marker.len;
        const cert_end = std.mem.indexOfPos(u8, pem_bytes, cert_start, end_marker) orelse
            return error.TrustBundleBuildFailed;
        start_index = cert_end + end_marker.len;
        const encoded_cert = std.mem.trim(u8, pem_bytes[cert_start..cert_end], " \t\r\n");
        const decoded_start: u32 = @intCast(cb.bytes.items.len);
        const dest = cb.bytes.allocatedSlice()[decoded_start..];
        const decoder = std.base64.standard.Decoder;
        // PEM allows embedded whitespace in the base64 region; strip it.
        const stripped = try stripWhitespace(gpa, encoded_cert);
        defer gpa.free(stripped);
        const decoded_len = decoder.calcSizeForSlice(stripped) catch
            return error.TrustBundleBuildFailed;
        if (dest.len < decoded_len) {
            try cb.bytes.ensureUnusedCapacity(gpa, decoded_len);
        }
        decoder.decode(cb.bytes.allocatedSlice()[decoded_start..], stripped) catch
            return error.TrustBundleBuildFailed;
        cb.bytes.items.len += decoded_len;
        try cb.parseCert(gpa, decoded_start, now_sec);
    }
}

fn stripWhitespace(gpa: std.mem.Allocator, s: []const u8) ![]u8 {
    var out = try gpa.alloc(u8, s.len);
    errdefer gpa.free(out);
    var n: usize = 0;
    for (s) |c| {
        if (c == ' ' or c == '\t' or c == '\r' or c == '\n') continue;
        out[n] = c;
        n += 1;
    }
    return out[0..n];
}

/// Verify that `leaf_der` chains to the embedded Fulcio root via the
/// embedded intermediate, using `verify_at` (Rekor `integratedTime`) as the
/// validity-window reference.
///
/// This walks pairwise: leaf → trust-bundle issuer (intermediate) →
/// trust-bundle issuer (root). The walk terminates when an issuer cannot
/// be found in the trust bundle; for sigstore we expect to terminate at the
/// self-signed root. Returns `error.IssuerNotInTrustBundle` if the path
/// breaks before reaching the root.
pub fn verifyCertChain(
    bundle: Certificate.Bundle,
    leaf_der: []const u8,
    verify_at: i64,
) ChainError!Certificate.Parsed {
    var subject_cert: Certificate = .{ .buffer = leaf_der, .index = 0 };
    var subject = subject_cert.parse() catch return error.LeafCertParseFailed;

    // Cap the chain depth to a small number to avoid pathological input.
    var depth: u8 = 0;
    while (depth < 8) : (depth += 1) {
        const issuer_name = subject.issuer();
        const issuer_idx = bundle.find(issuer_name) orelse return error.IssuerNotInTrustBundle;
        const issuer_cert: Certificate = .{ .buffer = bundle.bytes.items, .index = issuer_idx };
        const issuer = issuer_cert.parse() catch return error.TrustBundleBuildFailed;
        try subject.verify(issuer, verify_at);
        // If the issuer is self-signed, we've reached a trusted root and can stop.
        if (std.mem.eql(u8, issuer.issuer(), issuer.subject())) {
            // Also enforce that the root is valid at `verify_at`.
            if (verify_at < issuer.validity.not_before) return error.CertificateNotYetValid;
            if (verify_at > issuer.validity.not_after) return error.CertificateExpired;
            return subject_cert.parse() catch return error.LeafCertParseFailed;
        }
        subject = issuer;
        subject_cert = issuer_cert;
    }
    return error.IssuerNotInTrustBundle;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const test_bundle_json = @embedFile("sigstore/testdata/cosign-linux-arm64.sigstore.json");

test "findBundleAsset prefers .sigstore.json sidecar" {
    const assets = [_]AssetView{
        .{ .name = "cosign-linux-arm64", .browser_download_url = "" },
        .{ .name = "cosign-linux-arm64.sig", .browser_download_url = "" },
        .{ .name = "cosign-linux-arm64.sigstore.json", .browser_download_url = "" },
    };
    const got = findBundleAsset(&assets, "cosign-linux-arm64") orelse return error.TestUnexpectedNull;
    try std.testing.expectEqualStrings("cosign-linux-arm64.sigstore.json", got.name);
}

test "findBundleAsset returns null when absent" {
    const assets = [_]AssetView{
        .{ .name = "cosign-linux-arm64", .browser_download_url = "" },
    };
    try std.testing.expect(findBundleAsset(&assets, "cosign-linux-arm64") == null);
}

test "parseBundle on captured cosign fixture" {
    const allocator = std.testing.allocator;
    var bundle = try parseBundle(allocator, test_bundle_json);
    defer bundle.deinit();

    // Leaf is parseable as DER X.509.
    var leaf_cert: Certificate = .{ .buffer = bundle.leaf_der, .index = 0 };
    const leaf = try leaf_cert.parse();
    try std.testing.expect(leaf.subject_alt_name_slice.end > leaf.subject_alt_name_slice.start);

    // Sanity check on the artifact digest and signature.
    try std.testing.expect(bundle.artifact_signature.len > 64);
    // The digest should be the well-known cosign-linux-arm64 SHA256.
    const expected_digest = [_]u8{
        0xbe, 0xda, 0xc9, 0x2e, 0x8c, 0x37, 0x29, 0x86,
        0x4e, 0x13, 0xd4, 0xa1, 0x70, 0x48, 0x00, 0x7c,
        0xfa, 0xfa, 0x79, 0xd5, 0xde, 0xca, 0x99, 0x3a,
        0x43, 0xa9, 0x0f, 0xfe, 0x01, 0x8e, 0xf2, 0xb8,
    };
    try std.testing.expectEqualSlices(u8, &expected_digest, &bundle.artifact_digest);

    // Rekor scalars are parsed.
    try std.testing.expect(bundle.rekor_integrated_time > 1700000000);
    try std.testing.expect(bundle.rekor_log_index > 0);
    try std.testing.expect(bundle.rekor_set != null);
}

test "buildTrustBundle parses embedded Fulcio roots" {
    const allocator = std.testing.allocator;
    // Use a fixed 'now' inside the validity window (2026-05) so the certs
    // are not skipped as expired.
    const now: i64 = 1746878400; // 2025-05-10
    var trust = try buildTrustBundle(allocator, now);
    defer trust.deinit(allocator);
    try std.testing.expect(trust.bytes.items.len > 0);
}

test "verifyCertChain walks cosign fixture to embedded Fulcio root" {
    const allocator = std.testing.allocator;
    var bundle = try parseBundle(allocator, test_bundle_json);
    defer bundle.deinit();

    var trust = try buildTrustBundle(allocator, bundle.rekor_integrated_time);
    defer trust.deinit(allocator);

    const leaf_parsed = try verifyCertChain(trust, bundle.leaf_der, bundle.rekor_integrated_time);
    try std.testing.expect(leaf_parsed.subject_alt_name_slice.end > leaf_parsed.subject_alt_name_slice.start);
}
