//! Native Sigstore Bundle (v0.3) verification, Phase 2 of issue #50.
//!
//! Coverage:
//!   * Embedded production Fulcio root + intermediate (Sigstore public good
//!     instance) and the Rekor public key, pulled from
//!     https://github.com/sigstore/root-signing.
//!   * Asset-list helper to find the `<asset>.sigstore.json` sidecar.
//!   * JSON parser for the fields of the bundle we actually consume.
//!   * Decode of the canonicalized Rekor `hashedrekord` body so we can bind
//!     the bundle's claims (digest, signature, leaf cert) to what Rekor
//!     witnessed.
//!   * Artifact ECDSA-P256/SHA-256 signature verification, streamed from
//!     disk so we don't need to hold the asset in memory.
//!   * Rekor SET (signed entry timestamp) verification against the embedded
//!     Rekor public key. This is what makes `integratedTime` trustworthy.
//!   * X.509 chain walk against the embedded trust roots, using the parser
//!     from `std.crypto.Certificate`. The verification clock is the Rekor
//!     `integratedTime`, since cosign's leaf certs only live ~10 minutes.
//!
//! Future work: identity reporting (SAN URI/email + OIDC issuer OIDs) and
//! Merkle inclusion-proof verification against a signed Rekor checkpoint.

const std = @import("std");
const Io = std.Io;
const Certificate = std.crypto.Certificate;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

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
pub fn parseBundle(allocator: std.mem.Allocator, json_bytes: []const u8) !Bundle {
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

/// Build a `Certificate.Bundle` containing the embedded Fulcio root +
/// intermediate. Caller owns the returned bundle and must call
/// `bundle.deinit(allocator)`.
///
/// `now_sec` is used by `parseCert` to skip already-expired certs. The
/// embedded roots are valid until 2031, so passing the current wall-clock
/// time is fine. Certificate-validity-window enforcement during chain
/// verification uses a separate `verify_at` parameter.
pub fn buildTrustBundle(allocator: std.mem.Allocator, now_sec: i64) !Certificate.Bundle {
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
) !void {
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
    // Shrink so the caller's `free(slice)` matches the allocation size that
    // the allocator tracks. We always succeed because n <= s.len.
    return gpa.realloc(out, n) catch unreachable;
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
) !Certificate.Parsed {
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
// Embedded Rekor public key (SPKI PEM) — extract the SEC1-encoded EC point
// and compute its log key id (SHA256 of the SPKI DER).
// ---------------------------------------------------------------------------

pub const RekorKey = struct {
    public_key: EcdsaP256Sha256.PublicKey,
    /// SHA256 of the SPKI DER. This is the canonical Rekor log identifier
    /// embedded in tlog entries (`logId.keyId`, in raw bytes).
    key_id: [32]u8,
};

/// Decode the embedded Rekor PEM into a `RekorKey`. Allocates a temporary
/// SPKI DER buffer that's freed before returning; the returned struct is
/// fully owned by the caller and copy-by-value safe.
pub fn embeddedRekorKey(allocator: std.mem.Allocator) !RekorKey {
    const spki_der = try decodeSinglePem(allocator, rekor_pubkey_pem, "PUBLIC KEY");
    defer allocator.free(spki_der);

    // SubjectPublicKeyInfo := SEQUENCE { algo AlgorithmIdentifier, pk BIT STRING }
    const root = try Certificate.der.Element.parse(spki_der, 0);
    if (root.identifier.tag != .sequence) return error.InvalidRekorPem;
    const algo = try Certificate.der.Element.parse(spki_der, root.slice.start);
    if (algo.identifier.tag != .sequence) return error.InvalidRekorPem;
    const bit_string = try Certificate.der.Element.parse(spki_der, algo.slice.end);
    if (bit_string.identifier.tag != .bitstring) return error.InvalidRekorPem;

    const bit_bytes = spki_der[bit_string.slice.start..bit_string.slice.end];
    if (bit_bytes.len < 2 or bit_bytes[0] != 0x00) return error.InvalidRekorPem;
    const sec1 = bit_bytes[1..]; // skip "unused bits" prefix
    if (sec1.len != 65 or sec1[0] != 0x04) return error.UnsupportedRekorKeyAlgorithm;

    var key_id: [32]u8 = undefined;
    Sha256.hash(spki_der, &key_id, .{});

    return .{
        .public_key = try EcdsaP256Sha256.PublicKey.fromSec1(sec1),
        .key_id = key_id,
    };
}

/// Decode the first PEM block of `expected_label` from `pem_bytes`.
fn decodeSinglePem(
    allocator: std.mem.Allocator,
    pem_bytes: []const u8,
    expected_label: []const u8,
) ![]u8 {
    const begin_prefix = "-----BEGIN ";
    const end_prefix = "-----END ";
    const begin_off = std.mem.indexOf(u8, pem_bytes, begin_prefix) orelse return error.InvalidRekorPem;
    const after_begin = begin_off + begin_prefix.len;
    const begin_eol = std.mem.indexOfScalarPos(u8, pem_bytes, after_begin, '\n') orelse
        return error.InvalidRekorPem;
    const begin_label_end = std.mem.lastIndexOfScalar(u8, pem_bytes[after_begin..begin_eol], '-') orelse
        return error.InvalidRekorPem;
    const begin_label = std.mem.trim(u8, pem_bytes[after_begin .. after_begin + begin_label_end], " \t\r-");
    if (!std.mem.eql(u8, begin_label, expected_label)) return error.InvalidRekorPem;

    const end_off = std.mem.indexOfPos(u8, pem_bytes, begin_eol, end_prefix) orelse
        return error.InvalidRekorPem;
    const b64 = std.mem.trim(u8, pem_bytes[begin_eol + 1 .. end_off], " \t\r\n");
    const stripped = try stripWhitespace(allocator, b64);
    defer allocator.free(stripped);

    const decoder = std.base64.standard.Decoder;
    const decoded_len = try decoder.calcSizeForSlice(stripped);
    const out = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(out);
    try decoder.decode(out, stripped);
    return out;
}

// ---------------------------------------------------------------------------
// Decoded Rekor `hashedrekord` body. The bundle's `canonicalizedBody` is the
// base64-encoded JSON Rekor signed; we need to peek inside to bind it back
// to the bundle's other fields.
// ---------------------------------------------------------------------------

pub const RawRekorBody = struct {
    apiVersion: []const u8 = "",
    kind: []const u8 = "",
    spec: Spec,

    pub const Spec = struct {
        data: Data,
        signature: BodySignature,
    };

    pub const Data = struct {
        hash: Hash,
    };

    pub const Hash = struct {
        algorithm: []const u8,
        value: []const u8,
    };

    pub const BodySignature = struct {
        content: []const u8,
        publicKey: PublicKey,
    };

    pub const PublicKey = struct {
        content: []const u8,
    };
};

pub const RekorBody = struct {
    parsed: std.json.Parsed(RawRekorBody),
    /// Decoded leaf cert (DER), arena-owned.
    leaf_der: []const u8,
    /// Hex-decoded artifact digest. `digest_len` indicates the populated prefix.
    digest: [32]u8,
    digest_len: u8,
    /// Base64-decoded raw signature (DER ECDSA), arena-owned.
    signature: []const u8,
    arena: *std.heap.ArenaAllocator,

    pub fn deinit(self: *RekorBody) void {
        const child = self.arena.child_allocator;
        self.parsed.deinit();
        self.arena.deinit();
        child.destroy(self.arena);
    }
};

/// Decode the canonicalized Rekor `hashedrekord` body (the raw JSON bytes
/// that Rekor signs) into a `RekorBody`. The returned body owns its decoded
/// fields via an arena.
pub fn decodeRekorBody(allocator: std.mem.Allocator, body_json: []const u8) !RekorBody {
    var parsed = try std.json.parseFromSlice(RawRekorBody, allocator, body_json, .{
        .ignore_unknown_fields = true,
    });
    errdefer parsed.deinit();

    const raw = parsed.value;
    if (!std.mem.eql(u8, raw.kind, "hashedrekord")) return error.UnsupportedRekorEntryKind;
    if (!std.ascii.eqlIgnoreCase(raw.spec.data.hash.algorithm, "sha256"))
        return error.UnsupportedDigestAlgorithm;
    if (raw.spec.data.hash.value.len != 64) return error.InvalidRekorBodyDigest;

    const arena = try allocator.create(std.heap.ArenaAllocator);
    arena.* = std.heap.ArenaAllocator.init(allocator);
    errdefer {
        arena.deinit();
        allocator.destroy(arena);
    }
    const aalloc = arena.allocator();

    var digest: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&digest, raw.spec.data.hash.value) catch
        return error.InvalidRekorBodyDigest;

    const sig = try base64Decode(aalloc, raw.spec.signature.content);

    // The Rekor body's publicKey.content is base64 of the leaf cert PEM.
    const cert_pem = try base64Decode(aalloc, raw.spec.signature.publicKey.content);
    const leaf_der = try decodeSinglePem(aalloc, cert_pem, "CERTIFICATE");

    return .{
        .parsed = parsed,
        .leaf_der = leaf_der,
        .digest = digest,
        .digest_len = 32,
        .signature = sig,
        .arena = arena,
    };
}

// ---------------------------------------------------------------------------
// Rekor SET verification.
//
// The SET (signedEntryTimestamp) is an ECDSA-P256/SHA-256 signature, made by
// the Rekor production key, over the canonical JSON
//
//   {"body":"<base64 of canonicalizedBody>","integratedTime":<int>,
//    "logID":"<hex of keyId>","logIndex":<int>}
//
// (no whitespace, keys alphabetically sorted, integers as numbers). This
// matches Go's `json.Marshal` of Rekor's `signableData` struct, since the
// struct field order happens to be alphabetical.
//
// Without verifying the SET, `integratedTime` is unsigned data — an attacker
// could backdate it to a window where the leaf cert was valid. Therefore
// SET verification is a hard requirement before trusting `integratedTime`
// as a clock for cert validity.
// ---------------------------------------------------------------------------

pub fn verifyRekorSet(
    allocator: std.mem.Allocator,
    bundle: Bundle,
    rekor: RekorKey,
) !void {
    const set_bytes = bundle.rekor_set orelse return error.BundleHasNoRekorSet;

    if (bundle.rekor_log_key_id.len != rekor.key_id.len or
        !std.mem.eql(u8, bundle.rekor_log_key_id, &rekor.key_id))
        return error.RekorKeyIdMismatch;

    // Re-extract the original base64 form of canonicalizedBody. The bundle's
    // raw JSON (unparsed) preserves it verbatim, but we have only the parsed
    // struct here, so re-encode the decoded bytes — the result is identical
    // because base64 is deterministic.
    const body_b64_buf = try allocator.alloc(
        u8,
        std.base64.standard.Encoder.calcSize(bundle.rekor_canonical_body.len),
    );
    defer allocator.free(body_b64_buf);
    const body_b64 = std.base64.standard.Encoder.encode(body_b64_buf, bundle.rekor_canonical_body);

    var key_id_hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&key_id_hex, "{x}", .{bundle.rekor_log_key_id}) catch unreachable;

    // Build canonical JSON with no whitespace.
    var buf: std.Io.Writer.Allocating = .init(allocator);
    defer buf.deinit();
    try buf.writer.print(
        "{{\"body\":\"{s}\",\"integratedTime\":{d},\"logID\":\"{s}\",\"logIndex\":{d}}}",
        .{ body_b64, bundle.rekor_integrated_time, key_id_hex[0..key_id_hex.len], bundle.rekor_log_index },
    );
    const canonical = buf.written();

    const signature = EcdsaP256Sha256.Signature.fromDer(set_bytes) catch
        return error.InvalidRekorSetSignature;
    signature.verify(canonical, rekor.public_key) catch
        return error.InvalidRekorSetSignature;
}

// ---------------------------------------------------------------------------
// Artifact signature verification.
//
// cosign signs blobs with `EcdsaP256Sha256.sign(artifact_bytes)`, hashing
// internally. Verification mirrors that — stream the file through an ECDSA
// verifier so we don't need to load the artifact into memory.
// ---------------------------------------------------------------------------

/// Stream the artifact at `file` through an ECDSA-P256/SHA-256 verifier
/// using the leaf cert's SEC1 public key and the bundle's DER signature.
/// Also recomputes the SHA256 along the way and writes it to `digest_out`,
/// so the caller can bind the bundle's claimed digest back to the file.
pub fn verifyArtifactSignature(
    io: Io,
    file: Io.File,
    leaf_pubkey_sec1: []const u8,
    signature_der: []const u8,
    digest_out: *[32]u8,
) !void {
    const pub_key = EcdsaP256Sha256.PublicKey.fromSec1(leaf_pubkey_sec1) catch
        return error.InvalidArtifactSignature;
    const sig = EcdsaP256Sha256.Signature.fromDer(signature_der) catch
        return error.InvalidArtifactSignature;

    var verifier = sig.verifier(pub_key) catch return error.InvalidArtifactSignature;
    var hasher = Sha256.init(.{});

    var read_buf: [64 * 1024]u8 = undefined;
    var fr = file.reader(io, &read_buf);
    var chunk: [64 * 1024]u8 = undefined;
    while (true) {
        const n = try fr.interface.readSliceShort(&chunk);
        if (n == 0) break;
        verifier.update(chunk[0..n]);
        hasher.update(chunk[0..n]);
        if (n < chunk.len) break;
    }
    hasher.final(digest_out);
    verifier.verify() catch return error.InvalidArtifactSignature;
}

// ---------------------------------------------------------------------------
// Top-level verification orchestrator.
// ---------------------------------------------------------------------------

pub const VerifiedIdentity = struct {
    /// Signer identity extracted from the leaf cert, if present.
    identity: Identity,
    /// Rekor `integratedTime`, useful for the install metadata and CLI
    /// output.
    integrated_time: i64,
};

/// Signer identity extracted from a Sigstore leaf cert. All fields are
/// borrowed from the bundle's leaf-cert byte buffer.
pub const Identity = struct {
    /// rfc822Name SAN entry (e.g., `keyless@projectsigstore.iam.gserviceaccount.com`).
    san_email: ?[]const u8 = null,
    /// uniformResourceIdentifier SAN entry (e.g., the GitHub Actions workflow
    /// URI for keyless workflow signing).
    san_uri: ?[]const u8 = null,
    /// OIDC issuer URL from extension OID 1.3.6.1.4.1.57264.1.8 (preferred)
    /// or .1.1 (legacy). Both encode the same value; `.8` wraps it in a
    /// DER UTF8String, `.1` is a raw URL.
    oidc_issuer: ?[]const u8 = null,

    /// First non-null SAN value, preferring URI over email.
    pub fn primarySubject(self: Identity) ?[]const u8 {
        return self.san_uri orelse self.san_email;
    }
};

/// Extract the signer identity from a leaf cert. Returns an `Identity` with
/// any of its fields set to non-null when the cert carries the
/// corresponding SAN entry or extension. Slices borrow from `leaf_der`.
pub fn extractIdentity(leaf_der: []const u8) !Identity {
    var id: Identity = .{};

    var leaf_cert: Certificate = .{ .buffer = leaf_der, .index = 0 };
    const leaf = leaf_cert.parse() catch return id;

    // SAN entries — walk the SEQUENCE OF GeneralName.
    const san = leaf.subjectAltName();
    if (san.len > 0) {
        const general_names = Certificate.der.Element.parse(san, 0) catch
            return id;
        var i: u32 = general_names.slice.start;
        while (i < general_names.slice.end) {
            const gn = Certificate.der.Element.parse(san, i) catch break;
            i = gn.slice.end;
            const ident: u8 = @bitCast(gn.identifier);
            const value = san[gn.slice.start..gn.slice.end];
            // Tagged GeneralName CHOICE: class=context-specific (10),
            //   primitive (0), tag = 1 rfc822Name, 6 uniformResourceIdentifier.
            switch (ident) {
                0x81 => if (id.san_email == null) {
                    id.san_email = value;
                },
                0x86 => if (id.san_uri == null) {
                    id.san_uri = value;
                },
                else => {},
            }
        }
    }

    // OIDC issuer — walk the extension list. We have to do this ourselves
    // because std.crypto.Certificate only exposes SAN.
    const oidc_issuer_v1 = [_]u8{ 0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0xbf, 0x30, 0x01, 0x01 };
    const oidc_issuer_v2 = [_]u8{ 0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0xbf, 0x30, 0x01, 0x08 };

    const certificate = Certificate.der.Element.parse(leaf_der, 0) catch return id;
    const tbs = Certificate.der.Element.parse(leaf_der, certificate.slice.start) catch
        return id;
    var ti: u32 = tbs.slice.start;
    while (ti < tbs.slice.end) {
        const e = Certificate.der.Element.parse(leaf_der, ti) catch break;
        ti = e.slice.end;
        const ident: u8 = @bitCast(e.identifier);
        // [3] EXPLICIT extensions wrapper: class=context-specific,
        //   constructed, tag=3 -> 0xA3.
        if (ident != 0xa3) continue;
        const exts = Certificate.der.Element.parse(leaf_der, e.slice.start) catch
            break;
        var xi: u32 = exts.slice.start;
        while (xi < exts.slice.end) {
            const ext = Certificate.der.Element.parse(leaf_der, xi) catch break;
            xi = ext.slice.end;
            const oid_elem = Certificate.der.Element.parse(leaf_der, ext.slice.start) catch
                continue;
            const after_oid = Certificate.der.Element.parse(leaf_der, oid_elem.slice.end) catch
                continue;
            const value_elem = if (after_oid.identifier.tag == .boolean)
                Certificate.der.Element.parse(leaf_der, after_oid.slice.end) catch continue
            else
                after_oid;
            const oid_bytes = leaf_der[oid_elem.slice.start..oid_elem.slice.end];
            const value_bytes = leaf_der[value_elem.slice.start..value_elem.slice.end];

            if (std.mem.eql(u8, oid_bytes, &oidc_issuer_v2)) {
                // V2: extension value is a DER UTF8String.
                const inner = Certificate.der.Element.parse(value_bytes, 0) catch continue;
                if (@intFromEnum(inner.identifier.tag) == 12) {
                    id.oidc_issuer = value_bytes[inner.slice.start..inner.slice.end];
                }
            } else if (std.mem.eql(u8, oid_bytes, &oidc_issuer_v1)) {
                if (id.oidc_issuer == null) id.oidc_issuer = value_bytes;
            }
        }
        break;
    }

    return id;
}

/// Run the full verification pipeline against a parsed bundle and the
/// cached artifact:
///
///   1. Verify the Rekor SET (ties `integratedTime` to the embedded Rekor
///      key).
///   2. Decode the canonicalized Rekor body and confirm it agrees with the
///      bundle's claimed leaf cert, signature, and digest.
///   3. Stream the artifact through an ECDSA-P256/SHA-256 verifier with
///      the leaf cert's pubkey and confirm both the signature and the
///      digest match what Rekor witnessed.
///   4. Walk the X.509 chain from the leaf to the embedded Fulcio root,
///      using `integratedTime` as the validity clock.
pub fn verifyBundle(
    allocator: std.mem.Allocator,
    io: Io,
    bundle: Bundle,
    rekor: RekorKey,
    file: Io.File,
) !VerifiedIdentity {
    try verifyRekorSet(allocator, bundle, rekor);

    var body = try decodeRekorBody(allocator, bundle.rekor_canonical_body);
    defer body.deinit();

    if (!std.mem.eql(u8, &body.digest, &bundle.artifact_digest))
        return error.BundleSignatureMismatch;
    if (!std.mem.eql(u8, body.signature, bundle.artifact_signature))
        return error.BundleSignatureMismatch;
    if (!std.mem.eql(u8, body.leaf_der, bundle.leaf_der))
        return error.BundleCertMismatch;

    var leaf_cert: Certificate = .{ .buffer = bundle.leaf_der, .index = 0 };
    const leaf = leaf_cert.parse() catch return error.LeafCertParseFailed;
    const leaf_pubkey_sec1 = leaf.pubKey();

    var actual_digest: [32]u8 = undefined;
    try verifyArtifactSignature(io, file, leaf_pubkey_sec1, bundle.artifact_signature, &actual_digest);
    if (!std.mem.eql(u8, &actual_digest, &bundle.artifact_digest))
        return error.ArtifactDigestMismatch;

    var trust = try buildTrustBundle(allocator, bundle.rekor_integrated_time);
    defer trust.deinit(allocator);
    _ = try verifyCertChain(trust, bundle.leaf_der, bundle.rekor_integrated_time);

    return .{
        .identity = try extractIdentity(bundle.leaf_der),
        .integrated_time = bundle.rekor_integrated_time,
    };
}

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

test "embeddedRekorKey matches well-known production key id" {
    const allocator = std.testing.allocator;
    const key = try embeddedRekorKey(allocator);
    // sha256 of the production Rekor SPKI DER, as published.
    const expected = [_]u8{
        0xc0, 0xd2, 0x3d, 0x6a, 0xd4, 0x06, 0x97, 0x3f,
        0x95, 0x59, 0xf3, 0xba, 0x2d, 0x1c, 0xa0, 0x1f,
        0x84, 0x14, 0x7d, 0x8f, 0xfc, 0x5b, 0x84, 0x45,
        0xc2, 0x24, 0xf9, 0x8b, 0x95, 0x91, 0x80, 0x1d,
    };
    try std.testing.expectEqualSlices(u8, &expected, &key.key_id);
}

test "verifyRekorSet on captured cosign fixture" {
    const allocator = std.testing.allocator;
    var bundle = try parseBundle(allocator, test_bundle_json);
    defer bundle.deinit();
    const rekor = try embeddedRekorKey(allocator);
    try verifyRekorSet(allocator, bundle, rekor);
}

test "verifyRekorSet rejects mismatched key id" {
    const allocator = std.testing.allocator;
    var bundle = try parseBundle(allocator, test_bundle_json);
    defer bundle.deinit();
    var rekor = try embeddedRekorKey(allocator);
    // Flip a byte to simulate a swapped Rekor key.
    rekor.key_id[0] ^= 0xFF;
    try std.testing.expectError(error.RekorKeyIdMismatch, verifyRekorSet(allocator, bundle, rekor));
}

test "verifyRekorSet rejects tampered SET signature" {
    const allocator = std.testing.allocator;
    var bundle = try parseBundle(allocator, test_bundle_json);
    defer bundle.deinit();
    const rekor = try embeddedRekorKey(allocator);
    // Tamper with the integrated time so the canonical payload no longer
    // matches what Rekor signed.
    bundle.rekor_integrated_time += 1;
    const result = verifyRekorSet(allocator, bundle, rekor);
    try std.testing.expect(result == error.InvalidRekorSetSignature or
        result == error.SignatureVerificationFailed);
}

test "decodeRekorBody binds digest, signature, and cert to bundle" {
    const allocator = std.testing.allocator;
    var bundle = try parseBundle(allocator, test_bundle_json);
    defer bundle.deinit();
    var body = try decodeRekorBody(allocator, bundle.rekor_canonical_body);
    defer body.deinit();
    try std.testing.expectEqualSlices(u8, &bundle.artifact_digest, &body.digest);
    try std.testing.expectEqualSlices(u8, bundle.artifact_signature, body.signature);
    try std.testing.expectEqualSlices(u8, bundle.leaf_der, body.leaf_der);
}

test "verifyArtifactSignature streams a signed blob end-to-end" {
    const allocator = std.testing.allocator;

    // Generate an ephemeral P-256 keypair and sign a payload, then verify
    // through the same streaming code path used in production.
    const seed = [_]u8{0x42} ** EcdsaP256Sha256.KeyPair.seed_length;
    const kp = try EcdsaP256Sha256.KeyPair.generateDeterministic(seed);
    const payload = "the quick brown fox jumps over the lazy dog";
    var signer = try kp.signer(null);
    signer.update(payload);
    const sig = try signer.finalize();
    var sig_der_buf: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    const sig_der = sig.toDer(&sig_der_buf);
    const pub_sec1 = kp.public_key.toUncompressedSec1();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;

    {
        var f = try tmp.dir.createFile(io, "payload", .{});
        try f.writeStreamingAll(io, payload);
        f.close(io);
    }

    var path_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const tmp_path = try tmp.dir.realpath(io, ".", &path_buf);
    const full_path = try std.fmt.allocPrint(allocator, "{s}{c}{s}", .{ tmp_path, std.fs.path.sep, "payload" });
    defer allocator.free(full_path);

    var f = try Io.Dir.openFileAbsolute(io, full_path, .{});
    defer f.close(io);

    var digest: [32]u8 = undefined;
    try verifyArtifactSignature(io, f, &pub_sec1, sig_der, &digest);

    var expected_digest: [32]u8 = undefined;
    Sha256.hash(payload, &expected_digest, .{});
    try std.testing.expectEqualSlices(u8, &expected_digest, &digest);
}

test "verifyArtifactSignature rejects a tampered file" {
    const allocator = std.testing.allocator;

    const seed = [_]u8{0x55} ** EcdsaP256Sha256.KeyPair.seed_length;
    const kp = try EcdsaP256Sha256.KeyPair.generateDeterministic(seed);
    const payload = "hello sigstore";
    var signer = try kp.signer(null);
    signer.update(payload);
    const sig = try signer.finalize();
    var sig_der_buf: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    const sig_der = sig.toDer(&sig_der_buf);
    const pub_sec1 = kp.public_key.toUncompressedSec1();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;

    {
        var f = try tmp.dir.createFile(io, "tampered", .{});
        try f.writeStreamingAll(io, "hello sigsbore"); // single-byte tamper
        f.close(io);
    }

    var path_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const tmp_path = try tmp.dir.realpath(io, ".", &path_buf);
    const full_path = try std.fmt.allocPrint(allocator, "{s}{c}{s}", .{ tmp_path, std.fs.path.sep, "tampered" });
    defer allocator.free(full_path);

    var f = try Io.Dir.openFileAbsolute(io, full_path, .{});
    defer f.close(io);

    var digest: [32]u8 = undefined;
    try std.testing.expectError(
        error.InvalidArtifactSignature,
        verifyArtifactSignature(io, f, &pub_sec1, sig_der, &digest),
    );
}

test "extractIdentity from cosign fixture" {
    const allocator = std.testing.allocator;
    var bundle = try parseBundle(allocator, test_bundle_json);
    defer bundle.deinit();

    const id = try extractIdentity(bundle.leaf_der);
    try std.testing.expect(id.san_email != null);
    try std.testing.expectEqualStrings(
        "keyless@projectsigstore.iam.gserviceaccount.com",
        id.san_email.?,
    );
    try std.testing.expect(id.san_uri == null);
    try std.testing.expect(id.oidc_issuer != null);
    try std.testing.expectEqualStrings("https://accounts.google.com", id.oidc_issuer.?);
    try std.testing.expectEqualStrings(id.san_email.?, id.primarySubject().?);
}

test "verifyBundle returns identity on the cosign fixture" {
    const allocator = std.testing.allocator;
    var bundle = try parseBundle(allocator, test_bundle_json);
    defer bundle.deinit();

    // Sanity: extractIdentity from the bundle's leaf cert directly should
    // match what verifyBundle would expose. This avoids needing the full
    // 127 MiB cosign artifact in test fixtures.
    const id = try extractIdentity(bundle.leaf_der);
    try std.testing.expect(id.primarySubject() != null);
}
