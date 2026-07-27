//! Detached RFC 3161 TimeStampToken verification.
//!
//! A timestamp token is CMS SignedData whose encapsulated content is a
//! TSTInfo structure. `verifyDetached` verifies the CMS signer and TSA chain,
//! binds the TSTInfo message imprint to caller-provided bytes, and returns the
//! signed generation time.

const std = @import("std");

const Certificate = std.crypto.Certificate;
const der = @import("der.zig");

pub const ChainClock = enum {
    wall_clock,
    gen_time,
};

const HashAlgorithm = enum {
    sha256,
    sha384,
    sha512,
};

const SignatureAlgorithm = enum {
    rsa_pkcs1_v15_sha256,
    rsa_pkcs1_v15_sha384,
    rsa_pkcs1_v15_sha512,
    rsa_pkcs1_v15_implicit_hash,
    ecdsa_sha256,
    ecdsa_sha384,
};

const oid = struct {
    const signed_data = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02 };
    const content_type = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03 };
    const message_digest = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04 };
    const tst_info = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x04 };

    const sha256 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };
    const sha384 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02 };
    const sha512 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 };

    const rsa_encryption = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
    const sha256_with_rsa = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B };
    const sha384_with_rsa = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C };
    const sha512_with_rsa = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D };
    const ecdsa_with_sha256 = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };
    const ecdsa_with_sha384 = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03 };

    const extended_key_usage = [_]u8{ 0x55, 0x1D, 0x25 };
    const timestamping = [_]u8{ 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08 };
};

const SignerInfo = struct {
    digest_alg: HashAlgorithm,
    signature_alg: SignatureAlgorithm,
    signed_attrs_raw: []const u8,
    signature: []const u8,
    message_digest: []const u8,
    sid_raw: []const u8,
};

const TimestampToken = struct {
    tst_info_der: []const u8,
    certificates_raw: []const u8,
    signer: SignerInfo,
};

const TstInfo = struct {
    imprint_alg: HashAlgorithm,
    imprint: []const u8,
    gen_time: i64,
};

pub const VerifyError = error{
    InvalidContentInfo,
    InvalidTimestampResponse,
    TimestampStatusNotGranted,
    MissingTimestampToken,
    UnsupportedContentType,
    InvalidSignedData,
    UnsupportedSignedDataVersion,
    UnsupportedEncapContentType,
    InvalidTstInfo,
    UnsupportedTstInfoVersion,
    UnsupportedDigestAlgorithm,
    UnsupportedSignatureAlgorithm,
    InvalidSignerInfo,
    MissingSignedAttrs,
    MissingMessageDigestAttr,
    MissingContentTypeAttr,
    SignedAttrsTooLarge,
    InvalidCertificateChoice,
    InvalidDerElement,
    InvalidSignature,
    SignerCertNotFound,
    SignerCertMismatch,
    InvalidTsaExtendedKeyUsage,
    UnsupportedSignerKeyType,
    TimestampContentDigestMismatch,
    TstInfoMessageImprintMismatch,
    InvalidGeneralizedTime,
    OutOfMemory,
} || der.ParseError || der.CertificateParseError || Certificate.Parsed.VerifyError;

/// Verify an RFC 3161 token over detached `signed_message` bytes.
///
/// `.wall_clock` preserves Authenticode's TSA-chain policy. `.gen_time`
/// validates the TSA chain at the signed TSTInfo generation time, which is
/// required for timestamp-backed Sigstore bundles.
pub fn verifyDetached(
    allocator: std.mem.Allocator,
    token_der: []const u8,
    signed_message: []const u8,
    tsa_trust: Certificate.Bundle,
    now: i64,
    chain_clock: ChainClock,
) VerifyError!i64 {
    return verifyDetachedInternal(
        allocator,
        token_der,
        signed_message,
        tsa_trust,
        null,
        now,
        chain_clock,
    );
}

/// Verify an RFC 3161 token whose CMS signer must exactly match
/// `pinned_signer_der`.
pub fn verifyDetachedWithPinnedSigner(
    allocator: std.mem.Allocator,
    token_der: []const u8,
    signed_message: []const u8,
    tsa_trust: Certificate.Bundle,
    pinned_signer_der: []const u8,
    now: i64,
    chain_clock: ChainClock,
) VerifyError!i64 {
    return verifyDetachedInternal(
        allocator,
        token_der,
        signed_message,
        tsa_trust,
        pinned_signer_der,
        now,
        chain_clock,
    );
}

fn verifyDetachedInternal(
    allocator: std.mem.Allocator,
    token_der: []const u8,
    signed_message: []const u8,
    tsa_trust: Certificate.Bundle,
    pinned_signer_der: ?[]const u8,
    now: i64,
    chain_clock: ChainClock,
) VerifyError!i64 {
    const content_info = try unwrapTimestampToken(token_der);
    const token = try parseTimestampToken(content_info);
    const tst = try parseTstInfo(token.tst_info_der);

    try verifyDigest(
        token.signer.digest_alg,
        token.tst_info_der,
        token.signer.message_digest,
        error.TimestampContentDigestMismatch,
    );
    const tsa_leaf = (try findSignerCertDer(token, tsa_trust)) orelse
        return error.SignerCertNotFound;
    if (pinned_signer_der) |pinned| {
        if (!std.mem.eql(u8, tsa_leaf, pinned))
            return error.SignerCertMismatch;
    }
    try verifySignerSignature(allocator, token, tsa_leaf);
    try verifyDigest(
        tst.imprint_alg,
        signed_message,
        tst.imprint,
        error.TstInfoMessageImprintMismatch,
    );

    try verifyTimestampingExtendedKeyUsage(tsa_leaf);
    const verify_at = selectChainTime(chain_clock, now, tst.gen_time);
    try verifyChain(allocator, tsa_leaf, token.certificates_raw, tsa_trust, verify_at);

    return tst.gen_time;
}

fn unwrapTimestampToken(bytes: []const u8) VerifyError![]const u8 {
    const outer = try der.parseElement(bytes, 0);
    if (outer.identifier.tag != .sequence) return error.InvalidTimestampResponse;

    const first = try der.parseElement(bytes, outer.slice.start);
    if (first.identifier.tag == .object_identifier) {
        if (!std.mem.eql(u8, bytes[first.slice.start..first.slice.end], &oid.signed_data))
            return error.UnsupportedContentType;
        return bytes[0..outer.slice.end];
    }
    if (first.identifier.tag != .sequence) return error.InvalidTimestampResponse;

    const status = try der.parseElement(bytes, first.slice.start);
    if (status.identifier.tag != .integer or status.slice.end - status.slice.start != 1)
        return error.InvalidTimestampResponse;
    const status_value = bytes[status.slice.start];
    if (status_value != 0 and status_value != 1)
        return error.TimestampStatusNotGranted;

    if (first.slice.end >= outer.slice.end) return error.MissingTimestampToken;
    const token = try der.parseElement(bytes, first.slice.end);
    if (token.identifier.tag != .sequence or token.slice.end > outer.slice.end)
        return error.InvalidTimestampResponse;
    return bytes[first.slice.end..token.slice.end];
}

fn parseTimestampToken(bytes: []const u8) VerifyError!TimestampToken {
    const ci = try der.parseElement(bytes, 0);
    if (ci.identifier.tag != .sequence) return error.InvalidContentInfo;

    const ci_oid = try der.parseElement(bytes, ci.slice.start);
    if (ci_oid.identifier.tag != .object_identifier) return error.InvalidContentInfo;
    if (!std.mem.eql(u8, bytes[ci_oid.slice.start..ci_oid.slice.end], &oid.signed_data))
        return error.UnsupportedContentType;

    const ci_content = try der.parseElement(bytes, ci_oid.slice.end);
    if (!isContextSpecificTag(ci_content.identifier, 0) or ci_content.slice.end > ci.slice.end)
        return error.InvalidContentInfo;

    const signed_data = try der.parseElement(bytes, ci_content.slice.start);
    if (signed_data.identifier.tag != .sequence) return error.InvalidSignedData;
    var i: u32 = signed_data.slice.start;

    const version = try der.parseElement(bytes, i);
    if (version.identifier.tag != .integer) return error.InvalidSignedData;
    if (version.slice.end - version.slice.start != 1)
        return error.UnsupportedSignedDataVersion;
    const version_value = bytes[version.slice.start];
    if (version_value != 1 and version_value != 3)
        return error.UnsupportedSignedDataVersion;
    i = version.slice.end;

    const digest_algorithms = try der.parseElement(bytes, i);
    i = digest_algorithms.slice.end;

    const encap = try der.parseElement(bytes, i);
    if (encap.identifier.tag != .sequence) return error.InvalidSignedData;
    i = encap.slice.end;

    const encap_type = try der.parseElement(bytes, encap.slice.start);
    if (encap_type.identifier.tag != .object_identifier) return error.InvalidSignedData;
    if (!std.mem.eql(u8, bytes[encap_type.slice.start..encap_type.slice.end], &oid.tst_info))
        return error.UnsupportedEncapContentType;

    const content_wrapper = try der.parseElement(bytes, encap_type.slice.end);
    if (!isContextSpecificTag(content_wrapper.identifier, 0))
        return error.InvalidTstInfo;
    const content = try der.parseElement(bytes, content_wrapper.slice.start);
    if (content.identifier.tag != .octetstring and content.identifier.tag != .sequence)
        return error.InvalidTstInfo;
    const tst_info_der = if (content.identifier.tag == .octetstring)
        bytes[content.slice.start..content.slice.end]
    else
        bytes[content_wrapper.slice.start..content.slice.end];

    var certificates_raw: []const u8 = &.{};
    var next_index = i;
    if (next_index < signed_data.slice.end) {
        const next = try der.parseElement(bytes, next_index);
        if (isContextSpecificTag(next.identifier, 0)) {
            certificates_raw = bytes[next.slice.start..next.slice.end];
            next_index = next.slice.end;
        }
    }
    if (next_index < signed_data.slice.end) {
        const next = try der.parseElement(bytes, next_index);
        if (isContextSpecificTag(next.identifier, 1))
            next_index = next.slice.end;
    }

    const signer_infos = try der.parseElement(bytes, next_index);
    if (signer_infos.identifier.tag != .sequence_of and
        signer_infos.identifier.tag != .sequence)
        return error.InvalidSignedData;
    const first_signer = try der.parseElement(bytes, signer_infos.slice.start);
    if (first_signer.identifier.tag != .sequence) return error.InvalidSignerInfo;

    return .{
        .tst_info_der = tst_info_der,
        .certificates_raw = certificates_raw,
        .signer = try parseSignerInfo(bytes, first_signer),
    };
}

fn parseSignerInfo(bytes: []const u8, signer: der.Element) VerifyError!SignerInfo {
    var i: u32 = signer.slice.start;

    const version = try der.parseElement(bytes, i);
    if (version.identifier.tag != .integer or version.slice.end - version.slice.start != 1)
        return error.InvalidSignerInfo;
    i = version.slice.end;

    const sid = try der.parseElement(bytes, i);
    const sid_start = i;
    const sid_raw = bytes[sid_start..sid.slice.end];
    i = sid.slice.end;

    const digest_algorithm = try der.parseElement(bytes, i);
    if (digest_algorithm.identifier.tag != .sequence) return error.InvalidSignerInfo;
    const digest_oid = try der.parseElement(bytes, digest_algorithm.slice.start);
    if (digest_oid.identifier.tag != .object_identifier) return error.InvalidSignerInfo;
    const digest_alg = try hashAlgorithm(bytes[digest_oid.slice.start..digest_oid.slice.end]);
    i = digest_algorithm.slice.end;

    const signed_attrs = try der.parseElement(bytes, i);
    if (!isContextSpecificTag(signed_attrs.identifier, 0)) return error.MissingSignedAttrs;
    const signed_attrs_raw = bytes[i..signed_attrs.slice.end];
    if (signed_attrs_raw.len > std.math.maxInt(u32)) return error.SignedAttrsTooLarge;

    var message_digest: []const u8 = &.{};
    var found_content_type = false;
    var attr_index: u32 = signed_attrs.slice.start;
    while (attr_index < signed_attrs.slice.end) {
        const attr = try der.parseElement(bytes, attr_index);
        if (attr.identifier.tag != .sequence) return error.InvalidSignerInfo;
        attr_index = attr.slice.end;

        const attr_oid = try der.parseElement(bytes, attr.slice.start);
        if (attr_oid.identifier.tag != .object_identifier) return error.InvalidSignerInfo;
        const values = try der.parseElement(bytes, attr_oid.slice.end);
        const first_value = try der.parseElement(bytes, values.slice.start);
        const attr_oid_bytes = bytes[attr_oid.slice.start..attr_oid.slice.end];

        if (std.mem.eql(u8, attr_oid_bytes, &oid.message_digest)) {
            if (first_value.identifier.tag != .octetstring) return error.InvalidSignerInfo;
            message_digest = bytes[first_value.slice.start..first_value.slice.end];
        } else if (std.mem.eql(u8, attr_oid_bytes, &oid.content_type)) {
            if (first_value.identifier.tag != .object_identifier or
                !std.mem.eql(
                    u8,
                    bytes[first_value.slice.start..first_value.slice.end],
                    &oid.tst_info,
                ))
                return error.InvalidSignerInfo;
            found_content_type = true;
        }
    }
    if (message_digest.len == 0) return error.MissingMessageDigestAttr;
    if (!found_content_type) return error.MissingContentTypeAttr;
    i = signed_attrs.slice.end;

    const signature_algorithm = try der.parseElement(bytes, i);
    if (signature_algorithm.identifier.tag != .sequence) return error.InvalidSignerInfo;
    const signature_oid = try der.parseElement(bytes, signature_algorithm.slice.start);
    if (signature_oid.identifier.tag != .object_identifier) return error.InvalidSignerInfo;
    const signature_alg = try signatureAlgorithm(bytes[signature_oid.slice.start..signature_oid.slice.end]);
    i = signature_algorithm.slice.end;

    const signature = try der.parseElement(bytes, i);
    if (signature.identifier.tag != .octetstring) return error.InvalidSignerInfo;

    return .{
        .digest_alg = digest_alg,
        .signature_alg = signature_alg,
        .signed_attrs_raw = signed_attrs_raw,
        .signature = bytes[signature.slice.start..signature.slice.end],
        .message_digest = message_digest,
        .sid_raw = sid_raw,
    };
}

fn parseTstInfo(bytes: []const u8) VerifyError!TstInfo {
    const root = try der.parseElement(bytes, 0);
    if (root.identifier.tag != .sequence) return error.InvalidTstInfo;
    var i: u32 = root.slice.start;

    const version = try der.parseElement(bytes, i);
    if (version.identifier.tag != .integer) return error.InvalidTstInfo;
    if (version.slice.end - version.slice.start != 1)
        return error.UnsupportedTstInfoVersion;
    if (bytes[version.slice.start] != 1) return error.UnsupportedTstInfoVersion;
    i = version.slice.end;

    const policy = try der.parseElement(bytes, i);
    if (policy.identifier.tag != .object_identifier) return error.InvalidTstInfo;
    i = policy.slice.end;

    const message_imprint = try der.parseElement(bytes, i);
    if (message_imprint.identifier.tag != .sequence) return error.InvalidTstInfo;
    const algorithm = try der.parseElement(bytes, message_imprint.slice.start);
    if (algorithm.identifier.tag != .sequence) return error.InvalidTstInfo;
    const algorithm_oid = try der.parseElement(bytes, algorithm.slice.start);
    if (algorithm_oid.identifier.tag != .object_identifier) return error.InvalidTstInfo;
    const imprint_alg = hashAlgorithm(bytes[algorithm_oid.slice.start..algorithm_oid.slice.end]) catch
        return error.InvalidTstInfo;
    const imprint = try der.parseElement(bytes, algorithm.slice.end);
    if (imprint.identifier.tag != .octetstring) return error.InvalidTstInfo;
    i = message_imprint.slice.end;

    const serial_number = try der.parseElement(bytes, i);
    if (serial_number.identifier.tag != .integer) return error.InvalidTstInfo;
    i = serial_number.slice.end;

    const gen_time = try der.parseElement(bytes, i);
    if (gen_time.identifier.tag != .generalized_time) return error.InvalidTstInfo;

    return .{
        .imprint_alg = imprint_alg,
        .imprint = bytes[imprint.slice.start..imprint.slice.end],
        .gen_time = parseGeneralizedTime(bytes[gen_time.slice.start..gen_time.slice.end]) catch
            return error.InvalidGeneralizedTime,
    };
}

fn verifySignerSignature(
    allocator: std.mem.Allocator,
    token: TimestampToken,
    signer_cert_der: []const u8,
) VerifyError!void {
    const message = try allocator.dupe(u8, token.signer.signed_attrs_raw);
    defer allocator.free(message);
    if (message.len == 0 or message[0] != 0xA0) return error.InvalidSignerInfo;
    message[0] = 0x31;

    const cert: Certificate = .{ .buffer = signer_cert_der, .index = 0 };
    const parsed = try der.parseCertificate(cert);

    switch (token.signer.signature_alg) {
        .rsa_pkcs1_v15_sha256 => try verifyRsa(
            message,
            token.signer.signature,
            parsed.pubKey(),
            std.crypto.hash.sha2.Sha256,
        ),
        .rsa_pkcs1_v15_implicit_hash => switch (token.signer.digest_alg) {
            .sha256 => try verifyRsa(message, token.signer.signature, parsed.pubKey(), std.crypto.hash.sha2.Sha256),
            .sha384 => try verifyRsa(message, token.signer.signature, parsed.pubKey(), std.crypto.hash.sha2.Sha384),
            .sha512 => try verifyRsa(message, token.signer.signature, parsed.pubKey(), std.crypto.hash.sha2.Sha512),
        },
        .rsa_pkcs1_v15_sha384 => try verifyRsa(
            message,
            token.signer.signature,
            parsed.pubKey(),
            std.crypto.hash.sha2.Sha384,
        ),
        .rsa_pkcs1_v15_sha512 => try verifyRsa(
            message,
            token.signer.signature,
            parsed.pubKey(),
            std.crypto.hash.sha2.Sha512,
        ),
        .ecdsa_sha256 => try verifyEcdsa(
            std.crypto.sign.ecdsa.EcdsaP256Sha256,
            message,
            token.signer.signature,
            parsed.pubKey(),
        ),
        .ecdsa_sha384 => try verifyEcdsa(
            std.crypto.sign.ecdsa.Ecdsa(
                std.crypto.ecc.P384,
                std.crypto.hash.sha2.Sha384,
            ),
            message,
            token.signer.signature,
            parsed.pubKey(),
        ),
    }
}

fn verifyRsa(
    message: []const u8,
    signature: []const u8,
    public_key_der: []const u8,
    comptime Hash: type,
) VerifyError!void {
    const components = Certificate.rsa.PublicKey.parseDer(public_key_der) catch
        return error.InvalidSignature;
    if (components.exponent.len > components.modulus.len or
        signature.len != components.modulus.len)
        return error.InvalidSignature;

    switch (components.modulus.len) {
        inline 128, 256, 384, 512 => |modulus_len| {
            const public_key = Certificate.rsa.PublicKey.fromBytes(
                components.exponent,
                components.modulus,
            ) catch return error.InvalidSignature;
            Certificate.rsa.PKCS1v1_5Signature.verify(
                modulus_len,
                signature[0..modulus_len].*,
                message,
                public_key,
                Hash,
            ) catch return error.InvalidSignature;
        },
        else => return error.UnsupportedSignerKeyType,
    }
}

fn verifyEcdsa(
    comptime Ec: type,
    message: []const u8,
    signature_der: []const u8,
    public_key_sec1: []const u8,
) VerifyError!void {
    const signature = Ec.Signature.fromDer(signature_der) catch
        return error.InvalidSignature;
    const public_key = Ec.PublicKey.fromSec1(public_key_sec1) catch
        return error.InvalidSignature;
    signature.verify(message, public_key) catch return error.InvalidSignature;
}

fn findSignerCertDer(
    token: TimestampToken,
    tsa_trust: Certificate.Bundle,
) VerifyError!?[]const u8 {
    if (token.signer.sid_raw.len == 0) return null;
    const sid = token.signer.sid_raw;
    const sid_sequence = try der.parseElement(sid, 0);
    if (sid_sequence.identifier.tag != .sequence) return error.InvalidSignerInfo;
    const sid_issuer = try der.parseElement(sid, sid_sequence.slice.start);
    if (sid_issuer.identifier.tag != .sequence) return error.InvalidSignerInfo;
    const sid_serial = try der.parseElement(sid, sid_issuer.slice.end);
    if (sid_serial.identifier.tag != .integer) return error.InvalidSignerInfo;

    var iterator: CertificateSetIterator = .{ .bytes = token.certificates_raw };
    while (try iterator.next()) |cert_der| {
        if (try certificateMatchesSid(cert_der, 0, sid, sid_issuer, sid_serial))
            return cert_der;
    }

    var trust_iterator = tsa_trust.map.iterator();
    while (trust_iterator.next()) |entry| {
        const cert_index = entry.value_ptr.*;
        const cert_outer = try der.parseElement(tsa_trust.bytes.items, cert_index);
        if (try certificateMatchesSid(
            tsa_trust.bytes.items,
            cert_index,
            sid,
            sid_issuer,
            sid_serial,
        )) return tsa_trust.bytes.items[cert_index..cert_outer.slice.end];
    }
    return null;
}

fn certificateMatchesSid(
    cert_buffer: []const u8,
    cert_index: u32,
    sid: []const u8,
    sid_issuer: der.Element,
    sid_serial: der.Element,
) VerifyError!bool {
    const cert: Certificate = .{ .buffer = cert_buffer, .index = cert_index };
    const parsed = der.parseCertificate(cert) catch return false;
    if (!std.mem.eql(
        u8,
        cert_buffer[parsed.issuer_slice.start..parsed.issuer_slice.end],
        sid[sid_issuer.slice.start..sid_issuer.slice.end],
    )) return false;

    const outer = try der.parseElement(cert_buffer, cert_index);
    const tbs = try der.parseElement(cert_buffer, outer.slice.start);
    var serial_index: u32 = tbs.slice.start;
    const maybe_version = try der.parseElement(cert_buffer, serial_index);
    if (isContextSpecificTag(maybe_version.identifier, 0))
        serial_index = maybe_version.slice.end;
    const serial = try der.parseElement(cert_buffer, serial_index);
    if (serial.identifier.tag != .integer) return error.InvalidSignerInfo;
    return std.mem.eql(
        u8,
        cert_buffer[serial.slice.start..serial.slice.end],
        sid[sid_serial.slice.start..sid_serial.slice.end],
    );
}

fn verifyTimestampingExtendedKeyUsage(cert_der: []const u8) VerifyError!void {
    const certificate = try der.parseElement(cert_der, 0);
    if (certificate.identifier.tag != .sequence)
        return error.InvalidTsaExtendedKeyUsage;
    const tbs = try der.parseElement(cert_der, certificate.slice.start);
    if (tbs.identifier.tag != .sequence)
        return error.InvalidTsaExtendedKeyUsage;

    var i: u32 = tbs.slice.start;
    while (i < tbs.slice.end) {
        const field = try der.parseElement(cert_der, i);
        i = field.slice.end;
        if (!isContextSpecificTag(field.identifier, 3)) continue;

        const extensions = try der.parseElement(cert_der, field.slice.start);
        if (extensions.identifier.tag != .sequence)
            return error.InvalidTsaExtendedKeyUsage;
        var extension_index: u32 = extensions.slice.start;
        while (extension_index < extensions.slice.end) {
            const extension = try der.parseElement(cert_der, extension_index);
            extension_index = extension.slice.end;
            if (extension.identifier.tag != .sequence)
                return error.InvalidTsaExtendedKeyUsage;

            const extension_oid = try der.parseElement(cert_der, extension.slice.start);
            if (extension_oid.identifier.tag != .object_identifier)
                return error.InvalidTsaExtendedKeyUsage;
            if (!std.mem.eql(
                u8,
                cert_der[extension_oid.slice.start..extension_oid.slice.end],
                &oid.extended_key_usage,
            )) continue;

            var value = try der.parseElement(cert_der, extension_oid.slice.end);
            var critical = false;
            if (value.identifier.tag == .boolean) {
                critical = value.slice.end - value.slice.start == 1 and
                    cert_der[value.slice.start] != 0;
                value = try der.parseElement(cert_der, value.slice.end);
            }
            if (!critical or value.identifier.tag != .octetstring)
                return error.InvalidTsaExtendedKeyUsage;

            const encoded_eku = cert_der[value.slice.start..value.slice.end];
            const eku = try der.parseElement(encoded_eku, 0);
            if (eku.identifier.tag != .sequence or eku.slice.end != encoded_eku.len)
                return error.InvalidTsaExtendedKeyUsage;

            var purpose_index: u32 = eku.slice.start;
            var purpose_count: usize = 0;
            var timestamping_count: usize = 0;
            while (purpose_index < eku.slice.end) {
                const purpose = try der.parseElement(encoded_eku, purpose_index);
                purpose_index = purpose.slice.end;
                if (purpose.identifier.tag != .object_identifier)
                    return error.InvalidTsaExtendedKeyUsage;
                purpose_count += 1;
                if (std.mem.eql(
                    u8,
                    encoded_eku[purpose.slice.start..purpose.slice.end],
                    &oid.timestamping,
                )) timestamping_count += 1;
            }
            if (purpose_count != 1 or timestamping_count != 1)
                return error.InvalidTsaExtendedKeyUsage;
            return;
        }
        return error.InvalidTsaExtendedKeyUsage;
    }
    return error.InvalidTsaExtendedKeyUsage;
}

const CertificateSetIterator = struct {
    bytes: []const u8,
    index: u32 = 0,

    fn next(self: *CertificateSetIterator) VerifyError!?[]const u8 {
        while (self.index < self.bytes.len) {
            const element = try der.parseElement(self.bytes, self.index);
            const start = self.index;
            self.index = element.slice.end;

            if (element.identifier.tag == .sequence and
                element.identifier.class == .universal)
                return self.bytes[start..element.slice.end];
            if (element.identifier.class == .context_specific and
                @intFromEnum(element.identifier.tag) <= 3)
                continue;
            return error.InvalidCertificateChoice;
        }
        return null;
    }
};

fn verifyChain(
    allocator: std.mem.Allocator,
    leaf_der: []const u8,
    intermediates_raw: []const u8,
    trust: Certificate.Bundle,
    verify_at: i64,
) VerifyError!void {
    var pool = std.array_list.Managed(Certificate).init(allocator);
    defer pool.deinit();

    var iterator: CertificateSetIterator = .{ .bytes = intermediates_raw };
    while (try iterator.next()) |cert_der|
        try pool.append(.{ .buffer = cert_der, .index = 0 });

    var subject_cert: Certificate = .{ .buffer = leaf_der, .index = 0 };
    var subject = der.parseCertificate(subject_cert) catch return error.InvalidSignature;

    var depth: u8 = 0;
    while (depth < 8) : (depth += 1) {
        const issuer_name = subject.issuer();
        if (trust.find(issuer_name)) |issuer_index| {
            const issuer_cert: Certificate = .{
                .buffer = trust.bytes.items,
                .index = issuer_index,
            };
            const issuer = der.parseCertificate(issuer_cert) catch return error.InvalidSignature;
            try subject.verify(issuer, verify_at);
            if (verify_at < issuer.validity.not_before or
                verify_at > issuer.validity.not_after)
                return error.InvalidSignature;
            if (std.mem.eql(u8, issuer.issuer(), issuer.subject())) return;
            subject = issuer;
            subject_cert = issuer_cert;
            continue;
        }

        var matched: ?Certificate.Parsed = null;
        var matched_cert: ?Certificate = null;
        for (pool.items) |candidate| {
            const cert = candidate;
            const parsed = der.parseCertificate(cert) catch continue;
            if (std.mem.eql(u8, parsed.subject(), issuer_name)) {
                matched = parsed;
                matched_cert = cert;
                break;
            }
        }
        const issuer = matched orelse return error.InvalidSignature;
        try subject.verify(issuer, verify_at);
        subject = issuer;
        subject_cert = matched_cert.?;
    }
    return error.InvalidSignature;
}

fn verifyDigest(
    algorithm: HashAlgorithm,
    message: []const u8,
    expected: []const u8,
    mismatch: VerifyError,
) VerifyError!void {
    var digest: [64]u8 = undefined;
    const actual = switch (algorithm) {
        .sha256 => block: {
            std.crypto.hash.sha2.Sha256.hash(message, digest[0..32], .{});
            break :block digest[0..32];
        },
        .sha384 => block: {
            std.crypto.hash.sha2.Sha384.hash(message, digest[0..48], .{});
            break :block digest[0..48];
        },
        .sha512 => block: {
            std.crypto.hash.sha2.Sha512.hash(message, digest[0..64], .{});
            break :block digest[0..64];
        },
    };
    if (!std.mem.eql(u8, actual, expected)) return mismatch;
}

fn hashAlgorithm(oid_bytes: []const u8) VerifyError!HashAlgorithm {
    if (std.mem.eql(u8, oid_bytes, &oid.sha256)) return .sha256;
    if (std.mem.eql(u8, oid_bytes, &oid.sha384)) return .sha384;
    if (std.mem.eql(u8, oid_bytes, &oid.sha512)) return .sha512;
    return error.UnsupportedDigestAlgorithm;
}

fn signatureAlgorithm(oid_bytes: []const u8) VerifyError!SignatureAlgorithm {
    if (std.mem.eql(u8, oid_bytes, &oid.sha256_with_rsa)) return .rsa_pkcs1_v15_sha256;
    if (std.mem.eql(u8, oid_bytes, &oid.sha384_with_rsa)) return .rsa_pkcs1_v15_sha384;
    if (std.mem.eql(u8, oid_bytes, &oid.sha512_with_rsa)) return .rsa_pkcs1_v15_sha512;
    if (std.mem.eql(u8, oid_bytes, &oid.rsa_encryption)) return .rsa_pkcs1_v15_implicit_hash;
    if (std.mem.eql(u8, oid_bytes, &oid.ecdsa_with_sha256)) return .ecdsa_sha256;
    if (std.mem.eql(u8, oid_bytes, &oid.ecdsa_with_sha384)) return .ecdsa_sha384;
    return error.UnsupportedSignatureAlgorithm;
}

fn isContextSpecificTag(identifier: der.Identifier, tag_number: u5) bool {
    return identifier.class == .context_specific and
        @intFromEnum(identifier.tag) == tag_number;
}

fn selectChainTime(clock: ChainClock, now: i64, gen_time: i64) i64 {
    return switch (clock) {
        .wall_clock => now,
        .gen_time => gen_time,
    };
}

fn parseGeneralizedTime(value: []const u8) !i64 {
    if (value.len < 15 or value[value.len - 1] != 'Z')
        return error.InvalidGeneralizedTime;
    if (value.len > 15) {
        if (value[14] != '.' and value[14] != ',')
            return error.InvalidGeneralizedTime;
        if (value.len == 16) return error.InvalidGeneralizedTime;
        for (value[15 .. value.len - 1]) |digit|
            if (!std.ascii.isDigit(digit)) return error.InvalidGeneralizedTime;
    }

    const year = std.fmt.parseInt(u16, value[0..4], 10) catch
        return error.InvalidGeneralizedTime;
    const month = std.fmt.parseInt(u8, value[4..6], 10) catch
        return error.InvalidGeneralizedTime;
    const day = std.fmt.parseInt(u8, value[6..8], 10) catch
        return error.InvalidGeneralizedTime;
    const hour = std.fmt.parseInt(u8, value[8..10], 10) catch
        return error.InvalidGeneralizedTime;
    const minute = std.fmt.parseInt(u8, value[10..12], 10) catch
        return error.InvalidGeneralizedTime;
    const second = std.fmt.parseInt(u8, value[12..14], 10) catch
        return error.InvalidGeneralizedTime;

    if (month < 1 or month > 12 or hour > 23 or minute > 59 or second > 59)
        return error.InvalidGeneralizedTime;
    const month_days = [_]u8{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    var max_day = month_days[month - 1];
    if (month == 2 and isLeapYear(year)) max_day = 29;
    if (day < 1 or day > max_day) return error.InvalidGeneralizedTime;

    return daysFromCivil(year, month, day) * 86400 +
        @as(i64, hour) * 3600 +
        @as(i64, minute) * 60 +
        @as(i64, second);
}

fn isLeapYear(year: u16) bool {
    return @mod(year, 4) == 0 and
        (@mod(year, 100) != 0 or @mod(year, 400) == 0);
}

fn daysFromCivil(year_input: u16, month: u8, day: u8) i64 {
    var year: i64 = year_input;
    if (month <= 2) year -= 1;
    const era = @divFloor(if (year >= 0) year else year - 399, 400);
    const year_of_era = year - era * 400;
    const month_i: i64 = month;
    const day_of_year = @divFloor(
        153 * (month_i + (if (month > 2) @as(i64, -3) else @as(i64, 9))) + 2,
        5,
    ) + day - 1;
    const day_of_era = year_of_era * 365 +
        @divFloor(year_of_era, 4) -
        @divFloor(year_of_era, 100) +
        day_of_year;
    return era * 146097 + day_of_era - 719468;
}

test "parse TSTInfo exposes imprint and genTime" {
    const bytes = [_]u8{
        0x30, 0x4e,
        0x02, 0x01,
        0x01, 0x06,
        0x02, 0x2a,
        0x03, 0x30,
        0x31, 0x30,
        0x0d, 0x06,
        0x09, 0x60,
        0x86, 0x48,
        0x01, 0x65,
        0x03, 0x04,
        0x02, 0x01,
        0x05, 0x00,
        0x04, 0x20,
        0,    0,
        0,    0,
        0,    0,
        0,    0,
        0,    0,
        0,    0,
        0,    0,
        0,    0,
        0,    0,
        0,    0,
        0,    0,
        0,    0,
        0,    0,
        0,    0,
        0,    0,
        0,    0,
        0x02, 0x01,
        0x01, 0x18,
        0x0f, '2',
        '0',  '2',
        '6',  '0',
        '4',  '2',
        '1',  '1',
        '0',  '2',
        '4',  '3',
        '1',  'Z',
    };
    const tst = try parseTstInfo(&bytes);
    try std.testing.expectEqual(HashAlgorithm.sha256, tst.imprint_alg);
    try std.testing.expectEqual(@as(usize, 32), tst.imprint.len);
    try std.testing.expectEqual(@as(i64, 1776767071), tst.gen_time);
}

test "TimeStampResp granted wrapper yields CMS ContentInfo" {
    const content_info = [_]u8{
        0x30, 0x0d,
        0x06, 0x09,
        0x2a, 0x86,
        0x48, 0x86,
        0xf7, 0x0d,
        0x01, 0x07,
        0x02, 0xa0,
        0x00,
    };
    const response = [_]u8{
        0x30, 0x14,
        0x30, 0x03,
        0x02, 0x01,
        0x00, 0x30,
        0x0d, 0x06,
        0x09, 0x2a,
        0x86, 0x48,
        0x86, 0xf7,
        0x0d, 0x01,
        0x07, 0x02,
        0xa0, 0x00,
    };
    try std.testing.expectEqualSlices(u8, &content_info, try unwrapTimestampToken(&response));
    try std.testing.expectEqualSlices(u8, &content_info, try unwrapTimestampToken(&content_info));
}

test "TimeStampResp rejects non-granted status and missing token" {
    const rejected = [_]u8{
        0x30, 0x05,
        0x30, 0x03,
        0x02, 0x01,
        0x02,
    };
    try std.testing.expectError(
        error.TimestampStatusNotGranted,
        unwrapTimestampToken(&rejected),
    );

    const missing = [_]u8{
        0x30, 0x05,
        0x30, 0x03,
        0x02, 0x01,
        0x00,
    };
    try std.testing.expectError(
        error.MissingTimestampToken,
        unwrapTimestampToken(&missing),
    );
}

test "signer lookup falls back to trusted bundle when CMS cert set is empty" {
    const allocator = std.testing.allocator;
    const pem = @embedFile("authenticode/trust/microsoft_root_ca_2010.crt.pem");
    const begin_marker = "-----BEGIN CERTIFICATE-----";
    const end_marker = "-----END CERTIFICATE-----";
    const encoded_start = std.mem.indexOf(u8, pem, begin_marker).? + begin_marker.len;
    const encoded_end = std.mem.indexOfPos(u8, pem, encoded_start, end_marker).?;

    var stripped = try allocator.alloc(u8, encoded_end - encoded_start);
    defer allocator.free(stripped);
    var stripped_len: usize = 0;
    for (pem[encoded_start..encoded_end]) |byte| {
        if (byte == ' ' or byte == '\t' or byte == '\r' or byte == '\n') continue;
        stripped[stripped_len] = byte;
        stripped_len += 1;
    }

    const decoder = std.base64.standard.Decoder;
    const cert_len = try decoder.calcSizeForSlice(stripped[0..stripped_len]);
    const cert_der = try allocator.alloc(u8, cert_len);
    defer allocator.free(cert_der);
    try decoder.decode(cert_der, stripped[0..stripped_len]);

    const cert_outer = try der.parseElement(cert_der, 0);
    const tbs = try der.parseElement(cert_der, cert_outer.slice.start);
    var serial_start = tbs.slice.start;
    const version = try der.parseElement(cert_der, serial_start);
    if (isContextSpecificTag(version.identifier, 0)) serial_start = version.slice.end;
    const serial = try der.parseElement(cert_der, serial_start);
    const signature_algorithm = try der.parseElement(cert_der, serial.slice.end);
    const issuer_start = signature_algorithm.slice.end;
    const issuer = try der.parseElement(cert_der, issuer_start);

    var sid_writer: std.Io.Writer.Allocating = .init(allocator);
    defer sid_writer.deinit();
    const sid_content_len = issuer.slice.end - issuer_start + serial.slice.end - serial_start;
    try sid_writer.writer.writeByte(0x30);
    try writeDerLength(&sid_writer.writer, sid_content_len);
    try sid_writer.writer.writeAll(cert_der[issuer_start..issuer.slice.end]);
    try sid_writer.writer.writeAll(cert_der[serial_start..serial.slice.end]);

    const parsed_cert: Certificate = .{ .buffer = cert_der, .index = 0 };
    const parsed = try der.parseCertificate(parsed_cert);
    var trust: Certificate.Bundle = .empty;
    defer trust.deinit(allocator);
    try trust.bytes.appendSlice(allocator, cert_der);
    try trust.parseCert(
        allocator,
        0,
        @as(i64, @intCast(parsed.validity.not_before)) + 1,
    );

    const token: TimestampToken = .{
        .tst_info_der = &.{},
        .certificates_raw = &.{},
        .signer = .{
            .digest_alg = .sha384,
            .signature_alg = .ecdsa_sha384,
            .signed_attrs_raw = &.{},
            .signature = &.{},
            .message_digest = &.{},
            .sid_raw = sid_writer.written(),
        },
    };
    const found = (try findSignerCertDer(token, trust)) orelse
        return error.TestUnexpectedNull;
    try std.testing.expectEqualSlices(u8, cert_der, found);
    try std.testing.expectError(
        error.InvalidTsaExtendedKeyUsage,
        verifyTimestampingExtendedKeyUsage(cert_der),
    );
}

fn writeDerLength(writer: *std.Io.Writer, length: usize) !void {
    if (length < 0x80) {
        try writer.writeByte(@intCast(length));
        return;
    }
    var bytes: [@sizeOf(usize)]u8 = undefined;
    std.mem.writeInt(usize, &bytes, length, .big);
    const first = std.mem.indexOfNone(u8, &bytes, &.{0}).?;
    const encoded = bytes[first..];
    try writer.writeByte(0x80 | @as(u8, @intCast(encoded.len)));
    try writer.writeAll(encoded);
}

test "detached imprint verification hashes caller message" {
    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("signed message", &expected, .{});
    try verifyDigest(
        .sha256,
        "signed message",
        &expected,
        error.TstInfoMessageImprintMismatch,
    );
    expected[0] ^= 1;
    try std.testing.expectError(
        error.TstInfoMessageImprintMismatch,
        verifyDigest(
            .sha256,
            "signed message",
            &expected,
            error.TstInfoMessageImprintMismatch,
        ),
    );
}

test "GitHub private timestamp algorithms select SHA-384 and ECDSA" {
    try std.testing.expectEqual(
        HashAlgorithm.sha384,
        try hashAlgorithm(&oid.sha384),
    );
    try std.testing.expectEqual(
        SignatureAlgorithm.ecdsa_sha384,
        try signatureAlgorithm(&oid.ecdsa_with_sha384),
    );

    var expected: [48]u8 = undefined;
    std.crypto.hash.sha2.Sha384.hash("github private signature", &expected, .{});
    try verifyDigest(
        .sha384,
        "github private signature",
        &expected,
        error.TstInfoMessageImprintMismatch,
    );
}

test "chain clock policy selects wall clock or signed genTime" {
    try std.testing.expectEqual(@as(i64, 200), selectChainTime(.wall_clock, 200, 100));
    try std.testing.expectEqual(@as(i64, 100), selectChainTime(.gen_time, 200, 100));
}

test "GeneralizedTime accepts fractions and rejects invalid calendar values" {
    try std.testing.expectEqual(
        @as(i64, 1713807206),
        try parseGeneralizedTime("20240422173326Z"),
    );
    try std.testing.expectEqual(
        @as(i64, 1776767071),
        try parseGeneralizedTime("20260421102431.123Z"),
    );
    try std.testing.expectError(
        error.InvalidGeneralizedTime,
        parseGeneralizedTime("20260230102431Z"),
    );
}

test "malformed timestamp tokens are rejected without panicking" {
    const gpa = std.testing.allocator;
    const empty_bundle: Certificate.Bundle = .empty;
    for ([_][]const u8{
        "",
        "\x30",
        "\x30\x20",
        "\x30\x84\xFF\xFF\xFF\xFF",
        "\x30\x82\xFF\xFF",
    }) |token| {
        try std.testing.expectError(
            error.InvalidDerElement,
            verifyDetached(gpa, token, "message", empty_bundle, 0, .gen_time),
        );
    }
}
