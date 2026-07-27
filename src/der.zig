//! Bounds-checked DER parsing.
//!
//! Zig 0.16's `std.crypto.Certificate` parses DER without bounds checking:
//! `der.Element.parse` indexes the identifier and length octets and computes
//! `slice.end` without ever comparing them against `bytes.len`, and
//! `Certificate.parse` then walks siblings at offsets such as
//! `tbs_certificate.slice.end` that may already be past the end of the buffer.
//! A malformed or truncated certificate therefore *panics* rather than
//! returning an error, and a panic is not catchable with `catch`.
//!
//! Every DER byte `ghr` parses arrives from a downloaded artifact — a Sigstore
//! bundle's `certificate.rawBytes`, a GitHub attestation, or the PKCS#7 blob
//! embedded in a Windows `.exe` — so every parse in this repository goes
//! through this module instead.

const std = @import("std");
const mem = std.mem;
const Certificate = std.crypto.Certificate;

/// Re-exported so `const der = @import("der.zig");` is a drop-in replacement
/// for `const der = Certificate.der;`.
pub const Element = Certificate.der.Element;
pub const Identifier = Certificate.der.Identifier;
pub const Tag = Certificate.der.Tag;
pub const Slice = Certificate.der.Element.Slice;

pub const ParseError = error{
    InvalidDerElement,
    CertificateFieldHasInvalidLength,
};

/// Bounds-checked replacement for `Certificate.der.Element.parse`.
///
/// The standard-library parser reads the identifier and length octets and
/// computes `slice.end` without ever comparing them against `bytes.len`, so a
/// truncated or hostile encoding panics (and, for a 4-octet long form,
/// overflows the `u32` end offset) instead of returning an error. The element
/// returned here is guaranteed to lie entirely within `bytes`.
///
/// The result always satisfies `slice.end >= index + 2`, so callers that walk
/// siblings with `i = elem.slice.end` always make progress and cannot loop
/// forever on a zero-length element.
pub fn parseElement(bytes: []const u8, index: u32) ParseError!Element {
    if (bytes.len > std.math.maxInt(u32)) return error.InvalidDerElement;
    const len: u32 = @intCast(bytes.len);

    const header_end = std.math.add(u32, index, 2) catch
        return error.InvalidDerElement;
    if (header_end > len) return error.InvalidDerElement;

    const size_byte = bytes[index + 1];
    var content_start = header_end;
    var content_len: u32 = size_byte;

    if ((size_byte >> 7) != 0) {
        const len_size: u7 = @truncate(size_byte);
        // A 4-octet long form is the widest that fits the u32 offsets used
        // throughout this parser; the indefinite form (0) is not valid DER.
        if (len_size == 0 or len_size > @sizeOf(u32))
            return error.CertificateFieldHasInvalidLength;
        content_start = std.math.add(u32, header_end, len_size) catch
            return error.InvalidDerElement;
        if (content_start > len) return error.InvalidDerElement;

        content_len = 0;
        for (bytes[header_end..content_start]) |byte|
            content_len = (content_len << 8) | byte;
    }

    const content_end = std.math.add(u32, content_start, content_len) catch
        return error.InvalidDerElement;
    if (content_end > len) return error.InvalidDerElement;

    return .{
        .identifier = @bitCast(bytes[index]),
        .slice = .{ .start = content_start, .end = content_end },
    };
}

pub const CertificateParseError = ParseError ||
    Certificate.ParseVersionError ||
    Certificate.ParseTimeError ||
    Certificate.ParseEnumError ||
    Certificate.ParseBitStringError;

/// Bounds-checked replacement for `Certificate.parse`.
///
/// A faithful copy of `std.crypto.Certificate.parse` (Zig 0.16) with two
/// changes: every `der.Element.parse` becomes `parseElement`, and the local
/// `parseBitString` below rejects an empty BIT STRING instead of indexing past
/// the end of the buffer. Every other helper is the `pub` standard-library one,
/// which is safe to reuse once its element argument is bounds-checked.
///
/// Returns the standard `Certificate.Parsed`, so `verify`, `issuer`, `subject`,
/// `pubKey`, and `subjectAltName` all keep working unchanged.
pub fn parseCertificate(cert: Certificate) CertificateParseError!Certificate.Parsed {
    const cert_bytes = cert.buffer;
    const certificate = try parseElement(cert_bytes, cert.index);
    const tbs_certificate = try parseElement(cert_bytes, certificate.slice.start);
    const version_elem = try parseElement(cert_bytes, tbs_certificate.slice.start);
    const version = try Certificate.parseVersion(cert_bytes, version_elem);
    const serial_number = if (@as(u8, @bitCast(version_elem.identifier)) == 0xa0)
        try parseElement(cert_bytes, version_elem.slice.end)
    else
        version_elem;
    // RFC 5280, section 4.1.2.3:
    // "This field MUST contain the same algorithm identifier as
    // the signatureAlgorithm field in the sequence Certificate."
    const tbs_signature = try parseElement(cert_bytes, serial_number.slice.end);
    const issuer = try parseElement(cert_bytes, tbs_signature.slice.end);
    const validity = try parseElement(cert_bytes, issuer.slice.end);
    const not_before = try parseElement(cert_bytes, validity.slice.start);
    const not_before_utc = try Certificate.parseTime(cert, not_before);
    const not_after = try parseElement(cert_bytes, not_before.slice.end);
    const not_after_utc = try Certificate.parseTime(cert, not_after);
    const subject = try parseElement(cert_bytes, validity.slice.end);

    const pub_key_info = try parseElement(cert_bytes, subject.slice.end);
    const pub_key_signature_algorithm = try parseElement(cert_bytes, pub_key_info.slice.start);
    const pub_key_algo_elem = try parseElement(cert_bytes, pub_key_signature_algorithm.slice.start);
    const pub_key_algo: Certificate.Parsed.PubKeyAlgo = switch (try Certificate.parseAlgorithmCategory(cert_bytes, pub_key_algo_elem)) {
        inline else => |tag| @unionInit(Certificate.Parsed.PubKeyAlgo, @tagName(tag), {}),
        .X9_62_id_ecPublicKey => pub_key_algo: {
            // RFC 5480 Section 2.1.1.1 Named Curve
            // ECParameters ::= CHOICE {
            //   namedCurve         OBJECT IDENTIFIER
            //   -- implicitCurve   NULL
            //   -- specifiedCurve  SpecifiedECDomain
            // }
            const params_elem = try parseElement(cert_bytes, pub_key_algo_elem.slice.end);
            const named_curve = try Certificate.parseNamedCurve(cert_bytes, params_elem);
            break :pub_key_algo .{ .X9_62_id_ecPublicKey = named_curve };
        },
    };
    const pub_key_elem = try parseElement(cert_bytes, pub_key_signature_algorithm.slice.end);
    const pub_key = try parseBitString(cert, pub_key_elem);

    var common_name = Element.Slice.empty;
    var name_i = subject.slice.start;
    while (name_i < subject.slice.end) {
        const rdn = try parseElement(cert_bytes, name_i);
        var rdn_i = rdn.slice.start;
        while (rdn_i < rdn.slice.end) {
            const atav = try parseElement(cert_bytes, rdn_i);
            var atav_i = atav.slice.start;
            while (atav_i < atav.slice.end) {
                const ty_elem = try parseElement(cert_bytes, atav_i);
                const val = try parseElement(cert_bytes, ty_elem.slice.end);
                atav_i = val.slice.end;
                const ty = Certificate.parseAttribute(cert_bytes, ty_elem) catch |err| switch (err) {
                    error.CertificateHasUnrecognizedObjectId => continue,
                    else => |e| return e,
                };
                switch (ty) {
                    .commonName => common_name = val.slice,
                    else => {},
                }
            }
            rdn_i = atav.slice.end;
        }
        name_i = rdn.slice.end;
    }

    const sig_algo = try parseElement(cert_bytes, tbs_certificate.slice.end);
    const algo_elem = try parseElement(cert_bytes, sig_algo.slice.start);
    const signature_algorithm = try Certificate.parseAlgorithm(cert_bytes, algo_elem);
    const sig_elem = try parseElement(cert_bytes, sig_algo.slice.end);
    const signature = try parseBitString(cert, sig_elem);

    // Extensions
    var subject_alt_name_slice = Element.Slice.empty;
    ext: {
        if (version == .v1)
            break :ext;

        if (pub_key_info.slice.end >= tbs_certificate.slice.end)
            break :ext;

        const outer_extensions = try parseElement(cert_bytes, pub_key_info.slice.end);
        if (outer_extensions.identifier.tag != .bitstring)
            break :ext;

        const extensions = try parseElement(cert_bytes, outer_extensions.slice.start);

        var ext_i = extensions.slice.start;
        while (ext_i < extensions.slice.end) {
            const extension = try parseElement(cert_bytes, ext_i);
            ext_i = extension.slice.end;
            const oid_elem = try parseElement(cert_bytes, extension.slice.start);
            const ext_id = Certificate.parseExtensionId(cert_bytes, oid_elem) catch |err| switch (err) {
                error.CertificateHasUnrecognizedObjectId => continue,
                else => |e| return e,
            };
            const critical_elem = try parseElement(cert_bytes, oid_elem.slice.end);
            const ext_bytes_elem = if (critical_elem.identifier.tag != .boolean)
                critical_elem
            else
                try parseElement(cert_bytes, critical_elem.slice.end);
            switch (ext_id) {
                .subject_alt_name => subject_alt_name_slice = ext_bytes_elem.slice,
                else => continue,
            }
        }
    }

    return .{
        .certificate = cert,
        .common_name_slice = common_name,
        .issuer_slice = issuer.slice,
        .subject_slice = subject.slice,
        .signature_slice = signature,
        .signature_algorithm = signature_algorithm,
        .message_slice = .{ .start = certificate.slice.start, .end = tbs_certificate.slice.end },
        .pub_key_algo = pub_key_algo,
        .pub_key_slice = pub_key,
        .validity = .{
            .not_before = not_before_utc,
            .not_after = not_after_utc,
        },
        .subject_alt_name_slice = subject_alt_name_slice,
        .version = version,
    };
}

/// Bounds-checked replacement for `Certificate.parseBitString`.
///
/// The standard-library version reads `cert.buffer[elem.slice.start]` without
/// checking that the element is non-empty, so a zero-length BIT STRING whose
/// content begins at `buffer.len` panics even when the element itself was
/// bounds-checked.
fn parseBitString(cert: Certificate, elem: Element) CertificateParseError!Slice {
    if (elem.identifier.tag != .bitstring) return error.CertificateFieldHasWrongDataType;
    if (elem.slice.start >= elem.slice.end) return error.InvalidDerElement;
    if (cert.buffer[elem.slice.start] != 0) return error.CertificateHasInvalidBitString;
    return .{ .start = elem.slice.start + 1, .end = elem.slice.end };
}

test "malformed DER elements return errors instead of panicking" {
    // Every case below indexes out of bounds under `der.Element.parse`.
    try std.testing.expectError(error.InvalidDerElement, parseElement("", 0));
    // Identifier present but the length octet is missing.
    try std.testing.expectError(error.InvalidDerElement, parseElement("\x30", 0));
    // Short form claiming more content than the buffer holds.
    try std.testing.expectError(error.InvalidDerElement, parseElement("\x30\x20", 0));
    // 4-octet long form whose end offset overflows u32.
    try std.testing.expectError(
        error.InvalidDerElement,
        parseElement("\x30\x84\xFF\xFF\xFF\xFF", 0),
    );
    // Long form whose own size octets run past the buffer.
    try std.testing.expectError(error.InvalidDerElement, parseElement("\x30\x83\x00", 0));
    // Long form wider than the u32 offsets this parser uses.
    try std.testing.expectError(
        error.CertificateFieldHasInvalidLength,
        parseElement("\x30\x85\x00\x00\x00\x00\x00", 0),
    );
    // Indefinite length is not valid DER.
    try std.testing.expectError(
        error.CertificateFieldHasInvalidLength,
        parseElement("\x30\x80", 0),
    );
    // A start index past the end of the buffer.
    try std.testing.expectError(error.InvalidDerElement, parseElement("\x30\x00", 9));

    // Well-formed elements still parse, in both length forms.
    const short = try parseElement("\x30\x02\xAA\xBB", 0);
    try std.testing.expectEqual(@as(u32, 2), short.slice.start);
    try std.testing.expectEqual(@as(u32, 4), short.slice.end);

    const long = try parseElement("\x30\x81\x02\xAA\xBB", 0);
    try std.testing.expectEqual(@as(u32, 3), long.slice.start);
    try std.testing.expectEqual(@as(u32, 5), long.slice.end);
}

test "parsed elements always advance sibling walks" {
    // `slice.end >= index + 2` is what makes `i = elem.slice.end` loops
    // terminate. A zero-length element is the boundary case.
    const empty = try parseElement("\x05\x00", 0);
    try std.testing.expectEqual(@as(u32, 2), empty.slice.start);
    try std.testing.expectEqual(@as(u32, 2), empty.slice.end);
}

test "empty BIT STRING is rejected instead of indexing past the buffer" {
    // A zero-length BIT STRING at the end of the buffer. `slice.start` equals
    // `buffer.len`, so `std.crypto.Certificate.parseBitString` panics reading
    // the "unused bits" octet even though the element itself is well formed.
    const bytes = "\x03\x00";
    const elem = try parseElement(bytes, 0);
    try std.testing.expectError(
        error.InvalidDerElement,
        parseBitString(.{ .buffer = bytes, .index = 0 }, elem),
    );
}

/// Base64-decode the single PEM block in `pem_bytes`. Test-local so this
/// module stays free of dependencies on the verifiers that import it.
fn testDecodePem(allocator: mem.Allocator, pem_bytes: []const u8) ![]u8 {
    const begin_eol = mem.indexOfScalar(u8, pem_bytes, '\n') orelse return error.InvalidPem;
    const end_off = mem.indexOfPos(u8, pem_bytes, begin_eol, "-----END ") orelse
        return error.InvalidPem;

    var stripped: std.ArrayList(u8) = .empty;
    defer stripped.deinit(allocator);
    for (pem_bytes[begin_eol + 1 .. end_off]) |c| {
        if (!std.ascii.isWhitespace(c)) try stripped.append(allocator, c);
    }

    const decoder = std.base64.standard.Decoder;
    const out = try allocator.alloc(u8, try decoder.calcSizeForSlice(stripped.items));
    errdefer allocator.free(out);
    try decoder.decode(out, stripped.items);
    return out;
}

/// A real ECDSA certificate with v3 extensions, reused as a parser fixture.
const test_cert_pem = @embedFile("sigstore/trust/fulcio_intermediate_v1.crt.pem");
/// A real RSA certificate, to cover the other public-key algorithm branch.
const test_rsa_cert_pem = @embedFile("authenticode/trust/digicert_global_root_ca.crt.pem");

test "valid certificates parse identically to the standard library" {
    const allocator = std.testing.allocator;

    for ([_][]const u8{ test_cert_pem, test_rsa_cert_pem }) |pem| {
        const der_bytes = try testDecodePem(allocator, pem);
        defer allocator.free(der_bytes);

        const cert: Certificate = .{ .buffer = der_bytes, .index = 0 };
        const ours = try parseCertificate(cert);
        const theirs = try cert.parse();

        // Field-for-field equality is what keeps this vendored copy honest:
        // it must only change behavior on input that would otherwise panic.
        try std.testing.expectEqualDeep(theirs.issuer_slice, ours.issuer_slice);
        try std.testing.expectEqualDeep(theirs.subject_slice, ours.subject_slice);
        try std.testing.expectEqualDeep(theirs.common_name_slice, ours.common_name_slice);
        try std.testing.expectEqualDeep(theirs.signature_slice, ours.signature_slice);
        try std.testing.expectEqual(theirs.signature_algorithm, ours.signature_algorithm);
        try std.testing.expectEqualDeep(theirs.pub_key_algo, ours.pub_key_algo);
        try std.testing.expectEqualDeep(theirs.pub_key_slice, ours.pub_key_slice);
        try std.testing.expectEqualDeep(theirs.message_slice, ours.message_slice);
        try std.testing.expectEqualDeep(theirs.subject_alt_name_slice, ours.subject_alt_name_slice);
        try std.testing.expectEqualDeep(theirs.validity, ours.validity);
        try std.testing.expectEqual(theirs.version, ours.version);
    }
}

test "malformed certificates return errors instead of panicking" {
    const allocator = std.testing.allocator;

    // Empty buffer: panicked at Certificate.zig:905 via :424.
    try std.testing.expectError(
        error.InvalidDerElement,
        parseCertificate(.{ .buffer = "", .index = 0 }),
    );

    // Identifier present, length octets missing.
    try std.testing.expectError(
        error.InvalidDerElement,
        parseCertificate(.{ .buffer = "\x30", .index = 0 }),
    );

    // Truncated at the top level: the outer SEQUENCE claims more content than
    // the buffer holds.
    try std.testing.expectError(
        error.InvalidDerElement,
        parseCertificate(.{ .buffer = "\x30\x82\x05\xf4", .index = 0 }),
    );

    // 4-octet long-form length whose end offset overflows u32.
    try std.testing.expectError(
        error.InvalidDerElement,
        parseCertificate(.{ .buffer = "\x30\x84\xFF\xFF\xFF\xFF", .index = 0 }),
    );

    const der_bytes = try testDecodePem(allocator, test_cert_pem);
    defer allocator.free(der_bytes);

    // A real certificate truncated to half its length, with the outer SEQUENCE
    // length rewritten so the top-level TLV still spans the buffer exactly.
    // This panicked at Certificate.zig:490 parsing `sig_algo` at
    // `tbs_certificate.slice.end`, which proves a top-level length guard alone
    // is not sufficient.
    const half = der_bytes.len / 2;
    const truncated = try allocator.dupe(u8, der_bytes[0..half]);
    defer allocator.free(truncated);
    // The fixture's outer header is `30 82 hi lo` (2-octet long form).
    try std.testing.expectEqual(@as(u8, 0x82), truncated[1]);
    const content_len: u16 = @intCast(truncated.len - 4);
    std.mem.writeInt(u16, truncated[2..4], content_len, .big);
    const top = try parseElement(truncated, 0);
    try std.testing.expectEqual(@as(u32, @intCast(truncated.len)), top.slice.end);

    try std.testing.expectError(
        error.InvalidDerElement,
        parseCertificate(.{ .buffer = truncated, .index = 0 }),
    );

    // Every single-byte truncation of a real certificate must fail cleanly.
    var cut: usize = 1;
    while (cut < der_bytes.len) : (cut += 1) {
        _ = parseCertificate(.{ .buffer = der_bytes[0..cut], .index = 0 }) catch continue;
    }
}

test "no unchecked DER parsers remain in the verifiers" {
    // `Element` is re-exported from the standard library, so `Element.parse`
    // would silently resolve back to the panicking version if it were
    // reintroduced. The type system cannot catch that; this can.
    inline for (.{
        @embedFile("sigstore.zig"),
        @embedFile("authenticode.zig"),
        @embedFile("rfc3161.zig"),
    }) |source| {
        try std.testing.expect(mem.indexOf(u8, source, "Element.parse(") == null);
        try std.testing.expect(mem.indexOf(u8, source, ".parse()") == null);
    }
}
