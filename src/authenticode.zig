//! Native Authenticode (PKCS#7-over-PE) verification for downloaded
//! Windows release assets, addressing issue #77.
//!
//! Coverage delivered in this module:
//!   * PE/COFF header parsing: DOS header (`e_lfanew`), NT signature,
//!     File Header, Optional Header (PE32 / PE32+), data directory,
//!     section table.
//!   * Authenticode digest computation: SHA-256 over the file with
//!     `OptionalHeader.CheckSum` and `DataDirectory[Security]` skipped,
//!     and the certificate-table region at end of file excluded. See
//!     https://signify.readthedocs.io/en/latest/authenticode.html for
//!     a clear narrative of the byte ranges; we follow signify's
//!     `AuthenticodeFingerprinter` as the authoritative reference.
//!   * Certificate-table walk: locate the embedded `WIN_CERTIFICATE`
//!     blob containing the PKCS#7 SignedData.
//!
//! Layers above this (PKCS#7 SignedData parser, signer signature
//! verification, RFC 3161 timestamp verification, chain walk, ZIP
//! detection, and the wiring into `release.zig`) land in subsequent
//! commits on this branch — the verifier surface in `release.zig` is
//! only flipped on once all layers are in place.
//!
//! References:
//!   * Microsoft, "Windows Authenticode Portable Executable Signature
//!     Format" (PE spec section 5.3 of the Authenticode whitepaper).
//!   * `ralphje/signify` (Python). The test vectors in
//!     `tests/test_data/` are useful cross-checks once we expose the
//!     digest function.

const std = @import("std");

const Sha256 = std.crypto.hash.sha2.Sha256;

// ---------------------------------------------------------------------------
// PE/COFF constants and on-disk header layouts.
//
// All multi-byte integers in PE/COFF are little-endian.
// ---------------------------------------------------------------------------

/// "MZ" — the DOS executable magic at offset 0.
pub const dos_signature: [2]u8 = .{ 'M', 'Z' };

/// "PE\0\0" — the NT signature, found at offset `e_lfanew` of the DOS
/// header.
pub const nt_signature: [4]u8 = .{ 'P', 'E', 0, 0 };

/// `OptionalHeader.Magic` values we accept.
pub const pe32_magic: u16 = 0x010B;
pub const pe32_plus_magic: u16 = 0x020B;

/// Index of the certificate table entry in
/// `OptionalHeader.DataDirectory`.
pub const data_directory_security_index: usize = 4;

/// `WIN_CERTIFICATE.wCertificateType` value we accept (PKCS#7).
pub const win_cert_type_pkcs_signed_data: u16 = 0x0002;
/// `WIN_CERTIFICATE.wRevision` value for current Authenticode.
pub const win_cert_revision_2_0: u16 = 0x0200;

/// Parsed view of a PE/COFF image, with just enough offsets to locate
/// the Authenticode-relevant byte ranges and the embedded certificate
/// table.
///
/// All offsets are absolute byte offsets into the underlying file
/// image; all of them point inside `bytes`.
pub const PeImage = struct {
    bytes: []const u8,
    /// Offset of `OptionalHeader.CheckSum` (4 bytes).
    checksum_offset: usize,
    /// Offset of the Security data-directory entry within the optional
    /// header. The entry itself is 8 bytes (RVA + size); for the
    /// certificate table the RVA is actually a file offset.
    security_dir_offset: usize,
    /// File offset of the certificate table (`WIN_CERTIFICATE` blob).
    /// Zero when no certificate table is published.
    cert_table_offset: u32,
    /// Length of the certificate table in bytes (0 when absent).
    cert_table_size: u32,
    /// True for PE32+ (64-bit), false for PE32 (32-bit). Affects the
    /// optional-header layout but not the Authenticode digest
    /// algorithm.
    is_pe32_plus: bool,
};

pub const ParseError = error{
    NotPeImage,
    TruncatedDosHeader,
    TruncatedNtHeader,
    BadNtSignature,
    TruncatedFileHeader,
    TruncatedOptionalHeader,
    UnknownOptionalHeaderMagic,
    TruncatedDataDirectory,
    InvalidCertTable,
};

/// Parse just enough of `bytes` to expose the Authenticode-relevant
/// offsets. Does not validate sections, imports, relocations, or any
/// of the rest of the image — none of those affect Authenticode.
pub fn parsePe(bytes: []const u8) ParseError!PeImage {
    if (bytes.len < 0x40) return error.TruncatedDosHeader;
    if (!std.mem.eql(u8, bytes[0..2], &dos_signature)) return error.NotPeImage;
    // `e_lfanew` lives at DOS-header offset 0x3C (4 bytes, LE).
    const e_lfanew = std.mem.readInt(u32, bytes[0x3C..0x40], .little);
    if (e_lfanew < 0x40) return error.TruncatedDosHeader;

    const nt_off: usize = e_lfanew;
    if (nt_off + 4 > bytes.len) return error.TruncatedNtHeader;
    if (!std.mem.eql(u8, bytes[nt_off .. nt_off + 4], &nt_signature))
        return error.BadNtSignature;

    // File header is 20 bytes immediately after the NT signature.
    const fh_off: usize = nt_off + 4;
    if (fh_off + 20 > bytes.len) return error.TruncatedFileHeader;
    const size_of_optional_header = std.mem.readInt(
        u16,
        bytes[fh_off + 16 .. fh_off + 18][0..2],
        .little,
    );
    if (size_of_optional_header == 0) return error.TruncatedOptionalHeader;

    // Optional header starts right after the file header.
    const opt_off: usize = fh_off + 20;
    if (opt_off + size_of_optional_header > bytes.len)
        return error.TruncatedOptionalHeader;
    if (opt_off + 2 > bytes.len) return error.TruncatedOptionalHeader;

    const magic = std.mem.readInt(u16, bytes[opt_off .. opt_off + 2][0..2], .little);
    const is_pe32_plus = switch (magic) {
        pe32_magic => false,
        pe32_plus_magic => true,
        else => return error.UnknownOptionalHeaderMagic,
    };

    // `CheckSum` is at OptionalHeader+64 in both PE32 and PE32+.
    const checksum_offset = opt_off + 64;
    if (checksum_offset + 4 > bytes.len) return error.TruncatedOptionalHeader;

    // The data directory begins after the windows-specific fields.
    // PE32 windows-specific block: 68 bytes (ImageBase=4, ..., LoaderFlags=4,
    //   NumberOfRvaAndSizes=4) starting at OptionalHeader+68.
    // PE32+: the same fields are 88 bytes wide; data directory starts
    // at OptionalHeader+112.
    const data_dir_off = if (is_pe32_plus) opt_off + 112 else opt_off + 96;
    const num_rva_sizes_off = data_dir_off - 4;
    if (num_rva_sizes_off + 4 > bytes.len) return error.TruncatedOptionalHeader;
    const num_rva_and_sizes = std.mem.readInt(
        u32,
        bytes[num_rva_sizes_off .. num_rva_sizes_off + 4][0..2 + 2],
        .little,
    );
    if (num_rva_and_sizes <= data_directory_security_index) {
        // No certificate-table entry published. We still return a
        // valid view; the caller can decide whether absence is
        // fail-open or fail-closed (Authenticode treats it as
        // "no signature").
        return .{
            .bytes = bytes,
            .checksum_offset = checksum_offset,
            .security_dir_offset = data_dir_off + data_directory_security_index * 8,
            .cert_table_offset = 0,
            .cert_table_size = 0,
            .is_pe32_plus = is_pe32_plus,
        };
    }

    const security_dir_offset = data_dir_off + data_directory_security_index * 8;
    if (security_dir_offset + 8 > bytes.len) return error.TruncatedDataDirectory;
    const cert_table_offset = std.mem.readInt(
        u32,
        bytes[security_dir_offset .. security_dir_offset + 4][0..4],
        .little,
    );
    const cert_table_size = std.mem.readInt(
        u32,
        bytes[security_dir_offset + 4 .. security_dir_offset + 8][0..4],
        .little,
    );

    if (cert_table_offset != 0) {
        // The certificate table must live entirely inside the file
        // and at the very end (with optional 8-byte alignment slack).
        if (@as(usize, cert_table_offset) + @as(usize, cert_table_size) > bytes.len)
            return error.InvalidCertTable;
        if (@as(usize, cert_table_offset) + @as(usize, cert_table_size) + 8 < bytes.len)
            return error.InvalidCertTable;
    }

    return .{
        .bytes = bytes,
        .checksum_offset = checksum_offset,
        .security_dir_offset = security_dir_offset,
        .cert_table_offset = cert_table_offset,
        .cert_table_size = cert_table_size,
        .is_pe32_plus = is_pe32_plus,
    };
}

// ---------------------------------------------------------------------------
// Authenticode digest computation.
//
// Microsoft's Authenticode digest is SHA-256 (or SHA-1 historically) of
// the PE file with the following byte ranges removed before hashing:
//
//   1. OptionalHeader.CheckSum (4 bytes).
//   2. The Security data directory entry (8 bytes, located in the
//      OptionalHeader's DataDirectory at index 4).
//   3. The certificate table itself (last region of the file pointed
//      to by the Security data directory entry).
//
// Concretely: hash bytes [0 .. CheckSum), [CheckSum+4 .. SecurityDir),
// [SecurityDir+8 .. CertTableStart), and stop. Trailing slack between
// the last section and the certificate table (if any) is included in
// the hash; padding after the certificate table is not.
//
// When no certificate table is published, the "stop" point becomes
// `bytes.len`.
// ---------------------------------------------------------------------------

pub const DigestError = error{
    AuthenticodeRegionsOutOfOrder,
};

/// Compute the SHA-256 Authenticode digest of `image` into
/// `digest_out`. Allocation-free; streams directly through the
/// SHA-256 hasher.
pub fn computeAuthenticodeDigestSha256(
    image: PeImage,
    digest_out: *[32]u8,
) DigestError!void {
    // The three skipped ranges must appear in this order in a valid
    // PE: CheckSum (in the optional header) precedes the Security data
    // directory entry (also in the optional header), which in turn
    // precedes the certificate table at end-of-file.
    if (image.checksum_offset + 4 > image.security_dir_offset)
        return error.AuthenticodeRegionsOutOfOrder;

    const bytes = image.bytes;
    const end_offset: usize = if (image.cert_table_offset == 0)
        bytes.len
    else
        image.cert_table_offset;
    if (image.security_dir_offset + 8 > end_offset)
        return error.AuthenticodeRegionsOutOfOrder;

    var hasher = Sha256.init(.{});
    // [0, CheckSum)
    hasher.update(bytes[0..image.checksum_offset]);
    // [CheckSum+4, SecurityDir)
    hasher.update(bytes[image.checksum_offset + 4 .. image.security_dir_offset]);
    // [SecurityDir+8, CertTableStart or bytes.len)
    hasher.update(bytes[image.security_dir_offset + 8 .. end_offset]);
    hasher.final(digest_out);
}

// ---------------------------------------------------------------------------
// Certificate table walk.
//
// The certificate table (when present) is a sequence of WIN_CERTIFICATE
// structures laid out as:
//
//   struct WIN_CERTIFICATE {
//       u32 dwLength;             // total length including this header
//       u16 wRevision;            // 0x0200 for current Authenticode
//       u16 wCertificateType;     // 0x0002 for PKCS#7 SignedData
//       u8  bCertificate[];       // length = dwLength - 8, padded to 8 bytes
//   };
//
// Entries are 8-byte aligned in the file; padding between entries is
// not part of `dwLength`.
// ---------------------------------------------------------------------------

pub const WinCertificate = struct {
    revision: u16,
    cert_type: u16,
    /// PKCS#7 SignedData blob. Borrowed from the input image.
    data: []const u8,
};

pub const WinCertError = error{
    InvalidCertTable,
    UnsupportedCertRevision,
    UnsupportedCertType,
};

/// Iterator over `WIN_CERTIFICATE` entries in the embedded certificate
/// table. Skips entries that aren't PKCS#7 SignedData v2.0
/// (revision 0x0200, type 0x0002) — but returns an error if a malformed
/// entry would prevent further iteration.
pub const WinCertIterator = struct {
    table: []const u8,
    offset: usize,

    pub fn init(image: PeImage) WinCertIterator {
        if (image.cert_table_offset == 0) {
            return .{ .table = &.{}, .offset = 0 };
        }
        const start = image.cert_table_offset;
        const end = start + image.cert_table_size;
        return .{
            .table = image.bytes[start..end],
            .offset = 0,
        };
    }

    pub fn next(self: *WinCertIterator) WinCertError!?WinCertificate {
        // 8-byte align the offset between entries.
        const aligned = std.mem.alignForward(usize, self.offset, 8);
        if (aligned >= self.table.len) return null;
        if (aligned + 8 > self.table.len) return error.InvalidCertTable;

        const length = std.mem.readInt(u32, self.table[aligned .. aligned + 4][0..4], .little);
        const revision = std.mem.readInt(u16, self.table[aligned + 4 .. aligned + 6][0..2], .little);
        const cert_type = std.mem.readInt(u16, self.table[aligned + 6 .. aligned + 8][0..2], .little);
        if (length < 8) return error.InvalidCertTable;
        if (aligned + length > self.table.len) return error.InvalidCertTable;

        const data = self.table[aligned + 8 .. aligned + length];
        self.offset = aligned + length;

        return .{
            .revision = revision,
            .cert_type = cert_type,
            .data = data,
        };
    }
};

/// Find the first WIN_CERTIFICATE entry in `image` that carries a
/// PKCS#7 SignedData blob (revision 2.0, type 2). Returns null when
/// the image has no certificate table, or the table contains no
/// PKCS#7 entries.
pub fn findFirstPkcs7Entry(image: PeImage) WinCertError!?WinCertificate {
    var it = WinCertIterator.init(image);
    while (try it.next()) |entry| {
        if (entry.revision != win_cert_revision_2_0) continue;
        if (entry.cert_type != win_cert_type_pkcs_signed_data) continue;
        return entry;
    }
    return null;
}

// ---------------------------------------------------------------------------
// Authenticode signature stripping.
//
// Reverses what Trusted Signing (and signtool-style signers) append to a
// PE: the certificate table at end of file, and the
// `DataDirectory[Security]` entry pointing at it. Strict bit-equivalence
// to the pre-sign binary is the goal — every byte the signer touched is
// reverted to the value it would have had pre-signing. See issue #78
// Option E for why we need this exact bit-identity (not just
// Authenticode-digest equivalence).
//
// Constraints:
//   * The published PE MUST be signed (Security data-directory entry
//     non-zero, cert table size > 0). Stripping an unsigned binary is
//     never meaningful in this workflow.
//   * The certificate table MUST live at the very tail of the file (per
//     the Authenticode spec). We allow no slack beyond what `parsePe`
//     already permits (≤ 8 bytes of zero padding after the cert table).
//   * `OptionalHeader.CheckSum` is reset to 0. Zig's `build-exe` emits 0
//     for PE32+ binaries; Trusted Signing leaves it at 0 in practice.
//     If a future signer or compiler starts writing a non-zero CheckSum,
//     the stripper will produce a 4-byte mismatch which is unambiguous
//     and easy to diagnose.
// ---------------------------------------------------------------------------

pub const StripError = error{
    NotSigned,
    CertTableNotAtEnd,
    OutOfMemory,
} || ParseError;

pub const StripOutcome = struct {
    /// Stripped PE bytes. Owned by the caller; freed via `allocator.free`.
    bytes: []u8,
    /// File offset at which the cert table started — useful for logs.
    stripped_at: u32,
    /// Number of bytes removed (cert table + any trailing padding).
    stripped_bytes: u32,
};

/// Strip the Authenticode signature from a signed PE and return the
/// resulting bit-identical-to-unsigned bytes.
pub fn stripAuthenticodeIntoBuffer(
    allocator: std.mem.Allocator,
    pe_bytes: []const u8,
) StripError!StripOutcome {
    const image = try parsePe(pe_bytes);

    if (image.cert_table_offset == 0 or image.cert_table_size == 0)
        return error.NotSigned;

    // The cert table must run to the end of the file, modulo the same
    // 8-byte alignment slack `parsePe` already allowed.
    const cert_table_end: usize = @as(usize, image.cert_table_offset) +
        @as(usize, image.cert_table_size);
    if (cert_table_end > pe_bytes.len) return error.CertTableNotAtEnd;
    if (pe_bytes.len - cert_table_end > 8) return error.CertTableNotAtEnd;

    // Output is the file truncated to the start of the cert table.
    const stripped_len: usize = image.cert_table_offset;
    const out = try allocator.alloc(u8, stripped_len);
    errdefer allocator.free(out);
    @memcpy(out, pe_bytes[0..stripped_len]);

    // Zero the Security data-directory entry (RVA + size, 8 bytes).
    @memset(out[image.security_dir_offset .. image.security_dir_offset + 8], 0);

    // Reset OptionalHeader.CheckSum to 0 — the canonical unsigned
    // value for Zig-emitted PE32+ binaries.
    @memset(out[image.checksum_offset .. image.checksum_offset + 4], 0);

    return .{
        .bytes = out,
        .stripped_at = image.cert_table_offset,
        .stripped_bytes = @intCast(pe_bytes.len - stripped_len),
    };
}

test "stripAuthenticodeIntoBuffer round-trips a synthetic signed PE" {
    const allocator = std.testing.allocator;

    // Build a minimal PE32+ image — same shape as the digest test
    // fixture. The "unsigned" buffer is the reference we expect to
    // recover after stripping.
    var unsigned = try allocator.alloc(u8, 0x58 + 240);
    defer allocator.free(unsigned);
    @memset(unsigned, 0);
    @memcpy(unsigned[0..2], &dos_signature);
    std.mem.writeInt(u32, unsigned[0x3C..0x40], 0x40, .little);
    @memcpy(unsigned[0x40..0x44], &nt_signature);
    std.mem.writeInt(u16, unsigned[0x44 + 16 .. 0x44 + 18][0..2], 240, .little);
    std.mem.writeInt(u16, unsigned[0x58..0x5A][0..2], pe32_plus_magic, .little);
    std.mem.writeInt(u32, unsigned[0x58 + 108 .. 0x58 + 112][0..4], 16, .little);

    // Stuff a couple of non-zero bytes into the headers so a flipped
    // strip would be easy to spot if it accidentally zeroed them.
    unsigned[0x58 + 28] = 0xAB; // some innocuous OptionalHeader byte
    unsigned[0x58 + 200] = 0xCD;

    // Build the "signed" version: a copy with a fake WIN_CERTIFICATE
    // table appended and a non-zero CheckSum simulating a signer that
    // recomputed it.
    const fake_cert_payload = "fake-pkcs7-blob";
    const cert_entry_len: u32 = @intCast(8 + fake_cert_payload.len);
    const padded_cert_entry_len: u32 = std.mem.alignForward(u32, cert_entry_len, 8);
    const cert_table_offset: u32 = @intCast(unsigned.len);
    const cert_table_size: u32 = padded_cert_entry_len;

    var signed = try allocator.alloc(u8, cert_table_offset + cert_table_size);
    defer allocator.free(signed);
    @memcpy(signed[0..unsigned.len], unsigned);
    // Set CheckSum to a non-zero value (signer-emitted).
    std.mem.writeInt(u32, signed[0x58 + 64 .. 0x58 + 68][0..4], 0xDEAD_BEEF, .little);
    // Fill the Security data-directory entry.
    const sec_dir = 0x58 + 112 + 32;
    std.mem.writeInt(u32, signed[sec_dir .. sec_dir + 4][0..4], cert_table_offset, .little);
    std.mem.writeInt(u32, signed[sec_dir + 4 .. sec_dir + 8][0..4], cert_table_size, .little);
    // WIN_CERTIFICATE header + payload + zero padding.
    std.mem.writeInt(u32, signed[cert_table_offset .. cert_table_offset + 4][0..4], cert_entry_len, .little);
    std.mem.writeInt(u16, signed[cert_table_offset + 4 .. cert_table_offset + 6][0..2], win_cert_revision_2_0, .little);
    std.mem.writeInt(u16, signed[cert_table_offset + 6 .. cert_table_offset + 8][0..2], win_cert_type_pkcs_signed_data, .little);
    @memcpy(signed[cert_table_offset + 8 .. cert_table_offset + 8 + fake_cert_payload.len], fake_cert_payload);
    // padding bytes between cert_entry_len and padded_cert_entry_len
    // are already zero from the alloc.

    // Strip it.
    const outcome = try stripAuthenticodeIntoBuffer(allocator, signed);
    defer allocator.free(outcome.bytes);

    // Strict bit-identity with the unsigned reference.
    try std.testing.expectEqualSlices(u8, unsigned, outcome.bytes);
    try std.testing.expectEqual(cert_table_offset, outcome.stripped_at);
    try std.testing.expectEqual(cert_table_size, outcome.stripped_bytes);
}

test "stripAuthenticodeIntoBuffer rejects unsigned input" {
    const allocator = std.testing.allocator;
    var unsigned = try allocator.alloc(u8, 0x58 + 240);
    defer allocator.free(unsigned);
    @memset(unsigned, 0);
    @memcpy(unsigned[0..2], &dos_signature);
    std.mem.writeInt(u32, unsigned[0x3C..0x40], 0x40, .little);
    @memcpy(unsigned[0x40..0x44], &nt_signature);
    std.mem.writeInt(u16, unsigned[0x44 + 16 .. 0x44 + 18][0..2], 240, .little);
    std.mem.writeInt(u16, unsigned[0x58..0x5A][0..2], pe32_plus_magic, .little);
    std.mem.writeInt(u32, unsigned[0x58 + 108 .. 0x58 + 112][0..4], 16, .little);

    try std.testing.expectError(error.NotSigned, stripAuthenticodeIntoBuffer(allocator, unsigned));
}

test "stripAuthenticodeIntoBuffer rejects cert table not at end" {
    const allocator = std.testing.allocator;
    // Build a signed-ish PE where the cert table is NOT at end of file —
    // append 16 bytes of trailing data after the cert table. The
    // stripper must refuse rather than guess.
    var unsigned = try allocator.alloc(u8, 0x58 + 240);
    defer allocator.free(unsigned);
    @memset(unsigned, 0);
    @memcpy(unsigned[0..2], &dos_signature);
    std.mem.writeInt(u32, unsigned[0x3C..0x40], 0x40, .little);
    @memcpy(unsigned[0x40..0x44], &nt_signature);
    std.mem.writeInt(u16, unsigned[0x44 + 16 .. 0x44 + 18][0..2], 240, .little);
    std.mem.writeInt(u16, unsigned[0x58..0x5A][0..2], pe32_plus_magic, .little);
    std.mem.writeInt(u32, unsigned[0x58 + 108 .. 0x58 + 112][0..4], 16, .little);

    const cert_table_offset: u32 = @intCast(unsigned.len);
    const cert_payload = "x" ** 24;
    const cert_entry_len: u32 = 8 + cert_payload.len;
    const cert_table_size: u32 = cert_entry_len; // already 8-aligned
    const trailing: u32 = 16; // extra data past the cert table

    var signed = try allocator.alloc(u8, cert_table_offset + cert_table_size + trailing);
    defer allocator.free(signed);
    @memcpy(signed[0..unsigned.len], unsigned);
    const sec_dir = 0x58 + 112 + 32;
    std.mem.writeInt(u32, signed[sec_dir .. sec_dir + 4][0..4], cert_table_offset, .little);
    std.mem.writeInt(u32, signed[sec_dir + 4 .. sec_dir + 8][0..4], cert_table_size, .little);
    std.mem.writeInt(u32, signed[cert_table_offset .. cert_table_offset + 4][0..4], cert_entry_len, .little);
    std.mem.writeInt(u16, signed[cert_table_offset + 4 .. cert_table_offset + 6][0..2], win_cert_revision_2_0, .little);
    std.mem.writeInt(u16, signed[cert_table_offset + 6 .. cert_table_offset + 8][0..2], win_cert_type_pkcs_signed_data, .little);
    @memset(signed[cert_table_offset + 8 ..][0..cert_payload.len], 'x');
    @memset(signed[cert_table_offset + cert_table_size ..][0..trailing], 0xAA);

    // parsePe itself catches the "more than 8 bytes after cert table"
    // case via error.InvalidCertTable; the stripper inherits that.
    const result = stripAuthenticodeIntoBuffer(allocator, signed);
    try std.testing.expectError(error.InvalidCertTable, result);
}

// ---------------------------------------------------------------------------
// PKCS#7 SignedData (CMS) parser for Authenticode signatures.
//
// Authenticode embeds a single PKCS#7 `SignedData` structure in each
// `WIN_CERTIFICATE` entry. The relevant ASN.1 shape (RFC 5652 / PKCS#7
// + Microsoft's Authenticode extensions):
//
//   ContentInfo ::= SEQUENCE {
//       contentType OBJECT IDENTIFIER,   -- 1.2.840.113549.1.7.2 (signedData)
//       content     [0] EXPLICIT SignedData
//   }
//
//   SignedData ::= SEQUENCE {
//       version              INTEGER,
//       digestAlgorithms     SET OF AlgorithmIdentifier,
//       encapContentInfo     EncapsulatedContentInfo,  -- spcIndirectData
//       certificates         [0] IMPLICIT CertificateSet OPTIONAL,
//       crls                 [1] IMPLICIT RevocationInfoChoices OPTIONAL,
//       signerInfos          SET OF SignerInfo
//   }
//
//   EncapsulatedContentInfo ::= SEQUENCE {
//       eContentType         OBJECT IDENTIFIER,  -- 1.3.6.1.4.1.311.2.1.4
//       eContent             [0] EXPLICIT OCTET STRING OPTIONAL  -- SpcIndirectDataContent
//   }
//
//   SpcIndirectDataContent ::= SEQUENCE {
//       data                 SpcAttributeTypeAndOptionalValue,
//       messageDigest        DigestInfo
//   }
//
//   DigestInfo ::= SEQUENCE {
//       digestAlgorithm      AlgorithmIdentifier,
//       digest               OCTET STRING
//   }
//
//   SignerInfo ::= SEQUENCE {
//       version              INTEGER,
//       sid                  SignerIdentifier,    -- IssuerAndSerialNumber or [0] SKI
//       digestAlgorithm      AlgorithmIdentifier,
//       signedAttrs          [0] IMPLICIT SET OF Attribute OPTIONAL,
//       signatureAlgorithm   AlgorithmIdentifier,
//       signature            OCTET STRING,
//       unsignedAttrs        [1] IMPLICIT SET OF Attribute OPTIONAL
//   }
//
//   Attribute ::= SEQUENCE {
//       attrType             OBJECT IDENTIFIER,
//       attrValues           SET OF AttrValue
//   }
//
// The CMS signer signature is computed over the DER re-encoding of the
// signedAttrs SET with its IMPLICIT [0] tag (0xA0) replaced by the
// explicit SET OF tag (0x31). That re-encoding is a documented CMS
// quirk; we materialise it on demand for verification.
// ---------------------------------------------------------------------------

const Certificate = std.crypto.Certificate;
const der = Certificate.der;

/// Well-known OIDs in raw DER content form (without the leading tag +
/// length prefix). These match `Certificate.der.Element.slice` content
/// for an OID element.
pub const oid = struct {
    pub const signed_data = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02 };
    pub const spc_indirect_data = [_]u8{ 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04 };
    pub const message_digest = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04 };
    pub const content_type = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03 };
    pub const signing_time = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05 };
    pub const timestamp_token = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x0E };
    /// Microsoft's variant of the RFC 3161 timestamp counter-signature
    /// attribute (`szOID_RFC3161_counterSign`). DigiCert and other
    /// commercial Authenticode signers commonly use this OID instead of
    /// the standard `id-aa-signatureTimeStampToken`.
    pub const ms_timestamp_token = [_]u8{ 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x03, 0x03, 0x01 };
    pub const nested_signature = [_]u8{ 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x04, 0x01 };

    pub const sha256 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };
    pub const sha384 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02 };
    pub const sha512 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 };

    pub const rsa_encryption = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
    pub const sha256_with_rsa = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B };
    pub const sha384_with_rsa = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C };
    pub const sha512_with_rsa = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D };
    pub const ecdsa_with_sha256 = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };
    pub const ecdsa_with_sha384 = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03 };

    /// RFC 3161 id-ct-TSTInfo — encapContentType for TimeStampToken.
    pub const tst_info = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x04 };
};

/// Hash algorithm referenced by an Authenticode SignedData. Authenticode
/// itself is restricted to SHA-256 in practice; SHA-1 historically and
/// SHA-384/-512 in newer specs.
pub const HashAlgorithm = enum { sha256, sha384, sha512 };

/// Signature algorithm of the SignerInfo / TSA SignerInfo.
pub const SignatureAlgorithm = enum {
    rsa_pkcs1_v15_sha256,
    rsa_pkcs1_v15_sha384,
    rsa_pkcs1_v15_sha512,
    /// "Plain" rsaEncryption (no hash baked into the OID) — the hash is
    /// supplied separately via the SignerInfo's `digestAlgorithm`.
    rsa_pkcs1_v15_implicit_hash,
    ecdsa_sha256,
    ecdsa_sha384,
};

pub const Pkcs7Error = error{
    InvalidContentInfo,
    UnsupportedContentType,
    InvalidSignedData,
    UnsupportedSignedDataVersion,
    UnsupportedEncapContentType,
    InvalidSpcIndirectData,
    UnsupportedDigestAlgorithm,
    UnsupportedSignatureAlgorithm,
    InvalidSignerInfo,
    MissingSignedAttrs,
    MissingMessageDigestAttr,
    MissingContentTypeAttr,
    UnsupportedCertificateSet,
    SignedAttrsTooLarge,
} || der.Element.ParseError;

/// One signer of an Authenticode SignedData. We only model what we need
/// to verify: the message digest claim, the signed-attrs re-encoding,
/// and the signer's signature.
pub const SignerInfo = struct {
    /// `version` integer (must be 1 for IssuerAndSerialNumber form).
    version: u8,
    /// Hash algorithm declared by `digestAlgorithm`.
    digest_alg: HashAlgorithm,
    /// Signature algorithm declared by `signatureAlgorithm`.
    signature_alg: SignatureAlgorithm,
    /// Raw DER bytes of the `signedAttrs` SET (with its IMPLICIT [0]
    /// tag still in place). The CMS-canonical message-to-be-signed is
    /// obtained by replacing the leading 0xA0 with 0x31; see
    /// `signedAttrsForSigning`.
    signed_attrs_raw: []const u8,
    /// Decrypted-on-verify signature bytes. For RSA, this is the raw
    /// PKCS#1 v1.5 signature; for ECDSA, the DER-encoded (r,s) pair.
    signature: []const u8,
    /// Raw DER bytes of the `unsignedAttrs` SET (or empty when absent).
    /// The IMPLICIT [1] tag (0xA1) is still in place.
    unsigned_attrs_raw: []const u8,
    /// `messageDigest` attribute value (the file's digest, per the
    /// signer).
    message_digest: []const u8,
    /// Raw DER bytes of `SignerIdentifier`. For our purposes this is
    /// IssuerAndSerialNumber; we treat it as an opaque blob used only
    /// for "did this cert sign this SignerInfo?" lookups.
    sid_raw: []const u8,
};

/// Parsed Authenticode SignedData. All slices are sub-slices of the
/// input PKCS#7 blob; the struct does not own any memory.
pub const SignedData = struct {
    /// The whole PKCS#7 ContentInfo blob this was parsed from.
    raw: []const u8,
    /// `eContentType` of the encapContentInfo (always
    /// `oid.spc_indirect_data` for Authenticode).
    encap_content_type: []const u8,
    /// Raw DER bytes of the SpcIndirectDataContent SEQUENCE (without
    /// the OCTET STRING wrapper). Useful for the Rekor-like binding
    /// check: sha256(spc_indirect_data) must equal the
    /// `messageDigest` signed attribute on the SignerInfo.
    spc_indirect_data: []const u8,
    /// File digest extracted from SpcIndirectDataContent.messageDigest.
    file_digest_alg: HashAlgorithm,
    file_digest: []const u8,
    /// Raw DER of the certificates SET ([0] IMPLICIT). Each child
    /// is a complete X.509 certificate.
    certificates_raw: []const u8,
    /// The first SignerInfo. Authenticode signatures are
    /// single-signer; nested signatures live in the SignerInfo's
    /// `unsignedAttrs` and are walked separately.
    signer: SignerInfo,
};

/// Parse a PKCS#7 ContentInfo blob carrying SignedData. The returned
/// `SignedData` borrows from `pkcs7_bytes`.
pub fn parseSignedData(pkcs7_bytes: []const u8) Pkcs7Error!SignedData {
    return parseSignedDataInternal(pkcs7_bytes, &oid.spc_indirect_data);
}

/// Parse a PKCS#7 ContentInfo blob carrying SignedData whose
/// encapContentType is `id-ct-TSTInfo` — i.e. an RFC 3161 TimeStamp
/// Token (which is itself a PKCS#7 SignedData over a TSTInfo
/// structure).
///
/// The returned `SignedData.spc_indirect_data` field carries the
/// **raw TSTInfo bytes** in this case, not an SpcIndirectDataContent.
/// `file_digest` / `file_digest_alg` are unused for TSTInfo (set to
/// SHA-256 zero placeholders); callers parse the TSTInfo directly via
/// `parseTstInfo`.
pub fn parseTimestampToken(pkcs7_bytes: []const u8) Pkcs7Error!SignedData {
    return parseSignedDataInternal(pkcs7_bytes, &oid.tst_info);
}

fn parseSignedDataInternal(
    pkcs7_bytes: []const u8,
    expected_encap_content_type: []const u8,
) Pkcs7Error!SignedData {
    // ContentInfo := SEQUENCE { contentType OID, content [0] EXPLICIT SignedData }
    const ci = try der.Element.parse(pkcs7_bytes, 0);
    if (ci.identifier.tag != .sequence) return error.InvalidContentInfo;
    const ci_end = ci.slice.end;

    const ci_oid = try der.Element.parse(pkcs7_bytes, ci.slice.start);
    if (ci_oid.identifier.tag != .object_identifier) return error.InvalidContentInfo;
    if (!std.mem.eql(u8, pkcs7_bytes[ci_oid.slice.start..ci_oid.slice.end], &oid.signed_data))
        return error.UnsupportedContentType;

    const ci_content_explicit = try der.Element.parse(pkcs7_bytes, ci_oid.slice.end);
    if (!isContextSpecificTag(ci_content_explicit.identifier, 0))
        return error.InvalidContentInfo;
    if (ci_content_explicit.slice.end > ci_end) return error.InvalidContentInfo;

    // SignedData := SEQUENCE { ... }
    const sd = try der.Element.parse(pkcs7_bytes, ci_content_explicit.slice.start);
    if (sd.identifier.tag != .sequence) return error.InvalidSignedData;

    var i: u32 = sd.slice.start;
    const sd_end: u32 = sd.slice.end;

    // version INTEGER
    const ver_elem = try der.Element.parse(pkcs7_bytes, i);
    if (ver_elem.identifier.tag != .integer) return error.InvalidSignedData;
    if (ver_elem.slice.end - ver_elem.slice.start != 1) return error.UnsupportedSignedDataVersion;
    // version 1 (PKCS#7) or 3 (CMS with SubjectKeyIdentifier signer) are
    // both seen in the wild. Authenticode uses 1.
    const version = pkcs7_bytes[ver_elem.slice.start];
    if (version != 1 and version != 3) return error.UnsupportedSignedDataVersion;
    i = ver_elem.slice.end;

    // digestAlgorithms SET OF AlgorithmIdentifier — skipped; we trust
    // the SignerInfo's own digestAlgorithm.
    const dalgs = try der.Element.parse(pkcs7_bytes, i);
    i = dalgs.slice.end;

    // encapContentInfo SEQUENCE { eContentType, [0] EXPLICIT eContent OCTET STRING }
    const enc = try der.Element.parse(pkcs7_bytes, i);
    if (enc.identifier.tag != .sequence) return error.InvalidSignedData;
    i = enc.slice.end;

    const enc_ct = try der.Element.parse(pkcs7_bytes, enc.slice.start);
    if (enc_ct.identifier.tag != .object_identifier) return error.InvalidSignedData;
    const encap_content_type = pkcs7_bytes[enc_ct.slice.start..enc_ct.slice.end];
    if (!std.mem.eql(u8, encap_content_type, expected_encap_content_type))
        return error.UnsupportedEncapContentType;

    const enc_content_wrap = try der.Element.parse(pkcs7_bytes, enc_ct.slice.end);
    if (!isContextSpecificTag(enc_content_wrap.identifier, 0))
        return error.InvalidSpcIndirectData;
    const enc_content = try der.Element.parse(pkcs7_bytes, enc_content_wrap.slice.start);
    if (enc_content.identifier.tag != .octetstring and enc_content.identifier.tag != .sequence)
        return error.InvalidSpcIndirectData;

    // Two shapes appear in the wild:
    //
    //   * CMS-standard: `[0] EXPLICIT OCTET STRING` wrapping the
    //     payload. The OCTET STRING body IS the SpcIndirectData /
    //     TSTInfo SEQUENCE bytes. `inner_bytes` = octet-string body.
    //
    //   * Authenticode / Microsoft variant: `[0] EXPLICIT` wraps the
    //     payload SEQUENCE directly (no OCTET STRING). `inner_bytes`
    //     = the SEQUENCE's full TLV span so the downstream parser can
    //     locate its tag.
    const inner_bytes = if (enc_content.identifier.tag == .octetstring)
        pkcs7_bytes[enc_content.slice.start..enc_content.slice.end]
    else
        pkcs7_bytes[enc_content_wrap.slice.start..enc_content.slice.end];

    var file_digest_alg: HashAlgorithm = .sha256;
    var file_digest: []const u8 = &.{};
    if (std.mem.eql(u8, expected_encap_content_type, &oid.spc_indirect_data)) {
        const fd = try parseSpcIndirectDataMessageDigest(inner_bytes);
        file_digest_alg = fd.alg;
        file_digest = fd.digest;
    }

    // certificates [0] IMPLICIT CertificateSet OPTIONAL — required for our path.
    var certificates_raw: []const u8 = &.{};
    var ji = i;
    if (ji < sd_end) {
        const next = try der.Element.parse(pkcs7_bytes, ji);
        if (isContextSpecificTag(next.identifier, 0)) {
            certificates_raw = pkcs7_bytes[next.slice.start..next.slice.end];
            ji = next.slice.end;
        }
    }
    // crls [1] IMPLICIT — skipped.
    if (ji < sd_end) {
        const next = try der.Element.parse(pkcs7_bytes, ji);
        if (isContextSpecificTag(next.identifier, 1)) ji = next.slice.end;
    }

    // signerInfos SET OF SignerInfo
    const sinfos = try der.Element.parse(pkcs7_bytes, ji);
    if (sinfos.identifier.tag != .sequence_of and sinfos.identifier.tag != .sequence)
        return error.InvalidSignedData;

    const first_signer = try der.Element.parse(pkcs7_bytes, sinfos.slice.start);
    if (first_signer.identifier.tag != .sequence) return error.InvalidSignerInfo;
    const signer = try parseSignerInfo(pkcs7_bytes, first_signer);

    return .{
        .raw = pkcs7_bytes[ci.slice.start - 0 .. ci.slice.end], // span of ContentInfo content body
        .encap_content_type = encap_content_type,
        .spc_indirect_data = inner_bytes,
        .file_digest_alg = file_digest_alg,
        .file_digest = file_digest,
        .certificates_raw = certificates_raw,
        .signer = signer,
    };
}

const FileDigest = struct { alg: HashAlgorithm, digest: []const u8 };

fn parseSpcIndirectDataMessageDigest(spc: []const u8) Pkcs7Error!FileDigest {
    const root = try der.Element.parse(spc, 0);
    if (root.identifier.tag != .sequence) return error.InvalidSpcIndirectData;

    // SpcIndirectDataContent := SEQUENCE { data SpcAttributeTypeAndOptionalValue, messageDigest DigestInfo }
    const data = try der.Element.parse(spc, root.slice.start);
    if (data.identifier.tag != .sequence) return error.InvalidSpcIndirectData;

    const digest_info = try der.Element.parse(spc, data.slice.end);
    if (digest_info.identifier.tag != .sequence) return error.InvalidSpcIndirectData;

    // DigestInfo := SEQUENCE { digestAlgorithm AlgorithmIdentifier, digest OCTET STRING }
    const algo_seq = try der.Element.parse(spc, digest_info.slice.start);
    if (algo_seq.identifier.tag != .sequence) return error.InvalidSpcIndirectData;
    const algo_oid = try der.Element.parse(spc, algo_seq.slice.start);
    if (algo_oid.identifier.tag != .object_identifier) return error.InvalidSpcIndirectData;
    const alg = try hashAlgFromOid(spc[algo_oid.slice.start..algo_oid.slice.end]);

    const digest_oct = try der.Element.parse(spc, algo_seq.slice.end);
    if (digest_oct.identifier.tag != .octetstring) return error.InvalidSpcIndirectData;

    return .{ .alg = alg, .digest = spc[digest_oct.slice.start..digest_oct.slice.end] };
}

fn parseSignerInfo(buf: []const u8, sinfo: der.Element) Pkcs7Error!SignerInfo {
    var i: u32 = sinfo.slice.start;
    const end: u32 = sinfo.slice.end;

    // version INTEGER
    const ver = try der.Element.parse(buf, i);
    if (ver.identifier.tag != .integer) return error.InvalidSignerInfo;
    if (ver.slice.end - ver.slice.start != 1) return error.InvalidSignerInfo;
    const version = buf[ver.slice.start];
    i = ver.slice.end;

    // sid SignerIdentifier
    const sid = try der.Element.parse(buf, i);
    const sid_raw = buf[sid.slice.start - elementHeaderLen(buf, sid) .. sid.slice.end];
    i = sid.slice.end;

    // digestAlgorithm AlgorithmIdentifier
    const dalg = try der.Element.parse(buf, i);
    if (dalg.identifier.tag != .sequence) return error.InvalidSignerInfo;
    const dalg_oid = try der.Element.parse(buf, dalg.slice.start);
    if (dalg_oid.identifier.tag != .object_identifier) return error.InvalidSignerInfo;
    const digest_alg = try hashAlgFromOid(buf[dalg_oid.slice.start..dalg_oid.slice.end]);
    i = dalg.slice.end;

    // signedAttrs [0] IMPLICIT SET OF Attribute (required for Authenticode)
    const sa = try der.Element.parse(buf, i);
    if (!isContextSpecificTag(sa.identifier, 0)) return error.MissingSignedAttrs;
    // Raw signed-attrs span (including its own [0] tag + length header)
    // so we can re-emit it as SET OF for signature verification.
    const sa_full_start: usize = i;
    const sa_full_end: usize = sa.slice.end;
    const signed_attrs_raw = buf[sa_full_start..sa_full_end];
    if (signed_attrs_raw.len > std.math.maxInt(u32)) return error.SignedAttrsTooLarge;

    // Walk signedAttrs to find messageDigest + contentType.
    var msg_digest: []const u8 = &.{};
    var found_content_type = false;
    var ai: u32 = sa.slice.start;
    while (ai < sa.slice.end) {
        const attr = try der.Element.parse(buf, ai);
        if (attr.identifier.tag != .sequence) return error.InvalidSignerInfo;
        ai = attr.slice.end;

        const attr_oid_e = try der.Element.parse(buf, attr.slice.start);
        if (attr_oid_e.identifier.tag != .object_identifier) return error.InvalidSignerInfo;
        const attr_oid_bytes = buf[attr_oid_e.slice.start..attr_oid_e.slice.end];

        const attr_vals = try der.Element.parse(buf, attr_oid_e.slice.end);
        // SET OF AttrValue — first value is what we want.
        const first_val = try der.Element.parse(buf, attr_vals.slice.start);

        if (std.mem.eql(u8, attr_oid_bytes, &oid.message_digest)) {
            if (first_val.identifier.tag != .octetstring) return error.InvalidSignerInfo;
            msg_digest = buf[first_val.slice.start..first_val.slice.end];
        } else if (std.mem.eql(u8, attr_oid_bytes, &oid.content_type)) {
            found_content_type = true;
        }
    }
    if (msg_digest.len == 0) return error.MissingMessageDigestAttr;
    if (!found_content_type) return error.MissingContentTypeAttr;
    i = @intCast(sa_full_end);

    // signatureAlgorithm AlgorithmIdentifier
    const salg = try der.Element.parse(buf, i);
    if (salg.identifier.tag != .sequence) return error.InvalidSignerInfo;
    const salg_oid_e = try der.Element.parse(buf, salg.slice.start);
    if (salg_oid_e.identifier.tag != .object_identifier) return error.InvalidSignerInfo;
    const salg_oid_bytes = buf[salg_oid_e.slice.start..salg_oid_e.slice.end];
    const sig_alg = try sigAlgFromOid(salg_oid_bytes);
    i = salg.slice.end;

    // signature OCTET STRING
    const sig_e = try der.Element.parse(buf, i);
    if (sig_e.identifier.tag != .octetstring) return error.InvalidSignerInfo;
    const signature = buf[sig_e.slice.start..sig_e.slice.end];
    i = sig_e.slice.end;

    // unsignedAttrs [1] IMPLICIT SET OF Attribute OPTIONAL
    var unsigned_attrs_raw: []const u8 = &.{};
    if (i < end) {
        const ua = try der.Element.parse(buf, i);
        if (isContextSpecificTag(ua.identifier, 1)) {
            unsigned_attrs_raw = buf[i..ua.slice.end];
            i = ua.slice.end;
        }
    }

    return .{
        .version = version,
        .digest_alg = digest_alg,
        .signature_alg = sig_alg,
        .signed_attrs_raw = signed_attrs_raw,
        .signature = signature,
        .unsigned_attrs_raw = unsigned_attrs_raw,
        .message_digest = msg_digest,
        .sid_raw = sid_raw,
    };
}

/// Materialise the CMS-canonical message-to-be-signed from
/// `SignerInfo.signed_attrs_raw`: replace the leading IMPLICIT [0]
/// tag (0xA0) with the universal SET OF tag (0x31). The body bytes
/// are unchanged; only the first byte differs.
///
/// The returned buffer is allocated from `allocator`; ownership is
/// transferred to the caller. (We don't slice-in-place because
/// `signed_attrs_raw` may be a sub-slice of an `@embedFile`'d const
/// blob.)
pub fn signedAttrsForSigning(
    allocator: std.mem.Allocator,
    signer: SignerInfo,
) ![]u8 {
    if (signer.signed_attrs_raw.len == 0 or signer.signed_attrs_raw[0] != 0xA0)
        return error.InvalidSignerInfo;
    const buf = try allocator.alloc(u8, signer.signed_attrs_raw.len);
    @memcpy(buf, signer.signed_attrs_raw);
    buf[0] = 0x31; // [0] IMPLICIT → SET OF
    return buf;
}

/// Find the first unsigned-attribute value with the given OID in
/// `signer.unsigned_attrs_raw`. Returns the full TLV span of the
/// first `AttrValue` for that attribute (so the caller can re-parse
/// it as a SEQUENCE / OCTET STRING / etc.), or null when the
/// attribute is absent.
pub fn findUnsignedAttr(signer: SignerInfo, target_oid: []const u8) Pkcs7Error!?[]const u8 {
    if (signer.unsigned_attrs_raw.len == 0) return null;
    // unsigned_attrs_raw starts with the [1] IMPLICIT tag (0xA1).
    const ua = try der.Element.parse(signer.unsigned_attrs_raw, 0);
    if (!isContextSpecificTag(ua.identifier, 1)) return error.InvalidSignerInfo;

    var ai: u32 = ua.slice.start;
    while (ai < ua.slice.end) {
        const attr = try der.Element.parse(signer.unsigned_attrs_raw, ai);
        if (attr.identifier.tag != .sequence) return error.InvalidSignerInfo;
        ai = attr.slice.end;

        const attr_oid_e = try der.Element.parse(signer.unsigned_attrs_raw, attr.slice.start);
        if (attr_oid_e.identifier.tag != .object_identifier) return error.InvalidSignerInfo;
        const this_oid = signer.unsigned_attrs_raw[attr_oid_e.slice.start..attr_oid_e.slice.end];
        if (!std.mem.eql(u8, this_oid, target_oid)) continue;

        const attr_vals = try der.Element.parse(signer.unsigned_attrs_raw, attr_oid_e.slice.end);
        // Return the full TLV span of the first AttrValue so callers
        // can re-parse it as the appropriate ASN.1 type.
        const first_val = try der.Element.parse(signer.unsigned_attrs_raw, attr_vals.slice.start);
        const tlv_start = attr_vals.slice.start;
        const tlv_end = first_val.slice.end;
        return signer.unsigned_attrs_raw[tlv_start..tlv_end];
    }
    return null;
}

// ---------------------------------------------------------------------------
// DER helpers.
// ---------------------------------------------------------------------------

fn isContextSpecificTag(id: der.Identifier, tag_no: u5) bool {
    return id.class == .context_specific and @intFromEnum(id.tag) == tag_no;
}

fn hashAlgFromOid(oid_bytes: []const u8) Pkcs7Error!HashAlgorithm {
    if (std.mem.eql(u8, oid_bytes, &oid.sha256)) return .sha256;
    if (std.mem.eql(u8, oid_bytes, &oid.sha384)) return .sha384;
    if (std.mem.eql(u8, oid_bytes, &oid.sha512)) return .sha512;
    return error.UnsupportedDigestAlgorithm;
}

fn sigAlgFromOid(oid_bytes: []const u8) Pkcs7Error!SignatureAlgorithm {
    if (std.mem.eql(u8, oid_bytes, &oid.sha256_with_rsa)) return .rsa_pkcs1_v15_sha256;
    if (std.mem.eql(u8, oid_bytes, &oid.sha384_with_rsa)) return .rsa_pkcs1_v15_sha384;
    if (std.mem.eql(u8, oid_bytes, &oid.sha512_with_rsa)) return .rsa_pkcs1_v15_sha512;
    if (std.mem.eql(u8, oid_bytes, &oid.rsa_encryption)) return .rsa_pkcs1_v15_implicit_hash;
    if (std.mem.eql(u8, oid_bytes, &oid.ecdsa_with_sha256)) return .ecdsa_sha256;
    if (std.mem.eql(u8, oid_bytes, &oid.ecdsa_with_sha384)) return .ecdsa_sha384;
    return error.UnsupportedSignatureAlgorithm;
}

/// Number of header bytes (tag + length octets) preceding the content
/// bytes of `elem`. Used to recover the "whole TLV" span when we need
/// to copy/re-encode an element.
fn elementHeaderLen(buf: []const u8, elem: der.Element) u32 {
    _ = buf;
    const content_len = elem.slice.end - elem.slice.start;
    if (content_len < 0x80) return 2; // tag + 1 length byte
    var n: u32 = 0;
    var v: u32 = content_len;
    while (v != 0) : (v >>= 8) n += 1;
    return 2 + n; // tag + (0x80|len_len) + len_len bytes
}

// ---------------------------------------------------------------------------
// Signer signature verification and certificate chain walk.
// ---------------------------------------------------------------------------

const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP384Sha384 = std.crypto.sign.ecdsa.Ecdsa(
    std.crypto.ecc.P384,
    std.crypto.hash.sha2.Sha384,
);

pub const VerifyError = error{
    InvalidSignature,
    SignerCertNotFound,
    BundleSignerMismatch,
    UnsupportedSignerKeyType,
    InvalidCertificateChoice,
    OutOfMemory,
} || Pkcs7Error || der.Element.ParseError || Certificate.ParseError || Certificate.Parsed.VerifyError;

/// Iterator over a CMS `CertificateSet` body (i.e. `signed_data.certificates_raw`,
/// the body of the `[0] IMPLICIT CertificateSet` wrapper).
///
/// `CertificateSet ::= SET OF CertificateChoices`, where `CertificateChoices`
/// is a CHOICE between `Certificate` (SEQUENCE) and `extendedCertificate [0]`,
/// `v1AttrCert [1]`, `v2AttrCert [2]`, `other [3]` — all `IMPLICIT`-tagged
/// context-specific. Only the SEQUENCE choice carries an X.509 certificate
/// usable for chain building; the rest are skipped.
///
/// Microsoft's Time-Stamp Service routinely includes a `v2AttrCert [2]` entry
/// in the timestamp token's CertificateSet, so this skip behaviour is
/// load-bearing for verifying Microsoft-signed binaries.
const CertificateSetIterator = struct {
    bytes: []const u8,
    index: u32 = 0,

    /// DER bytes of the next `certificate` (X.509) entry, or null when
    /// exhausted. Non-`certificate` choices (attribute certs, etc.) are
    /// silently skipped. Returns `error.InvalidCertificateChoice` if an
    /// element has neither a universal SEQUENCE tag nor a context-specific
    /// tag in the [0..3] CHOICE range.
    fn next(self: *CertificateSetIterator) (der.Element.ParseError || error{InvalidCertificateChoice})!?[]const u8 {
        while (self.index < self.bytes.len) {
            const elem = try der.Element.parse(self.bytes, self.index);
            const start = self.index;
            self.index = elem.slice.end;

            if (elem.identifier.tag == .sequence and elem.identifier.class == .universal) {
                return self.bytes[start..elem.slice.end];
            }
            if (elem.identifier.class == .context_specific and @intFromEnum(elem.identifier.tag) <= 3) {
                // Valid CertificateChoices alternative we don't care about.
                continue;
            }
            return error.InvalidCertificateChoice;
        }
        return null;
    }
};

/// Verify `signer.signature` against the message-to-be-signed
/// (signedAttrs re-tagged as SET OF) using the signer cert's public
/// key. The cert is located in `signed_data.certificates_raw` by
/// matching `signer.sid_raw` (IssuerAndSerialNumber).
pub fn verifySignerSignature(
    allocator: std.mem.Allocator,
    signed_data: SignedData,
) VerifyError!void {
    // Re-encode signedAttrs as SET OF for the signature input.
    const msg = signedAttrsForSigning(allocator, signed_data.signer) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidSignerInfo,
    };
    defer allocator.free(msg);

    const signer_cert_der = (try findSignerCertDer(signed_data)) orelse
        return error.SignerCertNotFound;

    // Parse the leaf cert, extract its SubjectPublicKeyInfo, dispatch on
    // public-key + signature algorithm pair.
    var cert: Certificate = .{ .buffer = signer_cert_der, .index = 0 };
    const parsed = try cert.parse();

    switch (signed_data.signer.signature_alg) {
        .rsa_pkcs1_v15_sha256, .rsa_pkcs1_v15_implicit_hash => {
            // For .rsa_pkcs1_v15_implicit_hash the hash comes from the
            // SignerInfo's digestAlgorithm. We require that to also be
            // SHA-256 for now; SHA-384/-512 follow the same pattern.
            switch (signed_data.signer.digest_alg) {
                .sha256 => try verifyRsaPkcs1v15(
                    msg,
                    signed_data.signer.signature,
                    parsed.pubKey(),
                    std.crypto.hash.sha2.Sha256,
                ),
                .sha384 => try verifyRsaPkcs1v15(
                    msg,
                    signed_data.signer.signature,
                    parsed.pubKey(),
                    std.crypto.hash.sha2.Sha384,
                ),
                .sha512 => try verifyRsaPkcs1v15(
                    msg,
                    signed_data.signer.signature,
                    parsed.pubKey(),
                    std.crypto.hash.sha2.Sha512,
                ),
            }
        },
        .rsa_pkcs1_v15_sha384 => try verifyRsaPkcs1v15(
            msg,
            signed_data.signer.signature,
            parsed.pubKey(),
            std.crypto.hash.sha2.Sha384,
        ),
        .rsa_pkcs1_v15_sha512 => try verifyRsaPkcs1v15(
            msg,
            signed_data.signer.signature,
            parsed.pubKey(),
            std.crypto.hash.sha2.Sha512,
        ),
        .ecdsa_sha256 => try verifyEcdsa(EcdsaP256Sha256, msg, signed_data.signer.signature, parsed.pubKey()),
        .ecdsa_sha384 => try verifyEcdsa(EcdsaP384Sha384, msg, signed_data.signer.signature, parsed.pubKey()),
    }
}

fn verifyRsaPkcs1v15(
    msg: []const u8,
    signature: []const u8,
    pub_key_der: []const u8,
    comptime Hash: type,
) VerifyError!void {
    const pk_components = Certificate.rsa.PublicKey.parseDer(pub_key_der) catch
        return error.InvalidSignature;
    const exponent = pk_components.exponent;
    const modulus = pk_components.modulus;
    if (exponent.len > modulus.len) return error.InvalidSignature;
    if (signature.len != modulus.len) return error.InvalidSignature;

    switch (modulus.len) {
        inline 128, 256, 384, 512 => |modulus_len| {
            const pub_key = Certificate.rsa.PublicKey.fromBytes(exponent, modulus) catch
                return error.InvalidSignature;
            Certificate.rsa.PKCS1v1_5Signature.verify(
                modulus_len,
                signature[0..modulus_len].*,
                msg,
                pub_key,
                Hash,
            ) catch return error.InvalidSignature;
        },
        else => return error.UnsupportedSignerKeyType,
    }
}

fn verifyEcdsa(
    comptime Ec: type,
    msg: []const u8,
    signature_der: []const u8,
    pub_key_sec1: []const u8,
) VerifyError!void {
    const sig = Ec.Signature.fromDer(signature_der) catch return error.InvalidSignature;
    const pub_key = Ec.PublicKey.fromSec1(pub_key_sec1) catch return error.InvalidSignature;
    sig.verify(msg, pub_key) catch return error.InvalidSignature;
}

/// Locate the signer's leaf certificate in `signed_data.certificates_raw`
/// by matching against `signer.sid_raw` (the IssuerAndSerialNumber
/// SignerIdentifier). Returns the raw DER bytes of the cert, or null
/// when no matching cert was found.
pub fn findSignerCertDer(signed_data: SignedData) VerifyError!?[]const u8 {
    if (signed_data.certificates_raw.len == 0) return null;
    // certificates_raw is the body of the [0] IMPLICIT wrapper — i.e.
    // a concatenation of certificate SEQUENCEs.

    // Parse the SignerIdentifier (IssuerAndSerialNumber) once.
    const sid = signed_data.signer.sid_raw;
    if (sid.len == 0) return null;
    const sid_seq = try der.Element.parse(sid, 0);
    if (sid_seq.identifier.tag != .sequence) return error.InvalidSignerInfo;
    const sid_issuer = try der.Element.parse(sid, sid_seq.slice.start);
    if (sid_issuer.identifier.tag != .sequence) return error.InvalidSignerInfo;
    const sid_serial = try der.Element.parse(sid, sid_issuer.slice.end);
    if (sid_serial.identifier.tag != .integer) return error.InvalidSignerInfo;

    var iter: CertificateSetIterator = .{ .bytes = signed_data.certificates_raw };
    while (try iter.next()) |cert_der| {
        // Parse cert into Certificate.Parsed to grab issuer + serial.
        var cert: Certificate = .{ .buffer = cert_der, .index = 0 };
        const parsed = cert.parse() catch continue;

        // Compare issuer DN bytes.
        const cert_issuer = cert_der[parsed.issuer_slice.start..parsed.issuer_slice.end];
        const sid_issuer_bytes = sid[sid_issuer.slice.start..sid_issuer.slice.end];
        if (!std.mem.eql(u8, cert_issuer, sid_issuer_bytes)) continue;

        // Compare serial number bytes by walking the cert DER directly,
        // since Certificate.Parsed doesn't expose the serial number.
        // tbsCertificate := SEQUENCE { version [0] EXPLICIT, serial INTEGER, ... }
        // We don't need version; the serial is either the first or
        // second element of tbsCertificate.
        const cert_outer = try der.Element.parse(cert_der, 0);
        const tbs = try der.Element.parse(cert_der, cert_outer.slice.start);
        var serial_offset: u32 = tbs.slice.start;
        const maybe_version = try der.Element.parse(cert_der, serial_offset);
        if (isContextSpecificTag(maybe_version.identifier, 0)) {
            serial_offset = maybe_version.slice.end;
        }
        const serial_elem = try der.Element.parse(cert_der, serial_offset);
        if (serial_elem.identifier.tag != .integer) return error.InvalidSignerInfo;
        const cert_serial = cert_der[serial_elem.slice.start..serial_elem.slice.end];
        const sid_serial_bytes = sid[sid_serial.slice.start..sid_serial.slice.end];
        if (!std.mem.eql(u8, cert_serial, sid_serial_bytes)) continue;

        return cert_der;
    }
    return null;
}

// ---------------------------------------------------------------------------
// RFC 3161 TimeStampToken parsing and verification.
//
// The RFC 3161 timestamp countersignature is a separate PKCS#7
// SignedData (over a TSTInfo) that the upstream TSA produced when the
// signer asked for a trustworthy clock. It is what lets us verify
// signatures past the leaf cert's notAfter.
// ---------------------------------------------------------------------------

pub const TstError = error{
    InvalidTstInfo,
    UnsupportedTstInfoVersion,
    TstInfoMessageImprintMismatch,
    InvalidGeneralizedTime,
} || Pkcs7Error;

/// Parsed TSTInfo carrying just enough info to bind the timestamp
/// back to the signer's signature and expose `gen_time` as the
/// validity clock.
pub const TstInfo = struct {
    /// SHA-256 (or other) hash of the data the TSA witnessed. For an
    /// Authenticode timestamp countersignature this equals
    /// sha256(outer SignerInfo.signature).
    imprint_alg: HashAlgorithm,
    imprint: []const u8,
    /// GeneralizedTime seconds-since-epoch (UTC).
    gen_time: i64,
};

/// Parse the raw DER bytes of a TSTInfo SEQUENCE.
pub fn parseTstInfo(bytes: []const u8) TstError!TstInfo {
    const root = try der.Element.parse(bytes, 0);
    if (root.identifier.tag != .sequence) return error.InvalidTstInfo;
    var i: u32 = root.slice.start;

    // version INTEGER { v1(1) }
    const ver = try der.Element.parse(bytes, i);
    if (ver.identifier.tag != .integer) return error.InvalidTstInfo;
    if (ver.slice.end - ver.slice.start != 1) return error.UnsupportedTstInfoVersion;
    if (bytes[ver.slice.start] != 1) return error.UnsupportedTstInfoVersion;
    i = ver.slice.end;

    // policy TSAPolicyId (OBJECT IDENTIFIER)
    const policy = try der.Element.parse(bytes, i);
    if (policy.identifier.tag != .object_identifier) return error.InvalidTstInfo;
    i = policy.slice.end;

    // messageImprint SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }
    const mi = try der.Element.parse(bytes, i);
    if (mi.identifier.tag != .sequence) return error.InvalidTstInfo;
    const halg = try der.Element.parse(bytes, mi.slice.start);
    if (halg.identifier.tag != .sequence) return error.InvalidTstInfo;
    const halg_oid = try der.Element.parse(bytes, halg.slice.start);
    if (halg_oid.identifier.tag != .object_identifier) return error.InvalidTstInfo;
    const imprint_alg = hashAlgFromOid(bytes[halg_oid.slice.start..halg_oid.slice.end]) catch
        return error.InvalidTstInfo;
    const himg = try der.Element.parse(bytes, halg.slice.end);
    if (himg.identifier.tag != .octetstring) return error.InvalidTstInfo;
    const imprint = bytes[himg.slice.start..himg.slice.end];
    i = mi.slice.end;

    // serialNumber INTEGER
    const sn = try der.Element.parse(bytes, i);
    if (sn.identifier.tag != .integer) return error.InvalidTstInfo;
    i = sn.slice.end;

    // genTime GeneralizedTime
    const gt = try der.Element.parse(bytes, i);
    if (gt.identifier.tag != .generalized_time) return error.InvalidTstInfo;
    const gen_time = parseGeneralizedTime(bytes[gt.slice.start..gt.slice.end]) catch
        return error.InvalidGeneralizedTime;

    return .{
        .imprint_alg = imprint_alg,
        .imprint = imprint,
        .gen_time = gen_time,
    };
}

/// Verify the embedded RFC 3161 timestamp countersignature on a
/// SignerInfo. Returns the TSA's `gen_time` (UTC seconds) on success.
///
///   1. Locate the `id-aa-signatureTimeStampToken` attribute in
///      `signer.unsigned_attrs_raw`.
///   2. Parse the TimeStampToken as a PKCS#7 SignedData over a
///      TSTInfo (`parseTimestampToken`).
///   3. Verify the TSA SignerInfo's signature over its own
///      signedAttrs using the TSA's leaf cert.
///   4. Walk the TSA cert chain to a trusted TSA root in
///      `tsa_trust`, using the wall-clock `now` as the clock.
///   5. Verify TSTInfo.messageImprint.hashedMessage equals the hash
///      (per `imprint_alg`) of `signer.signature`.
pub fn verifyTimestamp(
    allocator: std.mem.Allocator,
    signer: SignerInfo,
    tsa_trust: Certificate.Bundle,
    now: i64,
) (TstError || VerifyError)!i64 {
    const token_bytes = (try findUnsignedAttr(signer, &oid.timestamp_token)) orelse
        (try findUnsignedAttr(signer, &oid.ms_timestamp_token)) orelse
        return error.MissingSignedAttrs; // re-purposed: caller treats as fail-closed
    const token = try parseTimestampToken(token_bytes);

    // Step 3: verify the TSA's own signer signature over its
    // signedAttrs (re-emitted as SET OF), using the TSA leaf cert
    // bundled inside this TimeStampToken.
    try verifySignerSignature(allocator, token);

    // Step 4: walk the TSA cert chain to one of the embedded TSA
    // roots. Use wall-clock `now` here since the TSA cert itself
    // does have a validity window we want to enforce against the
    // moment of verification.
    const tsa_leaf = (try findSignerCertDer(token)) orelse
        return error.SignerCertNotFound;
    _ = try verifyChain(allocator, tsa_leaf, token.certificates_raw, tsa_trust, now);

    // Step 5: bind the TSTInfo's messageImprint to sha256(signer.signature).
    const tst = try parseTstInfo(token.spc_indirect_data);
    var imprint_calc: [64]u8 = undefined; // big enough for sha-512
    const imprint_calc_slice = switch (tst.imprint_alg) {
        .sha256 => blk: {
            std.crypto.hash.sha2.Sha256.hash(signer.signature, imprint_calc[0..32], .{});
            break :blk imprint_calc[0..32];
        },
        .sha384 => blk: {
            std.crypto.hash.sha2.Sha384.hash(signer.signature, imprint_calc[0..48], .{});
            break :blk imprint_calc[0..48];
        },
        .sha512 => blk: {
            std.crypto.hash.sha2.Sha512.hash(signer.signature, imprint_calc[0..64], .{});
            break :blk imprint_calc[0..64];
        },
    };
    if (!std.mem.eql(u8, tst.imprint, imprint_calc_slice))
        return error.TstInfoMessageImprintMismatch;

    return tst.gen_time;
}

/// Parse an ASN.1 GeneralizedTime ("YYYYMMDDHHMMSSZ" — RFC 5280 form)
/// into seconds-since-Unix-epoch. Only the trailing-Z form is
/// supported (Authenticode TSAs always emit it).
fn parseGeneralizedTime(s: []const u8) !i64 {
    if (s.len < 15) return error.InvalidGeneralizedTime;
    if (s[s.len - 1] != 'Z') return error.InvalidGeneralizedTime;
    const y = try std.fmt.parseInt(u16, s[0..4], 10);
    const mo = try std.fmt.parseInt(u8, s[4..6], 10);
    const d = try std.fmt.parseInt(u8, s[6..8], 10);
    const h = try std.fmt.parseInt(u8, s[8..10], 10);
    const mi = try std.fmt.parseInt(u8, s[10..12], 10);
    const sc = try std.fmt.parseInt(u8, s[12..14], 10);
    return daysFromCivil(y, mo, d) * 86400 + @as(i64, h) * 3600 + @as(i64, mi) * 60 + @as(i64, sc);
}

/// Howard Hinnant's "days from civil" — algorithm 3 in
/// http://howardhinnant.github.io/date_algorithms.html — used to
/// convert a Gregorian (year, month, day) to Unix days without
/// timezone considerations.
fn daysFromCivil(y_in: u16, m: u8, d: u8) i64 {
    var y: i64 = y_in;
    if (m <= 2) y -= 1;
    const era: i64 = @divFloor(if (y >= 0) y else y - 399, 400);
    const yoe: i64 = y - era * 400;
    const m_i: i64 = m;
    const doy: i64 = @divFloor(153 * (m_i + (if (m > 2) @as(i64, -3) else @as(i64, 9))) + 2, 5) + d - 1;
    const doe: i64 = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

test "parseGeneralizedTime round-trips a known instant" {
    // 2026-04-21T10:24:31Z → 1776767071 epoch seconds.
    const t = try parseGeneralizedTime("20260421102431Z");
    try std.testing.expectEqual(@as(i64, 1776767071), t);
}

/// Format a Unix-epoch second count as a 20-byte ISO 8601 UTC string
/// of the form `YYYY-MM-DDTHH:MM:SSZ`. The slice is borrowed from
/// `buf` and is valid for the lifetime of `buf`.
///
/// Used to render RFC 3161 `genTime` values in human-readable logs;
/// the inverse of `parseGeneralizedTime` for the common Z-suffixed
/// shape. Year is clamped to four digits, so inputs outside
/// 0001–9999 will be truncated — fine for any plausible timestamp.
pub fn formatUnixTimeIso(epoch_sec: i64, buf: *[20]u8) []const u8 {
    const day_seconds: i64 = 86400;
    const days: i64 = @divFloor(epoch_sec, day_seconds);
    const tod: u32 = @intCast(epoch_sec - days * day_seconds); // [0, 86399]
    const ymd = civilFromDays(days);
    const hh: u8 = @intCast(tod / 3600);
    const mm: u8 = @intCast((tod / 60) % 60);
    const ss: u8 = @intCast(tod % 60);
    // We deliberately ignore fmt errors; the buffer is exactly 20 bytes
    // and the format string emits exactly 20 ASCII characters.
    _ = std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        @as(u16, @intCast(ymd.year)),
        ymd.month,
        ymd.day,
        hh,
        mm,
        ss,
    }) catch unreachable;
    return buf[0..20];
}

/// Howard Hinnant's "civil from days" — the inverse of `daysFromCivil`.
/// See http://howardhinnant.github.io/date_algorithms.html#civil_from_days.
fn civilFromDays(z_in: i64) struct { year: i64, month: u8, day: u8 } {
    const z: i64 = z_in + 719468;
    const era: i64 = @divFloor(if (z >= 0) z else z - 146096, 146097);
    const doe: u32 = @intCast(z - era * 146097); // [0, 146096]
    const yoe: u32 = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    const y: i64 = @as(i64, yoe) + era * 400;
    const doy: u32 = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    const mp: u32 = (5 * doy + 2) / 153; // [0, 11]
    const d: u8 = @intCast(doy - (153 * mp + 2) / 5 + 1); // [1, 31]
    const m: u8 = @intCast(if (mp < 10) mp + 3 else mp - 9); // [1, 12]
    return .{ .year = y + @as(i64, @intFromBool(m <= 2)), .month = m, .day = d };
}

test "formatUnixTimeIso renders known timestamps" {
    var buf: [20]u8 = undefined;
    // genTime printed by `ghr install AzureAD/microsoft-authentication-cli@0.9.6`.
    try std.testing.expectEqualStrings("2026-04-24T21:00:53Z", formatUnixTimeIso(1777064453, &buf));
    // Unix epoch itself.
    try std.testing.expectEqualStrings("1970-01-01T00:00:00Z", formatUnixTimeIso(0, &buf));
    // Round-trips with parseGeneralizedTime.
    const parsed = try parseGeneralizedTime("20260421102431Z");
    try std.testing.expectEqualStrings("2026-04-21T10:24:31Z", formatUnixTimeIso(parsed, &buf));
}

test "CertificateSetIterator skips non-certificate CertificateChoices" {
    // CMS CertificateSet body containing, in order:
    //   1. an X.509 certificate          (SEQUENCE,    universal tag 0x30)
    //   2. a v2AttrCert                  ([2] IMPLICIT, context-specific 0xa2)
    //   3. another X.509 certificate     (SEQUENCE,    universal tag 0x30)
    //   4. an `other` CertificateFormat  ([3] IMPLICIT, context-specific 0xa3)
    //
    // Microsoft's Time-Stamp Service emits exactly the SEQUENCE + v2AttrCert
    // pattern in the RFC 3161 timestamp token's certificate set; before this
    // change the iterator hard-failed on the v2AttrCert with
    // InvalidCertificateSet, breaking Authenticode verification for any
    // Microsoft-signed binary (e.g. AdoPat.dll inside the AzureAD/
    // microsoft-authentication-cli zip release).
    const buf = [_]u8{
        0x30, 0x03, 0x01, 0x02, 0x03, // SEQUENCE { 01 02 03 }
        0xa2, 0x02, 0xff, 0xff, // [2] IMPLICIT { ff ff }
        0x30, 0x02, 0x0a, 0x0b, // SEQUENCE { 0a 0b }
        0xa3, 0x01, 0x77, // [3] IMPLICIT { 77 }
    };

    var iter: CertificateSetIterator = .{ .bytes = &buf };

    const first = (try iter.next()) orelse return error.TestUnexpectedNull;
    try std.testing.expectEqualSlices(u8, &.{ 0x30, 0x03, 0x01, 0x02, 0x03 }, first);

    const second = (try iter.next()) orelse return error.TestUnexpectedNull;
    try std.testing.expectEqualSlices(u8, &.{ 0x30, 0x02, 0x0a, 0x0b }, second);

    try std.testing.expectEqual(@as(?[]const u8, null), try iter.next());
}

test "CertificateSetIterator rejects elements outside the CHOICE grammar" {
    // A universal INTEGER is not a valid CertificateChoices alternative.
    const buf = [_]u8{ 0x02, 0x01, 0x01 }; // INTEGER 1
    var iter: CertificateSetIterator = .{ .bytes = &buf };
    try std.testing.expectError(error.InvalidCertificateChoice, iter.next());
}

// ---------------------------------------------------------------------------
// Top-level orchestrator: end-to-end verification of a single PE.
// ---------------------------------------------------------------------------

pub const Outcome = struct {
    /// SHA-256 Authenticode digest of the verified PE.
    digest: [32]u8,
    /// Subject CN of the signer cert, or empty when none was found.
    subject_cn: []const u8,
    /// Organization name (O=) of the signer cert, or empty.
    organization: []const u8,
    /// RFC 3161 timestamp's `genTime` — Unix seconds.
    gen_time: i64,
};

pub const VerifyPeError = error{
    NoAuthenticodeSignature,
    AuthenticodeDigestMismatch,
    SignerMessageDigestMismatch,
} || VerifyError || TstError || ParseError || WinCertError || DigestError;

/// Top-level: verify the Authenticode signature on a PE/COFF image.
///
/// `signer_trust` and `tsa_trust` are bundles of trusted Authenticode
/// and TSA roots respectively (typically populated via
/// `buildEmbeddedTrustBundle` plus any caller-supplied additions).
/// `now` is the wall-clock used to enforce the TSA cert's own
/// validity window; the TSA's `genTime` is then used as the clock
/// for the signer chain so the signature remains valid past the
/// signer cert's notAfter.
pub fn verifyPe(
    allocator: std.mem.Allocator,
    pe_bytes: []const u8,
    signer_trust: Certificate.Bundle,
    tsa_trust: Certificate.Bundle,
    now: i64,
) VerifyPeError!Outcome {
    const image = try parsePe(pe_bytes);
    const cert_entry = (try findFirstPkcs7Entry(image)) orelse
        return error.NoAuthenticodeSignature;
    const signed = try parseSignedData(cert_entry.data);

    // (1) Authenticode digest of file == SpcIndirectDataContent.digest.
    var auth_digest: [32]u8 = undefined;
    try computeAuthenticodeDigestSha256(image, &auth_digest);
    if (signed.file_digest_alg != .sha256)
        return error.UnsupportedDigestAlgorithm;
    if (!std.mem.eql(u8, signed.file_digest, &auth_digest))
        return error.AuthenticodeDigestMismatch;

    // (2) SignerInfo.signedAttrs.messageDigest == sha256(SpcIndirectDataContent BODY).
    // Authenticode hashes only the body of the SpcIndirectDataContent
    // SEQUENCE — not the outer tag/length octets. See signify's
    // documentation on the Authenticode messageDigest derivation.
    const spc_outer = try der.Element.parse(signed.spc_indirect_data, 0);
    if (spc_outer.identifier.tag != .sequence) return error.InvalidSpcIndirectData;
    const spc_body = signed.spc_indirect_data[spc_outer.slice.start..spc_outer.slice.end];
    var spc_digest: [32]u8 = undefined;
    Sha256.hash(spc_body, &spc_digest, .{});
    if (signed.signer.digest_alg != .sha256)
        return error.UnsupportedDigestAlgorithm;
    if (!std.mem.eql(u8, signed.signer.message_digest, &spc_digest))
        return error.SignerMessageDigestMismatch;

    // (3) SignerInfo signature verifies over signedAttrs (SET OF form).
    try verifySignerSignature(allocator, signed);

    // (4) RFC 3161 timestamp verifies and gives us a trustworthy clock.
    const gen_time = try verifyTimestamp(allocator, signed.signer, tsa_trust, now);

    // (5) Signer chain walks to a trusted root, using genTime.
    const leaf_der = (try findSignerCertDer(signed)) orelse
        return error.SignerCertNotFound;
    const leaf = try verifyChain(allocator, leaf_der, signed.certificates_raw, signer_trust, gen_time);

    return .{
        .digest = auth_digest,
        .subject_cn = extractSubjectCn(leaf) catch "",
        .organization = extractOrganization(leaf) catch "",
        .gen_time = gen_time,
    };
}

/// Extract the Common Name (CN) attribute from the leaf cert's
/// subject DN. Returns the raw bytes; the caller can copy as needed.
/// Returns an empty slice when no CN is present.
fn extractSubjectCn(leaf: Certificate.Parsed) ![]const u8 {
    return findRdnAttribute(leaf.certificate.buffer[leaf.subject_slice.start..leaf.subject_slice.end], &.{ 0x55, 0x04, 0x03 });
}

/// Extract the Organization (O) attribute from the leaf cert's
/// subject DN.
fn extractOrganization(leaf: Certificate.Parsed) ![]const u8 {
    return findRdnAttribute(leaf.certificate.buffer[leaf.subject_slice.start..leaf.subject_slice.end], &.{ 0x55, 0x04, 0x0A });
}

fn findRdnAttribute(name_der: []const u8, target_oid: []const u8) ![]const u8 {
    // The subject_slice bytes already include the outer SEQUENCE
    // header in std.crypto.Certificate.Parsed, so we re-parse it to
    // step into the SEQUENCE OF RDN body.
    if (name_der.len < 2) return &.{};
    const outer = der.Element.parse(name_der, 0) catch return &.{};
    if (outer.identifier.tag != .sequence) return &.{};

    var i: u32 = outer.slice.start;
    while (i < outer.slice.end) {
        const rdn = try der.Element.parse(name_der, i);
        i = rdn.slice.end;
        if (@intFromEnum(rdn.identifier.tag) != 17) continue; // SET OF
        var j: u32 = rdn.slice.start;
        while (j < rdn.slice.end) {
            const attr = try der.Element.parse(name_der, j);
            j = attr.slice.end;
            if (attr.identifier.tag != .sequence) continue;
            const t = try der.Element.parse(name_der, attr.slice.start);
            if (t.identifier.tag != .object_identifier) continue;
            const oid_bytes = name_der[t.slice.start..t.slice.end];
            if (!std.mem.eql(u8, oid_bytes, target_oid)) continue;
            const v = try der.Element.parse(name_der, t.slice.end);
            // value is usually PrintableString / UTF8String / etc.
            return name_der[v.slice.start..v.slice.end];
        }
    }
    return &.{};
}

// ---------------------------------------------------------------------------
// ZIP-aware Authenticode verification.
//
// When the downloaded asset is a `.zip`, we walk its central directory
// in memory to find PE entries (`*.exe` / `*.dll` / `*.sys`),
// decompress each into a temporary buffer, and run `verifyPe`. The
// caller's pass / fail / no-verification decision is:
//
//   * Any PE that carries an Authenticode signature must verify or
//     the whole archive is rejected.
//   * If no PE in the archive carries an Authenticode signature,
//     return `.no_verification` (consistent with sha256 / sigstore
//     fail-open when no material is published).
// ---------------------------------------------------------------------------

const zip = std.zip;
const flate = std.compress.flate;

pub const ZipWalkError = error{
    ZipBadFile,
    ZipUnsupportedCompression,
    ZipTruncated,
    ZipFilenameTooLong,
    ZipEntryTooLarge,
} || std.mem.Allocator.Error;

pub const PeEntryResult = struct {
    /// Lower-cased filename of the entry within the zip (UTF-8).
    name: []const u8,
    /// Decompressed entry bytes. Owned by the caller; freed by the
    /// caller via `allocator.free`.
    bytes: []u8,
};

/// Limit (in bytes) on a single decompressed entry. Authenticode is
/// only relevant for executable PE files, which are bounded by
/// practical release sizes; the cap is generous but guards against
/// zip-bomb-style attacks.
pub const max_entry_size: u64 = 200 * 1024 * 1024;
const max_zip_filename: usize = 4096;

/// Walk a zip archive at `zip_bytes` and yield each entry whose
/// filename ends in `.exe`, `.dll`, or `.sys` as decompressed bytes.
/// `out` collects up to `out.capacity` results.
///
/// Returns the number of entries written. Each entry's `bytes` slice
/// must be freed by the caller.
pub fn walkZipPes(
    allocator: std.mem.Allocator,
    zip_bytes: []const u8,
    out: *std.array_list.Managed(PeEntryResult),
) ZipWalkError!void {
    // Parse end-of-central-directory record by scanning backwards for
    // the signature. std.zip.EndRecord.findBuffer has an error-set
    // mismatch with its implementation in this Zig version, so we
    // parse the small subset we need directly.
    const eocd_off = lastIndexOf4(zip_bytes, zip.end_record_sig) orelse return error.ZipBadFile;
    if (eocd_off + 22 > zip_bytes.len) return error.ZipBadFile;
    const cd_size: u32 = std.mem.readInt(u32, zip_bytes[eocd_off + 12 .. eocd_off + 16][0..4], .little);
    const cd_offset: u32 = std.mem.readInt(u32, zip_bytes[eocd_off + 16 .. eocd_off + 20][0..4], .little);
    if (cd_offset == std.math.maxInt(u32) or cd_size == std.math.maxInt(u32))
        return error.ZipBadFile; // ZIP64 not handled here.
    if (@as(usize, cd_offset) + @as(usize, cd_size) > zip_bytes.len)
        return error.ZipTruncated;

    var i: usize = cd_offset;
    const cd_end: usize = @as(usize, cd_offset) + @as(usize, cd_size);
    while (i < cd_end) {
        if (i + @sizeOf(zip.CentralDirectoryFileHeader) > zip_bytes.len) return error.ZipTruncated;
        const cdh_bytes = zip_bytes[i .. i + @sizeOf(zip.CentralDirectoryFileHeader)];
        const cdh: zip.CentralDirectoryFileHeader = std.mem.bytesAsValue(zip.CentralDirectoryFileHeader, cdh_bytes[0..@sizeOf(zip.CentralDirectoryFileHeader)]).*;
        if (!std.mem.eql(u8, &cdh.signature, &zip.central_file_header_sig))
            return error.ZipBadFile;

        const name_off: usize = i + @sizeOf(zip.CentralDirectoryFileHeader);
        const name_end: usize = name_off + cdh.filename_len;
        if (name_end > zip_bytes.len) return error.ZipTruncated;
        if (cdh.filename_len > max_zip_filename) return error.ZipFilenameTooLong;
        const name = zip_bytes[name_off..name_end];
        const extras_off = name_end;
        const extras_end = extras_off + cdh.extra_len;
        const comment_end = extras_end + cdh.comment_len;
        if (comment_end > zip_bytes.len) return error.ZipTruncated;
        i = comment_end;

        if (!hasPeSuffix(name)) continue;

        // Read the local file header to locate the data payload.
        const lfh_off: usize = cdh.local_file_header_offset;
        if (lfh_off + @sizeOf(zip.LocalFileHeader) > zip_bytes.len) return error.ZipTruncated;
        const lfh_bytes = zip_bytes[lfh_off .. lfh_off + @sizeOf(zip.LocalFileHeader)];
        const lfh = std.mem.bytesAsValue(zip.LocalFileHeader, lfh_bytes[0..@sizeOf(zip.LocalFileHeader)]).*;
        if (!std.mem.eql(u8, &lfh.signature, &zip.local_file_header_sig))
            return error.ZipBadFile;

        const data_off: usize = lfh_off + @sizeOf(zip.LocalFileHeader) + lfh.filename_len + lfh.extra_len;
        const compressed_end: usize = data_off + cdh.compressed_size;
        if (compressed_end > zip_bytes.len) return error.ZipTruncated;
        if (cdh.uncompressed_size > max_entry_size) return error.ZipEntryTooLarge;

        const data = zip_bytes[data_off..compressed_end];

        const buf = try allocator.alloc(u8, cdh.uncompressed_size);
        errdefer allocator.free(buf);

        switch (cdh.compression_method) {
            .store => {
                if (data.len != buf.len) return error.ZipBadFile;
                @memcpy(buf, data);
            },
            .deflate => {
                try decompressDeflateToBuf(data, buf);
            },
            else => return error.ZipUnsupportedCompression,
        }

        try out.append(.{
            .name = name,
            .bytes = buf,
        });
    }
}

fn hasPeSuffix(name: []const u8) bool {
    return std.ascii.endsWithIgnoreCase(name, ".exe") or
        std.ascii.endsWithIgnoreCase(name, ".dll") or
        std.ascii.endsWithIgnoreCase(name, ".sys");
}

fn lastIndexOf4(haystack: []const u8, needle: [4]u8) ?usize {
    if (haystack.len < 4) return null;
    var i: usize = haystack.len - 4;
    while (true) : (i -= 1) {
        if (std.mem.eql(u8, haystack[i .. i + 4], &needle)) return i;
        if (i == 0) return null;
    }
}

// ---------------------------------------------------------------------------
// Embedded Authenticode + RFC 3161 trust roots.
//
// Vendored at fixture-capture time from the sources listed below.
// Rotation: refresh this directory + bump ghr's version when a CA
// rotates or adds an Authenticode-trusted root.
//
// Most roots were extracted from `/etc/ssl/certs/ca-bundle.crt` on a
// Microsoft Azure Linux 3 host (the same Mozilla CCADB snapshot most
// Linux distros ship). The Microsoft Identity Verification Root 2020
// and GlobalSign Code Signing Root R45 were fetched directly from
// their issuing CAs because they aren't yet in Mozilla's TLS bundle.
//
// Microsoft has *two* operational PKI hierarchies in active use for
// Authenticode and RFC 3161 timestamping: the 2011 root (signs the
// "Microsoft Code Signing PCA" series) and the 2010 root (signs the
// "Microsoft Time-Stamp PCA 2010" — emitted by the Microsoft Time-
// Stamp Service that counter-signs most Microsoft binaries today,
// e.g. inside `AdoPat.dll` shipped in
// `AzureAD/microsoft-authentication-cli`). Both roots are required.
// ---------------------------------------------------------------------------

const embedded_roots = [_][]const u8{
    @embedFile("authenticode/trust/microsoft_identity_verification_root_2020.crt.pem"),
    @embedFile("authenticode/trust/microsoft_root_ca_2011.crt.pem"),
    @embedFile("authenticode/trust/microsoft_root_ca_2010.crt.pem"),
    @embedFile("authenticode/trust/digicert_trusted_root_g4.crt.pem"),
    @embedFile("authenticode/trust/digicert_global_root_g3.crt.pem"),
    @embedFile("authenticode/trust/digicert_global_root_ca.crt.pem"),
    @embedFile("authenticode/trust/digicert_high_assurance_ev_root_ca.crt.pem"),
    @embedFile("authenticode/trust/digicert_assured_id_root_g3.crt.pem"),
    @embedFile("authenticode/trust/globalsign_root_ca_r3.crt.pem"),
    @embedFile("authenticode/trust/globalsign_root_ca_r6.crt.pem"),
    @embedFile("authenticode/trust/globalsign_code_signing_root_r45.crt.pem"),
    @embedFile("authenticode/trust/usertrust_rsa_ca.crt.pem"),
    @embedFile("authenticode/trust/usertrust_ecc_ca.crt.pem"),
    @embedFile("authenticode/trust/entrust_root_ca_g2.crt.pem"),
    @embedFile("authenticode/trust/entrust_root_ca_ec1.crt.pem"),
};

/// Build a `Certificate.Bundle` populated with the embedded
/// Authenticode trust roots. Caller owns the returned bundle and
/// must call `bundle.deinit(allocator)`.
///
/// `now_sec` is used by `parseCert` to skip already-expired roots;
/// passing the current wall-clock time is fine since all 15 embedded
/// roots are valid through 2029 or later.
pub fn buildTrustBundle(allocator: std.mem.Allocator, now_sec: i64) !Certificate.Bundle {
    var bundle: Certificate.Bundle = .empty;
    errdefer bundle.deinit(allocator);
    for (embedded_roots) |pem| try addPemCertsToBundle(&bundle, allocator, pem, now_sec);
    return bundle;
}

/// Add every PEM-encoded `CERTIFICATE` block in `pem_bytes` to `cb`.
/// Mirrors `sigstore.zig`'s helper; kept local to avoid the
/// cross-module dependency.
fn addPemCertsToBundle(
    cb: *Certificate.Bundle,
    gpa: std.mem.Allocator,
    pem_bytes: []const u8,
    now_sec: i64,
) !void {
    const begin_marker = "-----BEGIN CERTIFICATE-----";
    const end_marker = "-----END CERTIFICATE-----";

    try cb.bytes.ensureUnusedCapacity(gpa, @intCast(pem_bytes.len));

    var start_index: usize = 0;
    while (std.mem.indexOfPos(u8, pem_bytes, start_index, begin_marker)) |begin_off| {
        const cert_start = begin_off + begin_marker.len;
        const cert_end = std.mem.indexOfPos(u8, pem_bytes, cert_start, end_marker) orelse
            return error.TrustBundleBuildFailed;
        start_index = cert_end + end_marker.len;
        const encoded_cert = std.mem.trim(u8, pem_bytes[cert_start..cert_end], " \t\r\n");
        const decoded_start: u32 = @intCast(cb.bytes.items.len);
        const decoder = std.base64.standard.Decoder;
        const stripped = try stripPemWhitespace(gpa, encoded_cert);
        defer gpa.free(stripped);
        const decoded_len = decoder.calcSizeForSlice(stripped) catch
            return error.TrustBundleBuildFailed;
        try cb.bytes.ensureUnusedCapacity(gpa, decoded_len);
        decoder.decode(cb.bytes.allocatedSlice()[decoded_start..], stripped) catch
            return error.TrustBundleBuildFailed;
        cb.bytes.items.len += decoded_len;
        try cb.parseCert(gpa, decoded_start, now_sec);
    }
}

fn stripPemWhitespace(gpa: std.mem.Allocator, s: []const u8) ![]u8 {
    var out = try gpa.alloc(u8, s.len);
    errdefer gpa.free(out);
    var n: usize = 0;
    for (s) |c| {
        if (c == ' ' or c == '\t' or c == '\r' or c == '\n') continue;
        out[n] = c;
        n += 1;
    }
    return gpa.realloc(out, n) catch unreachable;
}

test "buildTrustBundle parses all embedded Authenticode roots" {
    const allocator = std.testing.allocator;
    const now: i64 = 1746878400; // 2025-05-10, inside every root's validity window
    var bundle = try buildTrustBundle(allocator, now);
    defer bundle.deinit(allocator);
    try std.testing.expect(bundle.bytes.items.len > 0);
    // 15 embedded roots; map_size grows by 1 per parsed cert.
    try std.testing.expectEqual(@as(usize, embedded_roots.len), bundle.map.count());
}

fn decompressDeflateToBuf(compressed: []const u8, out: []u8) !void {
    // Wrap `compressed` in a memory Reader, drive a raw-deflate
    // Decompress over it, and read exactly `out.len` bytes into the
    // output buffer.
    var in_reader = std.Io.Reader.fixed(compressed);
    var flate_buffer: [flate.max_window_len]u8 = undefined;
    var decompress: flate.Decompress = .init(&in_reader, .raw, &flate_buffer);
    decompress.reader.readSliceAll(out) catch return error.ZipBadFile;
}

test "walkZipPes recovers PE entries from a fabricated archive" {
    const allocator = std.testing.allocator;

    // Build a tiny zip with two entries:
    //   foo.txt (skipped — not a PE suffix)
    //   tiny.exe ("MZHELLO" — 7 bytes, store-compressed)
    // Layout:
    //   [LFH foo.txt][data][LFH tiny.exe][data]
    //   [CDH foo.txt][CDH tiny.exe]
    //   [EOCD]
    const txt_name = "foo.txt";
    const txt_data = "hello";
    const pe_name = "tiny.exe";
    const pe_data = "MZHELLO";

    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();
    const w = &aw.writer;

    // LFH foo.txt
    const lfh1_off = aw.written().len;
    try w.writeAll(&zip.local_file_header_sig);
    try w.writeInt(u16, 20, .little); // version_needed
    try w.writeInt(u16, 0, .little); // flags
    try w.writeInt(u16, 0, .little); // method = store
    try w.writeInt(u16, 0, .little); // mod time
    try w.writeInt(u16, 0, .little); // mod date
    try w.writeInt(u32, std.hash.Crc32.hash(txt_data), .little);
    try w.writeInt(u32, @intCast(txt_data.len), .little); // compressed
    try w.writeInt(u32, @intCast(txt_data.len), .little); // uncompressed
    try w.writeInt(u16, @intCast(txt_name.len), .little);
    try w.writeInt(u16, 0, .little); // extra len
    try w.writeAll(txt_name);
    try w.writeAll(txt_data);

    // LFH tiny.exe
    const lfh2_off = aw.written().len;
    try w.writeAll(&zip.local_file_header_sig);
    try w.writeInt(u16, 20, .little);
    try w.writeInt(u16, 0, .little);
    try w.writeInt(u16, 0, .little);
    try w.writeInt(u16, 0, .little);
    try w.writeInt(u16, 0, .little);
    try w.writeInt(u32, std.hash.Crc32.hash(pe_data), .little);
    try w.writeInt(u32, @intCast(pe_data.len), .little);
    try w.writeInt(u32, @intCast(pe_data.len), .little);
    try w.writeInt(u16, @intCast(pe_name.len), .little);
    try w.writeInt(u16, 0, .little);
    try w.writeAll(pe_name);
    try w.writeAll(pe_data);

    // CDH foo.txt
    const cd_off = aw.written().len;
    try w.writeAll(&zip.central_file_header_sig);
    try w.writeInt(u16, 20, .little); // version made by
    try w.writeInt(u16, 20, .little); // version needed
    try w.writeInt(u16, 0, .little);
    try w.writeInt(u16, 0, .little);
    try w.writeInt(u16, 0, .little);
    try w.writeInt(u16, 0, .little);
    try w.writeInt(u32, std.hash.Crc32.hash(txt_data), .little);
    try w.writeInt(u32, @intCast(txt_data.len), .little);
    try w.writeInt(u32, @intCast(txt_data.len), .little);
    try w.writeInt(u16, @intCast(txt_name.len), .little);
    try w.writeInt(u16, 0, .little);
    try w.writeInt(u16, 0, .little);
    try w.writeInt(u16, 0, .little);
    try w.writeInt(u16, 0, .little);
    try w.writeInt(u32, 0, .little); // external attrs
    try w.writeInt(u32, @intCast(lfh1_off), .little);
    try w.writeAll(txt_name);

    // CDH tiny.exe
    try w.writeAll(&zip.central_file_header_sig);
    try w.writeInt(u16, 20, .little);
    try w.writeInt(u16, 20, .little);
    try w.writeInt(u16, 0, .little);
    try w.writeInt(u16, 0, .little);
    try w.writeInt(u16, 0, .little);
    try w.writeInt(u16, 0, .little);
    try w.writeInt(u32, std.hash.Crc32.hash(pe_data), .little);
    try w.writeInt(u32, @intCast(pe_data.len), .little);
    try w.writeInt(u32, @intCast(pe_data.len), .little);
    try w.writeInt(u16, @intCast(pe_name.len), .little);
    try w.writeInt(u16, 0, .little);
    try w.writeInt(u16, 0, .little);
    try w.writeInt(u16, 0, .little);
    try w.writeInt(u16, 0, .little);
    try w.writeInt(u32, 0, .little);
    try w.writeInt(u32, @intCast(lfh2_off), .little);
    try w.writeAll(pe_name);

    const cd_size = aw.written().len - cd_off;

    // EOCD
    try w.writeAll(&zip.end_record_sig);
    try w.writeInt(u16, 0, .little); // disk number
    try w.writeInt(u16, 0, .little); // disk where CD starts
    try w.writeInt(u16, 2, .little); // total entries on this disk
    try w.writeInt(u16, 2, .little); // total entries
    try w.writeInt(u32, @intCast(cd_size), .little);
    try w.writeInt(u32, @intCast(cd_off), .little);
    try w.writeInt(u16, 0, .little); // comment len

    var results: std.array_list.Managed(PeEntryResult) = .init(allocator);
    defer {
        for (results.items) |r| allocator.free(r.bytes);
        results.deinit();
    }
    try walkZipPes(allocator, aw.written(), &results);
    try std.testing.expectEqual(@as(usize, 1), results.items.len);
    try std.testing.expectEqualStrings("tiny.exe", results.items[0].name);
    try std.testing.expectEqualSlices(u8, pe_data, results.items[0].bytes);
}
///
/// Re-uses the std.crypto.Certificate.verify primitive, which
/// performs the per-step signature verification.
pub fn verifyChain(
    allocator: std.mem.Allocator,
    leaf_der: []const u8,
    intermediates_raw: []const u8,
    trust: Certificate.Bundle,
    verify_at: i64,
) VerifyError!Certificate.Parsed {
    // Build a working pool of {intermediate} certs we can lookup by
    // subject name.
    var pool = std.array_list.Managed(Certificate).init(allocator);
    defer pool.deinit();

    var iter: CertificateSetIterator = .{ .bytes = intermediates_raw };
    while (try iter.next()) |cert_der| {
        try pool.append(.{ .buffer = cert_der, .index = 0 });
    }

    var subject_cert: Certificate = .{ .buffer = leaf_der, .index = 0 };
    var subject = subject_cert.parse() catch return error.InvalidSignature;

    var depth: u8 = 0;
    while (depth < 8) : (depth += 1) {
        const issuer_name = subject.issuer();

        // 1. Try to find issuer in the embedded trust bundle.
        if (trust.find(issuer_name)) |issuer_idx| {
            const issuer_cert: Certificate = .{ .buffer = trust.bytes.items, .index = issuer_idx };
            const issuer = issuer_cert.parse() catch return error.InvalidSignature;
            try subject.verify(issuer, verify_at);
            // Confirm root is valid at the same clock.
            if (verify_at < issuer.validity.not_before) return error.InvalidSignature;
            if (verify_at > issuer.validity.not_after) return error.InvalidSignature;
            return subject_cert.parse() catch error.InvalidSignature;
        }

        // 2. Try to find issuer among the in-bundle intermediates.
        var matched: ?Certificate.Parsed = null;
        var matched_cert: ?Certificate = null;
        for (pool.items) |c| {
            var cc = c;
            const p = cc.parse() catch continue;
            if (std.mem.eql(u8, p.subject(), issuer_name)) {
                matched = p;
                matched_cert = cc;
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

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

test "parsePe rejects non-PE input" {
    try std.testing.expectError(error.TruncatedDosHeader, parsePe("hello, world"));
    try std.testing.expectError(error.TruncatedDosHeader, parsePe("MZ"));
    // 64+ bytes of non-PE data: MZ check should fire.
    var not_pe: [128]u8 = undefined;
    @memset(&not_pe, 0xAA);
    try std.testing.expectError(error.NotPeImage, parsePe(&not_pe));
}

test "parsePe + Authenticode digest on a minimal PE32+ fixture" {
    // The fixture below is a hand-assembled minimal PE32+ image just
    // big enough to exercise the parser. It has no sections, no real
    // executable code, no Authenticode signature — we only care that
    // the headers parse and the digest function hashes the expected
    // byte ranges.
    const allocator = std.testing.allocator;

    // Layout:
    //   0x00         DOS header (only e_lfanew at 0x3C matters; rest is zeros).
    //   0x40         "PE\0\0" NT signature.
    //   0x44         File header (20 bytes; SizeOfOptionalHeader = 240).
    //   0x58         Optional header (240 bytes for PE32+).
    //       +0   Magic = 0x020B (PE32+).
    //       +64  CheckSum.
    //       +108 NumberOfRvaAndSizes.
    //       +112 DataDirectory[0..NumberOfRvaAndSizes].
    //   end          (no sections, no cert table).
    var img = try allocator.alloc(u8, 0x58 + 240);
    defer allocator.free(img);
    @memset(img, 0);
    @memcpy(img[0..2], &dos_signature);
    std.mem.writeInt(u32, img[0x3C..0x40], 0x40, .little);
    @memcpy(img[0x40..0x44], &nt_signature);
    // SizeOfOptionalHeader at FileHeader+16.
    std.mem.writeInt(u16, img[0x44 + 16 .. 0x44 + 18][0..2], 240, .little);
    // Optional header magic.
    std.mem.writeInt(u16, img[0x58..0x5A][0..2], pe32_plus_magic, .little);
    // CheckSum at OptionalHeader+64.
    std.mem.writeInt(u32, img[0x58 + 64 .. 0x58 + 68][0..4], 0xDEAD_BEEF, .little);
    // NumberOfRvaAndSizes at OptionalHeader+108. Must include the
    // Security entry (index 4) so the parser exposes a security dir.
    std.mem.writeInt(u32, img[0x58 + 108 .. 0x58 + 112][0..4], 16, .little);
    // Security data directory entry (empty: zero RVA + zero size).
    @memset(img[0x58 + 112 + 32 .. 0x58 + 112 + 40], 0);

    const pe = try parsePe(img);
    try std.testing.expect(pe.is_pe32_plus);
    try std.testing.expectEqual(@as(usize, 0x58 + 64), pe.checksum_offset);
    try std.testing.expectEqual(@as(usize, 0x58 + 112 + 32), pe.security_dir_offset);
    try std.testing.expectEqual(@as(u32, 0), pe.cert_table_offset);
    try std.testing.expectEqual(@as(u32, 0), pe.cert_table_size);

    var digest: [32]u8 = undefined;
    try computeAuthenticodeDigestSha256(pe, &digest);

    // Recompute by hand: hash [0, CheckSum), [CheckSum+4, SecurityDir),
    // [SecurityDir+8, end). Build a side buffer with those regions
    // concatenated (not zeroed — that would change the length) and
    // hash it directly to compare.
    var concat = try allocator.alloc(u8, img.len - 4 - 8);
    defer allocator.free(concat);
    var idx: usize = 0;
    @memcpy(concat[idx..][0..pe.checksum_offset], img[0..pe.checksum_offset]);
    idx += pe.checksum_offset;
    const after_cs = pe.checksum_offset + 4;
    @memcpy(
        concat[idx..][0 .. pe.security_dir_offset - after_cs],
        img[after_cs..pe.security_dir_offset],
    );
    idx += pe.security_dir_offset - after_cs;
    const after_sd = pe.security_dir_offset + 8;
    @memcpy(concat[idx..][0 .. img.len - after_sd], img[after_sd..]);
    var expected: [32]u8 = undefined;
    Sha256.hash(concat, &expected, .{});
    try std.testing.expectEqualSlices(u8, &expected, &digest);

    // Sanity: flipping the CheckSum field doesn't change the digest.
    std.mem.writeInt(u32, img[pe.checksum_offset .. pe.checksum_offset + 4][0..4], 0xCAFE_BABE, .little);
    const pe2 = try parsePe(img);
    var digest2: [32]u8 = undefined;
    try computeAuthenticodeDigestSha256(pe2, &digest2);
    try std.testing.expectEqualSlices(u8, &digest, &digest2);

    // But flipping a byte outside the skipped regions does change it.
    // Tweak the last byte of the optional header (not in any skip
    // window) and re-parse.
    const tail = img.len - 1;
    img[tail] ^= 0xFF;
    defer img[tail] ^= 0xFF;
    const pe3 = try parsePe(img);
    var digest3: [32]u8 = undefined;
    try computeAuthenticodeDigestSha256(pe3, &digest3);
    try std.testing.expect(!std.mem.eql(u8, &digest, &digest3));
}

test "WinCertIterator handles an empty cert table" {
    var img = [_]u8{0} ** (0x58 + 240);
    @memcpy(img[0..2], &dos_signature);
    std.mem.writeInt(u32, img[0x3C..0x40], 0x40, .little);
    @memcpy(img[0x40..0x44], &nt_signature);
    std.mem.writeInt(u16, img[0x44 + 16 .. 0x44 + 18][0..2], 240, .little);
    std.mem.writeInt(u16, img[0x58..0x5A][0..2], pe32_plus_magic, .little);
    std.mem.writeInt(u32, img[0x58 + 108 .. 0x58 + 112][0..4], 16, .little);

    const pe = try parsePe(&img);
    var it = WinCertIterator.init(pe);
    try std.testing.expect((try it.next()) == null);

    try std.testing.expect((try findFirstPkcs7Entry(pe)) == null);
}

test "WinCertIterator walks a fabricated two-entry table" {
    // Build a PE image with two WIN_CERTIFICATE entries: a non-PKCS#7
    // one (skipped) and a PKCS#7 v2.0 one (returned by
    // findFirstPkcs7Entry).
    const allocator = std.testing.allocator;

    const pkcs7_payload = "fake-pkcs7-blob-for-tests";
    const other_payload = "fake-pkcs1-blob";

    // Each entry: 4 (length) + 2 (revision) + 2 (cert type) + payload,
    // 8-byte aligned.
    const entry1_payload_len = other_payload.len;
    const entry1_len = 8 + entry1_payload_len;
    const entry1_padded = std.mem.alignForward(usize, entry1_len, 8);
    const entry2_payload_len = pkcs7_payload.len;
    const entry2_len = 8 + entry2_payload_len;
    const entry2_padded = std.mem.alignForward(usize, entry2_len, 8);

    const cert_table_size = entry1_padded + entry2_padded;

    const cert_table_off: u32 = 0x600;
    const total_size = cert_table_off + cert_table_size;

    var img = try allocator.alloc(u8, total_size);
    defer allocator.free(img);
    @memset(img, 0);
    @memcpy(img[0..2], &dos_signature);
    std.mem.writeInt(u32, img[0x3C..0x40], 0x40, .little);
    @memcpy(img[0x40..0x44], &nt_signature);
    std.mem.writeInt(u16, img[0x44 + 16 .. 0x44 + 18][0..2], 240, .little);
    std.mem.writeInt(u16, img[0x58..0x5A][0..2], pe32_plus_magic, .little);
    std.mem.writeInt(u32, img[0x58 + 108 .. 0x58 + 112][0..4], 16, .little);

    // Fill Security data directory entry.
    const sec_dir = 0x58 + 112 + 32;
    std.mem.writeInt(u32, img[sec_dir .. sec_dir + 4][0..4], cert_table_off, .little);
    std.mem.writeInt(u32, img[sec_dir + 4 .. sec_dir + 8][0..4], @intCast(cert_table_size), .little);

    // Entry 1: non-PKCS#7.
    var off: usize = cert_table_off;
    std.mem.writeInt(u32, img[off .. off + 4][0..4], @intCast(entry1_len), .little);
    std.mem.writeInt(u16, img[off + 4 .. off + 6][0..2], win_cert_revision_2_0, .little);
    std.mem.writeInt(u16, img[off + 6 .. off + 8][0..2], 0x0001, .little); // X.509 not PKCS#7
    @memcpy(img[off + 8 .. off + 8 + entry1_payload_len], other_payload);
    off += entry1_padded;
    // Entry 2: PKCS#7.
    std.mem.writeInt(u32, img[off .. off + 4][0..4], @intCast(entry2_len), .little);
    std.mem.writeInt(u16, img[off + 4 .. off + 6][0..2], win_cert_revision_2_0, .little);
    std.mem.writeInt(u16, img[off + 6 .. off + 8][0..2], win_cert_type_pkcs_signed_data, .little);
    @memcpy(img[off + 8 .. off + 8 + entry2_payload_len], pkcs7_payload);

    const pe = try parsePe(img);
    try std.testing.expectEqual(cert_table_off, pe.cert_table_offset);

    var it = WinCertIterator.init(pe);
    const first = (try it.next()) orelse return error.TestUnexpectedNull;
    try std.testing.expectEqual(@as(u16, 0x0001), first.cert_type);
    const second = (try it.next()) orelse return error.TestUnexpectedNull;
    try std.testing.expectEqual(win_cert_type_pkcs_signed_data, second.cert_type);
    try std.testing.expectEqualStrings(pkcs7_payload, second.data);
    try std.testing.expect((try it.next()) == null);

    const sig = (try findFirstPkcs7Entry(pe)) orelse return error.TestUnexpectedNull;
    try std.testing.expectEqualStrings(pkcs7_payload, sig.data);
}
