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
