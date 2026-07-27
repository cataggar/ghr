# Harden Certificate DER Parsing Implementation Plan

Closes #167.

## Overview

Zig 0.16's `std.crypto.Certificate.parse` and `std.crypto.Certificate.der.Element.parse`
perform no bounds checking, so a malformed or truncated certificate supplied by a
downloaded artifact causes an index-out-of-bounds **panic** rather than a returned
error. A panic is not catchable with `catch`, so it aborts the process.

This plan routes every externally-supplied DER byte in `ghr` through a shared,
bounds-checked parser: a new `src/der.zig` module hosting `parseElement` (moved
from `src/rfc3161.zig`) and a new bounds-checked `parseCertificate` that returns
the standard `std.crypto.Certificate.Parsed`, so no downstream code changes shape.

## Current State Analysis

### The panicking primitives

`lib/std/crypto/Certificate.zig` `der.Element.parse` (0.16, lines 900-936):

- indexes `bytes[i]` and `bytes[i + 1]` without checking `i + 1 < bytes.len`
- computes `slice.end = i + len` without clamping to `bytes.len`
- can overflow the `u32` end offset for a 4-octet long form

`Certificate.parse` (Certificate.zig:422-556) then parses sibling elements at
offsets such as `tbs_certificate.slice.end`, which may already be past the end of
the buffer, so a top-level length guard alone is not sufficient.

### A second panic the issue does not mention

`Certificate.parseBitString` (Certificate.zig:563-567) reads
`cert.buffer[elem.slice.start]` with no check that the element is non-empty. A
zero-length `BIT STRING` whose content starts at `buffer.len` panics *even with
bounds-checked element parsing*. `Certificate.parse` calls it twice — once for
`pub_key` and once for `signature` — so the vendored parser must guard it.

### Call sites carrying externally-supplied bytes

| File | `cert.parse()` | raw `der.Element.parse` |
| --- | --- | --- |
| `src/sigstore.zig` | 9 (`:668`, `:692`, `:766`, `:774`, `:781`, `:1525`, `:1831`, `:1956`, `:2472`) | 13 (`:809`, `:811`, `:813`, `:1530`, `:1534`, `:1554`, `:1555`, `:1559`, `:1565`, `:1569`, `:1571`, `:1573`, `:1576`) |
| `src/authenticode.zig` | 6 (`:1152`, `:1260`, `:2050`, `:2059`, `:2064`, `:2072`) | 61 (`:739`-`:1648`) |
| `src/rfc3161.zig` | 6 (`:473`, `:602`, `:733`, `:743`, `:758`, `:1028`) | 0 (already fully routed through its local `parseElement`) |

`src/sigstore.zig:1524-1580` (`extractIdentity`) is the sharpest example: it walks
SAN `GeneralName` entries and the Fulcio extension sequence with raw
`Certificate.der.Element.parse` over freshly downloaded `leaf_der`.

### Prior art already in the repo

`src/rfc3161.zig:115-149` defines `parseElement`, a bounds-checked replacement that
returns `error.InvalidDerElement`, and routes all 64 of its own element parses
through it. Its regression test is `src/rfc3161.zig:1133` ("malformed DER elements
return errors instead of panicking"). `src/sigstore.zig:1616` already reaches
across module boundaries to call `rfc3161.parseElement`, which is the clearest
signal that the helper wants a shared home.

### Key discoveries

- Every helper `Certificate.parse` needs is **`pub`** in std: `parseVersion`
  (`:746`), `parseTime` (`:572`), `parseBitString` (`:563`), `parseAlgorithm`
  (`:715`), `parseAlgorithmCategory` (`:719`), `parseAttribute` (`:723`),
  `parseNamedCurve` (`:727`), `parseExtensionId` (`:731`). `Parsed`
  (`:178-193`) has public fields. So a vendored `parseCertificate` can be a
  faithful ~120-line copy that only swaps the element parser and returns a real
  `Certificate.Parsed` — `.verify()`, `.issuer()`, `.subject()`, `.pubKey()`,
  `.subjectAltName()` all keep working untouched.
- Bounds-checked elements make the sibling-walk loops (`while (name_i < subject.slice.end)`,
  `while (ext_i < extensions.slice.end)`) **termination-safe**: `parseElement`
  guarantees `slice.end >= index + 2`, so each iteration strictly advances. No
  infinite-loop guard is needed.
- Once elements are bounds-checked, the std helpers that slice by
  `elem.slice.start..elem.slice.end` (`parseEnum` at `:737`, `parseTime`,
  `parseVersion`) are safe to reuse as-is. Only `parseBitString` needs replacing.
- `Certificate.Bundle` instances are built exclusively from `@embedFile`'d trust
  roots (`src/sigstore.zig:695-700`, `src/authenticode.zig:1841-1860`). No
  downloaded certificate is ever added to a bundle, so bundle parsing is **out of
  scope**.
- Sigstore's cert-adjacent functions use inferred error sets, so routing there is
  mostly mechanical. `src/rfc3161.zig:104` and `src/authenticode.zig:1089`
  explicitly union `der.Element.ParseError || Certificate.ParseError` and must be
  updated to the new module's error sets.
- Tests are inline at file bottom and run with `zig build test`. `src/main.zig:756`
  carries an explicit `test { _ = @import(...) }` block because "Zig 0.16 does not
  auto-include tests from indirectly referenced files" — `src/der.zig` must be
  added there.

## Desired End State

No input reachable from `ghr download` / `ghr install` can panic the process
through DER parsing. Specifically:

- `src/der.zig` is the single source of bounds-checked DER parsing, exporting
  `parseElement` and `parseCertificate`.
- Zero occurrences of `Element.parse(` or `cert.parse()` remain in
  `src/sigstore.zig`, `src/authenticode.zig`, `src/rfc3161.zig`.
- Malformed certificates produce `error.InvalidDerElement` (or an existing
  domain error) and fail verification closed.
- `zig build test` passes, including new regression tests for empty input,
  truncation at the top level, internal truncation that keeps the top-level TLV
  consistent, 4-octet long-form overflow, and empty `BIT STRING` at end of buffer.

Verification: `zig build test`, plus a `-Doptimize=ReleaseFast` build to confirm
the hardened paths compile without the safety checks that currently mask the bug.

## What We're NOT Doing

- Not upstreaming the bounds checks to Zig's standard library (issue #167 option
  3). Worth a follow-up issue, but this plan must stand alone against 0.16.
- Not rewriting DER parsing from scratch or introducing a general ASN.1 library.
  `parseCertificate` stays a faithful, reviewable copy of the std function.
- Not hardening `Certificate.Bundle` ingestion or system trust store parsing —
  those consume embedded/OS-supplied bytes, not downloaded ones.
- Not changing any verification semantics, trust policy, or error surfaced to
  the user beyond turning aborts into ordinary verification failures.
- Not touching `src/minisign.zig` (no DER) or `src/snappy.zig`.

## Implementation Approach

Bottom-up. Build and test the shared module first (Phase 1), then convert call
sites one file at a time (Phases 2-4), each phase independently compiling and
testable. Finish with an end-to-end pass and a guard that prevents regressions
(Phase 5).

`parseCertificate` returns `std.crypto.Certificate.Parsed`, which is the decision
that keeps this change small: no call site changes types, only the function it
calls and, where explicit, its error set.

---

## Phase 1: `src/der.zig` foundation — ✅ COMPLETE

### Overview

Create the shared module, move `parseElement` into it, and add the bounds-checked
`parseCertificate`. Convert `src/rfc3161.zig` to import it (its 6 `cert.parse()`
sites are handled here too, since the module move already touches that file —
its element parses are already routed through the local `parseElement`).

### Changes Required:

#### 1. New shared DER module

**File**: `src/der.zig` (new)
**Changes**: Host the bounds-checked element parser (moved verbatim from
`src/rfc3161.zig:115-149`, with its error set narrowed to a module-local one) and
the vendored certificate parser.

```zig
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
/// truncated or hostile encoding panics (and, for a 4-octet long form, overflows
/// the `u32` end offset) instead of returning an error. Every element parsed
/// from downloaded bytes goes through here, so the returned slice is guaranteed
/// to lie entirely within `bytes`.
///
/// The returned element always satisfies `slice.end >= index + 2`, so callers
/// that advance with `i = elem.slice.end` always make progress.
pub fn parseElement(bytes: []const u8, index: u32) ParseError!Element {
    // Body moved verbatim from src/rfc3161.zig:115-149.
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
/// `parseBitString` rejects an empty BIT STRING instead of indexing past the
/// end of the buffer. All other helpers are the `pub` std ones, which are safe
/// once their element arguments are bounds-checked.
pub fn parseCertificate(cert: Certificate) CertificateParseError!Certificate.Parsed {
    // Copy of Certificate.zig:422-556 with `der.Element.parse` -> `parseElement`
    // and `Certificate.parseBitString` -> `parseBitString` below.
}

/// `std.crypto.Certificate.parseBitString` reads `cert.buffer[elem.slice.start]`
/// without checking that the element is non-empty, so a zero-length BIT STRING
/// whose content begins at `buffer.len` panics even when the element itself was
/// bounds-checked.
fn parseBitString(cert: Certificate, elem: Element) CertificateParseError!Slice {
    if (elem.identifier.tag != .bitstring) return error.CertificateFieldHasWrongDataType;
    if (elem.slice.start >= elem.slice.end) return error.InvalidDerElement;
    if (cert.buffer[elem.slice.start] != 0) return error.CertificateHasInvalidBitString;
    return .{ .start = elem.slice.start + 1, .end = elem.slice.end };
}
```

#### 2. Move `parseElement` out of `src/rfc3161.zig`

**File**: `src/rfc3161.zig`
**Changes**:

- Replace `const der = Certificate.der;` (`:11`) with `const der = @import("der.zig");`.
- Delete the `parseElement` body (`:115-149`) and re-export for existing callers:
  `pub const parseElement = der.parseElement;` (keeps `src/sigstore.zig:1616`
  compiling until Phase 2 removes it).
- Convert the 6 `cert.parse()` sites (`:473`, `:602`, `:733`, `:743`, `:758`,
  `:1028`) to `der.parseCertificate(cert)`.
- In `VerifyError` (`:104`), replace `der.Element.ParseError || Certificate.ParseError`
  with `der.ParseError || der.CertificateParseError`. `InvalidDerElement` is
  already a member (`:94`), so it can be dropped from the explicit list once it
  arrives via `der.ParseError`.
- Move the `malformed DER elements return errors instead of panicking` test
  (`:1133-1168`) into `src/der.zig` alongside the code it covers.

#### 3. Test discovery

**File**: `src/main.zig`
**Changes**: add `_ = @import("der.zig");` to the `test` block at `:756`.

#### 4. New regression tests

**File**: `src/der.zig`
**Changes**: the moved `parseElement` test, plus a new certificate test using an
`@embedFile`'d real leaf (reuse an existing fixture under `src/sigstore/testdata`)
mutated at runtime:

```zig
test "malformed certificates return errors instead of panicking" {
    const Certificate = std.crypto.Certificate;

    // Empty buffer — panicked at Certificate.zig:905 via :424.
    try std.testing.expectError(
        error.InvalidDerElement,
        parseCertificate(.{ .buffer = "", .index = 0 }),
    );

    // Truncated at the top level.
    try std.testing.expectError(
        error.InvalidDerElement,
        parseCertificate(.{ .buffer = "\x30\x82\x05\xf4", .index = 0 }),
    );

    // Real leaf truncated to half length with the outer SEQUENCE length
    // rewritten so the top-level TLV still spans the buffer exactly. This
    // panicked at Certificate.zig:490 (sig_algo at tbs_certificate.slice.end),
    // proving a top-level length guard alone is not sufficient.
    // ... build the mutated buffer, expect an error, not a panic.

    // 4-octet long-form length whose end offset overflows u32.
    // Empty BIT STRING at end of buffer (the parseBitString panic).

    // A well-formed leaf still parses, and yields the same fields as
    // std's parser on valid input.
}
```

The last assertion is the important one: for a **valid** certificate,
`parseCertificate` must return exactly what `Certificate.parse` returns, field for
field. That is the guard against the vendored copy drifting from std.

### Success Criteria:

- `zig build test` passes.
- `src/der.zig` contains `parseElement`, `parseCertificate`, and their tests.
- `src/rfc3161.zig` contains no `Certificate.der.Element.parse` and no `.parse()`
  on a `Certificate`.
- The valid-certificate equivalence test asserts field-for-field equality with
  `std.crypto.Certificate.parse` on a real leaf.

**Implementation Note**: After completing this phase, pause here for manual
confirmation that the testing was successful before proceeding.

---

## Phase 2: Route `src/sigstore.zig` — ✅ COMPLETE

### Overview

Convert all 22 unchecked parses in the Sigstore path — the most exposed surface,
since `certificate.rawBytes` comes straight out of a downloaded `.sigstore.json`
or a GitHub attestation bundle.

### Changes Required:

#### 1. Import and certificate parses

**File**: `src/sigstore.zig`
**Changes**:

- Add `const der = @import("der.zig");` next to the existing
  `const Certificate = std.crypto.Certificate;` (`:44`).
- Convert the 9 `cert.parse()` sites to `der.parseCertificate(...)`, preserving
  each site's existing `catch` mapping:
  - `:668` and `:1831` -> `catch return error.LeafCertParseFailed`
  - `:692` -> `catch return error.TrustBundleBuildFailed`
  - `:766`, `:781` -> `catch return error.LeafCertParseFailed`
  - `:774` -> `catch return error.TrustBundleBuildFailed`
  - `:1525` -> `catch return id` (best-effort identity extraction)
  - `:1956`, `:2472` -> `try`

#### 2. Raw element parses

**File**: `src/sigstore.zig`
**Changes**: replace all 13 `Certificate.der.Element.parse(...)` with
`der.parseElement(...)`:

- `:809`, `:811`, `:813` — `embeddedRekorKey` SPKI walk. Embedded input, but
  converted for uniformity so the grep guard in Phase 5 can be absolute.
- `:1530`, `:1534` — `extractIdentity` SAN `GeneralName` walk over downloaded
  `leaf_der`. **Highest-risk site in the file.**
- `:1554`, `:1555`, `:1559`, `:1565`, `:1569`, `:1571`, `:1573`, `:1576` —
  `extractIdentity` Fulcio extension walk, likewise over downloaded `leaf_der`.
- Replace the `rfc3161.parseElement` call at `:1616` with `der.parseElement` and
  drop the now-unnecessary cross-module reach.

The existing `catch break` / `catch return id` handling at these sites already
does the right thing once the parser returns errors instead of panicking, so the
control flow does not change.

#### 3. Tests

**File**: `src/sigstore.zig`
**Changes**: add a test that drives `extractIdentity` and `verifyCertChain` with
(a) an empty leaf, (b) a leaf truncated at half length with a rewritten outer
length, and (c) a leaf whose SAN extension octet-string is truncated mid
`GeneralName`. Each must return an error or an empty `Identity`, never panic.

### Success Criteria:

- `zig build test` passes.
- `grep -c "Element.parse(\|\.parse()" src/sigstore.zig` returns 0.
- New malformed-leaf tests pass and cover the SAN walk specifically.

**Implementation Note**: Pause for manual confirmation before proceeding.

---

## Phase 3: Route `src/authenticode.zig` — ✅ COMPLETE

### Overview

The largest mechanical change: 6 `cert.parse()` plus 61 raw element parses over
certificates and PKCS#7 structures embedded in a downloaded `.exe`/`.dll`.

### Changes Required:

#### 1. Import switch

**File**: `src/authenticode.zig`
**Changes**: replace `const der = Certificate.der;` (`:591`) with
`const der = @import("der.zig");`. Because `src/der.zig` re-exports `Element`,
`Identifier`, `Tag`, and `Slice`, every type reference keeps compiling and only
the `parse` calls need editing.

#### 2. Element parses

**File**: `src/authenticode.zig`
**Changes**: replace all 61 `der.Element.parse(` with `der.parseElement(` at
`:739`-`:1648`. These cluster into:

- `parseSignedDataInternal` and its helpers (`:739`-`:958`) — the PKCS#7
  ContentInfo / SignedData / SignerInfo walk.
- SpcIndirectData and attribute parsing (`:1006`-`:1114`).
- The `CertificateSet` iterator and issuer/serial extraction (`:1249`-`:1279`).
- Nested-signature and countersignature walking (`:1325`-`:1361`).
- `extractSubjectCn` / `extractOrganization` re-parsing (`:1584`-`:1648`).

#### 3. Certificate parses

**File**: `src/authenticode.zig`
**Changes**: convert `:1152`, `:1260`, `:2050`, `:2059`, `:2064`, `:2072` to
`der.parseCertificate(...)`, preserving each site's `try` / `catch continue` /
`catch return error.InvalidSignature` handling.

#### 4. Error sets

**File**: `src/authenticode.zig`
**Changes**:

- `Pkcs7Error` (`:642-657`): replace the trailing `|| der.Element.ParseError`
  with `|| der.ParseError`. `InvalidDerElement` therefore becomes reachable from
  every PKCS#7 entry point, which is the intended behavior change.
- `VerifyError` (`:1080-1089`): replace
  `der.Element.ParseError || Certificate.ParseError` with
  `der.ParseError || der.CertificateParseError`, and drop the now-redundant
  explicit `InvalidDerElement` member.

#### 5. Tests

**File**: `src/authenticode.zig`
**Changes**: add a test feeding truncated PKCS#7 blobs and a truncated embedded
certificate through `parseSignedData` and the chain walk, asserting errors rather
than aborts. Mirror the shape of the existing
`buildTrustBundle parses all embedded Authenticode roots` test (`:1895`) for
fixture handling.

### Success Criteria:

- `zig build test` passes.
- `grep -c "Element.parse(\|\.parse()" src/authenticode.zig` returns 0.
- All 13 pre-existing tests in the file still pass unchanged — the conversion
  must not alter behavior on valid input.

**Implementation Note**: Pause for manual confirmation before proceeding.

---

## Phase 4: Sweep and consolidate — ✅ COMPLETE

### Overview

Remove the transitional shims and confirm nothing unchecked remains anywhere in
`src/`.

### Changes Required:

#### 1. Drop the compatibility re-export

**File**: `src/rfc3161.zig`
**Changes**: remove `pub const parseElement = der.parseElement;` now that
`src/sigstore.zig:1616` calls `der.parseElement` directly (Phase 2). Verify no
other module references `rfc3161.parseElement`.

#### 2. Repository-wide sweep

**Files**: all of `src/`
**Changes**: search for any remaining `Certificate.der.Element.parse`,
`der.Element.parse`, `Certificate.parse`, or `.parse()` on a `Certificate` value
and convert. Confirm `src/release.zig:1910` and `:1947` only pass
`Certificate.Bundle` values around and need no change.

#### 3. Documentation

**File**: `doc/README.md`
**Changes**: if the document describes the verification pipeline's failure modes,
note that malformed certificates now fail verification closed with an error rather
than aborting. Skip if there is no relevant section — do not invent one.

### Success Criteria:

- `rg "Element\.parse\(" src/` returns no matches.
- `rg "\.parse\(\)" src/` returns no matches on `Certificate` values.
- `zig build test` passes.

**Implementation Note**: Pause for manual confirmation before proceeding.

---

## Phase 5: End-to-end verification and regression guard — ✅ COMPLETE

### Overview

Prove the fix at the boundary the user actually reaches, and prevent the
unchecked parsers from creeping back in.

### Changes Required:

#### 1. End-to-end malformed-input tests

**File**: `src/sigstore.zig` and `src/authenticode.zig`
**Changes**: drive the public verification entry points with corrupted bundles —
not just the parsers — so the test covers the full path a downloaded artifact
takes. Model these on
`src/rfc3161.zig:1170` ("malformed timestamp tokens are rejected without
panicking"), which already iterates a table of hostile inputs against
`verifyDetached` with an empty trust bundle.

#### 2. Grep-based regression guard

**File**: `src/der.zig`
**Changes**: add a test that `@embedFile`s the three converted sources and asserts
they contain no unchecked parser calls. This is cheap and catches the one failure
mode a type system cannot: `Element` is re-exported from std, so `Element.parse`
would silently resolve to the panicking version if reintroduced.

```zig
test "no unchecked DER parsers remain in converted sources" {
    inline for (.{
        @embedFile("sigstore.zig"),
        @embedFile("authenticode.zig"),
        @embedFile("rfc3161.zig"),
    }) |source| {
        try std.testing.expect(std.mem.indexOf(u8, source, "Element.parse(") == null);
    }
}
```

If `@embedFile` on a sibling `.zig` source proves awkward under the current build
graph, fall back to a `build.zig` check step; do not skip the guard.

#### 3. Optimize-mode check

**Changes**: build with `-Doptimize=ReleaseFast` and `-Doptimize=ReleaseSafe` to
confirm the hardened paths compile and that no safety check was load-bearing.

### Success Criteria:

- `zig build test` passes.
- `zig build -Doptimize=ReleaseSafe` and `zig build -Doptimize=ReleaseFast`
  both succeed.
- The grep guard test fails if `Element.parse(` is reintroduced (verify by
  temporarily reverting one call site).

---

## Testing Strategy

### Unit Tests

- `parseElement`: empty input, missing length octet, short form overrunning the
  buffer, 4-octet long form overflowing `u32`, long form whose size octets run
  past the buffer, long form wider than `u32`, indefinite length, start index past
  end of buffer, and both valid length forms. (Moved from `src/rfc3161.zig:1133`.)
- `parseCertificate`: empty buffer, top-level truncation, internal truncation with
  a consistent top-level TLV, 4-octet long-form overflow, empty `BIT STRING` at
  end of buffer, and field-for-field equivalence with `std.crypto.Certificate.parse`
  on a valid leaf.
- `extractIdentity`: truncated SAN octet string, truncated Fulcio extension
  sequence, certificate with no extensions.

### Integration Tests

- Sigstore bundle verification with a corrupted `certificate.rawBytes`, exercised
  through the public verify entry point with an empty trust bundle.
- Authenticode verification with a truncated embedded PKCS#7 blob and with a
  truncated certificate inside a well-formed `CertificateSet`.
- Existing valid-input tests across all three files must pass unchanged. This is
  the primary guard that the conversion is behavior-preserving.

### Manual Testing Steps

1. `zig build test` — full suite green.
2. `zig build -Doptimize=ReleaseSafe` and `zig build -Doptimize=ReleaseFast`.
3. Run a real `ghr install` of a Sigstore-attested tool and confirm verification
   still succeeds end to end.
4. Run a real `ghr download` of an Authenticode-signed Windows asset and confirm
   verification still succeeds.
5. Corrupt a cached `.sigstore.json` `certificate.rawBytes` and confirm `ghr`
   reports a verification failure and exits non-zero, with no `thread panic` in
   the output.

## Performance Considerations

`parseElement` adds a handful of comparisons and two checked adds per DER element.
Certificates parsed per verification are in the low tens, so the cost is
unmeasurable against a network download. `parseCertificate` is a copy of the std
function with identical algorithmic structure — no additional passes over the
buffer.

## Migration Notes

None. No on-disk formats, cached artifacts, or CLI flags change. Inputs that
previously aborted the process now fail verification with an error, which is
strictly better behavior for every existing caller. Inputs that previously
verified successfully continue to verify successfully — enforced by the
equivalence test in Phase 1 and the untouched valid-input test suites.

## References

- Issue: #167 "Harden certificate DER parsing against malformed input (panic on truncated certs)"
- Found while reviewing #165 Phase 2
- Prior art: `src/rfc3161.zig:115-149` (`parseElement`), `src/rfc3161.zig:1133`
  (malformed-element test), `src/rfc3161.zig:1170` (malformed-token test)
- Upstream source: `lib/std/crypto/Certificate.zig` (Zig 0.16) — `der.Element.parse`
  at `:900-936`, `Certificate.parse` at `:422-556`, `parseBitString` at `:563-567`
- Highest-risk call site: `src/sigstore.zig:1524-1580` (`extractIdentity`)
