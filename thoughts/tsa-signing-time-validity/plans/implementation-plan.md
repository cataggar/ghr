# Signing-Time Certificate Validity Implementation Plan

## Overview

Certificate validity must be evaluated at the time a signature was made, not
at the moment `ghr` happens to run. Authenticode verification currently
evaluates two things against the wall clock — the TSA certificate chain and
the embedded root set — so legitimately signed assets stop verifying as
certificates age out. Move both onto the signing-time clock.

Closes #172.

## Current State Analysis

`verifyPe` already gets this right for the signer chain. It verifies the RFC
3161 countersignature, then validates the signer chain at the token's
`genTime` (`src/authenticode.zig:1598-1603`), so a signature survives its
signer certificate's expiry. That is the whole point of timestamping.

Two other clocks contradict it.

### 1. The TSA chain is validated against the wall clock

`verifyTimestamp` passes `.wall_clock` to `rfc3161.verifyDetached`
(`src/authenticode.zig:1397`). Its doc comment is explicit that this was a
refactor-preservation choice, not a policy decision:

> Select `.wall_clock` so the refactor preserves Authenticode's existing TSA
> certificate validity policy.

`verifyPe`'s own doc comment describes the same split as intentional — `now`
for the TSA cert, `genTime` for the signer chain. The design is
self-defeating: it frees the signer chain from its expiry, then makes the TSA
chain the new ceiling. TSA certificates are routinely shorter-lived than the
signing certificates they attest to.

Observed on `main`:

| certificate | notAfter |
| --- | --- |
| git-lfs signer leaf (GitHub, Inc.) | 2025-10-19 |
| Microsoft ID Verified CS EOC CA 02 | 2026-04-13 |
| **Microsoft Public RSA Time Stamping Authority** | **2025-11-19** |

The signer chain validates cleanly at `genTime` (2025-10-16). The TSA leaf
expired 2025-11-19 and is checked against today, so verification fails with
`CertificateExpired` and the download is blocked.

Note the signer leaf is a Microsoft short-lived EOC certificate with a
**three day** window. Under that model the timestamp is not an optimization;
it is the only thing that makes the signature verifiable past day three.

### 2. The embedded root set is filtered by the wall clock

`release.zig:1896` builds the trust bundle at `Io.Clock.now(.real, io)`. That
value reaches `std`'s `Certificate.Bundle.parseCert`, which silently drops
any root already past its `notAfter`:

```zig
if (now_sec > parsed_cert.validity.not_after) {
    // Ignore expired cert.
    cb.bytes.items.len = decoded_start;
    return;
}
```

A dropped root is indistinguishable from a root that was never embedded: the
chain walk simply fails to find an issuer. This is the same bug as #172, not
yet triggered. The earliest embedded root is GlobalSign R3, expiring
**2029-03-18**; on that date every signature made under it stops verifying,
despite having been valid when made.

### Key Discoveries

- `rfc3161.ChainClock` already exists (`src/rfc3161.zig:13-16`) with a
  `selectChainTime` helper (`:773-778`) and unit coverage (`:1067`). The
  mechanism needs no new code — Authenticode just passes the wrong variant.
- **Sigstore already applies the intended policy.** It uses `.gen_time`
  (`src/sigstore.zig:615`) *and* anchors its root set at signing time,
  passing `bundle.rekor.?.integrated_time` to `buildTrustBundle`
  (`:1795-1801`, `:1997`, `:2499`). Authenticode is the outlier in this
  repo, so this plan makes it consistent rather than introducing a new idea.
- `std`'s `Parsed.verify` enforces only the **subject's** validity window,
  never the issuer's (`Certificate.zig:264-267`). Root validity is therefore
  enforced only by the explicit check in `verifyChain`
  (`src/authenticode.zig:2071-2073`), which already uses `verify_at`. That
  part is already correct.
- The trust anchor is anchored by being `@embedFile`'d into the binary, not
  by its `notAfter`. Distrusting a root is a code change (removing it from
  `embedded_roots`), which an expiry date does not express.
- **No test covers the Authenticode timestamp positive path.** The only
  `wall_clock` assertions are `selectChainTime`'s unit test, which tests the
  enum and stays valid either way. Nothing would catch a regression here.
- Empirically confirmed: flipping `authenticode.zig:1397` to `.gen_time`
  makes `git-lfs-windows-v3.7.1.exe` verify (genTime 2025-10-16T23:57:02Z)
  and leaves `azureauth-0.9.6-win-x64.zip` (290 PEs) verifying as before.

## Desired End State

Every certificate in an Authenticode verification — signer leaf,
intermediates, TSA chain, and trust anchors — is evaluated at the signing
time established by the RFC 3161 countersignature. The wall clock plays no
part in certificate validity.

Verified by: `git-lfs-windows-v3.7.1.exe` verifies and reports
`subject: GitHub, Inc.`; `azureauth-0.9.6-win-x64.zip` continues to verify;
a test pins the git-lfs chain, which is verifiable at its `genTime` and at no
useful wall-clock time.

## What We're NOT Doing

- **Not** adding a bound on `genTime` (future-dating, floors, skew windows).
  Sigstore bounds `gen_time` via a pinned TSA signer plus
  `period.contains(gen_time)`, but it can do that because it knows its one
  TSA. Authenticode must accept many. `genTime` is signed by a TSA that must
  chain to an embedded root and carry the timestamping EKU
  (`rfc3161.zig:185`) — the same anchor as everything else. A wall-clock
  bound on top would reintroduce the failure being removed.
- **Not** touching revocation. No CRL or OCSP checking exists today and this
  plan does not add any.
- **Not** changing Sigstore's clock handling; it is already correct.
- **Not** changing the `rfc3161` module. `ChainClock` is used as designed.
- **Not** fixing the leaf-attribution bug — separate, in PR #174.

## Implementation Approach

Two small changes, each independently verifiable, then the test coverage
that should have existed to catch either. The risk is not in the diff size —
it is that there is currently no positive-path test on this path at all, so
Phase 3 carries most of the weight.

---

## Phase 1: Validate the TSA chain at signing time ✅ COMPLETE

### Overview
Make the TSA chain use the same clock as the signer chain.

### Changes Required

**File**: `src/authenticode.zig`

Change the `chain_clock` argument in `verifyTimestamp` (~line 1397) from
`.wall_clock` to `.gen_time`, and rewrite the doc comment's step 3, which
currently documents the refactor-preservation rationale:

```zig
///   3. Select `.gen_time` so the TSA chain is validated at the instant the
///      token was issued. Validating it against the wall clock would make
///      every timestamped signature unverifiable once the TSA's own
///      certificate expires — the failure timestamping exists to prevent.
```

Update `verifyPe`'s doc comment (~line 1556), which currently states that
`now` "is the wall-clock used to enforce the TSA cert's own validity
window", to describe a single signing-time clock.

`now` remains a parameter: it is still threaded to `rfc3161.verifyDetached`
and is used by the trust-bundle construction Phase 2 addresses.

### Success Criteria

- `zig build test` — 362/363, only the pre-existing `.deb` failure.
- `ghr download git-lfs/git-lfs/git-lfs-windows-v3.7.1.exe` verifies,
  reporting `genTime 2025-10-16T23:57:02Z`.
- `ghr download 'AzureAD/microsoft-authentication-cli/azureauth-0.9.6-win-x64.zip@0.9.6'`
  still verifies 290 PEs.

**Implementation Note**: Pause for manual confirmation before proceeding.

---

## Phase 2: Stop filtering the trust anchors by the wall clock ✅ COMPLETE

### Overview
Prevent `std` from silently dropping embedded roots based on today's date.

### Changes Required

The constraint is ordering: the trust bundle is built in `release.zig:1896`
*before* any signature is parsed, so `genTime` is not yet known. The bundle
therefore cannot be anchored at signing time the way Sigstore anchors its
own at `integrated_time`.

Since root validity is separately enforced at `verify_at` inside
`verifyChain` (`:2071-2073`), the bundle-build filter is redundant as well as
wrong. Disable it rather than trying to feed it a time it cannot know.

**File**: `src/authenticode.zig`

Drop the `now_sec` parameter from `buildTrustBundle` and pass a documented
sentinel to `parseCert`. `std`'s check is one-sided — only `not_after` — so
`0` disables filtering without weakening anything:

```zig
/// `parseCert` drops roots whose `notAfter` precedes the time it is given.
/// Pass 0 so no root is filtered by the wall clock: an artifact signed while
/// a root was valid must stay verifiable after that root expires. Root
/// validity is enforced at signing time in `verifyChain`.
const no_wall_clock_filter: i64 = 0;
```

Update the two in-module test call sites (`:2298`, `:2392`) and
`release.zig:1896`.

Keep `buildTrustBundle`'s existing test, which asserts all 15 roots parse,
and extend it to assert the count is independent of the clock.

### Success Criteria

- `zig build test` — 362/363.
- A test builds the bundle at a time past a root's `notAfter` and confirms
  all 15 roots are still present.
- Both live downloads from Phase 1 still verify.

**Implementation Note**: Pause for manual confirmation before proceeding.

---

## Phase 3: Pin the behaviour with tests ✅ COMPLETE

### Overview
Close the coverage gap that let both bugs exist. This is the phase that
matters most: Phases 1 and 2 are two-line changes, and nothing in the suite
currently exercises Authenticode timestamp verification end to end.

### Changes Required

**File**: `src/authenticode.zig`

Add a test that verifies the timestamp on the real fixture
`src/authenticode/testdata/git-lfs-windows-v3.7.1.pkcs7.der` and asserts the
returned `genTime` is `1760659022` (2025-10-16T23:57:02Z).

This fixture is the regression test for #172 by construction: its TSA leaf
expired 2025-11-19, so the test can only pass when the TSA chain is validated
at `genTime`. Under `.wall_clock` it fails with `CertificateExpired` at any
real run date after that. No date arithmetic or mocking is required — the
fixture encodes the bug.

Add a second test asserting the root set is not clock-filtered, per Phase 2.

### Success Criteria

- `zig build test` — 362/363 plus the new tests.
- Reverting Phase 1 makes the timestamp test fail with `CertificateExpired`;
  reverting Phase 2 makes the root-set test fail. Both verified by temporary
  reintroduction, not assumed.
- `zig build -Doptimize=ReleaseSafe` and `-Doptimize=ReleaseFast` succeed.

**Implementation Note**: Pause for manual confirmation before proceeding.

---

## Testing Strategy

### Unit Tests
- TSA chain verifies at `genTime` on a fixture whose TSA certificate has
  since expired.
- Trust bundle retains all 15 roots regardless of the clock it is built at.
- Existing `selectChainTime` coverage (`rfc3161.zig:1067`) is unaffected.

### Integration Tests
- `git-lfs-windows-v3.7.1.exe` — single PE, expired TSA. Fails on `main`,
  must verify after Phase 1.
- `azureauth-0.9.6-win-x64.zip` — 290 PEs inside a zip, TSA still valid.
  Verifies on `main`, must keep verifying. Guards against over-correction.

### Manual Testing Steps
1. `zig build test`.
2. `zig build -Doptimize=ReleaseSafe` and `-Doptimize=ReleaseFast`.
3. `ghr download git-lfs/git-lfs/git-lfs-windows-v3.7.1.exe` — verifies,
   reports `subject: GitHub, Inc.` (with #174 merged).
4. `ghr download 'AzureAD/microsoft-authentication-cli/azureauth-0.9.6-win-x64.zip@0.9.6'`
   — still verifies 290 PEs.
5. Confirm a Sigstore-attested install (`ghr download cli/cli`) is unaffected.

## Security Considerations

Validating the TSA chain at `genTime` means an attacker holding a TSA private
key that leaked *after* that certificate expired could mint tokens with a
backdated `genTime`. This is inherent to timestamping and is what every
Authenticode implementation accepts; the alternative — the current behaviour
— makes timestamping useless, since signatures become unverifiable exactly
when the timestamp is supposed to be carrying them.

What still constrains a forged token:
- The TSA chain must reach a root embedded in the binary.
- The TSA leaf must carry the timestamping EKU (`rfc3161.zig:185`).
- The TSTInfo message imprint must bind to the signer's signature bytes.
- The signer chain must independently validate at that same `genTime`.

Phase 2 does not weaken the anchor. A root is trusted because it is compiled
into the binary; its `notAfter` was never what conferred trust, and removing
a root remains a code change.

## Performance Considerations

None. Both changes alter which `i64` is compared against, not how much work
is done.

## Migration Notes

No on-disk format, cached artifact, or CLI flag changes. Assets that
previously failed `CertificateExpired` will verify. No asset that verifies
today stops verifying: Phase 1 only relaxes a check that was contradicting
the signer-chain clock, and Phase 2 only stops discarding roots.

## References

- Issue: https://github.com/cataggar/ghr/issues/172
- Sigstore precedent: `src/sigstore.zig:615`, `:1795-1801`
- Clock mechanism: `src/rfc3161.zig:13-16`, `:773-778`
- Wall-clock call sites: `src/authenticode.zig:1397`, `src/release.zig:1896`
- `std` root filter: `lib/std/crypto/Certificate/Bundle.zig:305-309`
- Related: #167 (DER hardening), #174 (leaf attribution)
