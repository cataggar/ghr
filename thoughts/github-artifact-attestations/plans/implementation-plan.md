# GitHub-Native Artifact Attestation Support Implementation Plan

## Overview

Add automatic verification of GitHub-native artifact attestations to `ghr
install` and `ghr download` while preserving the existing release-sidecar
Sigstore flow. `--skip-sigstore` will continue to control only published
`*.sigstore.json` sidecars; a new `--skip-attestation` flag will control
GitHub's attestation service. When both forms are available, both will be
verified independently.

The implementation will support public and private GitHub.com repositories,
use the current versioned REST API, remain a single static Zig binary, and
fail closed on attestation API/transport/verification errors unless
`--skip-attestation` or the existing `--skip-verify` umbrella is supplied.

## Current State Analysis

- Verification gates currently cover checksum, minisign, sidecar Sigstore,
  and Authenticode only (`src/release.zig:55-61`,
  `src/download.zig:41-75`, `src/main.zig:64-87`).
- The shared download verification pipeline runs every enabled verifier and
  returns the strongest result (`src/release.zig:1949-2057`). Install has a
  parallel orchestration path with the same semantics
  (`src/install.zig:1907-2076`).
- Sidecar Sigstore verification discovers a release asset, downloads
  `<asset>.sigstore.json`, and invokes the native Sigstore verifier
  (`src/release.zig:1346-1437`).
- The existing Sigstore implementation already handles DSSE envelopes,
  in-toto subjects, SLSA-shaped payloads, Fulcio certificate chains, Rekor
  SETs, and inclusion proofs (`src/sigstore.zig:302-430`,
  `src/sigstore.zig:790-850`, `src/sigstore.zig:1362-1458`).
- The Sigstore parser currently requires a Rekor entry, does not retain or
  enforce `predicateType`, and extracts only SAN and OIDC issuer identity
  fields. It therefore cannot verify GitHub private-instance bundles or bind
  an attestation to the requested repository
  (`src/sigstore.zig:302-315`, `src/sigstore.zig:1238-1335`).
- GitHub's `2026-03-10` REST API returns attestation metadata containing a
  signed `bundle_url`. Current GitHub bundle URLs return raw-Snappy-compressed
  Sigstore Bundle v0.3 JSON, but that encoding is transport behavior rather
  than part of the REST schema. Relying on the older inline `bundle` response
  would make support depend on a legacy API representation.
- Public repositories use the Sigstore Public Good instance with Rekor.
  Private repositories use GitHub's Sigstore instance and RFC 3161 signed
  timestamps instead of a public transparency log.
- The Authenticode implementation already contains CMS/RFC 3161 parsing,
  signature verification, timestamp imprint binding, and certificate-chain
  validation that can be extracted for reuse
  (`src/authenticode.zig:1287-1430`).
- Owner/repository values are available during install resolution
  (`src/install.zig:2277-2360`) but are not passed into the verification
  helper. Download retains release metadata but not a uniform repository
  identity in `ResolvedTarget` (`src/download.zig:80-110`,
  `src/download.zig:488-625`).
- Both composite Actions expose every existing narrow verification gate and
  forward it to the CLI (`actions/install/action.yml:36-64`,
  `actions/install/action.yml:219-236`,
  `actions/download/action.yml:48-76`,
  `actions/download/action.yml:202-224`).

## Desired End State

For every downloaded GitHub release asset:

1. Existing checksum, minisign, Authenticode, and `*.sigstore.json`
   verification continues unchanged.
2. Unless `--skip-attestation` or `--skip-verify` is set, `ghr` computes the
   asset SHA-256 and requests SLSA provenance attestations from:

   ```text
   GET /repos/{owner}/{repo}/attestations/sha256:{digest}
       ?predicate_type=provenance&per_page=100
   ```

3. A `200` response with an empty `attestations` array means no native
   attestation was published and preserves today's fallback behavior.
4. Network, authentication, authorization, rate-limit, server, malformed
   response, bundle download, or decompression errors fail closed.
5. When attestations are returned, at least one must fully verify. Each
   candidate is checked until one satisfies all cryptographic and policy
   requirements; if none do, the operation fails.
6. Verification enforces:
   - Sigstore Bundle v0.3 structure.
   - A valid public Rekor proof or valid GitHub-instance RFC 3161 timestamp.
   - Fulcio certificate chain to the matching embedded trust root.
   - DSSE signature integrity.
   - In-toto Statement v1.
   - `https://slsa.dev/provenance/v1` predicate type.
   - SHA-256 subject binding. Native attestation lookup and verification are
     digest-based; subject names are informational because build artifacts
     may be renamed when uploaded as release assets.
   - GitHub Actions OIDC issuer.
   - Source repository and owner identity matching the requested
     `owner/repo`.
   - Build-config identity belonging to the requested repository while still
     allowing a reusable signer workflow from another repository.
7. If a release also publishes `*.sigstore.json`, both verifiers run and
   either verifier's failure aborts the operation.
8. Successful install metadata records `"verified":"github-attestation"` as
   the strongest result.

### Key Decisions

- `--skip-sigstore` remains sidecar-only.
- `--skip-attestation` skips only GitHub-native attestations.
- `--skip-verify` skips both, along with all other verification stages.
- Attestation discovery errors fail closed; users must explicitly pass
  `--skip-attestation` to continue.
- The feature uses the documented `bundle_url` representation and does not
  depend on the legacy inline bundle.
- A successful empty lookup is opportunistic absence, not proof that a
  release was intended to be unattested. Callers that require an attestation
  need a future explicit require-policy flag; this change preserves current
  fallback behavior.
- A focused native raw-Snappy decoder will be added rather than introducing
  runtime tools or third-party libraries. Transport decoding will also accept
  plain JSON and supported HTTP content encodings so GitHub can change storage
  representation without changing attestation semantics.
- The native attestation metadata label has precedence:

  ```text
  github-attestation > sigstore > minisign > authenticode
      > checksum > github-digest > none
  ```

## What We're NOT Doing

- Removing `*.sigstore.json` generation or uploads from ghr's release
  workflow.
- Changing `--skip-sigstore` semantics.
- Requiring every release to publish a GitHub-native attestation.
- Verifying SBOM, release, or arbitrary custom predicate types.
- Adding signer-workflow policy flags in this change.
- Supporting OCI image attestations or organization-wide attestation lookup.
- Adding GitHub Enterprise Server or Enterprise Cloud tenancy/hostname
  configuration; this plan targets `github.com`, matching current release
  lookup behavior.
- Shelling out to `gh attestation verify` or requiring `gh` beyond the
  existing optional authentication-token fallback.
- Implementing a general-purpose Snappy compressor.

## Implementation Approach

Add a small `attestation.zig` boundary around the GitHub REST API and bundle
transport. Keep cryptographic parsing and policy enforcement in
`sigstore.zig`, so sidecar and native attestations share DSSE, certificate,
and artifact-binding code without conflating their discovery or skip flags.

The API layer will use GitHub's current API version, fetch signed bundle URLs
without forwarding repository credentials, decompress the bounded response,
and hand the resulting standard Sigstore JSON to the existing parser.

The Sigstore verifier will be generalized from "Rekor-only public bundle" to
"trusted observation": public bundles use Rekor, while private GitHub bundles
use RFC 3161 timestamps. Repository policy will be applied only for
GitHub-native attestations; existing sidecar identity behavior remains
backward-compatible.

## Phase 1: GitHub Attestation API and Bundle Transport

### Overview

Implement deterministic attestation discovery and decode the current
`bundle_url` response into standard Sigstore Bundle JSON without adding an
external dependency.

### Implementation Status

- [x] Add the bounded raw-Snappy decoder and malformed-input tests.
- [x] Add the versioned GitHub attestation API and bundle transport client.
- [x] Register the new modules in the main test build.

### Changes Required

#### 1. Add a raw-Snappy decoder

**File**: `src/snappy.zig`

**Changes**:

- Implement only raw Snappy block decompression:
  - Decode and validate the uncompressed-length varint.
  - Support literal and copy tags 1, 2, and 4.
  - Correctly support overlapping back-references.
  - Reject truncated inputs, invalid offsets, integer overflow, and output
    larger than a fixed limit.
- Expose a single allocating API such as:

  ```zig
  pub fn decompressAlloc(
      allocator: std.mem.Allocator,
      compressed: []const u8,
      max_output: usize,
  ) ![]u8
  ```

- Add unit tests using Snappy specification vectors, overlapping copies,
  malformed tags, invalid offsets, and oversized declared lengths.

#### 2. Add the GitHub-native attestation client

**File**: `src/attestation.zig`

**Changes**:

- Define small API response types containing `repository_id`, `bundle_url`,
  and `initiator`. Treat those fields as transport metadata, not signed
  identity.
- Add a repository identity type:

  ```zig
  pub const Repository = struct {
      owner: []const u8,
      repo: []const u8,
  };
  ```

- Build the request using the artifact's lowercase SHA-256:

  ```text
  https://api.github.com/repos/{owner}/{repo}/attestations/sha256:{hex}
      ?predicate_type=provenance&per_page=100
  ```

- Send:
  - `Accept: application/vnd.github+json`
  - `X-GitHub-Api-Version: 2026-03-10`
  - Existing bearer authentication when available
  - Existing `ghr/<version>` user agent
- Bound the API response body and reject malformed/non-`200` responses.
- Return a distinct `.none` result only for a successful response with an
  empty `attestations` array.
- For each returned `bundle_url`:
  - Require HTTPS.
  - Download with a bounded helper that records `Content-Encoding`, using a
    temporary file under the existing ghr cache when needed.
  - Never attach the GitHub authorization header to the signed external URL.
  - Apply a compressed-size limit.
  - If the decoded body is already JSON, pass it through unchanged.
  - Honor supported HTTP compression such as gzip using Zig's standard
    library.
  - Otherwise decode the current raw-Snappy representation with
    `snappy.decompressAlloc`.
  - Reject unknown encodings and apply a bounded JSON size in every path.
  - Delete the temporary file on every path.
- Return owned bundle JSON candidates to the verification layer.
- Keep the candidate cap at the API page maximum of 100.

#### 3. Register modules in the test build

**File**: `src/main.zig`

**Changes**:

- Import `attestation.zig` and `snappy.zig` in the existing test import block
  so `zig build test` executes their unit tests.

### Success Criteria

- A captured current-version API response containing only `bundle_url`
  parses successfully.
- A captured signed bundle payload decompresses to valid Sigstore Bundle v0.3
  JSON.
- Equivalent plain-JSON and supported HTTP-compressed payloads reach the same
  Sigstore parser.
- Empty attestation responses are distinguishable from API/transport errors.
- Authorization is never sent to the external bundle host.
- Malformed or oversized Snappy data fails without partial output or
  unbounded allocation.

### Manual Verification

- [ ] Exercise an authenticated lookup against a private repository with a
  GitHub-native attestation. Blocked for user-owned private repositories:
  GitHub returns `Feature not available for user-owned private repositories`
  when `actions/attest-build-provenance` persists the attestation.
- [x] Inspect the requests with a local proxy or fixture and confirm the
  authorization header is sent to `api.github.com` but never to the external
  `bundle_url` host.

---

## Phase 2: Sigstore Trust, Timestamp, Predicate, and Identity Policy

### Overview

Generalize the existing Sigstore verifier so GitHub public and private
artifact attestations can be verified with repository-scoped policy while
preserving sidecar behavior.

### Changes Required

#### 1. Extract reusable RFC 3161 verification

**Files**:

- `src/rfc3161.zig`
- `src/authenticode.zig`

**Changes**:

- Move or wrap the existing CMS TimeStampToken parsing and verification
  primitives behind a detached-timestamp API:

  ```zig
  pub fn verifyDetached(
      allocator: std.mem.Allocator,
      token_der: []const u8,
      signed_message: []const u8,
      tsa_trust: Certificate.Bundle,
      now: i64,
      chain_clock: enum { wall_clock, gen_time },
    ) !i64
  ```

- Verify the timestamp token's CMS signer, TSA chain, and TSTInfo message
  imprint over the provided DSSE signature bytes.
- Parse and verify `genTime` before selecting the TSA-chain clock.
- For GitHub attestations, validate the TSA chain at signed `genTime` and
  return it for Fulcio leaf validation.
- For Authenticode, preserve its current wall-clock TSA-chain validation by
  selecting `.wall_clock`; extracting the helper must not silently change
  existing Authenticode acceptance behavior.

#### 2. Extend Bundle parsing

**File**: `src/sigstore.zig`

**Changes**:

- Make `verificationMaterial.tlogEntries` optional rather than requiring at
  least one at parse time.
- Parse
  `verificationMaterial.timestampVerificationData.rfc3161Timestamps[]`.
- Require at least one supported trusted observation:
  - Rekor entry for public-good verification, or
  - RFC 3161 timestamp for GitHub private-instance verification.
- Retain `predicateType` from the in-toto Statement in the parsed DSSE
  structure.
- Continue requiring exactly one DSSE signature.
- Preserve existing hashedrekord and sidecar DSSE parsing behavior.

#### 3. Add repository identity extraction and policy

**File**: `src/sigstore.zig`

**Changes**:

- Extend certificate identity parsing for the DER UTF8String Fulcio
  extensions:
  - `.1.8` OIDC issuer
  - `.1.9` Build Signer URI
  - `.1.11` Runner Environment
  - `.1.12` Source Repository URI
  - `.1.16` Source Repository Owner URI
  - `.1.18` Build Config URI
- Keep legacy issuer/repository extension parsing as a compatibility
  fallback where available.
- Add a verification policy type, for example:

  ```zig
  pub const VerificationPolicy = struct {
      expected_predicate_type: ?[]const u8 = null,
      expected_oidc_issuer: ?[]const u8 = null,
      expected_repository_uri: ?[]const u8 = null,
      expected_owner_uri: ?[]const u8 = null,
      expected_build_config_prefix: ?[]const u8 = null,
  };
  ```

- Add `verifyBundleWithPolicy`; keep the current `verifyBundle` as a wrapper
  with an empty policy so existing sidecar callers and tests remain
  compatible.
- For GitHub-native policy, enforce:
  - `predicateType == https://slsa.dev/provenance/v1`
  - issuer `https://token.actions.githubusercontent.com`
  - source repository `https://github.com/{owner}/{repo}`
  - source owner `https://github.com/{owner}`
  - build config under
    `https://github.com/{owner}/{repo}/.github/workflows/`
- Compare GitHub owner/repository identity case-insensitively while
  preserving exact URL structure and path boundaries.
- Do not require Build Signer URI/SAN to use the same repository; print it
  for review so reusable workflows remain supported.
- For native attestations, select a subject by the computed SHA-256 digest,
  not by filename. Require at least one digest match and treat the
  signed subject name as diagnostic output. Keep the existing filename +
  digest binding for release-sidecar DSSE bundles.

#### 4. Generalize trust-material selection

**Files**:

- `src/sigstore.zig`
- `src/sigstore/trust/*`
- `src/sigstore/trust/README.md`

**Changes**:

- Preserve the current embedded Sigstore Public Good Fulcio and Rekor
  material.
- Add embedded GitHub Sigstore Fulcio CA and timestamp-authority
  certificates extracted from `gh attestation trusted-root`.
- Select trust material by the verified leaf issuer/available observation:
  - Public Good: require Rekor verification and validate the Fulcio chain at
    Rekor `integratedTime`.
  - GitHub instance: require a valid RFC 3161 timestamp and validate the
    Fulcio chain at timestamp `genTime`.
- Reject unknown issuers and bundles whose observation type does not match
  the selected trust domain.
- Make the trust-domain invariant explicit: issuer, Fulcio root, and
  observation type must all agree; a GitHub-issued leaf with public Rekor
  material, or a Public Good leaf with only GitHub timestamp material, is
  rejected.
- Document exact trust refresh commands, source URLs, certificate
  fingerprints, and rotation expectations. Updating embedded roots continues
  to require a new ghr release, consistent with the existing Sigstore trust
  model.

### Success Criteria

- A captured public GitHub attestation verifies through Rekor and matches the
  requested repository, owner, SLSA predicate, and digest.
- A captured private GitHub attestation verifies through its RFC 3161
  timestamp and GitHub Fulcio/TSA trust roots.
- Wrong repository, owner, issuer, build-config prefix, predicate type,
  subject digest, DSSE signature, Rekor proof, timestamp imprint, or
  certificate chain fails closed.
- Renaming a release asset does not invalidate a native attestation when its
  computed digest is present in the signed subject list.
- Existing `cosign sign-blob` and multi-subject sidecar fixtures continue to
  pass unchanged.

---

## Phase 3: Verification Pipeline and CLI Integration

### Overview

Wire native attestation verification into both install and download as an
independent stage with its own gate, diagnostics, failure mapping, and
metadata result.

### Changes Required

#### 1. Add the independent verification gate and result

**File**: `src/release.zig`

**Changes**:

- Add `skip_attestation: bool = false` to `VerifyGates`.
- Add `.github_attestation_verified` to `VerifyOutcome`.
- Add a shared outcome-rank helper and use it in both download and install so
  the documented precedence is implemented consistently rather than relying
  on sequential label overwrites.
- Add a repository context accepted by `verifyAssetOnDisk` and the install
  verifier.
- Add `verifyDownloadedAssetAttestation` that:
  - Computes the downloaded file's SHA-256.
  - Fetches native attestation bundle candidates through `attestation.zig`.
  - Returns `.no_verification` only for a successful empty response.
  - Tries returned candidates until one fully verifies under GitHub policy.
  - Fails if candidates exist but none verify.
  - Prints the verified digest, source repository, initiating workflow,
    signer workflow, issuer, and trusted timestamp/log summary.
- Run this verifier even when sidecar Sigstore succeeds.
- Preserve fail-closed independence: an invalid sidecar fails even if the
  native attestation succeeds, and vice versa.
- Return `.github_attestation_verified` ahead of all other successful
  outcomes.
- Include attestation in the final "unverified" diagnostic.
- For API/auth/rate-limit failures, print an actionable hint that
  `--skip-attestation` bypasses this stage and that private fine-grained
  tokens require `attestations:read`.

#### 2. Carry repository identity through download resolution

**File**: `src/download.zig`

**Changes**:

- Add optional `attestation.Repository` owner/repository context to
  `ResolvedTarget`.
- Populate it for repository specs, file specs, and parsed GitHub
  release-download URLs whenever release verification context is available.
- Pass the repository context into `verifyAssetOnDisk`.
- Add `skip_attestation` to `Options`, argument parsing, and `gates()`.
- Add `--skip-attestation` to download help.
- Map:
  - API and bundle transport failures to exit code `2`.
  - Cryptographic, timestamp, identity, predicate, and subject failures to
    exit code `3`.
- Ensure `.part` files are deleted on every attestation failure.

#### 3. Carry repository identity through install verification

**File**: `src/install.zig`

**Changes**:

- Pass the resolved original `spec.owner` and `spec.repo` into
  `verifyDownloadedAsset`.
- Thread the same repository identity through the wasm-module installation
  path (`installWasmModuleUnit`) as well as archive/bare-binary installs.
- Add native attestation verification to the shared install verifier.
- On failure, delete the cached asset and return `InstallStepFailed`.
- Record `"github-attestation"` when it is the strongest successful method.
- Use the shared outcome-rank helper so existing documented ordering
  (`sigstore > minisign > authenticode > checksum`) is also consistent
  between install and download.
- Update comments and the "unverified" note to include native attestations.

#### 4. Add install command flag parsing

**File**: `src/main.zig`

**Changes**:

- Parse `--skip-attestation` for `ghr install`.
- Populate the new `VerifyGates.skip_attestation` field.
- Update install usage and umbrella text so `--skip-verify` explicitly
  includes attestations.

### Success Criteria

- Both install and download query native attestations by the actual
  downloaded digest.
- `--skip-sigstore` skips only release-sidecar Sigstore verification.
- `--skip-attestation` skips only GitHub-native attestation lookup and
  verification.
- `--skip-verify` skips both.
- A release with both verification forms prints success for both.
- A failure in either published verification form aborts the operation.
- A successful empty attestation response preserves all existing fallback
  verification behavior.
- API/network/auth/rate-limit errors fail unless
  `--skip-attestation` is present.
- Installed metadata uses `"github-attestation"` precedence without changing
  the metadata schema.
- Existing minisign/Authenticode precedence matches the documented order in
  both pipelines after the shared ranking change.

---

## Phase 4: Actions, Documentation, Fixtures, and End-to-End Coverage

### Overview

Expose the feature consistently across every user-facing surface and add
fixture-driven regression coverage.

### Changes Required

#### 1. Composite Action inputs

**Files**:

- `actions/install/action.yml`
- `actions/download/action.yml`

**Changes**:

- Add boolean `skip-attestation` inputs defaulting to `false`.
- Add `SKIP_ATTESTATION` environment forwarding.
- Append `--skip-attestation` independently from `--skip-sigstore`.
- Update the `skip-verify` descriptions to include native attestations.

#### 2. Action documentation

**Files**:

- `actions/install/README.md`
- `actions/download/README.md`

**Changes**:

- Add the new input to option tables and examples.
- Clarify that `skip-sigstore` controls release sidecars and
  `skip-attestation` controls GitHub's attestation service.

#### 3. CLI and verification documentation

**Files**:

- `README.md`
- `doc/README.md`

**Changes**:

- Advertise GitHub artifact attestation verification alongside current
  Sigstore/checksum support.
- Document automatic digest lookup, public/private trust models, SLSA v1
  policy, repository identity enforcement, API authentication requirements,
  and fail-closed transport behavior.
- State prominently that unauthenticated installs may hit GitHub API rate
  limits and should use `GH_TOKEN`/`GITHUB_TOKEN` or explicitly opt out with
  `--skip-attestation`.
- Document both narrow skip flags and the updated umbrella behavior.
- Add `"github-attestation"` to metadata outcomes and precedence.
- State explicitly that native attestations are not visible release assets
  and that `*.sigstore.json` sidecars are still verified independently.
- State that absence of an attestation preserves fallback behavior and is not
  equivalent to a policy requiring provenance.
- Link issue `#165`.

#### 4. Add deterministic fixtures and tests

**Files**:

- `src/attestation/testdata/*`
- `src/sigstore/testdata/*`
- Tests colocated in `src/attestation.zig`, `src/snappy.zig`,
  `src/sigstore.zig`, `src/release.zig`, `src/download.zig`, and
  `src/install.zig`

**Changes**:

- Commit sanitized captured fixtures for:
  - Current API metadata with `bundle_url`.
  - Snappy-compressed public GitHub SLSA bundle.
  - Plain-JSON and supported HTTP-compressed forms of the same bundle.
  - Decompressed public bundle JSON and matching artifact.
  - Private GitHub bundle with RFC 3161 timestamp and matching artifact.
- Unit-test:
  - Empty/multiple attestation responses.
  - Versioned headers and URL construction.
  - HTTPS-only bundle URLs.
  - Snappy bounds and malformed input.
  - Public Rekor and private timestamp trust paths.
  - SLSA predicate enforcement.
  - Repository/owner/build-config/OIDC policy.
  - Digest-only native subject binding, including a renamed release asset.
  - Filename + digest binding remaining intact for sidecar DSSE bundles.
  - Multiple candidates where one valid attestation succeeds.
  - Candidates present but none valid.
  - Independent `skip_sigstore` and `skip_attestation` gates.
  - `skip_verify` umbrella behavior.
  - Metadata precedence and `"github-attestation"` round-trip.
  - Exit-code classification for transport versus verification failures.
- Keep live GitHub calls out of the default test suite; all automated tests
  must be deterministic and offline.

### Success Criteria

- Both composite Actions expose and forward `skip-attestation`.
- Help and documentation use consistent terminology and flag semantics.
- All fixture-driven positive and negative cases pass.
- The full existing suite remains green with:

  ```sh
  zig build test
  ```

## Testing Strategy

### Unit Tests

- Raw Snappy decoding, including overlapping copies and malformed data.
- Plain JSON, raw Snappy, and supported HTTP content-encoding dispatch.
- API URL/header construction and response parsing.
- Trust-root selection and certificate extension extraction.
- Public Rekor verification and private RFC 3161 verification.
- Statement type, predicate, subject digest, and repository policy.
- Verification outcome precedence and skip-gate independence.

### Integration Tests

- Run the download/install verification orchestrators against a local mock
  HTTP server serving:
  - Release metadata.
  - Empty attestation response.
  - Public attestation metadata and compressed bundle.
  - Private attestation metadata and compressed bundle.
  - `401`, `403`, `429`, `500`, truncated bundle, and invalid bundle cases.
- Assert cleanup of partial downloads and cached attestation bundle files.
- Assert that Authorization reaches `api.github.com` mock endpoints but not
  the external bundle host.

### Manual Testing Steps

1. Download a current ghr release archive and observe both native
   attestation and `*.sigstore.json` success:

   ```sh
   zig build run -- download cataggar/ghr@v0.6.9
   ```

2. Repeat with `--skip-sigstore`; native attestation must still verify.
3. Repeat with `--skip-attestation`; sidecar Sigstore must still verify.
4. Repeat with `--skip-verify`; neither verifier may run.
5. Test a public repository with no attestations and confirm existing
   checksum/signature fallback behavior.
6. Test an authenticated private repository whose token has repository read
   and `attestations:read`; confirm the GitHub private trust/timestamp path.
7. Test the same private repository without sufficient permission; confirm
   fail-closed behavior and the `--skip-attestation` escape hatch.

## Performance Considerations

- Native attestation support adds one GitHub API request and one small signed
  bundle download per asset when an attestation exists.
- Request `per_page=100` once and stop after the first candidate that fully
  verifies.
- Cap API, compressed bundle, and decompressed JSON sizes.
- Stream the artifact SHA-256 from disk; never load release artifacts into
  memory.
- Reuse the invocation's existing HTTP/auth context and cache directory.
- Multi-asset installs may reuse one fetched multi-subject bundle by digest
  only if a later implementation can do so without complicating ownership;
  correctness takes priority over speculative caching in this change.

## Migration Notes

- Existing commands remain compatible; native attestation verification is an
  additional enabled-by-default stage.
- Existing `ghr.json` files continue to parse because `"verified"` is already
  a string. New installs may contain `"github-attestation"`.
- Existing Action workflows require no changes unless they need to bypass the
  new stage, in which case they can set `skip-attestation: 'true'`.
- Consumers behind restricted networks may need to permit:
  - `api.github.com`
  - GitHub-provided signed bundle URLs
  - or explicitly use `--skip-attestation`.
- Embedded GitHub private trust roots require periodic refresh and a new ghr
  release after GitHub rotates signing material.

## References

- Issue: <https://github.com/cataggar/ghr/issues/165>
- GitHub repository attestation API:
  <https://docs.github.com/en/rest/repos/attestations>
- GitHub offline verification and trust roots:
  <https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/verify-attestations-offline>
- GitHub CLI verification behavior:
  <https://cli.github.com/manual/gh_attestation_verify>
- Sigstore Bundle v0.3 schema:
  <https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto>
- Fulcio certificate extension OIDs:
  <https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md>
- Existing native Sigstore implementation: `src/sigstore.zig`
- Existing verification orchestration: `src/release.zig:1949-2057`
- Existing install orchestration: `src/install.zig:1907-2076`
