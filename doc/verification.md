# Verification

ghr's own releases ship per-asset `*.sigstore.json` sidecars (cosign
v0.3 bundles) and `*.minisig` sidecars (minisign v2) for every
published `.tar.gz` and `.zip`. The sigstore bundle is signed by the
release workflow's GitHub Actions OIDC identity; the minisign sidecar
is signed by a long-lived project key whose public token is:

```
RWSbsumpaHb+N3KCEt/EUXQ5y6Kkk8r/zCb5Z4jhEuEX8x2/U5wr5QC0
```

ghr no longer publishes `.sha256` sidecars: because releases are built on
GitHub Actions, a CI-generated checksum shares GitHub's trust root and adds
nothing over GitHub's built-in asset digest (added 2025-06-03), which ghr
verifies for free. Independent provenance is covered by the sigstore and
minisign signatures above.

`ghr install cataggar/ghr@<tag>` verifies the sigstore bundle
automatically, prints the leaf certificate's SAN (the release-workflow
URL) and OIDC issuer
(`https://token.actions.githubusercontent.com`) for visual review, and
fails-closed on any verification error. To also require minisign
verification, pass the public key inline (per-spec) or via
`--minisign`:

```sh
ghr install cataggar/ghr@v0.3.0 \
    RWSbsumpaHb+N3KCEt/EUXQ5y6Kkk8r/zCb5Z4jhEuEX8x2/U5wr5QC0
```

Minisign sidecars start appearing with the release that introduced
`.github/workflows/release.yml`'s signing step; pre-existing tags
have no `.minisig` and fail closed if a key is supplied. Key
rotation, if needed, will land as a new pubkey published in this
README and the previous key marked as deprecated alongside the last
tag it signed.

When you install or download a release asset, ghr automatically verifies
the downloaded bytes against any verification material the release
publishes:

- **GitHub asset digest** — GitHub computes a SHA-256 for every release
  asset at upload time and exposes it inline in the release JSON as
  `"digest": "sha256:<hex>"` (added 2025-06-03). ghr verifies the download
  against it with **no extra network request** — the digest already
  arrived with the release metadata. Its trust root is GitHub itself (the
  same as a CI-generated sidecar): it attests integrity, not independent
  provenance. Assets uploaded before the rollout carry no digest.
- **Checksum files** — sidecar `<asset>.sha256` / `<asset>.sha512` files
  and aggregate `*checksums*` / `SHA256SUMS` / `SHA512SUMS` files are all
  supported, in GNU and BSD formats, and may use SHA-256 (64-hex) or
  SHA-512 (128-hex) digests — the entry's hex width picks the algorithm
  per asset, so a single aggregate file can even mix both (e.g. some
  projects publish 128-hex SHA-512 in a file simply named
  `checksums.txt`). When a release publishes one it is **always
  validated** (in addition to the GitHub digest, never as a silent
  substitute); both must match. The sidecar download is the only case
  that costs an extra request, so releases that rely solely on the
  built-in digest verify for free.
- **Sigstore bundles** — `<asset>.sigstore.json` (cosign bundle v0.3),
  published as a release asset, is verified entirely natively in Zig.
  This is a separate mechanism from GitHub artifact attestations below;
  a release may publish either, both, or neither, and each is verified
  independently of the other. The X.509 chain is walked from the
  bundle's leaf cert to embedded production Fulcio roots, the artifact's
  ECDSA-P256/SHA-256 signature is checked against the leaf, and Rekor's
  signed entry timestamp is verified against the embedded Rekor public
  key. The Rekor `integratedTime` is used as the verification clock since
  cosign leaf certs only live for ~10 minutes. When the bundle carries
  an inclusion proof, the Merkle audit path is replayed (RFC 6962) to
  recompute the log root, and the signed checkpoint envelope is verified
  against the embedded Rekor key — anchoring the entry to a publicly
  observable log root. The signer's SAN (URI/email) and OIDC issuer are
  extracted from the leaf cert and printed to stdout for visual review;
  ghr does not yet enforce a specific identity.

  Two artifact-binding shapes are supported, matching the two Rekor entry
  kinds we see in the wild:

  - `hashedrekord` — cosign's classic blob-signing form. The bundle's
    `messageSignature` covers a single artifact whose sha256 is the
    `messageDigest`. ghr requires a sibling `<asset>.sigstore.json`.
  - `dsse` — a DSSE envelope wrapping an
    [in-toto v1 Statement](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md),
    typically a [SLSA Provenance v1](https://slsa.dev/provenance/v1)
    attestation produced by `slsa-github-generator` or
    `cosign attest`. The Statement's `subject` list binds one or more
    artifacts by `name` + `sha256`. ghr falls back to any bare
    `*.sigstore.json` asset (e.g. `wash.sigstore.json` covering all
    `wash-<platform>` binaries) when no per-asset sidecar is published,
    and requires the downloaded asset's name + sha256 to appear as one
    of the Statement's subjects.

  DSSE signatures are verified against the
  [DSSE v1 pre-authenticated encoding](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md)
  of the payload; the Rekor `dsse / 0.0.1` body is checked to bind back
  to the bundle's envelope (`payloadHash` equals sha256 of the payload;
  signature + verifier cert equal the bundle's).
- **GitHub artifact attestations** — unlike every other method here,
  these are **not published as release assets**, so there is nothing to
  spot in a release's file list. After downloading, ghr asks GitHub's
  [attestation API](https://docs.github.com/en/rest/repos/attestations)
  for any attestation matching the file's SHA-256, and verifies it with
  the same native Zig Sigstore stack described above. This is what
  `gh attestation verify` checks, and it covers the many releases built
  by [`actions/attest-build-provenance`](https://github.com/actions/attest-build-provenance)
  that publish no sidecar at all.

  Two trust models are handled, and the bundle itself selects which:

  - **Public repositories** are signed by the public Sigstore instance
    (`O=sigstore.dev, CN=sigstore-intermediate`) and logged in Rekor. A
    verified Rekor signed entry timestamp is **required**, and its
    `integratedTime` is the certificate-validity clock. An inclusion
    proof, when present, is replayed against the signed checkpoint.
  - **Private repositories** are signed by GitHub's own Fulcio
    (`O=GitHub, Inc., CN=Fulcio Intermediate l2`) and are not in a public
    log. In place of Rekor the bundle carries a full RFC 3161
    `TimeStampResp` from GitHub's TSA, whose `genTime` becomes the clock.
    The TSA chain is pinned to GitHub's embedded trust root, so a
    timestamp token cannot carry its own signer.

  The attestation must be a [SLSA Provenance v1](https://slsa.dev/provenance/v1)
  statement whose subject digest matches the download, and whose signing
  certificate names the repository the asset came from. The predicate type
  is checked against the *signed* statement rather than trusting the API's
  `predicate_type` filter, which is an unsigned request parameter that also
  admits older provenance versions. This is the same predicate
  `gh attestation verify` enforces by default, so an attestation ghr accepts
  here is one `gh` accepts too. Subject *names*
  are deliberately not matched — the local filename is chosen by the
  downloader, so it carries no meaning here. Repository identity is bound
  by the certificate's rename-stable numeric repository id as well as its
  URI, so a repository that was renamed or transferred after signing still
  verifies rather than failing as an impostor.

  Lookups are **fail-closed**: only two responses count as "no attestation
  exists" — a `404` (the repository has never produced one) and a success
  carrying an empty list (it uses attestations, but not for this digest).
  Both fall back to the other verifiers. Anything else — a rate limit, an
  expired token, a network error, a `500` — aborts the operation, so a
  transport failure can never be silently reported as an unattested
  artifact.

  Because each lookup is a GitHub API call, **unauthenticated use can hit
  API rate limits**. Set `GH_TOKEN` or `GITHUB_TOKEN` (private
  repositories additionally need the `attestations:read` permission), or
  opt out explicitly with `--skip-attestation`.

  A missing attestation is not a policy failure. ghr reports what a
  release actually published; it does not require provenance to exist. If
  you need "this artifact MUST be attested", enforce that separately.
- **Minisign signatures** — `<asset>.minisig` sidecars
  ([minisign v2](https://jedisct1.github.io/minisign/)) are verified when
  the caller supplies a public key — either via `--minisign <base64-pubkey>`
  (applied to every spec as a default) or as an inline positional
  immediately after a spec (per-spec override). The key value is the
  single-line base64 token from a minisign `.pub` file (algorithm `Ed`
  or `ED`, 8-byte key id, 32-byte Ed25519 public key). Both the artifact
  signature (`Ed` = pure Ed25519 over the file, `ED` = Ed25519 over the
  Blake2b-512 digest, streamed from disk) and the trailing trusted-comment
  global signature are verified against the same key. The trusted comment
  (often a `timestamp:... file:... hashed` blob) is printed on success.
  If a key is configured but no `<asset>.minisig` is published, ghr
  aborts before downloading — minisign verification is fail-closed when
  opted in.
  If a `<asset>.minisig` IS published but no key was configured and
  neither `--skip-minisign` nor `--skip-verify` was passed, ghr also
  aborts before downloading: ignoring a published signature would
  silently skip a real verification opportunity, so the caller must
  opt in (pass a key inline or via `--minisign <pubkey>`) or opt out
  (`--skip-minisign` to bypass just minisign, or `--skip-verify` to
  bypass every check).
- **Authenticode (Windows)** — auto-detected from the downloaded bytes.
  When the asset is a PE (DOS `MZ` magic) or a `.zip` containing one or
  more `.exe` / `.dll` / `.sys` entries, ghr verifies each PE's embedded
  PKCS#7 SignedData natively in Zig:

  1. Recompute the SHA-256 Authenticode digest (CheckSum, Security
     data-directory entry, and certificate table excluded — per the
     Authenticode whitepaper / `signify`).
  2. Parse the embedded `SpcIndirectDataContent` and bind its declared
     digest to the recomputed one.
  3. Verify the SignerInfo signature over `signedAttrs` (replacing the
     IMPLICIT `[0]` tag with the SET-OF tag for the CMS-canonical input)
     against the signer cert's public key. RSA-PKCS#1 v1.5 with SHA-256
     / SHA-384 / SHA-512 and ECDSA-P256 / -P384 are all accepted.
  4. Locate the RFC 3161 timestamp counter-signature (either
     `id-aa-signatureTimeStampToken` or Microsoft's
     `szOID_RFC3161_counterSign`), verify the TimeStampToken's own
     SignerInfo signature, walk the TSA cert chain to a trusted TSA
     root, and bind `TSTInfo.messageImprint` to `sha256(signer
     signature)`. The TSA chain is validated at the token's own
     `genTime`, the same clock used for the signer chain — timestamp
     authorities rotate their certificates too, and an archived
     signature does not stop being correctly timestamped when the TSA's
     cert expires.
  5. Walk the X.509 chain from the signer cert through the
     intermediates carried in the SignedData's `certificates` SET to
     one of the 15 embedded trust roots (Microsoft Identity
     Verification Root 2020, Microsoft Root CA 2011, Microsoft Root
     CA 2010, DigiCert Trusted Root G4 / Global G3 / Global / High
     Assurance EV / Assured ID G3, GlobalSign Root CA R3 / R6 / Code
     Signing R45, USERTrust RSA / ECC, Entrust Root G2 / EC1). The
     TSA's `genTime` is used as the validity clock so signatures
     remain trustworthy past the signer cert's `notAfter`. The wall
     clock plays no part in certificate validity anywhere in this
     path, including the construction of the trust root set itself.

  Authenticode is fail-closed when a PE inside the asset carries a
  signature that doesn't verify, and fail-open when no PE carries any
  signature (consistent with the other verifiers). Untimestamped
  signatures are rejected since the cert-validity clock can't be
  derived without a TSA witness.

On any verification failure the operation is aborted and the cached
download is deleted. Malformed input counts as a verification failure:
every DER structure `ghr` parses — X.509 certificates, PKCS#7
SignedData, RFC 3161 tokens — goes through a bounds-checked parser, so
a truncated or hostile encoding is reported as an ordinary failure
rather than crashing the process. If no checksum, minisign sidecar,
sigstore bundle, GitHub attestation, or Authenticode signature is
published the download proceeds with a `note:` line so you know it was
unverified.

Pass `--skip-verify` to bypass every check at once. To bypass only one
step (e.g. when its sidecar is broken in a particular release while the
others still apply), use the narrower flags: `--skip-checksum`,
`--skip-minisign`, `--skip-sigstore`, `--skip-attestation`,
`--skip-authenticode`.

Note that `--skip-sigstore` and `--skip-attestation` are **not**
interchangeable even though both verify Sigstore material:
`--skip-sigstore` covers only a `.sigstore.json` sidecar published as a
release asset, while `--skip-attestation` covers only GitHub's
attestation service. Skipping one leaves the other active. For
`install`, the strongest result is recorded in each tool's `ghr.json`
metadata as `"verified"`:

- `"github-attestation"` — a GitHub artifact attestation for the file's
  digest verified under the SLSA v1 + repository-identity policy.
- `"sigstore"` — sigstore bundle verified (also implies the bundle's
  declared SHA256 matches the file).
- `"minisign"` — minisign sidecar verified by the caller-supplied
  minisign key (artifact + trusted-comment signatures).
- `"authenticode"` — Authenticode signature on the downloaded PE (or on
  a PE inside the downloaded `.zip`) verified against an embedded MS /
  commercial CA trust root, with a valid RFC 3161 timestamp.
- `"checksum"` — checksum sidecar verified.
- `"github-digest"` — the asset's GitHub-published SHA-256 `digest` field
  matched the download (no extra request; integrity, not provenance).
- `"none"` — no verification material was published.
- `"skipped"` — `--skip-verify` was passed.

When more than one verifier succeeds (e.g. checksum *and* sigstore, or
checksum *and* Authenticode) the strongest one is recorded — precedence
is github-attestation > sigstore > minisign > authenticode > checksum.
All successful verifiers still print their own diagnostic line, so the
full set is visible at install time.

When the install actually verifies the asset with a minisign key
(inline per-spec or `--minisign`), the key itself is also recorded in
`ghr.json` as `"minisign"` and `ghr list` appends it to the matching
line so the full output is directly pasteable as `ghr install <line>`
on the next upgrade.

The trust roots embedded in ghr come from three sources:
[`sigstore/root-signing`](https://github.com/sigstore/root-signing)
for the sigstore + Rekor anchor, GitHub's own TUF trust root for the
GitHub Fulcio and TSA anchors used by artifact attestations, and a
Mozilla CCADB snapshot plus direct issuing-CA fetches for the
Authenticode + RFC 3161 roots (documented per-root in
[`src/authenticode/trust/README.md`](../src/authenticode/trust/README.md)).

Because these are embedded rather than fetched, GitHub rotating its
attestation signing material requires a new ghr release. In restricted
networks, attestation verification needs `api.github.com` and the
GitHub-hosted bundle URLs to be reachable, or `--skip-attestation`.

GitHub artifact attestation support is tracked in
[#165](https://github.com/cataggar/ghr/issues/165).
Rotating them requires a new ghr release.
