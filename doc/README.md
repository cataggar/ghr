# ghr — detailed documentation

This page covers download, install, directories, uninstall, and verification
details. For a quick overview and usage, see the [top-level README](../README.md).

## Install

It can be installed with pipx (great for CI), uv, pip, winget, Homebrew, or
downloaded straight from a GitHub release.

```sh
# pipx (recommended for one-shot use in GitHub Actions and other CI)
pipx install ghr-bin

# uv
uv tool install ghr-bin

# pip
python3 -m pip install ghr-bin

# winget
winget install ghr

# Homebrew (tap)
brew install cataggar/ghr/ghr
```

The Homebrew formula lives at [cataggar/homebrew-ghr](https://github.com/cataggar/homebrew-ghr).
It is installed through a custom tap (`cataggar/ghr/ghr`) because the short
name `ghr` collides with another formula in the default Homebrew tap — see
[issue #46](https://github.com/cataggar/ghr/issues/46) for context.

`pipx install ghr-bin` works the same on Ubuntu, macOS and Windows runners in
GitHub Actions, so it is a one-line way to put `ghr` on `PATH` in a workflow
step. The other commands above are equally usable in CI; pipx is highlighted
because it isolates the install without polluting the global Python
environment.

### Examples

```sh
# Install latest release
ghr install burntsushi/ripgrep

# Install a specific tag
ghr install burntsushi/ripgrep@15.1.0

# Install several tools in one invocation (shared HTTP client + auth)
ghr install burntsushi/ripgrep@15.1.0 sharkdp/fd@v10.2.0

# Install a specific asset by name (exact match or unique substring)
ghr install WebAssembly/wasi-sdk/wasi-sdk-25.0-x86_64-linux.tar.gz@wasi-sdk-25

# Show where tools are stored
ghr path tools

# Show where binaries are symlinked
ghr path bin
```

## Download

`ghr download` fetches a release asset using the same discovery logic as
`ghr install`, then drops the file in the current directory (or the path
given by `-o`). Use it as a cross-platform replacement for the common
`wget -O ... && tar -xf ...` pattern in CI — same syntax on Ubuntu,
macOS, and Windows; no `choco install wget` step needed.

```
ghr download <spec> [<pubkey>] [<spec> [<pubkey>] ...] [options]

OPTIONS:
    -o, --output <path>        Output file path (single-spec only)
        --extract <dir>        Extract archive(s) into <dir> after download
        --strip-components <N> Strip N leading path components when extracting
        --sha256 <hex>         Verify download against SHA-256 digest (single-spec only)
        --minisign <pubkey>    Default minisign key, applied to specs without an inline key
        --skip-verify          Umbrella: skip every verification step (checksum, minisign, sigstore, authenticode)
        --skip-checksum        Skip just the checksum-sidecar verification step
        --skip-minisign        Skip just the minisign verification step
        --skip-sigstore        Skip just the sigstore-bundle verification step
        --skip-authenticode    Skip just the Authenticode (Windows PE) verification step
        --keep-archive         Keep archive on disk after extraction
        --keep-going           For multi-spec, continue past per-spec failures
        --quiet                Suppress progress output
        --no-auth              Do not send GitHub auth even for github.com URLs
        --debug                Verbose diagnostic output
```

Each `<spec>` is `owner/repo[@tag]` (auto-pick asset for the current
OS/arch) or `owner/repo/file[@tag]` (exact match wins, otherwise a
unique case-insensitive substring wins; multiple matches print the
candidates). A 56-char `RW`/`RU`-prefixed base64 token immediately
after a spec is treated as that spec's minisign public key (overriding
the global `--minisign <pubkey>` default for that single spec).
Recognised archive formats: `.zip`, `.tar.gz`, `.tgz`, `.tar.xz`,
`.txz`. Format is detected from the filename. When `--extract` is used
the archive is deleted after extraction unless `--keep-archive` (or
`-o`) is set.

Multi-spec invocations share a single HTTP client + auth context, so
adding more specs costs little beyond the per-asset bytes. `-o` and
`--sha256` are inherently single-target and are rejected when more
than one spec is supplied — use `--extract <dir>` for "land each
archive in a shared directory", or invoke `ghr download` once per
spec for distinct outputs. `--keep-going` continues past per-spec
failures and exits non-zero with a summary if any spec failed.

GitHub auth is attached automatically (using `GH_TOKEN`,
`GITHUB_TOKEN`, or `gh auth token`); pass `--no-auth` to skip it.
Downloads are auto-verified against any sigstore bundle or checksum
sidecar published with the release; pass `--minisign <pubkey>` to
also require a minisign signature (or attach an inline key to a
spec), `--skip-<step>` to bypass one verifier individually, or
`--skip-verify` to bypass all checks. Exit codes: `0` success, `1`
argument/IO error, `2` HTTP error after retries, `3` checksum or
minisign mismatch. Multi-spec invocations exit with the most-severe
code observed across the batch.

## Caching in GitHub Actions

Running `pipx install ghr-bin && ghr install <tool>` from scratch on every
workflow run pays the download + extraction cost each time. Caching the
tool directory across runs reduces a warm install to a near-instant
restore.

The pattern is the same one
[pipx users settled on](https://github.com/pypa/pipx/discussions/1051) —
override the on-disk locations to a user-writable path (so
`actions/cache` can write back to it without `sudo`), then key the cache
on the sorted list of tools + `ghr` version.

### Recommended: composite actions

This repository ships two composite actions that wrap the dance below
end-to-end:

- [`cataggar/ghr/actions/install`](../actions/install/README.md) —
  install one or more tools with cross-run caching.
- [`cataggar/ghr/actions/download`](../actions/download/README.md) —
  download (and optionally extract) one or more release assets with
  cross-run caching.

```yaml
- uses: cataggar/ghr/actions/install@v0.3.0  # pin to the matching ghr release
  with:
    tools: |
      BurntSushi/ripgrep@14.1.1
      sharkdp/fd@v10.2.0
```

To verify some tools with minisign, attach the public key as a second
whitespace-separated token on the same line. Inline keys override the
action-level `minisign:` default for that one spec:

```yaml
- uses: cataggar/ghr/actions/install@v0.3.0
  with:
    tools: |
      jedisct1/minisign@0.12 RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3
      BurntSushi/ripgrep@14.1.1
      sharkdp/fd@v10.2.0
```

The actions ship in this same repository, so their git tags are the
same as `ghr`'s — pinning `@v0.3.0` pins both the action body and the
`ghr-bin` binary the action installs. Pick the latest tag from
[the releases page](https://github.com/cataggar/ghr/releases).

### Hand-rolled recipe (`ghr install`)

If you'd rather wire it up yourself — for instance to share a cache step
with other tools in the same job:

```yaml
- run: pipx install ghr-bin
  shell: bash

- name: Point ghr at a cacheable directory
  shell: bash
  run: |
    echo "GHR_TOOL_DIR=$RUNNER_TEMP/ghr-tools"  >> "$GITHUB_ENV"
    echo "GHR_BIN_DIR=$RUNNER_TEMP/ghr-bin"     >> "$GITHUB_ENV"
    echo "GHR_CACHE_DIR=$RUNNER_TEMP/ghr-cache" >> "$GITHUB_ENV"
    echo "$RUNNER_TEMP/ghr-bin" >> "$GITHUB_PATH"

- uses: actions/cache@v4
  id: ghr-cache
  with:
    path: |
      ${{ runner.temp }}/ghr-tools
      ${{ runner.temp }}/ghr-bin
      ${{ runner.temp }}/ghr-cache
    key: ghr-${{ runner.os }}-${{ runner.arch }}-ripgrep14.1.1_fdv10.2.0

- if: steps.ghr-cache.outputs.cache-hit != 'true'
  run: |
    ghr install \
      BurntSushi/ripgrep@14.1.1 \
      sharkdp/fd@v10.2.0

- run: ghr list  # sanity check after a cache restore
```

`ghr install` is multi-spec: pass every tool as a positional argument
in a single invocation so they share one HTTP client + auth context,
and the cache step pairs naturally with one install step. Use
`--keep-going` to attempt every spec even if one fails.

### Cache key shape

A cache-key like `ghr-<os>-<arch>-<sorted-specs>-<ghr-version>` invalidates
cleanly when:

- the runner OS or architecture changes,
- a tool is added, removed, or its pinned tag changes,
- `ghr` itself is upgraded (the install layout could shift between
  versions).

For tiny lists, an inline literal is fine. For larger lists, check the
tool list into a file and key on `${{ hashFiles('.github/ghr-tools.txt') }}`.
The composite actions above hash the sorted tool list internally, so you
don't have to choose.

### Caveats

- Verification metadata (`ghr.json`, sigstore bundles, checksum sidecars)
  is stored under `GHR_TOOL_DIR` as regular files and survives a cache
  round-trip — verification happens at install time, not on restore.
- Windows shims are regular files (the runtime resolves them through
  PATH) and survive the cache round-trip cleanly.
- `pipx install ghr-bin` is cheap (single static binary). Caching it
  separately isn't worth the complexity.

### Caching `ghr download`

`ghr download` lands files in the user-chosen directory rather than a
managed cache, so the pattern is slightly simpler — cache the
destination directory and the extracted contents (if `--extract` is
used):

```yaml
- uses: cataggar/ghr/actions/download@v0.3.0  # pin to the matching ghr release
  with:
    tools: |
      BurntSushi/ripgrep@14.1.1
      sharkdp/fd@v10.2.0
    extract: 'true'
    strip-components: '1'
    dest: ./bin
```

Hand-rolled equivalent:

```yaml
- uses: actions/cache@v4
  id: ghr-dl-cache
  with:
    path: ./bin
    key: ghr-dl-${{ runner.os }}-${{ runner.arch }}-ripgrep14.1.1_fdv10.2.0

- if: steps.ghr-dl-cache.outputs.cache-hit != 'true'
  run: |
    pipx install ghr-bin
    mkdir -p ./bin
    ghr download \
      BurntSushi/ripgrep@14.1.1 \
      sharkdp/fd@v10.2.0 \
      --extract ./bin --strip-components 1
```

The same multi-spec rules apply: `-o` and `--sha256` are rejected when
more than one spec is supplied — `--extract <dir>` is the multi-spec
equivalent of `-o`, and verification falls back to whatever sigstore /
sha256 sidecars the release publishes.

## Directories

Follows [uv tool](https://docs.astral.sh/uv/) conventions.

| Purpose | Unix | Windows |
|---------|------|---------|
| Binaries | `~/.local/bin/` | `%USERPROFILE%\.local\bin\` |
| Tool storage | `~/.local/share/ghr/tools/` | `%APPDATA%\ghr\data\tools\` |
| Cache | `~/.cache/ghr/` | `%LOCALAPPDATA%\ghr\cache\` |

Override with `GHR_BIN_DIR`, `GHR_TOOL_DIR`, `GHR_CACHE_DIR`.

Use `ghr path bin`, `ghr path tools`, or `ghr path cache` to print the current
location for each directory.

The bin directory is frequently not on `PATH` by default, especially on Windows. Run `ghr path ensure` once to fix that:

- **Windows**: updates `HKCU\Environment\Path` (user PATH) and broadcasts `WM_SETTINGCHANGE` so new terminals pick up the change. If `%APPDATA%\nushell\` exists, also updates `%APPDATA%\nushell\env.nu`.
- **macOS / Linux**: appends a guarded block to your shell rc files (bash: `.bash_profile` / `.bashrc` / `.profile`; zsh: `.zprofile`; nushell: `~/.config/nushell/env.nu`). The block is idempotent and is replaced in place on re-runs.

`ghr path ensure --dry-run` prints the changes it would make without writing.

## WSL: linking Windows-side bins (`ghr link` / `ghr unlink`)

When ghr is installed on Windows, a parallel WSL distribution can expose the same tools without re-downloading them. `ghr link` creates Linux symlinks in `~/.local/bin` that point directly at the Windows-side `.exe` (via `/mnt/c/...`); WSL interop runs the binary transparently.

```sh
# Link every bin advertised by the Windows install.
ghr link cataggar/microsoft-authentication-cli

# Or restrict to specific bins (repeatable).
ghr link cataggar/microsoft-authentication-cli --bin azureauth

# Remove the symlinks again (does not touch the Windows install).
ghr unlink cataggar/microsoft-authentication-cli
```

Notes:

- `ghr link` is a **reconciler**. Without `--bin`, it makes the WSL link set match the current Windows install — adding new bins, updating moved ones, and removing entries that disappeared from `ghr.json`. With `--bin <name>` filters, only the named entries are touched.
- The symlink target is the real `.exe` under `<tools>/<owner>/<repo>/`, not the Windows shim. A `C:\…` target would not trigger interop; the WSL path is required.
- Both commands require `WSL_INTEROP` to be set. They refuse to run outside WSL so you don't accidentally create dangling links on bare Linux or macOS.
- The owner/repo path is case-canonicalized to lowercase. `ghr link AzureAD/foo` and `ghr link azuread/foo` are equivalent regardless of how the install was created on Windows.

### Locating the Windows tools dir

`ghr link` resolves the Windows-side tools dir in this order:

1. `GHR_WIN_TOOLS_DIR` — explicit override. Accepts either a WSL path (`/mnt/c/Users/x/AppData/Roaming/ghr/data/tools`) or a Windows path (`C:\Users\x\AppData\Roaming\ghr\data\tools`).
2. `cmd.exe /c echo %APPDATA%`, run through `wslpath -u`. This is the canonical lookup and handles non-default Windows usernames and redirected APPDATA.
3. Fallback to `/mnt/c/Users/$USER/AppData/Roaming/ghr/data/tools` with a warning, assuming the WSL username matches the Windows one.

### Per-link manifest

For each linked repo, ghr records what it created at `$XDG_DATA_HOME/ghr/links/<owner>/<repo>.json` (or `~/.local/share/ghr/links/...`). The manifest is what `ghr unlink` consults; it verifies each live symlink still points where the manifest recorded before deleting, so a user-rewritten symlink is never clobbered.

## Uninstall

```sh
# pipx
pipx uninstall ghr-bin

# uv
uv tool uninstall ghr-bin

# pip
python -m pip uninstall ghr-bin -y

# winget
winget uninstall ghr

# Homebrew
brew uninstall ghr
```

## Verification

ghr's own releases ship per-asset `*.sigstore.json` sidecars (cosign
v0.3 bundles) and `*.minisig` sidecars (minisign v2) for every
published `.tar.gz` and `.zip`. The sigstore bundle is signed by the
release workflow's GitHub Actions OIDC identity; the minisign sidecar
is signed by a long-lived project key whose public token is:

```
RWSbsumpaHb+N3KCEt/EUXQ5y6Kkk8r/zCb5Z4jhEuEX8x2/U5wr5QC0
```

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

- **Checksum files** — sidecar `<asset>.sha256` files and aggregate
  `*checksums*` / `SHA256SUMS` files are both supported, in GNU and BSD
  formats.
- **Sigstore bundles** — `<asset>.sigstore.json` (cosign bundle v0.3) is
  verified entirely natively in Zig. The X.509 chain is walked from the
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
     signature)`.
  5. Walk the X.509 chain from the signer cert through the
     intermediates carried in the SignedData's `certificates` SET to
     one of the 15 embedded trust roots (Microsoft Identity
     Verification Root 2020, Microsoft Root CA 2011, Microsoft Root
     CA 2010, DigiCert Trusted Root G4 / Global G3 / Global / High
     Assurance EV / Assured ID G3, GlobalSign Root CA R3 / R6 / Code
     Signing R45, USERTrust RSA / ECC, Entrust Root G2 / EC1). The
     TSA's `genTime` is used as the validity clock so signatures
     remain trustworthy past the signer cert's `notAfter`.

  Authenticode is fail-closed when a PE inside the asset carries a
  signature that doesn't verify, and fail-open when no PE carries any
  signature (consistent with the other verifiers). Untimestamped
  signatures are rejected since the cert-validity clock can't be
  derived without a TSA witness.

On any verification failure the operation is aborted and the cached
download is deleted. If no checksum, minisign sidecar, sigstore bundle,
or Authenticode signature is published the download proceeds with a
`note:` line so you know it was unverified.

Pass `--skip-verify` to bypass every check at once. To bypass only one
step (e.g. when its sidecar is broken in a particular release while the
others still apply), use the narrower flags: `--skip-checksum`,
`--skip-minisign`, `--skip-sigstore`, `--skip-authenticode`. For
`install`, the strongest result is recorded in each tool's `ghr.json`
metadata as `"verified"`:

- `"sigstore"` — sigstore bundle verified (also implies the bundle's
  declared SHA256 matches the file).
- `"minisign"` — minisign sidecar verified by the caller-supplied
  minisign key (artifact + trusted-comment signatures).
- `"authenticode"` — Authenticode signature on the downloaded PE (or on
  a PE inside the downloaded `.zip`) verified against an embedded MS /
  commercial CA trust root, with a valid RFC 3161 timestamp.
- `"checksum"` — checksum sidecar verified.
- `"none"` — no verification material was published.
- `"skipped"` — `--skip-verify` was passed.

When more than one verifier succeeds (e.g. checksum *and* sigstore, or
checksum *and* Authenticode) the strongest one is recorded — precedence
is sigstore > minisign > authenticode > checksum. All successful
verifiers still print their own diagnostic line, so the full set is
visible at install time.

When the install actually verifies the asset with a minisign key
(inline per-spec or `--minisign`), the key itself is also recorded in
`ghr.json` as `"minisign"` and `ghr list` appends it to the matching
line so the full output is directly pasteable as `ghr install <line>`
on the next upgrade.

The trust roots embedded in ghr come from two sources:
[`sigstore/root-signing`](https://github.com/sigstore/root-signing)
for the sigstore + Rekor anchor, and a Mozilla CCADB snapshot plus
direct issuing-CA fetches for the Authenticode + RFC 3161 roots
(documented per-root in [`src/authenticode/trust/README.md`](../src/authenticode/trust/README.md)).
Rotating them requires a new ghr release.

## Reproducible builds

Linux and macOS release archives (`.tar.gz`) are produced deterministically:
the gzip header carries `mtime=0` and no filename, and every tar entry has
sorted order, fixed uid/gid 0, empty owner/group names, and `mtime` set to
`SOURCE_DATE_EPOCH` derived from the tagged commit. Packaging is performed
by [`scripts/pack.py`](../scripts/pack.py), and the same script is used
both at release time and during validation, so the published `.sha256`
sidecar can be reproduced bit-for-bit from source.

Windows `.zip` archives **cannot** be byte-reproduced at the archive level
— the `.exe` inside is Authenticode-signed by Azure Trusted Signing and
the signing key is, deliberately, not available to rebuilders. Instead,
the reproducibility workflow verifies Windows builds at the `.exe` level
(issue #78, Option E): it strips the Authenticode signature off the
published `.exe` and compares its sha256 against a locally-rebuilt
unsigned `.exe`. The stripping is performed by
[`ghr validate strip-authenticode`](../src/validate.zig) — a small
subcommand that reverses exactly what Trusted Signing appends
(the certificate table at end of file, the `IMAGE_DIRECTORY_ENTRY_SECURITY`
entry, and `OptionalHeader.CheckSum`).

The [`Reproducibility` workflow](../.github/workflows/reproducibility.yml)
runs automatically after each successful `Release` workflow and can also be
triggered manually with `workflow_dispatch` (provide the tag, e.g. `v0.3.0`).
For every release target it:

1. checks out the source at the tag,
2. installs the pinned Zig version,
3. rebuilds with the same flags as `release.yml`,
4. **for non-Windows targets**: repackages with `scripts/pack.py`,
   downloads the published `.tar.gz` + `.sha256`, and fails on hash
   mismatch (with `tar tvf` and `cmp` diffs as a diagnostic artifact),
5. **for Windows targets**: also builds a host-native `ghr.exe` as the
   stripper, downloads the published `.zip`, extracts `bin/ghr.exe`,
   strips its Authenticode signature, and fails if the stripped sha256
   doesn't match the locally-rebuilt unsigned `.exe`. Diagnostics
   include `cmp -l` byte differences and side-by-side header dumps.

Releases tagged at or before `v0.2.1` predate deterministic packaging and
the Authenticode signing pipeline; they will not reproduce.

### Running the strip locally

`ghr validate strip-authenticode <input.exe> <output.exe>` reads a
signed PE, removes the embedded `WIN_CERTIFICATE` table at end of file,
zeroes the security data-directory entry, and zeroes
`OptionalHeader.CheckSum`. Given a deterministic Zig-built unsigned
`.exe`, signing-then-stripping returns the exact bytes the compiler
emitted — the foundation of Option E.

```
$ ghr validate strip-authenticode published/ghr.exe stripped.exe
stripped published/ghr.exe -> stripped.exe: dropped 15672 bytes (cert table at offset 0x238be00)
$ sha256sum stripped.exe locally-rebuilt-ghr.exe
```
