# ghr — detailed documentation

This page covers download, install, directories, uninstall, and verification
details. For a quick overview and usage, see the [top-level README](../README.md).

## Install

It can be installed with pipx (great for CI), uv, pip, winget, or downloaded
straight from a GitHub release.

```sh
# pipx (recommended for one-shot use in GitHub Actions and other CI)
pipx install ghr-bin

# uv
uv tool install ghr-bin

# pip
python3 -m pip install ghr-bin

# winget
winget install ghr
```

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
ghr download <owner/repo[@tag]> [options]
ghr download <owner/repo/file[@tag]> [options]

OPTIONS:
    -o, --output <path>        Output file path (default: asset name in cwd)
        --extract <dir>        Extract archive into <dir> after download
        --strip-components <N> Strip N leading path components when extracting
        --sha256 <hex>         Verify download against SHA-256 digest (64 hex)
        --minisign <pubkey>    Require minisign signature; <pubkey> is a base64 minisign public key
        --skip-verify          Skip sigstore + sha256 + minisign verification
        --keep-archive         Keep archive on disk after extraction
        --quiet                Suppress progress output
        --no-auth              Do not send GitHub auth even for github.com URLs
        --debug                Verbose diagnostic output
```

The first form picks the asset that `ghr install` would install for the
current OS / architecture. The second form names a specific asset:
exact-name match wins, otherwise a unique case-insensitive substring
wins (multiple matches print the candidates). Recognised archive
formats: `.zip`, `.tar.gz`, `.tgz`, `.tar.xz`, `.txz`. Format is
detected from the filename. When `--extract` is used the archive is
deleted after extraction unless `--keep-archive` (or `-o`) is set.
GitHub auth is attached automatically (using `GH_TOKEN`,
`GITHUB_TOKEN`, or `gh auth token`); pass `--no-auth` to skip it.
Downloads are auto-verified against any sigstore bundle or sha256
checksum file published with the release; pass `--minisign <pubkey>` to
also require a minisign signature, or `--skip-verify` to bypass all
checks. Exit codes: `0` success, `1` argument/IO error, `2` HTTP error
after retries, `3` SHA-256/minisign mismatch.

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
```

## Verification

When you install or download a release asset, ghr automatically verifies
the downloaded bytes against any verification material the release
publishes:

- **SHA256 checksum files** — sidecar `<asset>.sha256` files and aggregate
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
- **Minisign signatures** — `<asset>.minisig` sidecars
  ([minisign v2](https://jedisct1.github.io/minisign/)) are verified when
  the caller passes `--minisign <base64-pubkey>`. The flag value is the
  single-line base64 token from a minisign `.pub` file (algorithm `Ed`
  or `ED`, 8-byte key id, 32-byte Ed25519 public key). Both the artifact
  signature (`Ed` = pure Ed25519 over the file, `ED` = Ed25519 over the
  Blake2b-512 digest, streamed from disk) and the trailing trusted-comment
  global signature are verified against the same key. The trusted comment
  (often a `timestamp:... file:... hashed` blob) is printed on success.
  If `--minisign` is set but no `<asset>.minisig` is published, ghr
  aborts the download — minisign verification is fail-closed when opted in.
  If a `<asset>.minisig` IS published but neither `--minisign` nor
  `--skip-verify` was passed, ghr also aborts: ignoring a published
  signature would silently skip a real verification opportunity, so the
  caller must opt in (pass `--minisign <pubkey>`) or opt out
  (`--skip-verify`).

On any verification failure the operation is aborted and the cached
download is deleted. If no checksum, minisign sidecar, or bundle is
published the download proceeds with a `note:` line so you know it was
unverified.

Pass `--skip-verify` to bypass all checks. For `install`, the strongest
result is recorded in each tool's `ghr.json` metadata as `"verified"`:

- `"sigstore"` — sigstore bundle verified (also implies the bundle's
  declared SHA256 matches the file).
- `"minisign"` — minisign sidecar verified by the caller-supplied
  `--minisign` key (artifact + trusted-comment signatures).
- `"sha256"` — SHA256 checksum verified.
- `"none"` — no verification material was published.
- `"skipped"` — `--skip-verify` was passed.

When more than one verifier succeeds (e.g. sha256 *and* sigstore, or
sha256 *and* minisign) the strongest one is recorded — precedence is
sigstore > minisign > sha256. All successful verifiers still print their
own diagnostic line, so the full set is visible at install time.

The trust roots embedded in ghr come from
[`sigstore/root-signing`](https://github.com/sigstore/root-signing).
Rotating them requires a new ghr release.
