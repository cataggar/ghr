# ghr

An installer for GitHub releases.

## Usage

```
ghr install <owner/repo[@tag]>           Install a tool from a GitHub release
ghr install <owner/repo/file[@tag]>      Install a specific asset by name
ghr uninstall <name>                     Remove an installed tool
ghr download <owner/repo[@tag]>          Download the asset 'install' would pick
ghr download <owner/repo/file[@tag]>     Download a specific asset by name
ghr list                                 List installed tools
ghr upgrade [name]                       Upgrade installed tools
ghr ensurepath [--dry-run]               Add ghr's bin dir to your user PATH
ghr dir [--bin] [--cache]                Show ghr directories
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
        --skip-verify          Skip sigstore + sha256 release verification
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
checksum file published with the release; pass `--skip-verify` to
bypass. Exit codes: `0` success, `1` argument/IO error, `2` HTTP error
after retries, `3` SHA-256 mismatch.

### Replacing wget + tar in workflows

Before — three OS-specific steps to fetch and extract a release archive:

```yaml
# Ubuntu / macOS
- run: |
    sudo wget -O wasi-sdk.tar.gz --progress=dot:giga \
      https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-25/wasi-sdk-25.0-x86_64-linux.tar.gz
    sudo tar -xf wasi-sdk.tar.gz -C /opt
# Windows
- run: |
    choco install -y wget
    wget -O wasi-sdk.tar.gz `
      https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-25/wasi-sdk-25.0-x86_64-linux.tar.gz
    tar -xf wasi-sdk.tar.gz -C /opt
```

After — one step on every OS:

```yaml
- run: |
    ghr download \
      WebAssembly/wasi-sdk/wasi-sdk-25.0-x86_64-linux.tar.gz@wasi-sdk-25 \
      --extract /opt
```

## Install

It can be installed using uv, pip, winget, or downloaded from releases.

```sh
# uv
uv tool install ghr-bin

# pip
python3 -m pip install ghr-bin

# winget
winget install ghr
```

### Examples

```sh
# Install latest release
ghr install burntsushi/ripgrep

# Install a specific tag
ghr install burntsushi/ripgrep@15.1.0

# Install a specific asset by name (exact match or unique substring)
ghr install WebAssembly/wasi-sdk/wasi-sdk-25.0-x86_64-linux.tar.gz@wasi-sdk-25

# Show where tools are stored
ghr dir

# Show where binaries are symlinked
ghr dir --bin
```

## Directories

Follows [uv tool](https://docs.astral.sh/uv/) conventions.

| Purpose | Unix | Windows |
|---------|------|---------|
| Binaries | `~/.local/bin/` | `%USERPROFILE%\.local\bin\` |
| Tool storage | `~/.local/share/ghr/tools/` | `%APPDATA%\ghr\data\tools\` |
| Cache | `~/.cache/ghr/` | `%LOCALAPPDATA%\ghr\cache\` |

Override with `GHR_BIN_DIR`, `GHR_TOOL_DIR`, `GHR_CACHE_DIR`.

The bin directory is frequently not on `PATH` by default, especially on Windows. Run `ghr ensurepath` once to fix that:

- **Windows**: updates `HKCU\Environment\Path` (user PATH) and broadcasts `WM_SETTINGCHANGE` so new terminals pick up the change. If `%APPDATA%\nushell\` exists, also updates `%APPDATA%\nushell\env.nu`.
- **macOS / Linux**: appends a guarded block to your shell rc files (bash: `.bash_profile` / `.bashrc` / `.profile`; zsh: `.zprofile`; nushell: `~/.config/nushell/env.nu`). The block is idempotent and is replaced in place on re-runs.

`ghr ensurepath --dry-run` prints the changes it would make without writing.

## Uninstall

```sh
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

On any verification failure the operation is aborted and the cached
download is deleted. If no checksum or bundle is published the download
proceeds with a `note:` line so you know it was unverified.

Pass `--skip-verify` to bypass both checks. For `install`, the strongest
result is recorded in each tool's `ghr.json` metadata as `"verified"`:

- `"sigstore"` — sigstore bundle verified (also implies the bundle's
  declared SHA256 matches the file).
- `"sha256"` — SHA256 checksum verified.
- `"none"` — no verification material was published.
- `"skipped"` — `--skip-verify` was passed.

The trust roots embedded in ghr come from
[`sigstore/root-signing`](https://github.com/sigstore/root-signing).
Rotating them requires a new ghr release.

## License

MIT
