# Download

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
        --skip-verify          Skip every verification step (checksum, minisign, sigstore, attestation, authenticode)
        --skip-checksum        Skip checksum verification (GitHub asset digest + .sha256/.sha512 sidecar)
        --skip-minisign        Skip just the minisign verification step
        --skip-sigstore        Skip just the published .sigstore.json sidecar verification step
        --skip-attestation     Skip just the GitHub-native artifact attestation verification step
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
When a token is present, release assets are fetched through the
GitHub asset API endpoint rather than the public download URL, so
private and SSO-protected enterprise releases work as long as the
token is authorized for the organization.
Downloads are auto-verified against any sigstore bundle or checksum
sidecar published with the release, and against any GitHub artifact
attestation covering the downloaded digest; pass `--minisign <pubkey>` to
also require a minisign signature (or attach an inline key to a
spec), `--skip-<step>` to bypass one verifier individually, or
`--skip-verify` to bypass all checks. Exit codes: `0` success, `1`
argument/IO error, `2` HTTP error after retries, `3` checksum or
minisign mismatch. Multi-spec invocations exit with the most-severe
code observed across the batch.
