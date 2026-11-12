# GitHub Actions

`cataggar/ghr` provides composite actions that bootstrap a verified static
`ghr` binary using the runner's Node runtime and cache installed tools or
downloaded release assets across workflow runs—without needing Python, `pipx`,
`curl`, `gh`, or system packages:

- [`cataggar/ghr/actions/install`](../actions/install/README.md) — install one
  or more tools onto `PATH` with cross-run caching.
- [`cataggar/ghr/actions/download`](../actions/download/README.md) — download
  (and optionally extract) one or more release assets with cross-run caching.
- [`cataggar/ghr/actions/setup`](../actions/setup/README.md) — install one
  exact, verified static `ghr` CLI release onto `PATH`.

## Installing tools (`actions/install`)

Pass one or more tool specs in `tools:`. Multi-line `tools:` blocks are
installed in a single `ghr install` invocation and share one cache entry:

```yaml
permissions:
  contents: read
  attestations: read

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Install Zig and Wasmtime via ghr
        uses: cataggar/ghr/actions/install@v0.10.3
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          tools: |
            cataggar/zig@v0.17.1 RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U
            bytecodealliance/wasmtime@v50.0.1
```

Each non-empty line in `tools:` is one install request (`owner/repo[@tag]`),
optionally followed by an inline minisign public key. When a public key is
supplied (inline or via the action-level `minisign:` input), `ghr` requires and
verifies the release's `<asset>.minisig` signature sidecar.

### Pinning the action

The actions live in the same repository as `ghr` and share its release tags:
pinning `@v0.10.3` pins both the action definition and the verified static
`ghr` binary. Pick the latest release from
[the releases page](https://github.com/cataggar/ghr/releases).

When pinning the action to a commit SHA, specify `ghr-version` explicitly:

```yaml
- uses: cataggar/ghr/actions/install@<commit-sha>
  with:
    ghr-version: v0.10.3
    tools: bytecodealliance/wasmtime@v50.0.1
```

## Attestations

By default, `ghr` checks for
[GitHub artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/verify-attestations-offline)
in two places:

1. **Bootstrap (`actions/setup`)**: verifies `cataggar/ghr`'s own Sigstore
   release provenance attestation before running `ghr`.
2. **Tool verification (`ghr install` / `ghr download`)**: queries GitHub's
   Attestations API by the downloaded asset's SHA-256 digest.

Attestation checks are **fail-closed**:

- If a release has no published attestations (`404` or an empty attestation
  list), `ghr` proceeds with other verifiers (GitHub asset SHA-256 digest,
  `.sha256` sidecars, minisign, `.sigstore.json` sidecars, Authenticode).
- If the Attestations API request itself fails (such as `403 Forbidden` from a
  token missing permission, or a rate limit), `ghr` treats that as a hard error
  rather than assuming the release is unattested.

### Recommended: grant `attestations: read`

If your workflow sets an explicit `permissions:` block (or your repository
restricts default `GITHUB_TOKEN` permissions), grant `contents: read` and
`attestations: read` and pass `GH_TOKEN`:

```yaml
permissions:
  contents: read
  attestations: read
```

### Skipping tool attestation verification (`skip-attestation`)

To skip the GitHub artifact attestation lookup for installed tools in
`actions/install` (or `actions/download`) while keeping checksum, minisign,
`.sigstore.json` sidecar, and Authenticode verification enabled, set
`skip-attestation: true`:

```yaml
- name: Install Zig and Wasmtime via ghr
  uses: cataggar/ghr/actions/install@v0.10.3
  env:
    GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    skip-attestation: true
    tools: |
      cataggar/zig@v0.17.1 RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U
      bytecodealliance/wasmtime@v50.0.1
```

(`skip-attestation` maps to `ghr install --skip-attestation`. To also bypass
the provenance attestation check when bootstrapping the `ghr` binary itself,
pass a trusted `ghr-sha256` digest matching the `cataggar/ghr` release asset.)

## Downloading assets (`actions/download`)

Use `cataggar/ghr/actions/download` when you want release archives downloaded
or extracted into a specific directory (`dest`) rather than installed into the
managed tool directory:

```yaml
- uses: cataggar/ghr/actions/download@v0.10.3
  env:
    GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    tools: |
      burntsushi/ripgrep@15.1.0
      sharkdp/fd@v10.2.0
    extract: true
    strip-components: 1
    dest: ./bin
```

## Caching and container notes

- **Tool cache key**: `actions/install` hashes the runner OS, architecture,
  target ABI (such as glibc vs. musl), normalized tool specs, verification
  flags/keys, install layout version, and `ghr` version. Changing any of these
  invalidates the cache automatically.
- **Setup cache**: `actions/setup` caches the `ghr` binary archive separately
  (`ghr-cache: true`) and rehashes and reverifies the archive on every restore
  before executing it.
- **Minimal Linux containers**: If a job container omits `ca-certificates`,
  `actions/setup` materializes the Node runtime's TLS root bundle under
  `$RUNNER_TEMP` and exports `SSL_CERT_FILE` for `ghr`.

## Signing releases

`ghr` includes built-in minisign key generation and signing powered by
[`cataggar/minizign`](https://github.com/cataggar/minizign), so workflows can
sign release artifacts without installing an external `minisign` binary.

### 1. Provision repository secrets

With `gh` authenticated locally for the target repository, generate a key pair
and upload `MINISIGN_SECRET_KEY` to GitHub Actions secrets:

```sh
ghr minisign generate
# Or target a specific repository:
ghr minisign generate --repo OWNER/REPO
```

This creates `minisign.key` (mode `0600` / owner-only ACL) and `minisign.pub`
in the current directory and uploads `MINISIGN_SECRET_KEY`. Never commit
`minisign.key`; publish `minisign.pub` in your README or documentation so
users can verify your releases.

If secret upload fails after local key creation, retry using the existing pair
rather than generating a new key:

```sh
ghr minisign generate --repo OWNER/REPO --reuse-existing-local-pair --force
```

To use a password-protected key instead, set `MINISIGN_PASSWORD` in your local
environment and pass `--encrypt` (`ghr minisign generate --encrypt`).

### 2. Sign release artifacts in CI

After bootstrapping `ghr` (via `cataggar/ghr/actions/setup`), sign release
archives directly from the environment secret:

```yaml
- uses: cataggar/ghr/actions/setup@v0.10.3
- run: ghr minisign sign artifact.tar.gz
  env:
    MINISIGN_SECRET_KEY: ${{ secrets.MINISIGN_SECRET_KEY }}
```

Each input file produces `<file>.minisig` alongside the artifact. If the key
was created with `--encrypt`, also pass
`MINISIGN_PASSWORD: ${{ secrets.MINISIGN_PASSWORD }}`.

