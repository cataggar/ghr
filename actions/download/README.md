# `ghr download` composite action

Download one or more release assets inside a workflow, optionally extracting
each archive into a destination directory, and cache the result across runs.

```yaml
- uses: cataggar/ghr/actions/download@v0.8.0  # pin to the matching ghr release
  with:
    tools: |
      BurntSushi/ripgrep@14.1.1
      sharkdp/fd@v10.2.0
    extract: 'true'
```

The action ships in the same git repository as `ghr` and shares its release
stream: a tag like `v0.8.0` pins **both** the action body and the verified
static `ghr` release the action bootstraps. Pick the tag from
[the releases page](https://github.com/cataggar/ghr/releases); pin to a
specific commit SHA and set `ghr-version` for full reproducibility.

The bootstrap uses the runner-provided Node 24 action runtime. It works in bare
Ubuntu and Debian job containers without Python, `pipx`, `curl`, `gh`, or
package-manager setup.

A cache-hit on subsequent runs restores the destination directory and skips
the download entirely. The cache key covers OS/architecture and ABI, sorted
sources, extraction settings, the complete verification policy, the minisign
key, and the ghr version. Changing any input that affects downloaded or
verified content therefore invalidates the cache.

## Inputs

| Input               | Default                          | Description |
|---------------------|----------------------------------|-------------|
| `tools`             | _(required)_                     | Newline-separated `owner/repo[@tag]` (or `owner/repo/file[@tag]`) specs. Empty lines and lines starting with `#` are ignored. |
| `dest`              | `$RUNNER_TEMP/ghr-download`      | Directory to download (and optionally extract) into. |
| `extract`           | `false`                          | Extract archive assets into `dest` after download. |
| `strip-components`  | _(none)_                         | When `extract: true`, strip N leading path components. |
| `cache`             | `true`                           | Cache the `dest` directory across runs. |
| `minisign`          | _(empty)_                        | Base64 minisign public key. When set, every spec is verified against a `.minisig` sidecar (fail-closed). |
| `skip-verify`       | `false`                          | Umbrella: skip every verification step (checksum, minisign, sigstore, GitHub attestation, authenticode). |
| `skip-checksum`     | `false`                          | Skip just the checksum-sidecar verification step. |
| `skip-minisign`     | `false`                          | Skip just the minisign verification step. Bypasses the fail-closed "sidecar published but no key" behavior. |
| `skip-sigstore`     | `false`                          | Skip just the `.sigstore.json` sidecar published as a release asset. Does not affect GitHub's attestation service. |
| `skip-attestation`  | `false`                          | Skip just GitHub artifact attestation verification, which is looked up by digest rather than published as a release asset. |
| `skip-authenticode` | `false`                          | Skip just the Authenticode (Windows PE) verification step. |
| `keep-going`        | `false`                          | Continue past per-spec failures; exit non-zero with a summary if any spec failed. |
| `ghr-version`       | _(exact action tags only)_       | Exact static CLI release. Commit, branch, and floating-tag action refs must set it; ranges and `latest` are rejected. |
| `ghr-sha256`        | _(empty)_                        | Optional independently trusted SHA-256 for the selected ghr archive; it must also match GitHub's asset digest. |
| `ghr-token`         | `github.token`                   | Used only for ghr release and provenance API requests. Downstream downloads still use `GH_TOKEN`/`GITHUB_TOKEN` from env. |
| `ghr-cache`         | `true`                           | Cache and reverify the exact static ghr archive separately from the downloaded-assets cache. |

## Outputs

| Output       | Description |
|--------------|-------------|
| `cache-hit`  | `'true'` when the download cache was restored from a prior run. |
| `dest`       | Absolute path of the resolved destination directory. |

## What it does

1. Resolves one exact static ghr release and verifies its GitHub digest plus
   Sigstore provenance (or an explicit trusted SHA-256), then safely extracts
   it below `$RUNNER_TEMP`.
2. Resolves `dest` to an absolute path (defaulting to `$RUNNER_TEMP/ghr-download`).
3. Computes a stable cache key from sorted sources, extraction settings,
   verification policy, minisign key, `ghr version`, and OS/architecture.
4. Restores the cache via `actions/cache@v4` (pinned by SHA).
5. On cache miss, runs `ghr download` with every spec (sharing a single
   HTTP client + auth context).
6. Lists `dest` as a sanity check.

## Examples

### Multiple downloads, no extraction

```yaml
- uses: cataggar/ghr/actions/download@v1
  with:
    tools: |
      BurntSushi/ripgrep@14.1.1
      sharkdp/fd@v10.2.0
    dest: ./artifacts
```

### Extract every archive into a shared directory

```yaml
- uses: cataggar/ghr/actions/download@v1
  with:
    tools: |
      BurntSushi/ripgrep@14.1.1
      sharkdp/fd@v10.2.0
    extract: 'true'
    strip-components: '1'
    dest: ./bin
```

### Single-spec with sha256

The `--sha256` flag is intentionally rejected for multi-spec invocations,
since a single digest cannot apply to N artifacts. For single-spec downloads
the underlying CLI flag still works — you'd usually drop the action and call
`ghr download --sha256 <hex>` directly in a single step.

### Two independent Sigstore forms

`skip-sigstore` and `skip-attestation` are not interchangeable. A release can
carry either, both, or neither, and each is verified on its own:

- **`.sigstore.json` sidecar** — a file the release publishes alongside the
  asset. Controlled by `skip-sigstore`.
- **GitHub artifact attestation** — not a release asset at all. `ghr` looks it
  up from GitHub's attestation API using the downloaded file's SHA-256 digest.
  Controlled by `skip-attestation`.

Attestation lookups go through the GitHub API, so an unauthenticated runner
can hit rate limits. Pass a token, which on GitHub-hosted runners you already
have:

```yaml
- uses: cataggar/ghr/actions/download@v1
  with:
    tools: cli/cli@v2.96.0
  env:
    GH_TOKEN: ${{ github.token }}
```

A lookup that fails for any reason other than "no attestation exists" is
fatal, so a rate limit or an expired token cannot be mistaken for an
unattested artifact. Set `skip-attestation: 'true'` to opt out deliberately.

## Pinning

The action shares git tags with the `ghr` CLI: `@v0.8.0` references the
action body and selects the matching static release. For full reproducibility,
pin the action to a commit SHA and supply the CLI version independently:

```yaml
- uses: cataggar/ghr/actions/download@<sha> # reviewed action commit
  with:
    ghr-version: v0.8.0
    tools: BurntSushi/ripgrep@14.1.1
```

Commit, branch, major-tag, range, and `latest` references never silently select
the latest CLI. The action requires Actions runner 2.336.0 or newer for exact
same-repository action composition.
