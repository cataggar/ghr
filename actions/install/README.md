# `ghr install` composite action

Install one or more tools from GitHub releases inside a workflow, and cache
the results across runs.

```yaml
- uses: cataggar/ghr/actions/install@v0.8.0  # pin to the matching ghr release
  with:
    tools: |
      BurntSushi/ripgrep@14.1.0 ?id=rg-14-1-0&alias=rg:rg-14-1-0
      BurntSushi/ripgrep@14.1.1 "?id=rg-14-1-1&alias=rg:rg-14-1-1"
      sharkdp/fd@v10.2.0
```

Each line of `tools:` is one complete
`source [query-token] [minisign-pubkey]` request. The query token supports
`id=`, repeatable `alias=`, and `minisign=` fields. Quotes around it are
accepted for parity with shell examples but are optional in a YAML block
scalar. A bare inline key remains compatible and overrides the action-level
`minisign:` default. Empty lines and `#` comments are ignored.

The action ships in the same git repository as `ghr` and shares its release
stream: a tag like `v0.8.0` pins **both** the action body and the
`ghr-bin` PyPI package the action installs. Pick the tag from
[the releases page](https://github.com/cataggar/ghr/releases); pin to a
specific commit SHA for full reproducibility.

A cache-hit on subsequent runs restores the complete tool, command, cache, and
transaction state and skips installation. The ID-capable CLI parses and hashes
normalized complete definitions, so request reordering is stable while a
changed source, ID, alias, selection, verification policy, minisign key, state
layout, target ABI (for example, glibc versus musl), or ghr version invalidates
the cache. The action fails with a clear version error if its installed CLI
predates stable-ID cache fingerprints.

## Inputs

| Input               | Default                  | Description |
|---------------------|--------------------------|-------------|
| `tools`             | _(required)_             | One `source [query-token] [minisign-pubkey]` request per line. Query fields configure stable IDs, aliases, and per-request minisign verification. |
| `cache`             | `true`                   | Cache the installed tools across runs. |
| `minisign`          | _(empty)_                | Default base64 minisign public key applied to every `tools:` line that does **not** include its own inline key. When set, ghr requires a `.minisig` sidecar (fail-closed). Inline per-spec keys override this default for that one spec. |
| `skip-verify`       | `false`                  | Umbrella: skip every verification step (checksum, minisign, sigstore, GitHub attestation, authenticode). |
| `skip-checksum`     | `false`                  | Skip just the checksum-sidecar verification step. |
| `skip-minisign`     | `false`                  | Skip just the minisign verification step. Bypasses the fail-closed "sidecar published but no key" behavior. |
| `skip-sigstore`     | `false`                  | Skip just the `.sigstore.json` sidecar published as a release asset. Does not affect GitHub's attestation service. |
| `skip-attestation`  | `false`                  | Skip just GitHub artifact attestation verification, which is looked up by digest rather than published as a release asset. |
| `skip-authenticode` | `false`                  | Skip just the Authenticode (Windows PE) verification step. |
| `keep-going`        | `false`                  | Continue past per-spec failures; exit non-zero with a summary if any spec failed. |
| `ghr-version`       | _(derived from action ref)_ | Override the `ghr-bin` version installed. Default: derived from the action's git ref (e.g. `@v0.8.0` -> `ghr-bin==0.8.0`). Pass `latest` to install the latest from PyPI. |

## Outputs

| Output       | Description |
|--------------|-------------|
| `cache-hit`  | `'true'` when the tool cache was restored from a prior run. |

## What it does

1. `pipx install ghr-bin` (pre-installed on GitHub-hosted runners).
2. Sets `GHR_TOOL_DIR`, `GHR_BIN_DIR`, `GHR_CACHE_DIR` to user-writable
   subdirectories of `$RUNNER_TEMP`, and prepends `GHR_BIN_DIR` to
   `$GITHUB_PATH`.
3. Keeps every source, query token, and optional bare key attached as one
   request, then asks the installed CLI to validate and normalize them.
4. Computes a stable cache key from complete normalized definitions, the state
   layout, `ghr version`, and OS/architecture.
5. Restores the cache via `actions/cache@v4` (pinned by SHA).
6. On cache miss, runs `ghr install` with every complete request as positional
   arguments.
7. Runs `ghr list` as a sanity check.

## Examples

### Verify with minisign (action-level default)

```yaml
- uses: cataggar/ghr/actions/install@v1
  with:
    tools: jedisct1/minisign@0.12
    minisign: RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3
```

### Per-spec inline minisign keys

Different tools can be verified against different keys in a single
action invocation. An inline key on a `tools:` line overrides the
action-level `minisign:` default for that spec.

```yaml
- uses: cataggar/ghr/actions/install@v1
  with:
    tools: |
      jedisct1/minisign@0.12 RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3
      BurntSushi/ripgrep@14.1.1
      sharkdp/fd@v10.2.0
```

### Skip a single verification step

Selectively bypass one verifier when its sidecar is broken or
unavailable in a given release, while keeping the others active.

```yaml
- uses: cataggar/ghr/actions/install@v1
  with:
    tools: BurntSushi/ripgrep@14.1.1
    skip-checksum: 'true'   # checksum-sidecar bypass; minisign + sigstore still apply
```

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
- uses: cataggar/ghr/actions/install@v1
  with:
    tools: cli/cli@v2.96.0
  env:
    GH_TOKEN: ${{ github.token }}
```

A lookup that fails for any reason other than "no attestation exists" is
fatal, so a rate limit or an expired token cannot be mistaken for an
unattested artifact. Set `skip-attestation: 'true'` to opt out deliberately.

### Continue past per-spec failures

```yaml
- uses: cataggar/ghr/actions/install@v1
  with:
    tools: |
      BurntSushi/ripgrep@14.1.1
      sharkdp/fd@v10.2.0
      maybe/missing@1.0
    keep-going: 'true'
```

## Pinning

The action shares git tags with the `ghr` CLI: `@v0.8.0` references the
action body **and** pins `ghr-bin` (via the `ghr-version` input default)
to the matching release. To explicitly pin the installed binary to a
different release, pass `ghr-version:`. For full reproducibility, pin to
a commit SHA: `cataggar/ghr/actions/install@<sha> # v0.8.0`.
