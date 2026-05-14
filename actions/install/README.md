# `ghr install` composite action

Install one or more tools from GitHub releases inside a workflow, and cache
the results across runs.

```yaml
- uses: cataggar/ghr/actions/install@v0.3.0  # pin to the matching ghr release
  with:
    tools: |
      BurntSushi/ripgrep@14.1.1
      sharkdp/fd@v10.2.0
```

The action ships in the same git repository as `ghr` and shares its release
stream: a tag like `v0.3.0` pins **both** the action body and the
`ghr-bin` PyPI package the action installs. Pick the tag from
[the releases page](https://github.com/cataggar/ghr/releases); pin to a
specific commit SHA for full reproducibility.

A cache-hit on subsequent runs restores the tool directory and skips the
install entirely. The cache key is `os + arch + sorted(tools) + ghr version`,
so adding a tool or bumping the action's tag invalidates the cache cleanly.

## Inputs

| Input          | Default                  | Description |
|----------------|--------------------------|-------------|
| `tools`        | _(required)_             | Newline-separated `owner/repo[@tag]` (or `owner/repo/file[@tag]`) specs. Empty lines and lines starting with `#` are ignored. |
| `cache`        | `true`                   | Cache the installed tools across runs. |
| `minisign`     | _(empty)_                | Base64 minisign public key. When set, every spec is verified against a `.minisig` sidecar (fail-closed). |
| `skip-verify`  | `false`                  | Skip sigstore + sha256 + minisign verification. |
| `keep-going`   | `false`                  | Continue past per-spec failures; exit non-zero with a summary if any spec failed. |
| `ghr-version`  | _(derived from action ref)_ | Override the `ghr-bin` version installed. Default: derived from the action's git ref (e.g. `@v0.3.0` → `ghr-bin==0.3.0`). Pass `latest` to install the latest from PyPI. |

## Outputs

| Output       | Description |
|--------------|-------------|
| `cache-hit`  | `'true'` when the tool cache was restored from a prior run. |

## What it does

1. `pipx install ghr-bin` (pre-installed on GitHub-hosted runners).
2. Sets `GHR_TOOL_DIR`, `GHR_BIN_DIR`, `GHR_CACHE_DIR` to user-writable
   subdirectories of `$RUNNER_TEMP`, and prepends `GHR_BIN_DIR` to
   `$GITHUB_PATH`.
3. Computes a stable cache key from the sorted tool list + `ghr version` +
   OS/arch.
4. Restores the cache via `actions/cache@v4` (pinned by SHA).
5. On cache miss, runs `ghr install` with every spec (sharing a single
   HTTP client + auth context).
6. Runs `ghr list` as a sanity check.

## Examples

### Verify with minisign

```yaml
- uses: cataggar/ghr/actions/install@v1
  with:
    tools: jedisct1/minisign@0.12
    minisign: RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3
```

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

The action shares git tags with the `ghr` CLI: `@v0.3.0` references the
action body **and** pins `ghr-bin` (via the `ghr-version` input default)
to the matching release. To explicitly pin the installed binary to a
different release, pass `ghr-version:`. For full reproducibility, pin to
a commit SHA: `cataggar/ghr/actions/install@<sha> # v0.3.0`.
