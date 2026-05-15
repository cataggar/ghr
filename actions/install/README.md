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

Each line of `tools:` is either `spec` or `spec <minisign-pubkey>` (a single
whitespace-separated pair). An inline key requests minisign verification for
that one spec and overrides the action-level `minisign:` default. Empty
lines and `#` comments are ignored.

The action ships in the same git repository as `ghr` and shares its release
stream: a tag like `v0.3.0` pins **both** the action body and the
`ghr-bin` PyPI package the action installs. Pick the tag from
[the releases page](https://github.com/cataggar/ghr/releases); pin to a
specific commit SHA for full reproducibility.

A cache-hit on subsequent runs restores the tool directory and skips the
install entirely. The cache key is
`os + arch + sorted(tools, including inline keys) + ghr version`, so adding
a tool, changing a tool's inline key, or bumping the action's tag
invalidates the cache cleanly.

## Inputs

| Input               | Default                  | Description |
|---------------------|--------------------------|-------------|
| `tools`             | _(required)_             | Newline-separated entries. Each entry is `owner/repo[@tag]` (or `owner/repo/file[@tag]`), optionally followed by a single whitespace-separated minisign pubkey. Empty lines and lines starting with `#` are ignored. |
| `cache`             | `true`                   | Cache the installed tools across runs. |
| `minisign`          | _(empty)_                | Default base64 minisign public key applied to every `tools:` line that does **not** include its own inline key. When set, ghr requires a `.minisig` sidecar (fail-closed). Inline per-spec keys override this default for that one spec. |
| `skip-verify`       | `false`                  | Umbrella: skip every verification step (checksum, minisign, sigstore, authenticode). |
| `skip-checksum`     | `false`                  | Skip just the checksum-sidecar verification step. |
| `skip-minisign`     | `false`                  | Skip just the minisign verification step. Bypasses the fail-closed "sidecar published but no key" behavior. |
| `skip-sigstore`     | `false`                  | Skip just the sigstore-bundle verification step. |
| `skip-authenticode` | `false`                  | Skip just the Authenticode (Windows PE) verification step. |
| `keep-going`        | `false`                  | Continue past per-spec failures; exit non-zero with a summary if any spec failed. |
| `ghr-version`       | _(derived from action ref)_ | Override the `ghr-bin` version installed. Default: derived from the action's git ref (e.g. `@v0.3.0` → `ghr-bin==0.3.0`). Pass `latest` to install the latest from PyPI. |

## Outputs

| Output       | Description |
|--------------|-------------|
| `cache-hit`  | `'true'` when the tool cache was restored from a prior run. |

## What it does

1. `pipx install ghr-bin` (pre-installed on GitHub-hosted runners).
2. Sets `GHR_TOOL_DIR`, `GHR_BIN_DIR`, `GHR_CACHE_DIR` to user-writable
   subdirectories of `$RUNNER_TEMP`, and prepends `GHR_BIN_DIR` to
   `$GITHUB_PATH`.
3. Parses every `tools:` line into a `spec [key]` pair, validating the
   optional key shape (56-char base64, `RW`/`RU` prefix).
4. Computes a stable cache key from the sorted list of `spec [key]`
   pairs + `ghr version` + OS/arch.
5. Restores the cache via `actions/cache@v4` (pinned by SHA).
6. On cache miss, runs `ghr install` with every spec (and its inline
   key, when present) as positional arguments.
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
