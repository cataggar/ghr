# `ghr download` composite action

Download one or more release assets inside a workflow, optionally extracting
each archive into a destination directory, and cache the result across runs.

```yaml
- uses: cataggar/ghr/actions/download@v0.3.0  # pin to the matching ghr release
  with:
    tools: |
      BurntSushi/ripgrep@14.1.1
      sharkdp/fd@v10.2.0
    extract: 'true'
```

The action ships in the same git repository as `ghr` and shares its release
stream: a tag like `v0.3.0` pins **both** the action body and the
`ghr-bin` PyPI package the action installs. Pick the tag from
[the releases page](https://github.com/cataggar/ghr/releases); pin to a
specific commit SHA for full reproducibility.

A cache-hit on subsequent runs restores the destination directory and skips
the download entirely. The cache key is
`os + arch + sorted(tools) + extract flag + strip-components + ghr version`,
so adding a tool, toggling extraction, or bumping the action's tag
invalidates the cache cleanly.

## Inputs

| Input               | Default                          | Description |
|---------------------|----------------------------------|-------------|
| `tools`             | _(required)_                     | Newline-separated `owner/repo[@tag]` (or `owner/repo/file[@tag]`) specs. Empty lines and lines starting with `#` are ignored. |
| `dest`              | `$RUNNER_TEMP/ghr-download`      | Directory to download (and optionally extract) into. |
| `extract`           | `false`                          | Extract archive assets into `dest` after download. |
| `strip-components`  | _(none)_                         | When `extract: true`, strip N leading path components. |
| `cache`             | `true`                           | Cache the `dest` directory across runs. |
| `minisign`          | _(empty)_                        | Base64 minisign public key. When set, every spec is verified against a `.minisig` sidecar (fail-closed). |
| `skip-verify`       | `false`                          | Skip sigstore + sha256 + minisign verification. |
| `keep-going`        | `false`                          | Continue past per-spec failures; exit non-zero with a summary if any spec failed. |
| `ghr-version`       | _(derived from action ref)_      | Override the `ghr-bin` version installed. Default: derived from the action's git ref (e.g. `@v0.3.0` → `ghr-bin==0.3.0`). Pass `latest` to install the latest from PyPI. |

## Outputs

| Output       | Description |
|--------------|-------------|
| `cache-hit`  | `'true'` when the download cache was restored from a prior run. |
| `dest`       | Absolute path of the resolved destination directory. |

## What it does

1. `pipx install ghr-bin` (pre-installed on GitHub-hosted runners).
2. Resolves `dest` to an absolute path (defaulting to `$RUNNER_TEMP/ghr-download`).
3. Computes a stable cache key from the sorted tool list + `extract` /
   `strip-components` settings + `ghr version` + OS/arch.
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

## Pinning

The action shares git tags with the `ghr` CLI: `@v0.3.0` references the
action body **and** pins `ghr-bin` (via the `ghr-version` input default)
to the matching release. To explicitly pin the installed binary to a
different release, pass `ghr-version:`. For full reproducibility, pin to
a commit SHA: `cataggar/ghr/actions/download@<sha> # v0.3.0`.
