# Caching in GitHub Actions

Running `pipx install ghr-bin && ghr install <tool>` from scratch on every
workflow run pays the download + extraction cost each time. Caching the
tool directory across runs reduces a warm install to a near-instant
restore.

The pattern is the same one
[pipx users settled on](https://github.com/pypa/pipx/discussions/1051) —
override the on-disk locations to a user-writable path (so
`actions/cache` can write back to it without `sudo`), then key the cache
on the sorted list of tools + `ghr` version.

## Recommended: composite actions

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

## Hand-rolled recipe (`ghr install`)

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

## Cache key shape

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

## Caveats

- Verification metadata (`ghr.json`, sigstore bundles, checksum sidecars)
  is stored under `GHR_TOOL_DIR` as regular files and survives a cache
  round-trip — verification happens at install time, not on restore.
- Windows shims are regular files (the runtime resolves them through
  PATH) and survive the cache round-trip cleanly.
- `pipx install ghr-bin` is cheap (single static binary). Caching it
  separately isn't worth the complexity.

## Caching `ghr download`

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
equivalent of `-o`, and verification falls back to whatever GitHub asset
digest, sigstore, or sha256 sidecars the release publishes, plus any
GitHub artifact attestation covering the downloaded digest.
