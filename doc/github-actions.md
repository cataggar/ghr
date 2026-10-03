# Caching in GitHub Actions

The first-party actions bootstrap an exact static `ghr` release with the
runner-provided Node action runtime, then cache downloaded or installed tools
under user-writable `$RUNNER_TEMP` paths. They do not require Python, `pipx`,
`curl`, `gh`, or package-manager setup.

Official minimal Linux images can also omit `ca-certificates`. If no standard
Linux CA bundle exists, `actions/setup` materializes the runner's maintained
Node 24 TLS roots under `$RUNNER_TEMP` and exports `SSL_CERT_FILE` for `ghr`.
Existing system trust is left untouched. Releases before `v0.8.0` also need a
compatibility link at Zig's standard CA location, so bootstrapping those older
versions in a bare non-root container requires a preinstalled CA bundle.

GitHub-hosted runner images include many convenience tools, including `pipx`.
A job-level `container:` supplies a different user space and does not inherit
those hosted-image packages. Do not assume a tool listed on the hosted runner
image is available in an arbitrary Ubuntu or Debian container.

## Recommended: composite actions

This repository ships two composite actions that wrap the dance below
end-to-end:

- [`cataggar/ghr/actions/setup`](../actions/setup/README.md) —
  install one exact, independently verified static CLI release.
- [`cataggar/ghr/actions/install`](../actions/install/README.md) —
  install one or more tools with cross-run caching.
- [`cataggar/ghr/actions/download`](../actions/download/README.md) —
  download (and optionally extract) one or more release assets with
  cross-run caching.

```yaml
- uses: cataggar/ghr/actions/install@v0.8.0  # pin to the matching ghr release
  with:
    tools: |
      BurntSushi/ripgrep@14.1.0 ?id=rg-14-1-0&alias=rg:rg-14-1-0
      BurntSushi/ripgrep@14.1.1 ?id=rg-14-1-1&alias=rg:rg-14-1-1
      sharkdp/fd@v10.2.0
```

Each line is one complete install request: a source, optional query token, and
optional bare minisign key. Query tokens do not need shell quotes inside the
YAML block, though matching quotes are accepted. To verify some tools with
minisign, attach the public key after that request. Inline keys override the
action-level `minisign:` default:

```yaml
- uses: cataggar/ghr/actions/install@v0.8.0
  with:
    tools: |
      jedisct1/minisign@0.12 RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3
      BurntSushi/ripgrep@14.1.1
      sharkdp/fd@v10.2.0
```

The actions ship in this same repository, so their git tags are the
same as `ghr`'s — pinning `@v0.8.0` pins both the action body and the
static binary the action verifies. Pick the latest tag from
[the releases page](https://github.com/cataggar/ghr/releases).

For a reviewed commit pin, select the CLI release separately:

```yaml
- uses: cataggar/ghr/actions/install@<reviewed-commit-sha>
  with:
    ghr-version: v0.8.0
    tools: sharkdp/fd@v10.2.0
```

An explicit exact version always wins. Commit, branch, floating-tag, range, and
`latest` action refs cannot imply a CLI version and fail if `ghr-version` is
omitted. The composite actions use GitHub's exact-commit `$/actions/setup`
self-reference and require Actions runner 2.336.0 or newer.

## Manual development recipe (`ghr install`)

If Python and `pipx` are already available in a development environment, a
manual recipe remains possible:

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

The install action asks the ID-capable CLI to hash normalized complete
definitions. Its key invalidates cleanly when:

- the runner OS or architecture changes,
- the target ABI changes (for example, glibc versus musl),
- a source, pinned tag, stable ID, alias, or selected command changes,
- a verification skip policy or minisign key changes,
- the install-state schema/layout generation changes,
- `ghr` itself is upgraded (the install layout could shift between
  versions).

Request order does not affect the key, but query tokens and keys are never
sorted away from their source. The action refuses to run with an older CLI
that cannot produce this fingerprint.

## Caveats

- Verification metadata (`ghr.json`, sigstore bundles, checksum sidecars)
  is stored under `GHR_TOOL_DIR` as regular files and survives a cache
  round-trip — verification happens at install time, not on restore.
- Windows shims are regular files (the runtime resolves them through
  PATH) and survive the cache round-trip cleanly.
- The setup cache is independent from the installed-tool cache. Its exact key
  includes the setup-cache schema, normalized target, release tag, and archive
  digest. Every restore is rehashed, safely re-extracted, compared with the
  authenticated archive, and version/target checked before execution.
- The default bootstrap requires GitHub release provenance. Grant
  `contents: read` and `attestations: read`, or supply an independently trusted
  `ghr-sha256` that also matches GitHub's asset digest.

## Caching `ghr download`

`ghr download` lands files in the user-chosen directory rather than a
managed cache, so the pattern is slightly simpler — cache the
destination directory and the extracted contents (if `--extract` is
used):

```yaml
- uses: cataggar/ghr/actions/download@v0.8.0  # pin to the matching ghr release
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

The download action's cache key includes extraction settings, every
verification skip flag, and the minisign key as hashed material. A cache
created under one verification policy is therefore never reused under another.

## Signing releases

### Configure repository secrets

Run setup locally with `gh` installed and authenticated as an account allowed
to manage the target repository's Actions secrets:

```sh
ghr minisign generate
# Alternative: override gh's current repository context.
ghr minisign generate --repo OWNER/REPO
```

The default repository follows GitHub CLI context; there is no interactive
repository chooser. If that context cannot be resolved, setup fails before
creating keys or uploading secrets. The command identifies the target
repository, creates `minisign.key` and `minisign.pub` in the current directory,
and refuses to overwrite existing key files. It checks for both
`MINISIGN_SECRET_KEY` and `MINISIGN_PASSWORD` before provisioning and refuses
if either secret already exists, unless you explicitly authorize replacement
with `--replace-existing-secrets`. Default setup never changes the password
secret, even with that flag.

Generation and signing both use
[`cataggar/minizign`](https://github.com/cataggar/minizign) as an in-process
library: neither needs a standalone `minisign` or `minizign` executable.
Authenticated `gh` is still needed to upload repository secrets.

The default uploads **only `MINISIGN_SECRET_KEY`**. Its value is an
unencrypted minisign-format private key; GitHub encrypts the repository secret
in storage. `MINISIGN_PASSWORD` is optional and is not created or changed by
default setup. No password-manager integration or separate passphrase-storage
step is required.

The generated private file has mode `0600` on POSIX. Keep the local private
key protected with restrictive permissions/ACLs.
Never commit it, include it in a cache, upload it as a release or workflow
artifact, or print key/password values in logs. Publish `minisign.pub` through
a trusted channel (for example, the project's README or website) so consumers
can pin the public key for verification. The public key and `.minisig`
signatures can accompany release artifacts; the private key cannot.

For comparison, the rough manual equivalent requires a separate `minisign`
installation:

```sh
umask 077
minisign -G -W -p minisign.pub -s minisign.key  # -W: no password encryption
gh repo view --json nameWithOwner --jq .nameWithOwner
gh secret list
# Verify the target and that MINISIGN_SECRET_KEY does not already exist.
gh secret set MINISIGN_SECRET_KEY < minisign.key
```

The `gh` commands use the current repository; add `--repo OWNER/REPO` to each
to override it. Unlike `ghr minisign generate`, `gh secret set` can replace an
existing secret, so inspect the target and existing secrets before using the
manual upload.

If setup fails, check `gh` installation/authentication, repository context,
and access to Actions secrets. For overwrite refusals, inspect the existing
files and secrets rather than deleting them blindly. If an upload fails
after key creation or after only some secrets were uploaded, retain the key
pair and fix access. From the directory containing the original
`minisign.key` and `minisign.pub`, retry against the same repository:

```sh
ghr minisign generate --repo OWNER/REPO \
  --reuse-existing-local-pair --replace-existing-secrets
```

`--reuse-existing-local-pair` validates that the private and public keys
match; it never generates a key or rewrites either file.
`--replace-existing-secrets` explicitly permits replacing signing secrets,
including any uploaded before the failure, with values from **the same key
pair**. Inspect the target and existing secrets first; do not regenerate or
rotate a key just to recover from an upload failure.

If the original pair was password-encrypted, set the original
`MINISIGN_PASSWORD` in the local environment and also pass `--encrypt`:

```sh
ghr minisign generate --repo OWNER/REPO --encrypt \
  --reuse-existing-local-pair --replace-existing-secrets
```

The encrypted retry decrypts and validates the existing pair before upload,
then configures both secrets. Run `ghr minisign generate --help` for all
options.

### Sign artifacts

After installing `ghr` with the setup action, sign without a private-key file
on the runner:

```yaml
- run: ghr minisign sign artifact.tar.gz
  env:
    MINISIGN_SECRET_KEY: ${{ secrets.MINISIGN_SECRET_KEY }}
```

Each positional file produces its own `<file>.minisig`. The existing `-t`
trusted-comment option remains supported. Signing takes keys and any required
password from the environment, never a tty or stdin. Upload the artifacts
and their signatures, not the private key.

### Opt in to password-encrypted keys

Supply a strong, nonempty `MINISIGN_PASSWORD` in the local environment, then
run `ghr minisign generate --encrypt` (with `--repo OWNER/REPO` if needed).
This mode also uploads `MINISIGN_PASSWORD` for unattended signing. Existing
password-encrypted minisign keys remain supported. Only encrypted keys need
both variables in the signing step:

```yaml
- run: ghr minisign sign artifact.tar.gz
  env:
    MINISIGN_SECRET_KEY: ${{ secrets.MINISIGN_SECRET_KEY }}
    MINISIGN_PASSWORD: ${{ secrets.MINISIGN_PASSWORD }}
```
