# `ghr` setup action

This first-party JavaScript action installs one exact static `ghr` release. It
uses the runner-provided Node 24 action runtime and needs no Python, `pipx`,
`curl`, `gh`, package manager, or host archive utility.

## Recommended usage

Pin the action implementation to a reviewed commit and pin the CLI separately:

```yaml
permissions:
  contents: read
  attestations: read

steps:
  - id: ghr
    uses: cataggar/ghr/actions/setup@<reviewed-commit-sha>
    with:
      ghr-version: v0.8.0
  - run: '"${{ steps.ghr.outputs.ghr-path }}" version'
```

The action commit controls installer code. `ghr-version` independently selects
the exact immutable release. A commit, branch, major tag, range, or `latest`
action ref cannot safely imply a CLI version, so omitting `ghr-version` in
those cases fails rather than selecting the latest release.

When using an exact action tag, the CLI version may be coupled to it:

```yaml
- uses: cataggar/ghr/actions/setup@v0.8.0
```

Only an exact `vMAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]` action ref is accepted
for this derivation. An explicit `ghr-version` always wins.

## Inputs

| Input | Default | Contract |
| --- | --- | --- |
| `ghr-version` | derived only from an exact semver action ref | Exact release tag or version, such as `v0.8.0`; no ranges or latest fallback. |
| `sha256` | empty | Independently trusted 64-hex SHA-256 for the selected archive. It must also match GitHub's release-asset digest. |
| `token` | `github.token` on `github.com`, otherwise empty | Used only for GitHub release and attestation API requests. It is never sent to release storage or Sigstore TUF. |
| `cache` | `true` | Restore/save only the exact verified CLI archive and install tree. Must be exactly `true` or `false`. |

## Outputs

| Output | Value |
| --- | --- |
| `ghr-path` | Absolute path to the verified executable. |
| `ghr-version` | Canonical exact release tag, for example `v0.8.0`. |
| `target` | Normalized release target, such as `linux-musl-x64`. |
| `cache-hit` | String `true` only for an exact, successfully reverified cache restore; otherwise `false`. |

Only the installation's `bin/` directory is added to `PATH`.

## Verification and trust

The action resolves the release by exact tag and selects exactly one archive
for the normalized runner OS and architecture. Linux always uses the portable
static musl release. The asset must be uploaded, nonempty, bounded in size, and
expose a lowercase `sha256:<digest>` through the GitHub release API.
Downloaded bytes always have to match that digest.

One additional trust path is mandatory:

1. **GitHub provenance (default):** the action obtains the Sigstore trusted
   root through TUF and cryptographically verifies a GitHub artifact
   attestation, transparency evidence, GitHub OIDC issuer, repository and
   `release.yml` workflow identity, exact tag ref, peeled tag commit, SLSA
   workflow build type, and matching filename/digest subject.
2. **Trusted SHA:** setting `sha256` supplies an out-of-band trust root. The
   value must match both GitHub's asset digest and the downloaded bytes.

Release titles, filenames, cache entries, redirects, and mere attestation API
presence are never trust roots. Provenance/TUF failure is fatal unless the
caller supplied a matching trusted SHA.

The token is not read from `GH_TOKEN`, Git credential helpers, proxy variables,
or other ambient credential configuration. Authorization is stripped before a
release-storage redirect. Public releases can be verified anonymously with
lower API rate limits.

## Extraction, installation, and cache

Gzip/tar and ZIP are decoded in the Node process. Extraction rejects absolute
and parent paths, links, devices, duplicate or unexpected entries, malformed
headers, truncated streams, oversized content, and noncanonical layout or
modes. A staging directory is atomically published below:

```text
$RUNNER_TEMP/ghr-setup/<version>/<target>/<archive-sha256>/
```

The cache key contains its schema, normalized target, exact tag, and archive
digest. There are no restore prefixes. On a hit, the archive is rehashed,
reparsed by the bounded extractor, and compared byte-for-byte with the complete
restored install tree. Corruption fails closed; it never triggers an unverified
fallback. The post-action repeats verification before uploading the raw
archive through the Actions cache v2 service.

After installation, `ghr version` and `ghr version --target` must exactly match
the requested release and selected target before success outputs are written.

## Compatibility

- Supported: GitHub-hosted Linux, macOS, and Windows x64/arm64 runners, plus
  compatible job containers and self-hosted runners able to execute Node 24
  actions.
- The first-party `download` and `install` actions compose this action through
  GitHub's `$/` exact-commit self-reference syntax, which requires Actions
  runner 2.336.0 or newer.
- Unsupported: GHES mirrors, arbitrary release mirrors, 32-bit architectures,
  and runners without the maintained Node 24 action runtime.

Unsupported targets, malformed releases, unavailable required evidence, cache
tampering, or version/target mismatches fail before success outputs are emitted.
