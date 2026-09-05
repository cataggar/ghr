# Install

It can be installed with pipx, uv, pip, winget, Homebrew, or
downloaded straight from a GitHub release.

```sh
# pipx
pipx install ghr-bin

# uv
uv tool install ghr-bin

# pip
python3 -m pip install ghr-bin

# winget
winget install ghr

# Homebrew (tap)
brew install cataggar/ghr/ghr
```

The Homebrew formula lives at [cataggar/homebrew-ghr](https://github.com/cataggar/homebrew-ghr).
It is installed through a custom tap (`cataggar/ghr/ghr`) because the short
name `ghr` collides with another formula in the default Homebrew tap — see
[issue #46](https://github.com/cataggar/ghr/issues/46) for context.

`pipx` is preinstalled on GitHub-hosted runner images, but a job-level
`container:` replaces that user space and does not inherit hosted-image tools.
Official Ubuntu, Debian slim, and Python containers do not promise `pipx`.
Use the first-party [`actions/setup`](../actions/setup/README.md),
[`actions/install`](../actions/install/README.md), or
[`actions/download`](../actions/download/README.md) action for a verified
static bootstrap that does not require Python or a package manager. A manual
`pipx install` remains useful in development environments where Python tooling
is already present.

For HTTPS on a minimal system without a conventional CA bundle, set
`SSL_CERT_FILE` to the absolute path of a nonempty PEM root bundle. The
first-party setup action supplies this automatically from the maintained Node
24 runtime when a bare Linux image has no system trust store.

## Examples

```sh
# Install latest release
ghr install burntsushi/ripgrep

# Install a specific tag
ghr install burntsushi/ripgrep@15.1.0

# Install several tools in one invocation (shared HTTP client + auth)
ghr install burntsushi/ripgrep@15.1.0 sharkdp/fd@v10.2.0

# Install a specific asset by name (exact match or unique substring)
ghr install WebAssembly/wasi-sdk/wasi-sdk-25.0-x86_64-linux.tar.gz@wasi-sdk-25

# Keep two releases from the same repository under independent IDs
ghr install BurntSushi/ripgrep@14.1.0 "?id=rg-14-1-0&alias=rg:rg-14-1-0"
ghr install BurntSushi/ripgrep@14.1.1 "?id=rg-14-1-1&alias=rg:rg-14-1-1"

# A direct URL has no repository identity, so its ID is explicit
ghr install https://example.com/tool.tar.xz "?id=example/tool"

# Install only a selected binary from a release
ghr install azuread/microsoft-authentication-cli@0.9.6 --bin azureauth

# Report stable identities or complete machine-readable definitions
ghr list --ids
ghr list --json

# Remove exactly one ID
ghr uninstall rg-14-1-0

# Show where tools are stored
ghr path tools

# Show where binaries are symlinked
ghr path bin
```

## Stable IDs and replacement

Install IDs are ownership keys, separate from release sources and published
command names. GitHub sources default to lowercase `owner/repo`; an optional
quoted query token overrides the ID and configures aliases:

```text
"?id=<id>&alias=<source-command>:<published-command>&minisign=<public-key>"
```

`alias=` is repeatable. Query names and values use percent encoding, and `+`
remains a literal plus so base64 minisign keys round-trip unchanged. An ID does
not rename a command implicitly.

Installing an existing ID is the upgrade operation: ghr stages the replacement
and publishes its complete command set transactionally, or restores the prior
unit. `ghr uninstall <id>` removes exactly that ID; ID prefixes are not
recursive.

Legacy owner/repo installs remain readable in place. Reinstalling the same
derived ID migrates one unambiguous legacy unit only after the replacement is
durable. Use an ID-capable ghr for later mutations; older releases do not
understand v2 install state.

For `.zip`, `.tar.gz`, `.tgz`, `.tar.xz`, `.txz`, `.tar.zst`, `.tzst`, and
`.deb` assets, `ghr install` exposes executable candidates from the shallowest
directory level containing any executables. It searches deeper only when no
shallower candidates exist, so nested-only package layouts still work without
putting executable-looking firmware or data files on `PATH`.

## Filtering installed binaries

`--bin <name>` is repeatable. When present, only the selected executable
candidates are linked into ghr's bin directory and recorded in `ghr.json`. The
release archive is still fully extracted; download verification and extraction
are unchanged.

A filtered reinstall reconciles existing links, removing ghr-owned binaries
excluded by the new selection. If a name does not match, ghr reports an error
with the available binary names and leaves the existing installation unchanged.
Filters currently require exactly one install spec; combining them with
multiple specs is rejected.

This install-time filtering is separate from WSL-specific `ghr link --bin`,
which filters links for a tool already installed on Windows. See
[WSL linking](wsl-linking.md).

## Uninstall ghr itself

```sh
# pipx
pipx uninstall ghr-bin

# uv
uv tool uninstall ghr-bin

# pip
python -m pip uninstall ghr-bin -y

# winget
winget uninstall ghr

# Homebrew
brew uninstall ghr
```
