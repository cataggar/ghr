# Getting started

ghr installs tools from GitHub releases. It selects the asset for your operating
system and architecture, verifies the download, and exposes the installed
commands from one shared bin directory.

## Install ghr

Choose the command for your environment:

```sh
# macOS with Homebrew
brew install cataggar/ghr/ghr

# Windows with winget
winget install ghr

# Linux, macOS, or Windows with uv
uv tool install ghr-bin
```

Check that ghr is available:

```sh
ghr --version
```

See [Installation](install.md) for other package managers, direct release
downloads, and uninstall instructions. In CI, use the first-party
[GitHub Actions](github-actions.md) instead of installing a package manager.

## Install your first tool

Install ripgrep from its latest GitHub release:

```sh
ghr install BurntSushi/ripgrep
```

Add ghr's bin directory to your user `PATH`, then open a new terminal:

```sh
ghr path add
```

Run the tool and inspect your installed tools:

```sh
rg --version
ghr list
```

To choose a release, append its tag to the repository:

```sh
ghr install BurntSushi/ripgrep@15.1.0
```

Reinstalling the same repository upgrades that installation. See
[Installation](install.md#stable-ids-and-replacement) for independent install
IDs and command aliases, and [Directories](directories.md) for storage and
`PATH` details.

## Understand verification

ghr checks the GitHub asset digest and supported verification material published
with a release, including checksum files, Sigstore bundles, and GitHub artifact
attestations. Minisign verification additionally requires a trusted public key.
Verification failures stop the operation; an unavailable signature is not a
claim that an asset has been independently authenticated.

See [Verification](verification.md) for trust roots, recorded results, and how
to require Minisign verification. Keep verification enabled for normal installs.

## Next steps

- [Download assets](download.md) without installing them.
- [Use ghr in GitHub Actions](github-actions.md) with caching.
- [Link Windows tools into WSL](wsl-linking.md).
- Browse the [documentation overview](README.md) for all topics.
