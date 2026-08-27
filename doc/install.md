# Install

It can be installed with pipx (great for CI), uv, pip, winget, Homebrew, or
downloaded straight from a GitHub release.

```sh
# pipx (recommended for one-shot use in GitHub Actions and other CI)
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

`pipx install ghr-bin` works the same on Ubuntu, macOS and Windows runners in
GitHub Actions, so it is a one-line way to put `ghr` on `PATH` in a workflow
step. The other commands above are equally usable in CI; pipx is highlighted
because it isolates the install without polluting the global Python
environment.

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

# Install only a selected binary from a release
ghr install azuread/microsoft-authentication-cli@0.9.6 --bin azureauth

# Show where tools are stored
ghr path tools

# Show where binaries are symlinked
ghr path bin
```

For archive assets, `ghr install` exposes executable candidates from the
shallowest directory level containing any executables. It searches deeper only
when no shallower candidates exist, so nested-only package layouts still work
without putting executable-looking firmware or data files on `PATH`.

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

## Uninstall

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
