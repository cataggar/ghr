# ghr

A toolkit for GitHub releases.

Install tools from GitHub releases with one cross-platform command. A single
static binary that picks the right asset for your OS and architecture,
verifies it with any published sigstore bundle or SHA256 checksum, and drops
the executable onto your `PATH`. Install it on a GitHub-hosted runner with
`pipx install ghr-bin`.

## Usage

```
ghr list                                 List installed tools
ghr install <owner/repo[@tag]>           Install a tool from a GitHub release
ghr install <owner/repo/file[@tag]>      Install a specific asset by name
ghr upgrade [name]                       Upgrade installed tools
ghr uninstall <name>                     Remove an installed tool
ghr download <owner/repo[@tag]>          Download the asset 'install' would pick
ghr download <owner/repo/file[@tag]>     Download a specific asset by name
ghr path ensure [--dry-run]              Add ghr's bin dir to your user PATH
ghr path [bin|tools|cache]               Show ghr directories
ghr version                              Print version and exit
ghr help                                 Print this help and exit
```

### Examples

```sh
# Install the latest release of a tool
ghr install burntsushi/ripgrep

# Install a specific version
# https://github.com/bytecodealliance/wasmtime/releases/tag/v44.0.1
ghr install bytecodealliance/wasmtime@v44.0.1
```

## Install

```sh
pipx install ghr-bin
uv tool install ghr-bin
winget install ghr
```

See [doc/README.md](doc/README.md) for download, install, directories,
uninstall, and verification details.

## License

MIT
