# ghr

A toolkit for GitHub releases.

Install tools from GitHub releases with one cross-platform command. A single
static binary that picks the right asset for your OS and architecture.
Supports verifying with [minisign](https://jedisct1.github.io/minisign/),
[sigstore](https://sigstore.dev/), and checksums. Install it on a
GitHub-hosted runner with `pipx install ghr-bin`.

## Usage

```
ghr list                                          List installed tools
ghr install <spec> [<pubkey>] [<spec> ...]        Install one or more tools from GitHub releases
ghr uninstall <name>                              Remove an installed tool
ghr download <spec> [<pubkey>] [<spec> ...]       Download one or more release assets
ghr path ensure [--dry-run]                       Add ghr's bin dir to your user PATH
ghr path [bin|tools|cache]                        Show ghr directories
ghr version                                       Print version and exit
ghr help                                          Print this help and exit
```

Each `<spec>` is `owner/repo[@tag]` (auto-pick asset) or
`owner/repo/file[@tag]` (specific asset). A 56-char `RW`/`RU`-prefixed
base64 token immediately after a spec is treated as that spec's
minisign public key. Run `ghr <COMMAND> help` to show help for a
specific command, e.g. `ghr download help`.

### Examples

```sh
# Install the latest release of a tool
ghr install burntsushi/ripgrep

# Install a specific version
# https://github.com/bytecodealliance/wasmtime/releases/tag/v44.0.1
ghr install bytecodealliance/wasmtime@v44.0.1

# Install several tools in one invocation (shared HTTP client + auth)
ghr install burntsushi/ripgrep@15.1.0 sharkdp/fd@v10.2.0

# Install minisign itself, verifying with its minisign public key
ghr install jedisct1/minisign@0.12 RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3
```

## Install

```sh
pipx install ghr-bin
uv tool install ghr-bin
winget install ghr
brew install cataggar/ghr/ghr
curl -fsSL https://raw.githubusercontent.com/cataggar/ghr/main/install.sh | sh
ghr install cataggar/ghr RWSbsumpaHb+N3KCEt/EUXQ5y6Kkk8r/zCb5Z4jhEuEX8x2/U5wr5QC0
```

See [doc/README.md](doc/README.md) for download, install, directories,
uninstall, and verification details (including
[verifying ghr's own releases](doc/README.md#verification)).

## GitHub Actions

For workflows, install several tools in one cached step:

```yaml
- uses: cataggar/ghr/actions/install@v0.3.1  # pin to the matching ghr release
  with:
    tools: |
      BurntSushi/ripgrep@14.1.1
      sharkdp/fd@v10.2.0
```

The action shares git tags with the `ghr` CLI — pinning `@v0.3.0` pins
both the action body and the `ghr-bin` binary. Pick the latest tag from
[the releases page](https://github.com/cataggar/ghr/releases).

See [`actions/install`](actions/install/README.md),
[`actions/download`](actions/download/README.md), and the
[Caching in GitHub Actions](doc/README.md#caching-in-github-actions)
section for details.

## License

MIT
