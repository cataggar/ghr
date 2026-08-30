<img src="https://github.com/cataggar/ghr/releases/download/v0.6.2/ghr-logo.jpg" alt="ghr logo">

<sub>Logo by [Talia Blasquez](https://www.instagram.com/my_artistic_sidetrip/). Licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).</sub>

# ghr

A toolkit for GitHub releases.

Install tools from GitHub releases with one cross-platform command. A single
static binary that picks the right asset for your OS and architecture.
Supports verifying with [minisign](https://jedisct1.github.io/minisign/),
[sigstore](https://sigstore.dev/),
[GitHub artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/verify-attestations-offline),
and checksums. Install it on a GitHub-hosted runner with
`pipx install ghr-bin`.

## Usage

```
ghr list [--ids|--json]                            Report installed units
ghr install <source> ["?<query>"] [<pubkey>] ...   Install or replace tools by stable ID
ghr uninstall <id>                                 Remove exactly one installed ID
ghr download <spec> [<pubkey>] [<spec> ...]        Download one or more release assets
ghr link <id>|[--path] <name>                      Link Windows commands into WSL
ghr unlink <id>|[--path] <name>                    Remove ghr-created WSL links
ghr path add [--dry-run]                           Add ghr's bin dir to your user PATH
ghr path [bin|tools|cache]                         Show ghr directories
ghr minisign sign <file> [<file> ...]              Sign release artifacts with a minisign key
ghr version [--target]                             Print version or build target and exit
ghr -h | --help                                    Print this help and exit
```

Each install `<source>` is `owner/repo[@tag]`,
`owner/repo/file[@tag]`, a GitHub release-download URL, or a direct URL. GitHub
sources derive the stable lowercase ID `owner/repo`; direct URLs require
`?id=<id>`. A quoted query token can set `id`, repeat
`alias=<source>:<published>`, and set `minisign`. A 56-character
`RW`/`RU`-prefixed key immediately after a source remains supported.
Reinstalling an existing ID replaces it transactionally.

Run `ghr <COMMAND> --help` for complete syntax and examples.

> [!IMPORTANT]
> **Breaking change in v0.8.0:** the `help` command and positional help
> aliases were removed. Replace `ghr help` with `ghr --help`, and replace
> `ghr <COMMAND> help` with `ghr <COMMAND> --help` or `ghr <COMMAND> -h`.

### Examples

```sh
# Install the latest release of a tool
ghr install burntsushi/ripgrep

# Install a specific version
# https://github.com/bytecodealliance/wasmtime/releases/tag/v44.0.1
ghr install bytecodealliance/wasmtime@v44.0.1

# Install several tools in one invocation (shared HTTP client + auth)
ghr install burntsushi/ripgrep@15.1.0 sharkdp/fd@v10.2.0

# Keep two releases from one repository under independent IDs and commands
ghr install BurntSushi/ripgrep@14.1.0 "?id=rg-14-1-0&alias=rg:rg-14-1-0"
ghr install BurntSushi/ripgrep@14.1.1 "?id=rg-14-1-1&alias=rg:rg-14-1-1"

# Replace one ID, list exact identities, then remove only that ID
ghr install BurntSushi/ripgrep@14.1.1 "?id=rg-14-1-0&alias=rg:rg-14-1-0"
ghr list --ids
ghr uninstall rg-14-1-0

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
iwr -useb https://raw.githubusercontent.com/cataggar/ghr/main/install.ps1 | iex
ghr install cataggar/ghr RWSbsumpaHb+N3KCEt/EUXQ5y6Kkk8r/zCb5Z4jhEuEX8x2/U5wr5QC0
```

See the
[documentation](https://github.com/cataggar/ghr/blob/main/doc/README.md)
for download, install, directories, uninstall, and verification details
(including
[verifying ghr's own releases](https://github.com/cataggar/ghr/blob/main/doc/verification.md)).

## GitHub Actions

For workflows, install several tools in one cached step:

```yaml
- uses: cataggar/ghr/actions/install@v0.8.0  # pin to the matching ghr release
  with:
    tools: |
      burntsushi/ripgrep@14.1.0 ?id=rg-14-1-0&alias=rg:rg-14-1-0
      burntsushi/ripgrep@14.1.1 ?id=rg-14-1-1&alias=rg:rg-14-1-1
      sharkdp/fd@v10.2.0
```

The action shares git tags with the `ghr` CLI — pinning `@v0.8.0` pins
both the action body and the `ghr-bin` binary. Pick the latest tag from
[the releases page](https://github.com/cataggar/ghr/releases).

See
[`actions/install`](https://github.com/cataggar/ghr/blob/main/actions/install/README.md),
[`actions/download`](https://github.com/cataggar/ghr/blob/main/actions/download/README.md),
and
[Caching in GitHub Actions](https://github.com/cataggar/ghr/blob/main/doc/github-actions.md)
for details.

## Signing releases

`ghr minisign sign` produces a minisign `.minisig` sidecar without an
external `minisign` binary, a key file on disk, or an `expect` script. The
secret key and password come from the environment, so a release job is a
single step:

```yaml
- run: ghr minisign sign hello.wasm -t "tag:${{ github.ref_name }} commit:${GITHUB_SHA}"
  env:
    MINISIGN_SECRET_KEY: ${{ secrets.MINISIGN_SECRET_KEY }}
    MINISIGN_PASSWORD:   ${{ secrets.MINISIGN_PASSWORD }}
```

Input files are bare positional arguments (each `<file>` is signed to
`<file>.minisig`). A trusted comment may be given with `-t` (applied to
every input); when omitted it defaults, like minisign, to
`timestamp:<unix>\tfile:<name>\thashed` per file. The secret key **must**
come from `MINISIGN_SECRET_KEY` and an encrypted key's password from
`MINISIGN_PASSWORD` — there is no key-file flag, and the password is never
read from a tty or stdin. Signatures use the prehashed (`ED`) format and
are byte-for-byte identical to `minisign -S` output. Run
`ghr minisign sign --help` for all options.

## License

MIT
