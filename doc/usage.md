# Usage

```text
ghr list [--ids|--json]                           Report installed units
ghr install <source> ["?<query>"] [<pubkey>] ...  Install or replace tools by stable ID
ghr uninstall <id>                              Remove exactly one installed ID
ghr download <spec> [<pubkey>] [<spec> ...]       Download one or more release assets
ghr link <id>|[--path] <name>                     Link Windows commands into WSL
ghr unlink <id>|[--path] <name>                   Remove ghr-created WSL links
ghr path add [--dry-run]                         Add ghr's bin dir to your user PATH
ghr path [bin|tools|cache]                       Show ghr directories
ghr minisign generate [--repo owner/repo]        Create a signing key and configure repository secrets
ghr minisign sign <file> [<file> ...]             Sign release artifacts with a minisign key
ghr version [--target]                          Print version or build target and exit
ghr -h | --help                                 Print this help and exit
```

Each install `<source>` is `owner/repo[@tag]`,
`owner/repo/file[@tag]`, a GitHub release-download URL, or a direct URL. GitHub
sources derive the stable lowercase ID `owner/repo`; direct URLs require
`?id=<id>`. A quoted query token can set `id`, repeat
`alias=<source>:<published>`, and set `minisign`. A 56-character
`RW`/`RU`-prefixed key immediately after a source remains supported.
Reinstalling an existing ID replaces it transactionally.

Run `ghr <command> --help` for complete syntax and examples.

> [!IMPORTANT]
> **Breaking change in v0.8.0:** the `help` command and positional help
> aliases were removed. Replace `ghr help` with `ghr --help`, and replace
> `ghr <command> help` with `ghr <command> --help` or `ghr <command> -h`.

## Examples

Install the latest release of a tool:

```sh
ghr install burntsushi/ripgrep
```

Install a specific version:

```sh
ghr install bytecodealliance/wasmtime@v44.0.1
```

Install several tools in one invocation (shared HTTP client and authentication):

```sh
ghr install burntsushi/ripgrep@15.1.0 sharkdp/fd@v10.2.0
```

Keep two releases from one repository under independent IDs and commands:

```sh
ghr install burntsushi/ripgrep@14.1.0 "?id=rg-14-1-0&alias=rg:rg-14-1-0"
```

```sh
ghr install burntsushi/ripgrep@14.1.1 "?id=rg-14-1-1&alias=rg:rg-14-1-1"
```

Replace one ID:

```sh
ghr install burntsushi/ripgrep@14.1.1 "?id=rg-14-1-0&alias=rg:rg-14-1-0"
```

List exact identities:

```sh
ghr list --ids
```

Remove only that ID:

```sh
ghr uninstall rg-14-1-0
```

Install Minisign itself, verifying with its Minisign public key:

```sh
ghr install jedisct1/minisign@0.12 RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3
```
