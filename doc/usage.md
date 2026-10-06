# Usage

```text
ghr list [--ids|--tags|--install|--full|--json]   List installed tools
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

List installed tools with tags and configuration:

```sh
ghr list
# burntsushi/ripgrep@14.1.1 ?id=rg-14-1-0&alias=rg:rg-14-1-0
```

`--tags` explicitly selects the same output. Use `ghr list --ids` for bare
canonical IDs, `ghr list --install` for shell-ready install commands,
`ghr list --full` for the detailed human report, or `ghr list --json` for
machine-readable definitions. These output flags are mutually exclusive.

All formats are alphabetical, ignoring ASCII case. Default/`--tags` and
`--install` sort by displayed source, with install IDs breaking ties.
`--ids`, `--full`, and `--json` sort by canonical install ID. Shell quoting does
not affect the order.

Default/`--tags` output contains raw, unquoted arguments, without a `ghr install`
prefix. It includes the installed GitHub tag, stored asset selectors, aliases,
minisign keys, and
non-default verification options, but omits redundant IDs, default options, and
binary filters (`--bin`). Use `--json` to inspect the original binary selection.
Query tokens do not need quotes in the install action's `tools: |` input.
Raw tagged output is not shell-escaped; use `--install` for shell commands.

Show shell-ready commands with quoting and any stored binary filters:

```sh
ghr list --install
# ghr install burntsushi/ripgrep@14.1.1 "?id=rg-14-1-0&alias=rg:rg-14-1-0"
```

Each `--install` line starts with `ghr install`, uses POSIX-shell quoting, and
includes `--bin` for stored binary selections. Legacy or incomplete definitions
use available recorded information best-effort, without warnings. Direct URLs
are preserved rather than given an invented tag; release tags and URLs do not
guarantee immutable content.

Remove only that ID:

```sh
ghr uninstall rg-14-1-0
```

Install Minisign itself, verifying with its Minisign public key:

```sh
ghr install jedisct1/minisign@0.12 RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3
```
