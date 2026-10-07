# Examples

Install the latest release:

```sh
ghr install burntsushi/ripgrep
```

Install ghr itself (a published Minisign signature is noted, not verified
without a key):

```sh
ghr install cataggar/ghr
```

Install a specific tag:

```sh
ghr install burntsushi/ripgrep@15.1.0
```

Install several tools in one invocation (shared HTTP client and authentication):

```sh
ghr install burntsushi/ripgrep@15.1.0 sharkdp/fd@v10.2.0
```

Install a specific asset by name (exact match or unique substring):

```sh
ghr install webassembly/wasi-sdk/wasi-sdk-25.0-x86_64-linux.tar.gz@wasi-sdk-25
```

Keep two releases from the same repository under independent IDs:

```sh
ghr install burntsushi/ripgrep@14.1.0 "?id=rg-14-1-0&alias=rg:rg-14-1-0"
```

```sh
ghr install burntsushi/ripgrep@14.1.1 "?id=rg-14-1-1&alias=rg:rg-14-1-1"
```

A direct URL has no repository identity, so its ID is explicit:

```sh
ghr install https://example.com/tool.tar.xz "?id=example/tool"
```

Install only a selected binary from a release:

```sh
ghr install azuread/microsoft-authentication-cli@0.9.6 --bin azureauth
```

Report stable identities:

```sh
ghr list --ids
```

Report installed units with their status, source, tag, and commands:

```sh
ghr list --full
```

Report compact, tagged install arguments:

```sh
ghr list --tags
```

Each line contains raw arguments only, without quotes or a `ghr install` prefix.
GitHub sources use the installed tag, together with any stored selector, custom
ID, aliases, minisign key, and non-default verification options. IDs implied by
the source, default options, and binary
filters (`--bin`) are omitted. `--json` retains the stored binary selection.
Legacy or incomplete definitions are best-effort without warnings; direct URLs
remain unchanged. Raw tagged output is not shell-escaped, and tags/URLs do not
guarantee immutable content.

Report shell-ready install commands:

```sh
ghr list --install
```

This is also the default `ghr list` output. Each line starts with `ghr install`,
quotes arguments for POSIX shells, and includes stored `--bin` filters when
configured. Source, query configuration, and verification options are the same
as tagged output.

Report complete machine-readable definitions:

```sh
ghr list --json
```

`--install` explicitly selects the default shell-ready output. The `--ids`,
`--tags`, `--install`, `--full`, and `--json` flags are mutually exclusive.

All formats are alphabetical, ignoring ASCII case. Default/`--install` and
`--tags` sort by displayed source before shell quoting, with install IDs
breaking ties. `--ids`, `--full`, and `--json` sort by canonical install ID.

Remove exactly one ID:

```sh
ghr uninstall rg-14-1-0
```

Show where tools are stored:

```sh
ghr path tools
```

Show where binaries are symlinked:

```sh
ghr path bin
```
