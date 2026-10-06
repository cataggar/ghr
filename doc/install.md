# Install

Install ghr with the bootstrap script for your operating system:

Linux and macOS:

```sh
curl -fsSL https://raw.githubusercontent.com/cataggar/ghr/main/install.sh | sh
```

Windows (PowerShell):

```powershell
iwr -useb https://raw.githubusercontent.com/cataggar/ghr/main/install.ps1 | iex
```

Open a new terminal after installation so the updated `PATH` is available.

## Package managers

ghr is also available through winget, pipx, uv, and pip. You can download it
directly from a [GitHub release](https://github.com/cataggar/ghr/releases).

winget:

```sh
winget install ghr
```

pipx:

```sh
pipx install ghr-bin
```

uv:

```sh
uv tool install ghr-bin
```

pip:

```sh
python3 -m pip install ghr-bin
```

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

This is also the default `ghr list` output. Each line contains arguments only,
without quotes or a `ghr install` prefix. GitHub sources use the installed tag,
together with any stored selector, custom ID, aliases, minisign key, and non-default
verification options. IDs implied by the source, default options, and binary
filters (`--bin`) are omitted. `--json` retains the stored binary selection.
Legacy or incomplete definitions are best-effort without warnings; direct URLs
remain unchanged. Raw tagged output is not shell-escaped, and tags/URLs do not
guarantee immutable content.

Report shell-ready install commands:

```sh
ghr list --install
```

Each line starts with `ghr install`, quotes arguments for POSIX shells, and
includes stored `--bin` filters when configured. Source, query configuration,
and verification options are the same as tagged output.

Report complete machine-readable definitions:

```sh
ghr list --json
```

`--tags` explicitly selects the default tagged output. The `--ids`,
`--tags`, `--install`, `--full`, and `--json` flags are mutually exclusive.

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

On Windows, publishing a staged unit briefly retries directory renames that
fail with `AccessDenied` or `FileBusy`, as an extracted file may be temporarily
held open. Persistent failures still stop the install and preserve the previous
unit; close programs using the tool and check directory permissions or
file-scanning software before retrying the command.

Legacy owner/repo installs remain readable in place. Reinstalling the same
derived ID migrates one unambiguous legacy unit only after the replacement is
durable. Use an ID-capable ghr for later mutations; older releases do not
understand v2 install state.

For `.zip`, `.tar.gz`, `.tgz`, `.tar.xz`, `.txz`, `.tar.zst`, `.tzst`, and
`.deb` assets, `ghr install` exposes executable candidates from the shallowest
directory level containing any executables. It searches deeper only when no
shallower candidates exist, so nested-only package layouts still work without
putting executable-looking firmware or data files on `PATH`.

Relative symlink aliases at that level are exposed under their own command
names when their chains resolve to executable files inside the extracted
package. For example, `bin/llvm-readelf -> llvm-readobj` publishes
`llvm-readelf` as well as `llvm-readobj`, without rewriting or copying the
package's links. Absolute links, escaping paths, broken links, cycles, and
chains longer than 40 symlinks are ignored. Symlinked directories are not
searched recursively.

These archive-provided aliases are ordinary owned commands: `--bin llvm-readelf`
can select an alias without publishing its target's command, and replacement
and uninstall manage it normally. They are distinct from the `alias=` query
option, which explicitly renames a discovered command.

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

pipx:

```sh
pipx uninstall ghr-bin
```

uv:

```sh
uv tool uninstall ghr-bin
```

pip:

```sh
python -m pip uninstall ghr-bin -y
```

winget:

```sh
winget uninstall ghr
```
