# ghr

An installer for GitHub releases.

## Usage

```
ghr install <owner/repo[@tag]>   Install a tool from a GitHub release
ghr uninstall <name>             Remove an installed tool
ghr download <url> [options]     Download a file (cross-platform wget/curl)
ghr list                         List installed tools
ghr upgrade [name]               Upgrade installed tools
ghr ensurepath [--dry-run]       Add ghr's bin dir to your user PATH
ghr dir [--bin] [--cache]        Show ghr directories
```

## Download

`ghr download` is a cross-platform replacement for the common
`wget -O ... && tar -xf ...` pattern in CI. Same syntax on Ubuntu, macOS,
and Windows; no `choco install wget` step needed.

```
ghr download <url> [options]

OPTIONS:
    -o, --output <path>        Output file path (default: URL basename in cwd)
        --extract <dir>        Extract archive into <dir> after download
        --strip-components <N> Strip N leading path components when extracting
        --sha256 <hex>         Verify download against SHA-256 digest (64 hex)
        --keep-archive         Keep archive on disk after extraction
        --quiet                Suppress progress output
        --no-auth              Do not send GitHub auth even for github.com URLs
        --debug                Verbose diagnostic output
```

Recognised archive formats: `.zip`, `.tar.gz`, `.tgz`, `.tar.xz`, `.txz`.
Format is detected from the URL/filename. When `--extract` is used the
archive is deleted after extraction unless `--keep-archive` (or `-o`) is
set. GitHub auth is attached automatically for `github.com`-owned hosts
(using `GH_TOKEN`, `GITHUB_TOKEN`, or `gh auth token`); pass `--no-auth`
to skip it. Exit codes: `0` success, `1` argument/IO error, `2` HTTP
error after retries, `3` SHA-256 mismatch.

### Replacing wget + tar in workflows

Before — three OS-specific steps to fetch and extract a release archive:

```yaml
# Ubuntu / macOS
- run: |
    sudo wget -O wasi-sdk.tar.gz --progress=dot:giga \
      https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-25/wasi-sdk-25.0-x86_64-linux.tar.gz
    sudo tar -xf wasi-sdk.tar.gz -C /opt
# Windows
- run: |
    choco install -y wget
    wget -O wasi-sdk.tar.gz `
      https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-25/wasi-sdk-25.0-x86_64-linux.tar.gz
    tar -xf wasi-sdk.tar.gz -C /opt
```

After — one step on every OS:

```yaml
- run: |
    ghr download \
      https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-25/wasi-sdk-25.0-x86_64-linux.tar.gz \
      --extract /opt
```

## Install

It can be installed using uv, pip, winget, or downloaded from releases.

```sh
# uv
uv tool install ghr-bin

# pip
python3 -m pip install ghr-bin

# winget
winget install ghr
```

### Examples

```sh
# Install latest release
ghr install burntsushi/ripgrep

# Install a specific tag
ghr install burntsushi/ripgrep@15.1.0

# Show where tools are stored
ghr dir

# Show where binaries are symlinked
ghr dir --bin
```

## Directories

Follows [uv tool](https://docs.astral.sh/uv/) conventions.

| Purpose | Unix | Windows |
|---------|------|---------|
| Binaries | `~/.local/bin/` | `%USERPROFILE%\.local\bin\` |
| Tool storage | `~/.local/share/ghr/tools/` | `%APPDATA%\ghr\data\tools\` |
| Cache | `~/.cache/ghr/` | `%LOCALAPPDATA%\ghr\cache\` |

Override with `GHR_BIN_DIR`, `GHR_TOOL_DIR`, `GHR_CACHE_DIR`.

The bin directory is frequently not on `PATH` by default, especially on Windows. Run `ghr ensurepath` once to fix that:

- **Windows**: updates `HKCU\Environment\Path` (user PATH) and broadcasts `WM_SETTINGCHANGE` so new terminals pick up the change. If `%APPDATA%\nushell\` exists, also updates `%APPDATA%\nushell\env.nu`.
- **macOS / Linux**: appends a guarded block to your shell rc files (bash: `.bash_profile` / `.bashrc` / `.profile`; zsh: `.zprofile`; nushell: `~/.config/nushell/env.nu`). The block is idempotent and is replaced in place on re-runs.

`ghr ensurepath --dry-run` prints the changes it would make without writing.

## Uninstall

```sh
# uv
uv tool uninstall ghr-bin

# pip
python -m pip uninstall ghr-bin -y

# winget
winget uninstall ghr
```

## License

MIT
