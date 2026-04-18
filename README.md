# ghr

An installer for GitHub releases.

## Usage

```
ghr install <owner/repo[@tag]>   Install a tool from a GitHub release
ghr uninstall <name>             Remove an installed tool
ghr list                         List installed tools
ghr upgrade [name]               Upgrade installed tools
ghr ensurepath [--dry-run]       Add ghr's bin dir to your user PATH
ghr dir [--bin] [--cache]        Show ghr directories
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

- **Windows**: updates `HKCU\Environment\Path` (user PATH) and broadcasts `WM_SETTINGCHANGE` so new terminals pick up the change.
- **macOS / Linux**: appends a guarded block to your shell rc files (bash: `.bash_profile` / `.bashrc` / `.profile`; zsh: `.zprofile`; fish: `~/.config/fish/conf.d/ghr.fish`). The block is idempotent and is replaced in place on re-runs.

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
