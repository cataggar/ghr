# ghr

An installer for GitHub releases.

## Usage

```
ghr install <owner/repo[@tag]>   Install a tool from a GitHub release
ghr uninstall <name>             Remove an installed tool
ghr list                         List installed tools
ghr upgrade [name]               Upgrade installed tools
ghr dir [--bin] [--cache]        Show ghr directories
```

## Install

It can be installed using uv, using pip, or manually from releases.

```sh
# uv
uv tool install ghr-bin

# pip
python3 -m pip install ghr-bin
```

### Examples

```sh
# Install latest release
ghr install ctaggart/zig

# Install a specific tag
ghr install ctaggart/zig@v0.16.0

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

## Uninstall

```sh
# uv
uv tool uninstall ghr-bin

# pip
python -m pip uninstall ghr-bin -y
```

## License

MIT
