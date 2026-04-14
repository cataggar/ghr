# ghr

Install tools from GitHub releases.

## Usage

```
ghr install <owner/repo[@tag]>   Install a tool from a GitHub release
ghr uninstall <name>             Remove an installed tool
ghr list                         List installed tools
ghr upgrade [name]               Upgrade installed tools
ghr dir [--bin] [--cache]        Show ghr directories
```

### Examples

```sh
# Install latest release
ghr install ctaggart/zig

# Install a specific tag (URL-encoded '+' handled transparently)
ghr install ctaggart/zig@v0.16.0-dev.3153+d6f43caad

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

## Install

```sh
# Recommended
uv tool install ghr-bin

# pip (requires pip >= 24.3)
pip install ghr-bin
```

## Build

Requires [Zig](https://ziglang.org/) 0.15+.

```sh
zig build
zig build run -- --help
zig build test
```

## License

MIT
