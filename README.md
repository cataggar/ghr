# ghr

An installer for GitHub releases.

## Usage

```
ghr install <owner/repo[@tag]>   Install a tool from a GitHub release
ghr uninstall <name>             Remove an installed tool
ghr list                         List installed tools
ghr upgrade [name]               Upgrade installed tools
ghr ensurepath [--dry-run]       Add ghr's bin dir to your user PATH
ghr upload <TAG> [PATH] [opts]   Create a GitHub Release and upload artifacts
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

- **Windows**: updates `HKCU\Environment\Path` (user PATH) and broadcasts `WM_SETTINGCHANGE` so new terminals pick up the change. If `%APPDATA%\nushell\` exists, also updates `%APPDATA%\nushell\env.nu`.
- **macOS / Linux**: appends a guarded block to your shell rc files (bash: `.bash_profile` / `.bashrc` / `.profile`; zsh: `.zprofile`; nushell: `~/.config/nushell/env.nu`). The block is idempotent and is replaced in place on re-runs.

`ghr ensurepath --dry-run` prints the changes it would make without writing.

## Uploading release artifacts (experimental)

`ghr upload` creates a GitHub Release and uploads artifacts to it, mirroring the interface of [`tcnksm/ghr`](https://github.com/tcnksm/ghr) (the Go tool available via `brew install ghr`). This gives existing users a migration path: change `ghr ...` to `ghr upload ...` — the flags are the same.

```sh
# Create v1.0.0 and upload every file in ./dist
ghr upload v1.0.0 dist/

# Override owner/repo, draft release, replace existing assets
ghr upload -u myorg -r myrepo -draft -replace v1.0.0 dist/
```

Flags: `-t TOKEN -u USER -r REPO -c COMMITTISH -n TITLE -b BODY -p NUM -delete -replace -draft -soft -prerelease -generatenotes`. Auth is resolved in order: `-t`, `$GITHUB_TOKEN`, `$GH_TOKEN`, `gh auth token`. Set `$GITHUB_API` for GitHub Enterprise.

See [issue #46](https://github.com/cataggar/ghr/issues/46) for context on the name collision with `tcnksm/ghr`.

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
