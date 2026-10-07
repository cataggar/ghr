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

ghr is also available through winget, uv, pipx, and pip. You can download it
directly from a [GitHub release](https://github.com/cataggar/ghr/releases).

winget:

```sh
winget install ghr
```

uv:

```sh
uv tool install ghr-bin
```

pipx:

```sh
pipx install ghr-bin
```

pip:

```sh
python3 -m pip install ghr-bin
```

## Filtering installed binaries

`--bin <name>` is repeatable. When present, only the selected executable
candidates are linked into ghr's bin directory and recorded. The
release archive is still fully extracted; download verification and extraction
are unchanged.

## Uninstall

uv:

```sh
uv tool uninstall ghr-bin
```

pipx:

```sh
pipx uninstall ghr-bin
```

pip:

```sh
python -m pip uninstall ghr-bin -y
```

winget:

```sh
winget uninstall ghr
```
