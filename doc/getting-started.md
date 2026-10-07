# Getting started

ghr installs tools from GitHub releases. It selects the asset for your operating
system and architecture, verifies the download, and exposes the installed
commands from one shared bin directory.

## Install ghr

Choose the command for your environment:

Linux and macOS:

```sh
curl -fsSL https://raw.githubusercontent.com/cataggar/ghr/main/install.sh | sh
```

Windows (PowerShell):

```powershell
iwr -useb https://raw.githubusercontent.com/cataggar/ghr/main/install.ps1 | iex
```

Open a new terminal after installation, then check that ghr is available:

```sh
ghr version
```

See [Installation](install.md) for package managers, direct release downloads,
and uninstall instructions.

## Install your first tool

Install bottom, a terminal system monitor:

```sh
ghr install clementtsang/bottom
```

Without a tag, ghr installs the latest release:
[https://github.com/ClementTsang/bottom/releases/latest](https://github.com/ClementTsang/bottom/releases/latest).

Check the version, then launch it:

```sh
btm --version
btm
```
