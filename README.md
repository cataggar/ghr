<img src="https://github.com/cataggar/ghr/releases/download/v0.6.2/ghr-logo.jpg" alt="ghr logo">

<sub>Logo by [Talia Blasquez](https://www.instagram.com/my_artistic_sidetrip/). Licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).</sub>

# ghr

A toolkit for GitHub releases.

Install tools from GitHub releases with one cross-platform command. A single
static binary that picks the right asset for your OS and architecture.
Supports verifying with [minisign](https://jedisct1.github.io/minisign/),
[sigstore](https://sigstore.dev/),
[GitHub artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/verify-attestations-offline),
and checksums. Use it locally or in GitHub Actions.

## Quick start

Linux and macOS:

```sh
curl -fsSL https://raw.githubusercontent.com/cataggar/ghr/main/install.sh | sh
```

Windows (PowerShell):

```powershell
iwr -useb https://raw.githubusercontent.com/cataggar/ghr/main/install.ps1 | iex
```

Open a new terminal after installation.

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

See [Quick start](https://cataggar.github.io/ghr/docs/getting-started.html)
for a step-by-step guide, and
[Installation](https://cataggar.github.io/ghr/docs/install.html)
for package managers and uninstall instructions.

## Documentation

See [Usage](https://cataggar.github.io/ghr/docs/usage.html) for command syntax
and examples, or browse the
[documentation](https://cataggar.github.io/ghr/docs.html)
for download, directories, and verification details.
The [Markdown sources](doc/README.md) remain in this repository.

Contributor instructions are in [Build from source](doc/build-from-source.md),
a repository-only guide that is not published on the website.

## License

MIT
