# ghr documentation

Detailed guides and command reference for ghr. For a project overview, see the
[top-level README](../README.md).

New to ghr? Follow [Getting started](getting-started.md) to install ghr and
your first tool.

## Topics

- [Usage](usage.md) — command syntax and examples.
- [Install](install.md) — install ghr and uninstall it.
- [Examples](examples.md) — install and manage tools from the command line.
- [Download](download.md) — fetch, extract, authenticate, and verify release assets.
- [Caching in GitHub Actions](github-actions.md) — cache ghr installs and downloads in workflows.
- [Directories](directories.md) — default directories and `ghr path add` behavior.
- [WSL linking](wsl-linking.md) — expose Windows-side tools inside WSL.
- [Troubleshooting](troubleshooting.md) — Linux name-resolution fallback for long `resolv.conf` files.
- [Verification](verification.md) — verifier behavior, trust roots, skip flags, and recorded results.
- [Reproducible builds](reproducible-builds.md) — release archive reproducibility and Authenticode stripping.

## Design and implementation

- [Install identifiers](install-identifiers.md) — stable install IDs,
  explicit command aliases, versioned state, and lazy migration, implemented
  since v0.8.0.

## Install

Install ghr with the shell or PowerShell bootstrap, or a package manager;
see [Install](install.md).

## Usage

See [Usage](usage.md) for the command overview, install source syntax,
and examples.

## Download

Download one or more GitHub release assets, optionally extracting archives; see
[Download](download.md).

## Caching in GitHub Actions

Cache installed tools or downloaded assets in workflows; see
[Caching in GitHub Actions](github-actions.md),
[`actions/setup`](../actions/setup/README.md),
[`actions/install`](../actions/install/README.md), and
[`actions/download`](../actions/download/README.md).

## Directories

ghr follows uv-style directory conventions and supports environment overrides;
see [Directories](directories.md).

## WSL: linking Windows-side bins (`ghr link` / `ghr unlink`)

Expose Windows-side installs and selected Windows `PATH` executables inside WSL;
see [WSL linking](wsl-linking.md).

## Name resolution on Linux

ghr includes a fallback DNS path for oversized WSL-generated `resolv.conf`
files; see [Name resolution on Linux](troubleshooting.md).

## Uninstall

Uninstall ghr from the package manager that installed it; see
[Uninstall](install.md#uninstall).

## Verification

Review automatic verification, skip/failure behavior, trust roots, and recorded
install results in [Verification](verification.md).

## Reproducible builds

Linux and macOS release archives are byte-reproducible, and Windows builds are
checked after stripping Authenticode signatures; see
[Reproducible builds](reproducible-builds.md).
