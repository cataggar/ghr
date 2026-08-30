# WSL: linking Windows-side bins (`ghr link` / `ghr unlink`)

When ghr is installed on Windows, a parallel WSL distribution can expose the
same tools without re-downloading them. `ghr link <id>` resolves the exact
Windows install from ghr's inventory and creates Linux symlinks in
`~/.local/bin` for that ID's persisted command names. The links point directly
at the Windows-side `.exe` (via `/mnt/c/...`); WSL interop runs the binary
transparently.

```sh
# Link an executable already on the Windows %PATH% (no install needed).
ghr link --path az           # → bash wrapper that runs az.cmd via cmd.exe
ghr unlink --path az
```

Notes:

- `ghr link` is a **reconciler**. Without `--bin`, it makes the WSL link set match the current Windows install — adding new bins, updating moved ones, and removing entries that disappeared from `ghr.json`. With `--bin <name>` filters, only the named entries are touched.
- The symlink target is the real `.exe` under the inventory-selected unit, not the Windows shim. A `C:\…` target would not trigger interop; the WSL path is required.
- Both commands require `WSL_INTEROP` to be set. They refuse to run outside WSL so you don't accidentally create dangling links on bare Linux or macOS.
- IDs are canonicalized to lowercase. Multiple IDs sourced from the same repository remain independent.
- Raw wasm modules are refused because direct symlinks to `.wasm` bytes are not executable through WSL interop.

## Bare executable form

A one-segment argument is ambiguous: an existing install ID or ID manifest
wins; otherwise ghr retains the historical Windows-PATH behavior. Use `--id`
or `--path` to select explicitly. PATH mode resolves the name via `where.exe`
(honouring `PATHEXT`), converts the result with `wslpath -u`, and writes an
entry in ghr's bin directory based on the resolved file's extension:

- `.exe` / `.com` → symlink. WSL interop direct-executes the PE image, no extra process hop.
- `.cmd` / `.bat` -> small bash wrapper that runs `cmd.exe /c '<windows-path>' "$@"` via WSL interop. This is how `ghr link --path az` exposes Azure CLI's `az.cmd`, for example.
- `.ps1` (and anything else) → rejected. Running PowerShell scripts safely needs a different launcher and arg-quoting model; install `pwsh` separately if you want it.

Other guardrails:

- The resolved path must live under `/mnt/<letter>/` (drvfs); UNC and `/mnt/wsl/` paths are rejected.
- `--bin` is not supported with the bare form (there is exactly one bin to link).
- `ghr unlink --path <name>` removes the symlink or wrapper created by PATH
  mode. Wrappers are only deleted when their magic comment and embedded Windows
  target match what the manifest recorded, so a user-edited wrapper is left
  alone.
- Automatic one-segment disambiguation requires canonical `%APPDATA%`
  discovery. If discovery fails, ghr requires `--path` or
  `GHR_WIN_TOOLS_DIR` instead of guessing and possibly selecting the wrong
  ownership mode.

## Recipe: Git Credential Manager from WSL

Use this when Git runs natively in WSL but credentials should be prompted for
and stored by Windows Git Credential Manager.

In Windows PowerShell:

```powershell
ghr install git-ecosystem/git-credential-manager
```

Inside WSL:

```sh
ghr link git-ecosystem/git-credential-manager
git config --global credential.helper manager
```

`ghr link` exposes the Windows `git-credential-manager.exe` as
`git-credential-manager` on the WSL `PATH`. Native WSL Git remains in use; when
Git needs credentials, it runs the linked Windows helper through WSL interop, so
the sign-in flow and credential storage happen on Windows.

Do not link the bare Windows Git executable for this setup: that would expose
Windows Git itself, not just the credential helper. Git authentication through
GCM does not require a separate `keyring` install.

For Azure Repos, also configure WSL Git to pass the organization path:

```sh
git config --global credential.https://dev.azure.com.useHttpPath true
```

To prefer Microsoft Entra OAuth tokens for Azure Repos, configure the Windows
Git/GCM settings from Windows PowerShell:

```powershell
git config --global credential.azreposCredentialType oauth
```

If `ghr link` cannot find the Windows install, see
[Locating the Windows tools dir](#locating-the-windows-tools-dir).

## Recipe: uv with Azure DevOps feeds from WSL

Use this when `uv` runs in WSL but Azure DevOps authentication should reuse the
Windows Microsoft identity cache.

In Windows PowerShell:

```powershell
ghr install cataggar/keyring
```

Inside WSL:

```sh
ghr link cataggar/keyring
ghr install astral-sh/uv
keyring -b ado diagnose
export UV_KEYRING_PROVIDER=subprocess
```

Use an Azure Artifacts index URL that includes the conventional
`VssSessionToken` username:

```sh
uv pip install \
  --index-url "https://VssSessionToken@pkgs.dev.azure.com/<organization>/<project>/_packaging/<feed>/pypi/simple/" \
  <package>
```

`UV_KEYRING_PROVIDER=subprocess` tells `uv` to invoke the `keyring` command.
Because `ghr link cataggar/keyring` points to the Windows `keyring.exe`, the `ado`
backend can reuse the Windows Microsoft identity cache and return the session
token to `uv`; the token is not written into the URL or config. This path does
not require Python `artifacts-keyring` or a .NET runtime inside WSL.

For troubleshooting, run `keyring -b ado diagnose`, then see
[cataggar/keyring Azure DevOps](https://github.com/cataggar/keyring/blob/main/doc/azure-devops.md)
and [uv keyring providers](https://docs.astral.sh/uv/concepts/authentication/http/#keyring-providers).

## Locating the Windows tools dir

`ghr link` resolves the Windows-side tools dir in this order:

1. `GHR_WIN_TOOLS_DIR` — explicit override. Accepts either a WSL path (`/mnt/c/Users/x/AppData/Roaming/ghr/data/tools`) or a Windows path (`C:\Users\x\AppData\Roaming\ghr\data\tools`).
2. `cmd.exe /c echo %APPDATA%`, run through `wslpath -u`. This is the canonical lookup and handles non-default Windows usernames and redirected APPDATA.
3. For explicit ID operations, fallback to
   `/mnt/c/Users/$USER/AppData/Roaming/ghr/data/tools` with a warning, assuming
   the WSL username matches the Windows one. Automatic one-segment
   disambiguation does not use this heuristic.

## Per-link manifest

For each linked ID, ghr records what it created at
`$XDG_DATA_HOME/ghr/links/by-id/u-<segment>/.../_manifest.json` (or under
`~/.local/share`). The prefixed segment encoding keeps IDs such as `a` and
`a/b` independent. Bare-executable links live in the sibling
`by-path/<name>.json` tree.

The manifest records the canonical ID and exact published command names.
`ghr unlink` verifies each live symlink still points where the manifest
recorded before deleting, so a user-rewritten symlink is never clobbered.
Validated legacy owner/repo manifests migrate lazily during a full
reconciliation and can still be unlinked after the Windows install disappears.

## Recipe: Microsoft Authentication CLI from WSL

Use this when Microsoft Authentication CLI is installed on Windows and only the
`azureauth` binary should be exposed inside WSL.

In Windows PowerShell:

```powershell
ghr install azuread/microsoft-authentication-cli@0.9.6 --bin azureauth
```

Inside WSL:

```sh
ghr link azuread/microsoft-authentication-cli --bin azureauth
```

The release archive also contains `createdump.exe`. Install-time `--bin`
selection keeps that command out of the Windows publication set, while
link-time `--bin` limits which already-owned Windows commands are exposed in
WSL.
