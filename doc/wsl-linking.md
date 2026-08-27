# WSL: linking Windows-side bins (`ghr link` / `ghr unlink`)

When ghr is installed on Windows, a parallel WSL distribution can expose the same tools without re-downloading them. `ghr link` creates Linux symlinks in `~/.local/bin` that point directly at the Windows-side `.exe` (via `/mnt/c/...`); WSL interop runs the binary transparently.

```sh
# Link an executable already on the Windows %PATH% (no install needed).
ghr link az           # → bash wrapper that runs az.cmd via cmd.exe
ghr unlink az
```

Notes:

- `ghr link` is a **reconciler**. Without `--bin`, it makes the WSL link set match the current Windows install — adding new bins, updating moved ones, and removing entries that disappeared from `ghr.json`. With `--bin <name>` filters, only the named entries are touched.
- The symlink target is the real `.exe` under `<tools>/<owner>/<repo>/`, not the Windows shim. A `C:\…` target would not trigger interop; the WSL path is required.
- Both commands require `WSL_INTEROP` to be set. They refuse to run outside WSL so you don't accidentally create dangling links on bare Linux or macOS.
- The owner/repo path is case-canonicalized to lowercase. `ghr link AzureAD/foo` and `ghr link azuread/foo` are equivalent regardless of how the install was created on Windows.

## Bare executable form

A spec without a `/` (e.g. `ghr link az`) is treated as a bare Windows-PATH executable name. ghr resolves it via `where.exe` (honouring `PATHEXT`), converts the result with `wslpath -u`, and writes an entry in ghr's bin directory based on the resolved file's extension:

- `.exe` / `.com` → symlink. WSL interop direct-executes the PE image, no extra process hop.
- `.cmd` / `.bat` → small bash wrapper that runs `cmd.exe /c '<windows-path>' "$@"` via WSL interop. This is how `ghr link az` exposes Azure CLI's `az.cmd`, for example.
- `.ps1` (and anything else) → rejected. Running PowerShell scripts safely needs a different launcher and arg-quoting model; install `pwsh` separately if you want it.

Other guardrails:

- The resolved path must live under `/mnt/<letter>/` (drvfs); UNC and `/mnt/wsl/` paths are rejected.
- `--bin` is not supported with the bare form (there is exactly one bin to link).
- `ghr unlink <name>` removes the symlink or wrapper created by `ghr link <name>`. Wrappers are only deleted when their magic comment and embedded Windows target match what the manifest recorded, so a user-edited wrapper is left alone.

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
ghr link keyring
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
Because `ghr link keyring` points to the Windows `keyring.exe`, the `ado`
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
3. Fallback to `/mnt/c/Users/$USER/AppData/Roaming/ghr/data/tools` with a warning, assuming the WSL username matches the Windows one.

## Per-link manifest

For each linked repo, ghr records what it created at `$XDG_DATA_HOME/ghr/links/<owner>/<repo>.json` (or `~/.local/share/ghr/links/...`). Bare-executable links live in the sibling `by-path/<name>.json` tree (with `kind = "wsl-path"`). The manifest is what `ghr unlink` consults; it verifies each live symlink still points where the manifest recorded before deleting, so a user-rewritten symlink is never clobbered.

## Recipe: Microsoft Authentication CLI from WSL

Use this when Microsoft Authentication CLI is installed on Windows and only the
`azureauth` binary should be exposed inside WSL.

In Windows PowerShell:

```powershell
ghr install azuread/microsoft-authentication-cli@0.9.6
```

Inside WSL:

```sh
ghr link azuread/microsoft-authentication-cli --bin azureauth
```

The release archive also contains `createdump.exe`. `ghr install` currently
links both executable candidates on Windows, while `ghr link --bin azureauth`
limits what is exposed in WSL. The `--bin` option belongs to `ghr link`, not
`ghr install`; do not run the failing command `ghr install ... --bin azureauth`.
Install-time filtering is tracked in [issue #185](https://github.com/cataggar/ghr/issues/185).
