# ghr installer for Windows -- https://github.com/cataggar/ghr
#
# Usage:
#   iwr -useb https://raw.githubusercontent.com/cataggar/ghr/main/install.ps1 | iex
#   $env:GHR_VERSION = "v0.3.1"; iwr -useb https://raw.githubusercontent.com/cataggar/ghr/main/install.ps1 | iex
#
# With named params (iex/pipe discards args, so use the scriptblock form):
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/cataggar/ghr/main/install.ps1))) -Version v0.3.1
#
# Downloads the latest ghr release into a temp dir, then uses that
# bootstrap binary to self-install via `ghr install cataggar/ghr <pubkey>`,
# which re-downloads the real artifact and verifies it with the pinned
# minisign public key. The temp dir is always removed.
#
# Pure ASCII -- Windows PowerShell 5.1 parser compatible.

#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Version = $env:GHR_VERSION
)

$ErrorActionPreference = 'Stop'

# Invoke-WebRequest's per-chunk progress bar on PS 5.1 repaints synchronously
# on every received byte, pegs one CPU core, and throttles downloads 10-100x
# (a 5 MB zip can take a minute with progress on vs a second off). Restored
# automatically when the script exits.
$ProgressPreference = 'SilentlyContinue'

# ---------- constants ----------
$Repo           = 'cataggar/ghr'
$MinisignPubkey = 'RWSbsumpaHb+N3KCEt/EUXQ5y6Kkk8r/zCb5Z4jhEuEX8x2/U5wr5QC0'

# ---------- output helpers ----------
$script:UseColor = -not $env:NO_COLOR -and -not [Console]::IsOutputRedirected

function Write-Info {
    param([string]$Message)
    if ($script:UseColor) {
        Write-Host '==> ' -ForegroundColor Green -NoNewline
        Write-Host $Message
    } else {
        Write-Host "==> $Message"
    }
}

function Write-Warn {
    param([string]$Message)
    if ($script:UseColor) {
        [Console]::Error.Write([char]27 + '[33m! ' + [char]27 + '[0m')
    } else {
        [Console]::Error.Write('! ')
    }
    [Console]::Error.WriteLine($Message)
}

function Write-Err {
    param([string]$Message)
    if ($script:UseColor) {
        [Console]::Error.Write([char]27 + '[31merror:' + [char]27 + '[0m ')
    } else {
        [Console]::Error.Write('error: ')
    }
    [Console]::Error.WriteLine($Message)
}

# ---------- arch detection ----------
# Return the real OS architecture as a lowercase string: "x64" or "arm64".
# Win32_Processor.Architecture is invariant to x64 emulation, which matters
# on Windows-on-ARM where Windows PowerShell 5.1 runs under Prism x64 and
# [RuntimeInformation]::OSArchitecture reports X64 instead of Arm64.
# Values: 0=x86, 5=ARM, 9=AMD64/x64, 12=ARM64.
function Get-WindowsArch {
    try {
        $proc = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop |
            Select-Object -First 1
        switch ([int]$proc.Architecture) {
            12 { return 'arm64' }
            9  { return 'x64' }
            5  { return 'arm' }
            0  { return 'x86' }
        }
    } catch {
        # CIM unavailable -- fall through to env-var path
    }

    $envArch = if ($env:PROCESSOR_ARCHITEW6432) {
        $env:PROCESSOR_ARCHITEW6432
    } else {
        $env:PROCESSOR_ARCHITECTURE
    }
    switch ($envArch) {
        'ARM64' { return 'arm64' }
        'AMD64' { return 'x64' }
        'x86'   { return 'x86' }
        default {
            if ([Environment]::Is64BitOperatingSystem) { return 'x64' } else { return 'x86' }
        }
    }
}

# ---------- version resolution ----------
# Follow the redirect on /releases/latest -- no API rate limit. Falls back
# to the GitHub API if the redirect lookup fails.
function Resolve-GhrVersion {
    param([string]$Pinned)

    if ($Pinned) {
        Write-Info "using pinned version: $Pinned"
        return $Pinned
    }

    $url = "https://github.com/$Repo/releases/latest"
    try {
        $resp = Invoke-WebRequest -UseBasicParsing -Method Head -Uri $url `
            -MaximumRedirection 0 -ErrorAction Stop
        $location = $resp.Headers.Location
    } catch {
        # On PS 5.1 a non-success status throws even though we got a redirect
        # we wanted -- pull the Location out of the exception's response.
        $exResp = $_.Exception.Response
        if ($exResp) {
            try { $location = $exResp.Headers.Location.ToString() } catch { $location = $null }
        }
    }

    if ($location -and $location -match '/tag/([^/\s]+)') {
        return $matches[1]
    }

    Write-Warn 'redirect lookup failed, falling back to GitHub API'
    try {
        $api = Invoke-RestMethod -UseBasicParsing -Uri "https://api.github.com/repos/$Repo/releases/latest"
        if ($api.tag_name) { return $api.tag_name }
    } catch {
        # fall through to final error
    }

    throw 'could not resolve latest ghr version (set $env:GHR_VERSION or pass -Version vX.Y.Z to pin)'
}

# ---------- install ----------
function Invoke-GhrInstall {
    param(
        [string]$Tag,
        [string]$Arch,
        [bool]$Pinned
    )

    $ver     = $Tag -replace '^v', ''
    $asset   = "ghr-$ver-windows-$Arch.zip"
    $url     = "https://github.com/$Repo/releases/download/$Tag/$asset"
    $assetDir = "ghr-$ver-windows-$Arch"

    Write-Info "detected: windows $Arch"
    Write-Info "version:  $Tag"

    $tmp = New-Item -ItemType Directory -Force -Path (
        Join-Path ([IO.Path]::GetTempPath()) ("ghr-install-" + [Guid]::NewGuid().ToString('N'))
    )

    try {
        $archive = Join-Path $tmp.FullName 'ghr.zip'

        Write-Info "downloading $url"
        try {
            Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $archive -ErrorAction Stop
        } catch {
            throw "failed to download $asset -- check that this OS/arch is published for $Tag ($($_.Exception.Message))"
        }

        Write-Info 'extracting'
        try {
            Expand-Archive -Path $archive -DestinationPath $tmp.FullName -Force -ErrorAction Stop
        } catch {
            throw "failed to extract $asset ($($_.Exception.Message))"
        }

        # Expected layout: <tmp>\ghr-<ver>-windows-<arch>\bin\ghr.exe
        $bootstrap = Join-Path $tmp.FullName (Join-Path $assetDir 'bin\ghr.exe')
        if (-not (Test-Path -LiteralPath $bootstrap)) {
            # Fallback: hunt for any ghr.exe within a small depth.
            $found = Get-ChildItem -Path $tmp.FullName -Recurse -Filter 'ghr.exe' `
                -ErrorAction SilentlyContinue | Select-Object -First 1
            if (-not $found) {
                throw 'ghr.exe not found in archive'
            }
            $bootstrap = $found.FullName
        }

        Write-Info 'running self-install with pinned minisign pubkey'
        # Thread the tag through when the user pinned a version, otherwise
        # the self-install would resolve to the latest *stable* release and
        # silently downgrade away from a pinned pre-release (e.g. -dev.N).
        $spec = if ($Pinned) { "$Repo@$Tag" } else { $Repo }
        & $bootstrap install $spec $MinisignPubkey
        if ($LASTEXITCODE -ne 0) {
            throw "bootstrap 'ghr install' exited with code $LASTEXITCODE"
        }
    } finally {
        # Best-effort cleanup; never let it mask the original error.
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue -LiteralPath $tmp.FullName
    }
}

# ---------- post-install ----------
function Show-PostInstallHint {
    if (Get-Command ghr -ErrorAction SilentlyContinue) { return }

    $ghrExe = Join-Path $env:USERPROFILE '.local\bin\ghr.exe'
    Write-Host ''
    Write-Warn 'ghr is installed but not on your PATH'
    if (Test-Path -LiteralPath $ghrExe) {
        Write-Warn "run:  & '$ghrExe' path ensure"
    } else {
        Write-Warn "add  $env:USERPROFILE\.local\bin  to your user PATH"
    }
    Write-Warn 'then open a new terminal'
}

# ---------- main ----------
try {
    $arch = Get-WindowsArch
    if ($arch -notin @('x64', 'arm64')) {
        throw "unsupported architecture: $arch (ghr publishes windows-x64 and windows-arm64)"
    }

    $tag = Resolve-GhrVersion -Pinned $Version
    Invoke-GhrInstall -Tag $tag -Arch $arch -Pinned ([bool]$Version)
    Show-PostInstallHint

    Write-Info "done -- run 'ghr help' to get started"
} catch {
    Write-Err $_.Exception.Message
    exit 1
}
