param(
    [string]$Version = "latest",
    [string]$Repository = "Agent-Remote/agent-remote-cli",
    [Alias("Home")]
    [string]$AgentRemoteHome = $(if ($env:AGENT_REMOTE_HOME) { $env:AGENT_REMOTE_HOME } else { Join-Path $env:LOCALAPPDATA "agent-remote" }),
    [switch]$NoPathUpdate,
    [switch]$InstallPrerequisites
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Install-Package([string]$PackageDirectory) {
    $destinationBin = Join-Path $AgentRemoteHome "bin"
    $destinationDependencies = Join-Path $AgentRemoteHome "dependencies"
    New-Item -ItemType Directory -Force $destinationBin, $destinationDependencies | Out-Null
    foreach ($file in @("agent-remote.exe", "fclaude.exe", "agent-remote-wireguard.exe", "mutagen.exe", "mutagen-agents.tar.gz", "scp.exe")) {
        $source = Join-Path $PackageDirectory "bin/$file"
        if (-not (Test-Path $source -PathType Leaf)) { throw "Missing packaged file: $source" }
        Copy-Item $source (Join-Path $destinationBin $file) -Force
    }
    Copy-Item (Join-Path $PackageDirectory "dependencies/manifest.json") (Join-Path $destinationDependencies "manifest.json") -Force

    if (-not $NoPathUpdate) {
        $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
        $entries = @($userPath -split ";" | Where-Object { $_ })
        if ($entries -notcontains $destinationBin) {
            [Environment]::SetEnvironmentVariable("Path", (($entries + $destinationBin) -join ";"), "User")
        }
        if (($env:Path -split ";") -notcontains $destinationBin) { $env:Path += ";$destinationBin" }
    }
}

function Install-SystemPrerequisites {
    if (-not (Get-Command ssh.exe -ErrorAction SilentlyContinue) -or -not (Get-Command scp.exe -ErrorAction SilentlyContinue)) {
        Write-Host "Installing the Windows OpenSSH Client capability..."
        Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0 | Out-Null
    }
    if (-not (Test-Path (Join-Path $env:ProgramFiles "WireGuard/wireguard.exe"))) {
        if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
            throw "winget is required to install WireGuard automatically"
        }
        winget.exe install --id WireGuard.WireGuard --exact --accept-package-agreements --accept-source-agreements
        if ($LASTEXITCODE -ne 0) { throw "WireGuard installation failed" }
    }
}

if ($InstallPrerequisites) { Install-SystemPrerequisites }

$localPackage = $PSScriptRoot
if ((Test-Path (Join-Path $localPackage "bin")) -and (Test-Path (Join-Path $localPackage "dependencies"))) {
    Install-Package $localPackage
} else {
    if ($Version -eq "latest") {
        $release = Invoke-RestMethod "https://api.github.com/repos/$Repository/releases/latest"
        $Version = $release.tag_name.TrimStart("v")
    } else {
        $Version = $Version.TrimStart("v")
    }
    $target = switch ($env:PROCESSOR_ARCHITECTURE) {
        { $_ -in @("AMD64", "x86_64") } { "x86_64-pc-windows-msvc"; break }
        { $_ -in @("ARM64", "aarch64") } { "aarch64-pc-windows-msvc"; break }
        default { throw "Unsupported Windows architecture: $env:PROCESSOR_ARCHITECTURE" }
    }
    $packageName = "agent-remote-cli-$Version-$target"
    $url = "https://github.com/$Repository/releases/download/v$Version/$packageName.zip"
    $temporary = Join-Path ([System.IO.Path]::GetTempPath()) "agent-remote-install-$([guid]::NewGuid())"
    New-Item -ItemType Directory $temporary | Out-Null
    try {
        $archive = Join-Path $temporary "$packageName.zip"
        Write-Host "Downloading $url"
        Invoke-WebRequest -Uri $url -OutFile $archive
        Expand-Archive $archive -DestinationPath $temporary
        Install-Package (Join-Path $temporary $packageName)
    } finally {
        Remove-Item $temporary -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "agent-remote CLI installed in $(Join-Path $AgentRemoteHome 'bin')"
if (-not (Get-Command ssh.exe -ErrorAction SilentlyContinue)) {
    Write-Warning "Windows OpenSSH Client is required. Re-run with -InstallPrerequisites from an elevated PowerShell."
}
if (-not (Test-Path (Join-Path $env:ProgramFiles "WireGuard/wireguard.exe"))) {
    Write-Warning "WireGuard for Windows is required for tunnel commands. Re-run with -InstallPrerequisites."
}
Write-Host "Open a new terminal, then run: agent-remote init"
