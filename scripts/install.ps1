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

function Repair-WireGuardConfigPermissions {
    $config = Join-Path $AgentRemoteHome "wireguard/agent-remote.conf"
    if (-not (Test-Path $config -PathType Leaf)) { return }

    $principal = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    & icacls.exe $config /inheritance:r /grant:r "${principal}:(F)" "*S-1-5-18:(R)" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to grant LocalSystem read access to WireGuard configuration: $config"
    }
}

function Get-ManagedMutagenProcesses([string]$MutagenPath) {
    $expectedPath = [System.IO.Path]::GetFullPath($MutagenPath)
    foreach ($process in @(Get-Process -Name "mutagen" -ErrorAction SilentlyContinue)) {
        try {
            $processPath = $process.Path
        } catch {
            continue
        }
        if ($processPath -and [System.StringComparer]::OrdinalIgnoreCase.Equals(
            [System.IO.Path]::GetFullPath($processPath),
            $expectedPath
        )) {
            $process
        }
    }
}

function Stop-ManagedMutagen([string]$MutagenPath) {
    $processes = @(Get-ManagedMutagenProcesses $MutagenPath)
    if ($processes.Count -eq 0) { return $false }

    Write-Host "Stopping the managed Mutagen daemon for the upgrade..."
    & $MutagenPath daemon stop 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Mutagen did not stop cleanly; terminating only processes running from $MutagenPath"
    }
    Start-Sleep -Milliseconds 250

    $remaining = @(Get-ManagedMutagenProcesses $MutagenPath)
    foreach ($process in $remaining) {
        Stop-Process -Id $process.Id -Force
        if (-not $process.WaitForExit(5000)) {
            throw "Timed out stopping managed Mutagen process $($process.Id)"
        }
    }
    if (@(Get-ManagedMutagenProcesses $MutagenPath).Count -ne 0) {
        throw "Managed Mutagen processes are still running from $MutagenPath"
    }
    return $true
}

function Start-ManagedMutagen([string]$MutagenPath) {
    Write-Host "Restarting the managed Mutagen daemon..."
    $managedBin = Split-Path $MutagenPath -Parent
    $previousAgentRemoteHome = $env:AGENT_REMOTE_HOME
    $previousMutagenSshPath = $env:MUTAGEN_SSH_PATH
    $previousPath = $env:Path
    try {
        $env:AGENT_REMOTE_HOME = $AgentRemoteHome
        $env:MUTAGEN_SSH_PATH = $managedBin
        if (($env:Path -split ";") -notcontains $managedBin) {
            $env:Path = "$managedBin;$env:Path"
        }
        & $MutagenPath daemon start | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to restart the managed Mutagen daemon"
        }
    } finally {
        $env:AGENT_REMOTE_HOME = $previousAgentRemoteHome
        $env:MUTAGEN_SSH_PATH = $previousMutagenSshPath
        $env:Path = $previousPath
    }
}

function Install-Package([string]$PackageDirectory) {
    $destinationBin = Join-Path $AgentRemoteHome "bin"
    $destinationDependencies = Join-Path $AgentRemoteHome "dependencies"
    New-Item -ItemType Directory -Force $destinationBin, $destinationDependencies | Out-Null
    $packageFiles = @("agent-remote.exe", "fclaude.exe", "agent-remote-wireguard.exe", "mutagen.exe", "mutagen-agents.tar.gz", "scp.exe", "ssh.exe")
    foreach ($file in $packageFiles) {
        $source = Join-Path $PackageDirectory "bin/$file"
        if (-not (Test-Path $source -PathType Leaf)) { throw "Missing packaged file: $source" }
    }
    $destinationMutagen = Join-Path $destinationBin "mutagen.exe"
    $mutagenWasRunning = (Test-Path $destinationMutagen -PathType Leaf) -and (Stop-ManagedMutagen $destinationMutagen)
    $installCompleted = $false
    try {
        foreach ($file in $packageFiles) {
            Copy-Item (Join-Path $PackageDirectory "bin/$file") (Join-Path $destinationBin $file) -Force
        }
        Copy-Item (Join-Path $PackageDirectory "dependencies/*") $destinationDependencies -Recurse -Force
        $installCompleted = $true
    } finally {
        if ($mutagenWasRunning) {
            try {
                Start-ManagedMutagen $destinationMutagen
            } catch {
                if ($installCompleted) { throw }
                Write-Warning "The install failed and the managed Mutagen daemon could not be restarted: $_"
            }
        }
    }
    Repair-WireGuardConfigPermissions

    if (-not $NoPathUpdate) {
        $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
        $entries = @($userPath -split ";" | Where-Object { $_ })
        if ($entries -notcontains $destinationBin) {
            [Environment]::SetEnvironmentVariable("Path", (($entries + $destinationBin) -join ";"), "User")
        }
        if (($env:Path -split ";") -notcontains $destinationBin) { $env:Path += ";$destinationBin" }
    }
}

function Install-SystemPrerequisites([string]$PackageDirectory) {
    if (-not (Get-Command ssh.exe -ErrorAction SilentlyContinue) -or -not (Get-Command scp.exe -ErrorAction SilentlyContinue)) {
        Write-Host "Installing the Windows OpenSSH Client capability..."
        Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0 | Out-Null
    }
    if (-not (Test-Path (Join-Path $env:ProgramFiles "WireGuard/wireguard.exe"))) {
        $installer = Get-ChildItem (Join-Path $PackageDirectory "dependencies/installers") -Filter "wireguard-*.msi" | Select-Object -First 1
        if (-not $installer) {
            throw "The packaged WireGuard for Windows installer is missing"
        }
        Write-Host "Installing the packaged WireGuard for Windows $($installer.Name)..."
        $process = Start-Process msiexec.exe -Verb RunAs -Wait -PassThru -ArgumentList @(
            "/i", "`"$($installer.FullName)`"", "/qn", "/norestart"
        )
        if ($process.ExitCode -notin @(0, 3010)) { throw "WireGuard installation failed with exit code $($process.ExitCode)" }
    }
}

function Resolve-LatestVersion([string]$Repository) {
    $tag = $null
    try {
        $response = Invoke-WebRequest -Uri "https://github.com/$Repository/releases/latest" -UseBasicParsing
        $responseUri = $response.BaseResponse.PSObject.Properties["ResponseUri"]
        if ($responseUri -and $responseUri.Value) {
            $finalUri = $responseUri.Value
        } else {
            $finalUri = $response.BaseResponse.RequestMessage.RequestUri
        }
        $tag = $finalUri.Segments[-1].TrimEnd("/")
    } catch {
        $tag = $null
    }

    if (-not $tag -or $tag -in @("latest", "releases")) {
        $release = Invoke-RestMethod "https://api.github.com/repos/$Repository/releases/latest"
        $tag = $release.tag_name
    }
    if (-not $tag) { throw "Failed to resolve the latest release for $Repository; retry with -Version 0.0.4" }
    return $tag.TrimStart("v")
}

$localPackage = $PSScriptRoot
if ((Test-Path (Join-Path $localPackage "bin")) -and (Test-Path (Join-Path $localPackage "dependencies"))) {
    if ($InstallPrerequisites) { Install-SystemPrerequisites $localPackage }
    Install-Package $localPackage
} else {
    if ($Version -eq "latest") {
        $Version = Resolve-LatestVersion $Repository
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
        $packageDirectory = Join-Path $temporary $packageName
        if ($InstallPrerequisites) { Install-SystemPrerequisites $packageDirectory }
        Install-Package $packageDirectory
    } finally {
        Remove-Item $temporary -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "agent-remote CLI installed in $(Join-Path $AgentRemoteHome 'bin')"
if (-not (Get-Command ssh.exe -ErrorAction SilentlyContinue)) {
    Write-Warning "Windows OpenSSH Client is required. Re-run with -InstallPrerequisites from an elevated PowerShell."
}
if (-not (Test-Path (Join-Path $env:ProgramFiles "WireGuard/wireguard.exe"))) {
    Write-Warning "WireGuard for Windows is included in the release package. Re-run with -InstallPrerequisites to install it."
}
Write-Host "Open a new terminal, then run: agent-remote init"
