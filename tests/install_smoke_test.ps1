param(
    [Parameter(Mandatory = $true)]
    [string]$PackageDirectory,
    [Parameter(Mandatory = $true)]
    [string]$InstallHome,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedVersion
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Assert-File([string]$Path) {
    if (-not (Test-Path $Path -PathType Leaf)) { throw "Missing file: $Path" }
}

function Resolve-PackageBinary([string]$RelativePath) {
    if (-not [System.IO.Path]::GetExtension($RelativePath)) {
        return "$RelativePath.exe"
    }
    return $RelativePath
}

function Get-ProcessesAtPath([string]$Name, [string]$Path) {
    $expectedPath = [System.IO.Path]::GetFullPath($Path)
    foreach ($process in @(Get-Process -Name $Name -ErrorAction SilentlyContinue)) {
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

$binFiles = @(
    "agent-remote.exe",
    "fclaude.exe",
    "agent-remote-wireguard.exe",
    "mutagen.exe",
    "mutagen-agents.tar.gz",
    "scp.exe",
    "ssh.exe"
)
foreach ($file in $binFiles) {
    Assert-File (Join-Path $PackageDirectory "bin/$file")
    Assert-File (Join-Path $InstallHome "bin/$file")
}

$packageDependencies = Join-Path $PackageDirectory "dependencies"
$installedDependencies = Join-Path $InstallHome "dependencies"
$manifestPath = Join-Path $packageDependencies "manifest.json"
Assert-File $manifestPath
$manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json

$requiredDependencies = @("mutagen", "wireguard-helper", "wireguard-windows", "scp-proxy", "ssh-proxy")
foreach ($name in $requiredDependencies) {
    if (-not ($manifest.dependencies | Where-Object name -eq $name)) {
        throw "Manifest is missing dependency: $name"
    }
}
$wireGuardDependency = $manifest.dependencies | Where-Object name -eq "wireguard-windows"

foreach ($dependency in $manifest.dependencies) {
    $binary = Join-Path $PackageDirectory (Resolve-PackageBinary $dependency.binary)
    Assert-File $binary
    if ($dependency.PSObject.Properties.Name -contains "binary_sha256") {
        $actual = (Get-FileHash $binary -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $dependency.binary_sha256) { throw "Binary checksum mismatch: $binary" }
    }
    if ($dependency.source.StartsWith("dependencies/")) {
        Assert-File (Join-Path $PackageDirectory $dependency.source)
    }
    if ($dependency.license_notice.StartsWith("See dependencies/")) {
        $license = $dependency.license_notice.Substring(4)
        Assert-File (Join-Path $PackageDirectory $license)
    }
}

foreach ($property in $manifest.managed_files.PSObject.Properties) {
    $path = Join-Path $PackageDirectory $property.Name
    Assert-File $path
    $actual = (Get-FileHash $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $property.Value.sha256) { throw "Managed file checksum mismatch: $($property.Name)" }
}

foreach ($archive in $manifest.source_archives) {
    $path = Join-Path $PackageDirectory $archive.file
    Assert-File $path
    $actual = (Get-FileHash $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $archive.sha256) { throw "Source archive checksum mismatch: $($archive.file)" }
}

$packageFiles = Get-ChildItem $packageDependencies -File -Recurse | ForEach-Object {
    $_.FullName.Substring($packageDependencies.Length).TrimStart("\", "/")
} | Sort-Object
$installedFiles = Get-ChildItem $installedDependencies -File -Recurse | ForEach-Object {
    $_.FullName.Substring($installedDependencies.Length).TrimStart("\", "/")
} | Sort-Object
if (Compare-Object $packageFiles $installedFiles) {
    throw "Installed dependency file list does not match the package"
}
foreach ($relative in $packageFiles) {
    $packageHash = (Get-FileHash (Join-Path $packageDependencies $relative) -Algorithm SHA256).Hash
    $installedHash = (Get-FileHash (Join-Path $installedDependencies $relative) -Algorithm SHA256).Hash
    if ($packageHash -ne $installedHash) { throw "Installed dependency differs from package: $relative" }
}

$commands = @("agent-remote.exe", "fclaude.exe", "agent-remote-wireguard.exe")
foreach ($command in $commands) {
    $output = & (Join-Path $InstallHome "bin/$command") --version
    if ($LASTEXITCODE -ne 0 -or $output -notmatch [regex]::Escape($ExpectedVersion)) {
        throw "$command did not report version $ExpectedVersion"
    }
}
$installedMutagen = Join-Path $InstallHome "bin/mutagen.exe"
& $installedMutagen version
if ($LASTEXITCODE -ne 0) { throw "Mutagen did not execute successfully" }

try {
    & $installedMutagen daemon start
    if ($LASTEXITCODE -ne 0) { throw "Mutagen daemon did not start successfully" }
    Start-Sleep -Milliseconds 250
    if (@(Get-ProcessesAtPath "mutagen" $installedMutagen).Count -eq 0) {
        throw "Mutagen daemon is not running from the managed installation"
    }

    & (Join-Path $PackageDirectory "install.ps1") -AgentRemoteHome $InstallHome -NoPathUpdate
    if (@(Get-ProcessesAtPath "mutagen" $installedMutagen).Count -eq 0) {
        throw "The Windows installer did not restore the managed Mutagen daemon"
    }
} finally {
    & $installedMutagen daemon stop 2>$null | Out-Null
}

$managedWireGuardConfig = Join-Path $InstallHome "wireguard/agent-remote.conf"
Assert-File $managedWireGuardConfig
$systemAccount = ([System.Security.Principal.SecurityIdentifier]::new("S-1-5-18")).Translate(
    [System.Security.Principal.NTAccount]
)
$systemCanRead = (Get-Acl $managedWireGuardConfig).Access | Where-Object {
    $_.IdentityReference -eq $systemAccount -and
    $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
    ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::ReadData)
}
if (-not $systemCanRead) {
    throw "Installed WireGuard configuration is not readable by LocalSystem"
}

$wireGuard = Join-Path $env:ProgramFiles "WireGuard/wireguard.exe"
Assert-File $wireGuard
$installedWireGuardVersion = (Get-Item $wireGuard).VersionInfo.ProductVersion
if (-not $installedWireGuardVersion.StartsWith([string]$wireGuardDependency.required_version)) {
    throw "Installed WireGuard version $installedWireGuardVersion does not match $($wireGuardDependency.required_version)"
}
$wireGuardStdout = Join-Path $env:RUNNER_TEMP "wireguard-smoke.stdout"
$wireGuardStderr = Join-Path $env:RUNNER_TEMP "wireguard-smoke.stderr"
$wireGuardProcess = Start-Process $wireGuard -Wait -PassThru `
    -ArgumentList "/agent-remote-install-smoke-test" `
    -RedirectStandardOutput $wireGuardStdout -RedirectStandardError $wireGuardStderr
$wireGuardOutput = ((Get-Content $wireGuardStdout -Raw), (Get-Content $wireGuardStderr -Raw)) -join "`n"
if ($wireGuardProcess.ExitCode -ne 1 -or $wireGuardOutput -notmatch "Command Line Options") {
    throw "Installed WireGuard command-line entry point did not execute as expected"
}

$wireGuardConfig = Join-Path $env:RUNNER_TEMP "agent-remote-install-smoke.conf"
Set-Content -Path $wireGuardConfig -Value "[Interface]`nPrivateKey = install-smoke-test" -Encoding ascii
& (Join-Path $InstallHome "bin/agent-remote-wireguard.exe") check --config $wireGuardConfig
if ($LASTEXITCODE -ne 0) { throw "agent-remote-wireguard did not find the installed WireGuard executable" }

Write-Host "Windows install smoke test passed"
