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

$binFiles = @(
    "agent-remote.exe",
    "fclaude.exe",
    "agent-remote-wireguard.exe",
    "mutagen.exe",
    "mutagen-agents.tar.gz",
    "scp.exe"
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

$requiredDependencies = @("mutagen", "wireguard-helper", "wireguard-windows", "scp-proxy")
foreach ($name in $requiredDependencies) {
    if (-not ($manifest.dependencies | Where-Object name -eq $name)) {
        throw "Manifest is missing dependency: $name"
    }
}

foreach ($dependency in $manifest.dependencies) {
    $binary = Join-Path $PackageDirectory $dependency.binary
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
& (Join-Path $InstallHome "bin/mutagen.exe") version
if ($LASTEXITCODE -ne 0) { throw "Mutagen did not execute successfully" }

Write-Host "Windows install smoke test passed"
