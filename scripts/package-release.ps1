param(
    [string]$Version,
    [string]$Target = "x86_64-pc-windows-msvc",
    [string]$OutDir = "dist",
    [string]$MutagenVersion = "0.18.1",
    [string]$WireGuardVersion = "1.1"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not $Version) {
    $manifest = Get-Content Cargo.toml -Raw
    $Version = [regex]::Match($manifest, '(?m)^version = "([^"]+)"').Groups[1].Value
}
$architecture = switch ($Target) {
    "x86_64-pc-windows-msvc" { @{ Mutagen = "amd64"; WireGuard = "amd64" } }
    "aarch64-pc-windows-msvc" { @{ Mutagen = "arm64"; WireGuard = "arm64" } }
    default { throw "Unsupported Windows release target: $Target" }
}

$env:AGENT_REMOTE_VERSION = $Version
cargo build --release --target $Target
if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }

$packageName = "agent-remote-cli-$Version-$Target"
$work = Join-Path $OutDir $packageName
$bin = Join-Path $work "bin"
$dependencies = Join-Path $work "dependencies"
$installers = Join-Path $dependencies "installers"
$sources = Join-Path $dependencies "sources"
$licenses = Join-Path $dependencies "licenses"
if (Test-Path $work) { Remove-Item $work -Recurse -Force }
New-Item -ItemType Directory -Force $bin, $installers, $sources, $licenses | Out-Null

foreach ($name in @("agent-remote", "fclaude", "agent-remote-wireguard")) {
    Copy-Item "target/$Target/release/$name.exe" "$bin/$name.exe"
}
Copy-Item "target/$Target/release/agent-remote-scp.exe" "$bin/scp.exe"
Copy-Item "target/$Target/release/agent-remote-ssh.exe" "$bin/ssh.exe"

$download = Join-Path ([System.IO.Path]::GetTempPath()) "agent-remote-mutagen-$([guid]::NewGuid()).tar.gz"
$mutagenUrl = "https://github.com/mutagen-io/mutagen/releases/download/v$MutagenVersion/mutagen_windows_$($architecture.Mutagen)_v$MutagenVersion.tar.gz"
Invoke-WebRequest -Uri $mutagenUrl -OutFile $download
tar.exe -xzf $download -C $bin
if ($LASTEXITCODE -ne 0) { throw "failed to extract Mutagen" }
Remove-Item $download

$wireGuardMsiName = "wireguard-$($architecture.WireGuard)-$WireGuardVersion.msi"
$wireGuardMsiUrl = "https://download.wireguard.com/windows-client/$wireGuardMsiName"
$wireGuardMsi = Join-Path $installers $wireGuardMsiName
Invoke-WebRequest -Uri $wireGuardMsiUrl -OutFile $wireGuardMsi

$wireGuardSourceName = "wireguard-windows-$WireGuardVersion.tar.gz"
$wireGuardSourceUrl = "https://github.com/WireGuard/wireguard-windows/archive/refs/tags/v$WireGuardVersion.tar.gz"
$wireGuardSource = Join-Path $sources $wireGuardSourceName
Invoke-WebRequest -Uri $wireGuardSourceUrl -OutFile $wireGuardSource
$wireGuardLicense = Join-Path $licenses "wireguard-windows-COPYING"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/WireGuard/wireguard-windows/v$WireGuardVersion/COPYING" -OutFile $wireGuardLicense

$manifest = [ordered]@{
    schema_version = 1
    dependencies = @(
        [ordered]@{
            name = "mutagen"
            required_version = "v$MutagenVersion"
            binary = "bin/mutagen"
            source = $mutagenUrl
            license = "MIT, with SSPL notice required for official v0.17+ builds"
            license_notice = "See THIRD_PARTY_NOTICES.md and the exact packaged Mutagen artifact notice"
        },
        [ordered]@{
            name = "wireguard-helper"
            required_version = $Version
            binary = "bin/agent-remote-wireguard"
            source = "agent-remote-cli release artifact"
            license = "GPL-3.0-only"
            license_notice = "See THIRD_PARTY_NOTICES.md"
        },
        [ordered]@{
            name = "wireguard-windows"
            required_version = $WireGuardVersion
            binary = "dependencies/installers/$wireGuardMsiName"
            source = "dependencies/sources/$wireGuardSourceName"
            license = "MIT"
            license_notice = "See dependencies/licenses/wireguard-windows-COPYING"
            binary_sha256 = (Get-FileHash $wireGuardMsi -Algorithm SHA256).Hash.ToLowerInvariant()
        },
        [ordered]@{
            name = "scp-proxy"
            required_version = $Version
            binary = "bin/scp"
            source = "agent-remote-cli release artifact"
            license = "GPL-3.0-only"
            license_notice = "See THIRD_PARTY_NOTICES.md"
        },
        [ordered]@{
            name = "ssh-proxy"
            required_version = $Version
            binary = "bin/ssh"
            source = "agent-remote-cli release artifact"
            license = "GPL-3.0-only"
            license_notice = "See THIRD_PARTY_NOTICES.md"
        }
    )
    managed_files = [ordered]@{
        "bin/mutagen-agents.tar.gz" = @{ sha256 = (Get-FileHash "$bin/mutagen-agents.tar.gz" -Algorithm SHA256).Hash.ToLowerInvariant() }
        "bin/scp.exe" = @{ sha256 = (Get-FileHash "$bin/scp.exe" -Algorithm SHA256).Hash.ToLowerInvariant() }
        "bin/ssh.exe" = @{ sha256 = (Get-FileHash "$bin/ssh.exe" -Algorithm SHA256).Hash.ToLowerInvariant() }
    }
    source_archives = @(
        [ordered]@{
            file = "dependencies/sources/$wireGuardSourceName"
            sha256 = (Get-FileHash $wireGuardSource -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    )
}
$manifestJson = $manifest | ConvertTo-Json -Depth 8
$utf8WithoutBom = [System.Text.UTF8Encoding]::new($false)
[System.IO.File]::WriteAllText("$dependencies/manifest.json", $manifestJson + "`n", $utf8WithoutBom)

Copy-Item README.md, README.zh-CN.md, CHANGELOG.md, LICENSE, THIRD_PARTY_NOTICES.md -Destination $work
Copy-Item scripts/install.ps1 "$work/install.ps1"
$archive = Join-Path $OutDir "$packageName.zip"
if (Test-Path $archive) { Remove-Item $archive }
Compress-Archive -Path $work -DestinationPath $archive
$archiveHash = (Get-FileHash $archive -Algorithm SHA256).Hash.ToLowerInvariant()
$checksumPath = "$archive.sha256"
[System.IO.File]::WriteAllText(
    $checksumPath,
    "$archiveHash  $([System.IO.Path]::GetFileName($archive))`n",
    $utf8WithoutBom
)
Write-Host "Windows release artifact written to $archive"
