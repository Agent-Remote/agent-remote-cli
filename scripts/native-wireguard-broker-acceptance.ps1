# Verify a protected WireGuard broker on the current Windows host.
# This entry point is status-only. It never treats an SCM service, a named
# pipe, or an installed executable as an authenticated broker handshake.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string]$CliBinary,
    [string]$EvidenceDir = ""
)

$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($EvidenceDir)) {
    $EvidenceDir = Join-Path ([IO.Path]::GetTempPath()) "agent-remote-wireguard-native"
}
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null

$goos = (& go env GOHOSTOS).Trim()
$goarch = (& go env GOHOSTARCH).Trim()
if ($goos -ne "windows" -or @("amd64", "arm64") -notcontains $goarch) {
    throw "native-wireguard-broker-acceptance: unsupported host $goos/$goarch"
}
if ($env:GOOS -or $env:GOARCH) {
    throw "native-wireguard-broker-acceptance: GOOS/GOARCH selectors are not allowed"
}
$cli = Get-Item -LiteralPath $CliBinary -ErrorAction Stop
$isLink = $false
if ($cli.PSObject.Properties.Name -contains "LinkType") { $isLink = [bool]$cli.LinkType }
if ($cli.PSIsContainer -or $isLink) {
    throw "CliBinary must be an executable regular file"
}

$home = Join-Path ([IO.Path]::GetTempPath()) ("agent-remote-wireguard-home-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $home | Out-Null
$request = @{ protocol_version = 1; request_id = "native-wireguard-status"; method = "wireguard.bridge.status"; params = @{ expected_home = $home } } | ConvertTo-Json -Compress
$statusPath = Join-Path $EvidenceDir "status-response.json"
$statusErrorPath = Join-Path $EvidenceDir "status.stderr"
$oldHome = $env:AGENT_REMOTE_HOME
$oldGoos = $env:GOOS
$oldGoarch = $env:GOARCH
try {
    $env:AGENT_REMOTE_HOME = $home
    $env:GOOS = $null
    $env:GOARCH = $null
    $response = $request | & $CliBinary --desktop-control 2> $statusErrorPath
    $exit = $LASTEXITCODE
    ($response -join "`n") | Set-Content -Encoding utf8 $statusPath
} finally {
    $env:AGENT_REMOTE_HOME = $oldHome
    $env:GOOS = $oldGoos
    $env:GOARCH = $oldGoarch
    Remove-Item -Recurse -Force -LiteralPath $home -ErrorAction SilentlyContinue
}

$installation = "failed"
$identity = "failed"
$service = Get-Service -Name "AgentRemoteWireGuardBroker" -ErrorAction SilentlyContinue
$brokerPath = Join-Path $env:ProgramFiles "Agent-Remote/bin/agent-remote-wireguard-broker.exe"
if ((Test-Path -LiteralPath $brokerPath -PathType Leaf) -and $service) {
    $installation = "passed"
    if ($service.Status -eq "Running") { $identity = "passed" }
}

$handshake = "failed"
$authentication = "failed"
$parsed = $null
if ($exit -eq 0) {
    try {
        $parsedResponse = Get-Content -Raw -LiteralPath $statusPath | ConvertFrom-Json
        $parsed = $parsedResponse.result
        $keys = @($parsed.PSObject.Properties.Name | Sort-Object)
        $expected = @("approval", "authentication", "execution", "home", "installation", "platform", "protocol", "state", "version")
        if ($parsedResponse.type -eq "result" -and $parsed.version -eq 1 -and (@($keys) -join ",") -eq ($expected -join ",")) {
            if ($parsed.installation -eq "installed" -and $parsed.state -notin @("unsupported", "unavailable") -and $parsed.protocol -ne "unsupported") {
                $handshake = "passed"
            }
            if ($handshake -eq "passed" -and $parsed.authentication -eq "authenticated") { $authentication = "passed" }
            $parsed | ConvertTo-Json -Depth 8 | Set-Content -Encoding utf8 (Join-Path $EvidenceDir "bridge-status.json")
        }
    } catch { }
}

$overall = "failed"
if ($installation -eq "passed" -and $identity -eq "passed" -and $handshake -eq "passed" -and $authentication -eq "passed") { $overall = "status-only" }
$evidence = [ordered]@{
    schema_version = 1; probe = "agent-remote-wireguard.native"; native = $true; cross_compilation = $false
    runtime = @{ goos = $goos; goarch = $goarch }
    installation = @{ status = $installation; entrypoint = "scripts/install.ps1 -InstallBroker (elevated SCM install)"; service_path = $brokerPath }
    service_identity = @{ status = $identity }
    status_handshake = @{ status = $handshake }
    caller_authentication = @{ status = $authentication }
    up_receipt = @{ status = "not_run" }; down_receipt = @{ status = "not_run" }
    replay_rejected = @{ status = "not_run" }; service_restart = @{ status = "not_run" }
    execution = @{ status = $overall; reason = "status-only; reviewed tunnel up/down requires a real desktop plan and explicit destructive acceptance" }
}
$evidence | ConvertTo-Json -Depth 8 | Set-Content -Encoding utf8 (Join-Path $EvidenceDir "evidence.json")
Write-Output "native-wireguard-broker-acceptance: overall=$overall evidence=$EvidenceDir"
if ($overall -eq "failed") { exit 1 }
