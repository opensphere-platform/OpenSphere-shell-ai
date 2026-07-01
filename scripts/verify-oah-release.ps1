param(
  [switch]$RequireUpstream,
  [switch]$SkipLocalBuild
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")

function Fail([string]$Message) {
  Write-Error "[oah-release] $Message"
  exit 1
}

function Run-Step([string]$Name, [scriptblock]$Command) {
  $started = Get-Date
  Write-Output "[oah-release] step=$Name status=Running"
  try {
    & $Command
    if ($LASTEXITCODE -ne 0) {
      Fail "Step '$Name' failed with exit code $LASTEXITCODE."
    }
  } catch {
    Fail "Step '$Name' failed. $_"
  }
  $elapsed = [math]::Round(((Get-Date) - $started).TotalSeconds, 1)
  Write-Output "[oah-release] step=$Name status=Passed seconds=$elapsed"
}

Push-Location $Root
try {
  $packageText = Get-Content -Raw "uipluginpackage.yaml"
  $repositoryMatch = [regex]::Match($packageText, "(?m)^\s*repository:\s*(\S+)\s*$")
  $digestMatch = [regex]::Match($packageText, "(?m)^\s*digest:\s*(\S+)\s*$")
  $desiredImage = if ($repositoryMatch.Success -and $digestMatch.Success) { "$($repositoryMatch.Groups[1].Value):$($digestMatch.Groups[1].Value)" } else { "unknown" }
  Write-Output "[oah-release] desiredImage=$desiredImage requireUpstream=$RequireUpstream skipLocalBuild=$SkipLocalBuild"

  if (-not $SkipLocalBuild) {
    Run-Step "local-contract-and-browser" { npm.cmd test }
  } else {
    Run-Step "local-contracts" { npm.cmd run test:contracts }
  }

  Run-Step "live-support-services" {
    powershell -ExecutionPolicy Bypass -File scripts/verify-live-support-services.ps1
  }

  Run-Step "product-flow" {
    powershell -ExecutionPolicy Bypass -File scripts/verify-oah-product-flow.ps1
  }

  Run-Step "live-browser-support-services" {
    npm.cmd run test:live-browser-support-services
  }

  Run-Step "upstream-parity" {
    if ($RequireUpstream) {
      powershell -ExecutionPolicy Bypass -File scripts/verify-upstream-parity.ps1 -RequireAll
    } else {
      powershell -ExecutionPolicy Bypass -File scripts/verify-upstream-parity.ps1
    }
  }

  Write-Output "[oah-release] checks passed"
} finally {
  Pop-Location
}
