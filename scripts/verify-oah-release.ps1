param(
  [switch]$RequireUpstream,
  [switch]$SkipLocalBuild,
  [string]$ReportDir = "release-reports"
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$GeneratedAt = Get-Date
$ReportStamp = $GeneratedAt.ToUniversalTime().ToString("yyyyMMdd-HHmmss")
$StepResults = New-Object System.Collections.Generic.List[object]

function Fail([string]$Message) {
  Write-Error "[oah-release] $Message"
  exit 1
}

function Run-Step([string]$Name, [scriptblock]$Command) {
  $started = Get-Date
  Write-Output "[oah-release] step=$Name status=Running"
  $output = @()
  try {
    $global:LASTEXITCODE = 0
    $output = @(& $Command 2>&1)
    foreach ($line in $output) {
      Write-Output $line
    }
    if ($LASTEXITCODE -ne 0) {
      Fail "Step '$Name' failed with exit code $LASTEXITCODE."
    }
  } catch {
    Fail "Step '$Name' failed. $_"
  }
  $elapsed = [math]::Round(((Get-Date) - $started).TotalSeconds, 1)
  $StepResults.Add([pscustomobject]@{
    name = $Name
    status = "Passed"
    seconds = $elapsed
    output = @($output | ForEach-Object { "$_" })
  })
  Write-Output "[oah-release] step=$Name status=Passed seconds=$elapsed"
}

function Write-ReleaseReport([string]$DesiredImage) {
  $resolvedReportDir = if ([System.IO.Path]::IsPathRooted($ReportDir)) { $ReportDir } else { Join-Path $Root $ReportDir }
  New-Item -ItemType Directory -Force -Path $resolvedReportDir | Out-Null
  $summary = [pscustomobject][ordered]@{
    generatedAt = $GeneratedAt.ToUniversalTime().ToString("o")
    desiredImage = $DesiredImage
    requireUpstream = [bool]$RequireUpstream
    skipLocalBuild = [bool]$SkipLocalBuild
    status = "Passed"
    stepsPassed = [int]$StepResults.Count
    steps = @($StepResults.ToArray())
  }
  $jsonPath = Join-Path $resolvedReportDir "oah-release-$ReportStamp.json"
  $mdPath = Join-Path $resolvedReportDir "oah-release-$ReportStamp.md"
  $summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

  $lines = New-Object System.Collections.Generic.List[string]
  $lines.Add("# OAH Release Verification")
  $lines.Add("")
  $lines.Add("- Generated: $($summary.generatedAt)")
  $lines.Add("- Desired image: ``$DesiredImage``")
  $lines.Add("- Require upstream: $RequireUpstream")
  $lines.Add("- Skip local build: $SkipLocalBuild")
  $lines.Add("- Status: Passed")
  $lines.Add("")
  $lines.Add("| Step | Status | Seconds |")
  $lines.Add("|---|---|---:|")
  foreach ($step in $StepResults) {
    $lines.Add("| $($step.name) | $($step.status) | $($step.seconds) |")
  }
  $lines.Add("")
  $lines.Add("## Evidence")
  foreach ($step in $StepResults) {
    $lines.Add("")
    $lines.Add("### $($step.name)")
    $lines.Add("")
    $lines.Add('```text')
    $lines.Add(($step.output -join "`n"))
    $lines.Add('```')
  }
  $lines | Set-Content -LiteralPath $mdPath -Encoding UTF8
  Write-Output "[oah-release] reportJson=$jsonPath"
  Write-Output "[oah-release] reportMarkdown=$mdPath"
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
  Write-ReleaseReport $desiredImage
} finally {
  Pop-Location
}
