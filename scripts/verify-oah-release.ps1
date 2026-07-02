param(
  [switch]$RequireUpstream,
  [switch]$RequireLiveBrowser,
  [switch]$RequireRemoteImages,
  [switch]$RequireSignedImages,
  [switch]$SkipLocalBuild,
  [string]$ReportDir = "release-reports",
  [string]$Namespace = "opensphere-system",
  [string]$CosignKeyRef = "",
  [string]$CosignIdentity = "",
  [string]$CosignIssuer = "",
  [string]$AiDeployment = "ai",
  [string]$ControllerDeployment = "dupa-registry-controller"
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
  $status = "Passed"
  if ($Name -eq "live-browser-support-services" -and (($output -join "`n") -match "skipped; set OAH_ID_TOKEN")) {
    $status = "Skipped"
    if ($RequireLiveBrowser) {
      Fail "Step '$Name' was skipped because OAH_ID_TOKEN is missing, but -RequireLiveBrowser was set."
    }
  }
  $StepResults.Add([pscustomobject]@{
    name = $Name
    status = $status
    seconds = $elapsed
    output = @($output | ForEach-Object { "$_" })
  })
  Write-Output "[oah-release] step=$Name status=$status seconds=$elapsed"
}

function Kube-Json([string[]]$ArgsList) {
  try {
    $output = & kubectl @ArgsList -o json 2>$null
  } catch {
    return $null
  }
  if ($LASTEXITCODE -ne 0 -or -not $output) {
    return $null
  }
  try {
    return ($output -join "`n") | ConvertFrom-Json
  } catch {
    return $null
  }
}

function Test-LocalImage([string]$Image) {
  return $Image -match '^(localhost|127\.0\.0\.1|\[::1\])(:|/)'
}

function Test-DigestImage([string]$Image) {
  return $Image -match '@sha256:[a-fA-F0-9]{64}$'
}

function Require-Cosign() {
  $cmd = Get-Command cosign -ErrorAction SilentlyContinue
  if (-not $cmd) {
    Fail "cosign was not found. Install cosign or run without -RequireSignedImages."
  }
}

function Invoke-Cosign([string[]]$ArgsList) {
  Write-Output "[oah-release] cosign $($ArgsList -join ' ')"
  & cosign @ArgsList
  if ($LASTEXITCODE -ne 0) {
    Fail "cosign $($ArgsList -join ' ') failed with exit code $LASTEXITCODE."
  }
}

function Verify-CosignSignature([string]$Image) {
  Require-Cosign
  $args = New-Object System.Collections.Generic.List[string]
  $args.Add("verify")
  if ($CosignKeyRef) {
    $args.Add("--key")
    $args.Add($CosignKeyRef)
  } else {
    if ($CosignIdentity) {
      $args.Add("--certificate-identity")
      $args.Add($CosignIdentity)
    }
    if ($CosignIssuer) {
      $args.Add("--certificate-oidc-issuer")
      $args.Add($CosignIssuer)
    }
  }
  $args.Add($Image)
  Invoke-Cosign $args.ToArray()
}

function Verify-ImagePolicy([string]$DesiredImage) {
  $ai = Kube-Json @("get", "deploy", $AiDeployment, "-n", $Namespace)
  $controller = Kube-Json @("get", "deploy", $ControllerDeployment, "-n", $Namespace)
  $images = @(
    [pscustomobject]@{ id = "package"; image = $DesiredImage },
    [pscustomobject]@{ id = "ai-deployment"; image = "$($ai.spec.template.spec.containers[0].image)" },
    [pscustomobject]@{ id = "dupa-controller"; image = "$($controller.spec.template.spec.containers[0].image)" }
  )

  foreach ($entry in $images) {
    Write-Output "[oah-release] image=$($entry.id) value=$($entry.image)"
    if ($RequireRemoteImages -and (Test-LocalImage $entry.image)) {
      Fail "Image '$($entry.id)' uses local registry '$($entry.image)' but -RequireRemoteImages was set."
    }
    if ($RequireSignedImages -and -not (Test-DigestImage $entry.image)) {
      Fail "Image '$($entry.id)' is not pinned to a sha256 digest ('$($entry.image)') but -RequireSignedImages was set."
    }
    if ($RequireSignedImages -and (Test-DigestImage $entry.image)) {
      Verify-CosignSignature $entry.image
    }
  }
}

function Write-ReleaseReport([string]$DesiredImage) {
  $resolvedReportDir = if ([System.IO.Path]::IsPathRooted($ReportDir)) { $ReportDir } else { Join-Path $Root $ReportDir }
  New-Item -ItemType Directory -Force -Path $resolvedReportDir | Out-Null
  $summary = [pscustomobject][ordered]@{
    generatedAt = $GeneratedAt.ToUniversalTime().ToString("o")
    desiredImage = $DesiredImage
    requireUpstream = [bool]$RequireUpstream
    requireLiveBrowser = [bool]$RequireLiveBrowser
    requireRemoteImages = [bool]$RequireRemoteImages
    requireSignedImages = [bool]$RequireSignedImages
    cosignKeyRef = $CosignKeyRef
    cosignIdentity = $CosignIdentity
    cosignIssuer = $CosignIssuer
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
  $lines.Add("- Require live browser: $RequireLiveBrowser")
  $lines.Add("- Require remote images: $RequireRemoteImages")
  $lines.Add("- Require signed images: $RequireSignedImages")
  $lines.Add("- Cosign key ref: ``$CosignKeyRef``")
  $lines.Add("- Cosign identity: ``$CosignIdentity``")
  $lines.Add("- Cosign issuer: ``$CosignIssuer``")
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
  $desiredImage = "unknown"
  if ($repositoryMatch.Success -and $digestMatch.Success) {
    $repo = $repositoryMatch.Groups[1].Value
    $digest = $digestMatch.Groups[1].Value
    $desiredImage = if ($digest.StartsWith("sha256:")) { "$repo@$digest" } else { "$repo`:$digest" }
  }
  Write-Output "[oah-release] desiredImage=$desiredImage requireUpstream=$RequireUpstream requireLiveBrowser=$RequireLiveBrowser requireRemoteImages=$RequireRemoteImages requireSignedImages=$RequireSignedImages skipLocalBuild=$SkipLocalBuild"

  Run-Step "image-policy" {
    Verify-ImagePolicy $desiredImage
  }

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
