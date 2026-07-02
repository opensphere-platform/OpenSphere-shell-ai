param(
  [string]$ReportDir = "release-reports",
  [string]$Namespace = "opensphere-system",
  [string]$AiDeployment = "ai",
  [string]$ControllerDeployment = "dupa-registry-controller",
  [string]$InferenceService = "osinf-oah-serving-contract-smoke",
  [string]$TargetRegistry = "ghcr.io",
  [switch]$RequireProductionReady
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$GeneratedAt = Get-Date
$Stamp = $GeneratedAt.ToUniversalTime().ToString("yyyyMMdd-HHmmss")
$Checks = New-Object System.Collections.Generic.List[object]

function Add-Check([string]$Id, [string]$Status, [string]$Evidence, [string]$NextAction = "") {
  $Checks.Add([pscustomobject][ordered]@{
    id = $Id
    status = $Status
    evidence = $Evidence
    nextAction = $NextAction
  })
  Write-Output "[oah-preflight] $Id=$Status evidence=$Evidence"
}

function Command-Exists([string]$Name) {
  return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Resolve-CosignCommand() {
  foreach ($name in @("cosign", "cosign-windows-amd64")) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
  }
  $wingetPath = Join-Path $env:LOCALAPPDATA "Microsoft\WinGet\Packages\Sigstore.Cosign_Microsoft.Winget.Source_8wekyb3d8bbwe\cosign-windows-amd64.exe"
  if (Test-Path -LiteralPath $wingetPath) { return $wingetPath }
  $wingetRoot = Join-Path $env:LOCALAPPDATA "Microsoft\WinGet\Packages"
  if (Test-Path -LiteralPath $wingetRoot) {
    $match = Get-ChildItem $wingetRoot -Recurse -File -Filter "cosign*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($match) { return $match.FullName }
  }
  return $null
}

function Invoke-Text([scriptblock]$Command) {
  try {
    $global:LASTEXITCODE = 0
    $output = @(& $Command 2>&1)
    if ($LASTEXITCODE -ne 0) {
      return $null
    }
    return ($output -join "`n")
  } catch {
    return $null
  }
}

function Kube-Json([string[]]$ArgsList) {
  $text = Invoke-Text { kubectl @ArgsList -o json }
  if (-not $text) { return $null }
  try { return $text | ConvertFrom-Json } catch { return $null }
}

function Test-LocalImage([string]$Image) {
  return $Image -match '^(localhost|127\.0\.0\.1|\[::1\])(:|/)'
}

function Test-DigestImage([string]$Image) {
  return $Image -match '@sha256:[a-fA-F0-9]{64}$'
}

function Docker-Image-Exists([string]$Image) {
  Invoke-Text { docker image inspect $Image } | Out-Null
  return $LASTEXITCODE -eq 0
}

function Docker-Registry-Auth([string]$Registry) {
  $configPath = Join-Path $env:USERPROFILE ".docker\config.json"
  if (-not (Test-Path -LiteralPath $configPath)) { return $false }
  try {
    $config = Get-Content -Raw -LiteralPath $configPath | ConvertFrom-Json
    return [bool]($config.auths.PSObject.Properties.Name -contains $Registry)
  } catch {
    return $false
  }
}

Push-Location $Root
try {
  foreach ($tool in @("kubectl", "docker", "node", "npm.cmd", "powershell")) {
    if (Command-Exists $tool) {
      Add-Check "tool-$tool" "Ready" "$tool is available."
    } else {
      Add-Check "tool-$tool" "Blocked" "$tool is missing." "Install $tool on the release runner."
    }
  }

  $cosign = Resolve-CosignCommand
  if ($cosign) {
    Add-Check "tool-cosign" "Ready" "cosign is available for image signature verification: $cosign"
  } else {
    Add-Check "tool-cosign" "Blocked" "cosign is missing." "Install cosign before running -SignImages or -RequireSignedImages."
  }

  $packageText = Get-Content -Raw "uipluginpackage.yaml"
  $repositoryMatch = [regex]::Match($packageText, "(?m)^\s*repository:\s*(\S+)\s*$")
  $digestMatch = [regex]::Match($packageText, "(?m)^\s*digest:\s*(\S+)\s*$")
  $desiredImage = "unknown"
  if ($repositoryMatch.Success -and $digestMatch.Success) {
    $repo = $repositoryMatch.Groups[1].Value
    $digest = $digestMatch.Groups[1].Value
    $desiredImage = if ($digest.StartsWith("sha256:")) { "$repo@$digest" } else { "$repo`:$digest" }
  }

  if (Test-LocalImage $desiredImage) {
    Add-Check "package-image-remote" "Blocked" "UIPluginPackage image is local: $desiredImage" "Promote the image with release:promote-images and update manifests to a remote digest."
  } elseif (Test-DigestImage $desiredImage) {
    Add-Check "package-image-remote" "Ready" "UIPluginPackage image is remote digest pinned: $desiredImage"
  } else {
    Add-Check "package-image-remote" "Blocked" "UIPluginPackage image is not digest pinned: $desiredImage" "Use repo@sha256 digest references for production."
  }

  if (Docker-Registry-Auth $TargetRegistry) {
    Add-Check "registry-auth" "Ready" "Docker config has an auth entry for $TargetRegistry."
  } else {
    Add-Check "registry-auth" "Blocked" "Docker config has no auth entry for $TargetRegistry." "Run docker login $TargetRegistry on the release runner."
  }

  foreach ($image in @("localhost:5000/ai:v203", "localhost:5000/dupa-registry-controller:bb22")) {
    if (Docker-Image-Exists $image) {
      Add-Check "local-image-$image" "Ready" "$image exists locally for promotion."
    } else {
      Add-Check "local-image-$image" "Blocked" "$image was not found locally." "Build or pull the source image before promotion."
    }
  }

  $ai = Kube-Json @("get", "deploy", $AiDeployment, "-n", $Namespace)
  if ($ai -and $ai.status.readyReplicas -ge 1) {
    Add-Check "cluster-ai-deployment" "Ready" "$Namespace/$AiDeployment ready=$($ai.status.readyReplicas)/$($ai.spec.replicas) image=$($ai.spec.template.spec.containers[0].image)"
  } else {
    Add-Check "cluster-ai-deployment" "Blocked" "$Namespace/$AiDeployment is not ready." "Restore the AI shell deployment before release verification."
  }

  $controller = Kube-Json @("get", "deploy", $ControllerDeployment, "-n", $Namespace)
  if ($controller -and $controller.status.readyReplicas -ge 1) {
    Add-Check "cluster-controller-deployment" "Ready" "$Namespace/$ControllerDeployment ready=$($controller.status.readyReplicas)/$($controller.spec.replicas) image=$($controller.spec.template.spec.containers[0].image)"
  } else {
    Add-Check "cluster-controller-deployment" "Blocked" "$Namespace/$ControllerDeployment is not ready." "Restore the DUPA registry controller before release verification."
  }

  $isvc = Kube-Json @("get", "inferenceservice", $InferenceService, "-n", $Namespace)
  $isvcReady = $false
  if ($isvc) {
    foreach ($condition in @($isvc.status.conditions)) {
      if ($condition.type -eq "Ready" -and $condition.status -eq "True") { $isvcReady = $true }
    }
  }
  if ($isvcReady) {
    Add-Check "serving-contract" "Ready" "$Namespace/$InferenceService is Ready; latestReadyRevision=$($isvc.status.components.predictor.latestReadyRevision)."
  } else {
    Add-Check "serving-contract" "Blocked" "$Namespace/$InferenceService is not Ready." "Repair KServe/Knative serving and rerun product-flow verification."
  }

  if ($env:OAH_ID_TOKEN) {
    Add-Check "live-browser-token" "Ready" "OAH_ID_TOKEN is present for authenticated browser verification."
  } else {
    Add-Check "live-browser-token" "Blocked" "OAH_ID_TOKEN is not set." "Set OAH_ID_TOKEN in CI/release verification to enable authenticated live browser checks."
  }

  $blocked = @($Checks.ToArray() | Where-Object { $_.status -eq "Blocked" })
  $phase = if ($blocked.Count -eq 0) { "Ready" } else { "Blocked" }

  $resolvedReportDir = if ([System.IO.Path]::IsPathRooted($ReportDir)) { $ReportDir } else { Join-Path $Root $ReportDir }
  New-Item -ItemType Directory -Force -Path $resolvedReportDir | Out-Null
  $summary = [pscustomobject][ordered]@{
    generatedAt = $GeneratedAt.ToUniversalTime().ToString("o")
    phase = $phase
    requireProductionReady = [bool]$RequireProductionReady
    namespace = $Namespace
    targetRegistry = $TargetRegistry
    checksTotal = [int]$Checks.Count
    checksBlocked = [int]$blocked.Count
    checks = @($Checks.ToArray())
  }
  $jsonPath = Join-Path $resolvedReportDir "oah-production-preflight-$Stamp.json"
  $mdPath = Join-Path $resolvedReportDir "oah-production-preflight-$Stamp.md"
  $summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

  $lines = New-Object System.Collections.Generic.List[string]
  $lines.Add("# OAH Production Preflight")
  $lines.Add("")
  $lines.Add("- Generated: $($summary.generatedAt)")
  $lines.Add("- Phase: $phase")
  $lines.Add("- Target registry: ``$TargetRegistry``")
  $lines.Add("- Blocked checks: $($blocked.Count)")
  $lines.Add("")
  $lines.Add("| Check | Status | Evidence | Next action |")
  $lines.Add("|---|---|---|---|")
  foreach ($check in $Checks) {
    $lines.Add("| $($check.id) | $($check.status) | $($check.evidence.Replace('|','/')) | $($check.nextAction.Replace('|','/')) |")
  }
  $lines | Set-Content -LiteralPath $mdPath -Encoding UTF8
  Write-Output "[oah-preflight] phase=$phase blocked=$($blocked.Count)"
  Write-Output "[oah-preflight] reportJson=$jsonPath"
  Write-Output "[oah-preflight] reportMarkdown=$mdPath"

  if ($RequireProductionReady -and $blocked.Count -gt 0) {
    Write-Error "[oah-preflight] production preflight blocked by $($blocked.Count) check(s)."
    exit 1
  }
} finally {
  Pop-Location
}
