param(
  [string]$TargetRegistry = "ghcr.io",
  [string]$TargetNamespace = "opensphere-platform",
  [string]$ReleaseTag = "",
  [string]$AiSourceImage = "localhost:5000/ai:v203",
  [string]$ControllerSourceImage = "localhost:5000/dupa-registry-controller:bb21",
  [string]$AiRepository = "",
  [string]$ControllerRepository = "",
  [string]$PackagePath = "uipluginpackage.yaml",
  [string]$ControllerDeploymentPath = "..\OpenSphere-console\backend\dupa-control\dupa-registry-controller.yaml",
  [string]$ReportDir = "release-reports",
  [switch]$DryRun,
  [switch]$UpdateManifests
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$GeneratedAt = Get-Date
$Stamp = $GeneratedAt.ToUniversalTime().ToString("yyyyMMdd-HHmmss")

function Fail([string]$Message) {
  Write-Error "[oah-promote] $Message"
  exit 1
}

function Normalize-Path([string]$PathValue) {
  if ([System.IO.Path]::IsPathRooted($PathValue)) {
    return $PathValue
  }
  return Join-Path $Root $PathValue
}

function Require-Image([string]$Image) {
  & docker image inspect $Image *> $null
  if ($LASTEXITCODE -ne 0) {
    Fail "Source image '$Image' was not found locally."
  }
}

function Invoke-Docker([string[]]$ArgsList) {
  Write-Output "[oah-promote] docker $($ArgsList -join ' ')"
  & docker @ArgsList
  if ($LASTEXITCODE -ne 0) {
    Fail "docker $($ArgsList -join ' ') failed with exit code $LASTEXITCODE."
  }
}

function Push-Image([string]$Source, [string]$Target) {
  Invoke-Docker @("tag", $Source, $Target)
  Write-Output "[oah-promote] docker push $Target"
  $pushOutput = @(& docker push $Target 2>&1)
  foreach ($line in $pushOutput) {
    Write-Output $line
  }
  if ($LASTEXITCODE -ne 0) {
    Fail "docker push $Target failed with exit code $LASTEXITCODE."
  }
  $digestLine = @($pushOutput | Where-Object { "$_" -match "digest:\s*(sha256:[a-fA-F0-9]{64})" } | Select-Object -Last 1)[0]
  if (-not $digestLine -or "$digestLine" -notmatch "digest:\s*(sha256:[a-fA-F0-9]{64})") {
    Fail "Could not parse pushed digest for '$Target'."
  }
  return $Matches[1]
}

function Replace-RegexFile([string]$PathValue, [string]$Pattern, [string]$Replacement) {
  $text = Get-Content -Raw -LiteralPath $PathValue
  $updated = [regex]::Replace($text, $Pattern, $Replacement)
  if ($updated -eq $text) {
    Fail "No manifest change was made for pattern '$Pattern' in '$PathValue'."
  }
  Set-Content -LiteralPath $PathValue -Value $updated -Encoding UTF8
}

Push-Location $Root
try {
  if (-not $ReleaseTag) {
    $ReleaseTag = "release-$Stamp"
  }
  if (-not $AiRepository) {
    $AiRepository = "$TargetRegistry/$TargetNamespace/ai"
  }
  if (-not $ControllerRepository) {
    $ControllerRepository = "$TargetRegistry/$TargetNamespace/dupa-registry-controller"
  }

  $aiTarget = "$AiRepository`:$ReleaseTag"
  $controllerTarget = "$ControllerRepository`:$ReleaseTag"
  $reportPath = Normalize-Path $ReportDir
  New-Item -ItemType Directory -Force -Path $reportPath | Out-Null

  Require-Image $AiSourceImage
  Require-Image $ControllerSourceImage

  Write-Output "[oah-promote] aiSource=$AiSourceImage aiTarget=$aiTarget"
  Write-Output "[oah-promote] controllerSource=$ControllerSourceImage controllerTarget=$controllerTarget"
  Write-Output "[oah-promote] dryRun=$DryRun updateManifests=$UpdateManifests"

  $aiDigest = ""
  $controllerDigest = ""
  if ($DryRun) {
    $aiDigest = "sha256:DRYRUN_AI_DIGEST_REPLACE_AFTER_PUSH"
    $controllerDigest = "sha256:DRYRUN_CONTROLLER_DIGEST_REPLACE_AFTER_PUSH"
  } else {
    $aiDigest = Push-Image $AiSourceImage $aiTarget
    $controllerDigest = Push-Image $ControllerSourceImage $controllerTarget
  }

  $aiPinned = "$AiRepository@$aiDigest"
  $controllerPinned = "$ControllerRepository@$controllerDigest"

  if ($UpdateManifests) {
    if ($DryRun) {
      Fail "-UpdateManifests cannot be used with -DryRun because dry-run digests are placeholders."
    }
    $packageFile = Normalize-Path $PackagePath
    $controllerFile = Normalize-Path $ControllerDeploymentPath
    Replace-RegexFile $packageFile "(?ms)(image:\s*\r?\n\s*repository:\s*)\S+(\s*\r?\n\s*digest:\s*)\S+" "`${1}$AiRepository`${2}$aiDigest"
    Replace-RegexFile $controllerFile "image:\s*\S+/dupa-registry-controller(?::[^\s]+|@sha256:[a-fA-F0-9]{64})" "image: $controllerPinned"
    Write-Output "[oah-promote] manifests updated package=$packageFile controller=$controllerFile"
  }

  $summary = [pscustomobject][ordered]@{
    generatedAt = $GeneratedAt.ToUniversalTime().ToString("o")
    dryRun = [bool]$DryRun
    releaseTag = $ReleaseTag
    ai = [pscustomobject][ordered]@{
      source = $AiSourceImage
      target = $aiTarget
      digest = $aiDigest
      pinned = $aiPinned
    }
    controller = [pscustomobject][ordered]@{
      source = $ControllerSourceImage
      target = $controllerTarget
      digest = $controllerDigest
      pinned = $controllerPinned
    }
    updateManifests = [bool]$UpdateManifests
  }
  $jsonPath = Join-Path $reportPath "oah-image-promotion-$Stamp.json"
  $mdPath = Join-Path $reportPath "oah-image-promotion-$Stamp.md"
  $summary | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

  $lines = New-Object System.Collections.Generic.List[string]
  $lines.Add("# OAH Image Promotion")
  $lines.Add("")
  $lines.Add("- Generated: $($summary.generatedAt)")
  $lines.Add("- Dry run: $DryRun")
  $lines.Add("- Release tag: ``$ReleaseTag``")
  $lines.Add("")
  $lines.Add("| Component | Source | Target | Pinned |")
  $lines.Add("|---|---|---|---|")
  $lines.Add("| AI shell | ``$AiSourceImage`` | ``$aiTarget`` | ``$aiPinned`` |")
  $lines.Add("| DUPA controller | ``$ControllerSourceImage`` | ``$controllerTarget`` | ``$controllerPinned`` |")
  $lines | Set-Content -LiteralPath $mdPath -Encoding UTF8

  Write-Output "[oah-promote] aiPinned=$aiPinned"
  Write-Output "[oah-promote] controllerPinned=$controllerPinned"
  Write-Output "[oah-promote] reportJson=$jsonPath"
  Write-Output "[oah-promote] reportMarkdown=$mdPath"
} finally {
  Pop-Location
}
