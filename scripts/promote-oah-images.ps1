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
  [switch]$SignImages,
  [switch]$VerifySignatures,
  [string]$CosignKeyRef = "",
  [string]$CosignIdentity = "",
  [string]$CosignIssuer = "",
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

function Require-Cosign() {
  $cmd = Resolve-CosignCommand
  if (-not $cmd) {
    Fail "cosign was not found. Install cosign or run without -SignImages/-VerifySignatures."
  }
}

function Invoke-Cosign([string[]]$ArgsList) {
  Write-Output "[oah-promote] cosign $($ArgsList -join ' ')"
  $cosign = Require-Cosign
  & $cosign @ArgsList
  if ($LASTEXITCODE -ne 0) {
    Fail "cosign $($ArgsList -join ' ') failed with exit code $LASTEXITCODE."
  }
}

function Sign-Image([string]$PinnedRef) {
  Require-Cosign
  if ($CosignKeyRef) {
    Invoke-Cosign @("sign", "--yes", "--key", $CosignKeyRef, $PinnedRef)
  } else {
    Invoke-Cosign @("sign", "--yes", $PinnedRef)
  }
}

function Verify-ImageSignature([string]$PinnedRef) {
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
  $args.Add($PinnedRef)
  Invoke-Cosign $args.ToArray()
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
  Write-Output "[oah-promote] dryRun=$DryRun updateManifests=$UpdateManifests signImages=$SignImages verifySignatures=$VerifySignatures"

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

  $signatureStatus = [ordered]@{
    requested = [bool]$SignImages
    verificationRequested = [bool]$VerifySignatures
    mode = $(if ($CosignKeyRef) { "key" } else { "keyless" })
    ai = "NotRequested"
    controller = "NotRequested"
  }
  if (($SignImages -or $VerifySignatures) -and $DryRun) {
    $signatureStatus.ai = "Planned"
    $signatureStatus.controller = "Planned"
    Write-Output "[oah-promote] dry-run signature plan uses cosign against digest refs after push"
  } else {
    if ($SignImages) {
      Sign-Image $aiPinned
      Sign-Image $controllerPinned
      $signatureStatus.ai = "Signed"
      $signatureStatus.controller = "Signed"
    }
    if ($VerifySignatures) {
      Verify-ImageSignature $aiPinned
      Verify-ImageSignature $controllerPinned
      $signatureStatus.ai = $(if ($SignImages) { "SignedAndVerified" } else { "Verified" })
      $signatureStatus.controller = $(if ($SignImages) { "SignedAndVerified" } else { "Verified" })
    }
  }

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
    signatures = [pscustomobject]$signatureStatus
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
  $lines.Add("")
  $lines.Add("## Signatures")
  $lines.Add("")
  $lines.Add("- Requested: $($signatureStatus.requested)")
  $lines.Add("- Verification requested: $($signatureStatus.verificationRequested)")
  $lines.Add("- Mode: ``$($signatureStatus.mode)``")
  $lines.Add("- AI shell: $($signatureStatus.ai)")
  $lines.Add("- DUPA controller: $($signatureStatus.controller)")
  $lines | Set-Content -LiteralPath $mdPath -Encoding UTF8

  Write-Output "[oah-promote] aiPinned=$aiPinned"
  Write-Output "[oah-promote] controllerPinned=$controllerPinned"
  Write-Output "[oah-promote] reportJson=$jsonPath"
  Write-Output "[oah-promote] reportMarkdown=$mdPath"
} finally {
  Pop-Location
}

