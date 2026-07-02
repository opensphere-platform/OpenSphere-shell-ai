param(
  [string]$ReportDir = "release-reports",
  [string]$Namespace = "opensphere-system",
  [string]$AiDeployment = "ai",
  [string]$ControllerDeployment = "dupa-registry-controller",
  [string]$InferenceService = "osinf-oah-serving-contract-smoke",
  [string]$DspaName = "oah-dspa",
  [string]$TargetRegistry = "ghcr.io",
  [switch]$RequireSignedImages,
  [switch]$AllowDevKey,
  [string]$CosignKeyRef = "",
  [string]$CosignIdentity = "",
  [string]$CosignIssuer = "",
  [string]$RequiredTokenIssuer = "https://auth.console.opensphere.dev/oauth2/openid/opensphere-console",
  [string]$RequiredTokenAudience = "opensphere-console",
  [switch]$RequireProductionReady
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$GeneratedAt = Get-Date
$Stamp = $GeneratedAt.ToUniversalTime().ToString("yyyyMMdd-HHmmss")
$Checks = New-Object System.Collections.Generic.List[object]

if ($RequireProductionReady -and -not $PSBoundParameters.ContainsKey("RequireSignedImages")) {
  $RequireSignedImages = $true
}
if (-not $PSBoundParameters.ContainsKey("CosignKeyRef") -and $env:OAH_COSIGN_KEY_REF) {
  $CosignKeyRef = $env:OAH_COSIGN_KEY_REF
}
if (-not $PSBoundParameters.ContainsKey("CosignIdentity") -and $env:OAH_COSIGN_IDENTITY) {
  $CosignIdentity = $env:OAH_COSIGN_IDENTITY
}
if (-not $PSBoundParameters.ContainsKey("CosignIssuer") -and $env:OAH_COSIGN_ISSUER) {
  $CosignIssuer = $env:OAH_COSIGN_ISSUER
}
if (-not $PSBoundParameters.ContainsKey("RequiredTokenIssuer") -and $env:OAH_REQUIRED_TOKEN_ISSUER) {
  $RequiredTokenIssuer = $env:OAH_REQUIRED_TOKEN_ISSUER
}
if (-not $PSBoundParameters.ContainsKey("RequiredTokenAudience") -and $env:OAH_REQUIRED_TOKEN_AUDIENCE) {
  $RequiredTokenAudience = $env:OAH_REQUIRED_TOKEN_AUDIENCE
}

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

function Test-LocalCosignKeyRef([string]$KeyRef) {
  if (-not $KeyRef) { return $false }
  if ($KeyRef -match '^(kms|awskms|azurekms|gcpkms|hashivault|k8s)://') { return $false }
  if ($KeyRef -match '^https?://') { return $false }
  return $true
}

function Add-LiveBrowserToken-Check() {
  if (-not $env:OAH_ID_TOKEN) {
    Add-Check "live-browser-token" "Blocked" "OAH_ID_TOKEN is not set." "Set OAH_ID_TOKEN in CI/release verification to enable authenticated live browser checks."
    return
  }
  try {
    $output = @(& node --use-system-ca scripts/verify-oah-id-token.js 2>&1)
    $text = ($output -join "`n")
    $jsonLine = @($output | Where-Object { "$_".Trim().StartsWith("{") } | Select-Object -Last 1)
    $result = if ($jsonLine) { ($jsonLine | ConvertFrom-Json) } else { $null }
    if ($LASTEXITCODE -ne 0 -or -not $result -or -not $result.ok) {
      $message = if ($result -and $result.error) { $result.error } elseif ($text) { $text } else { "token verifier failed" }
      Add-Check "live-browser-token" "Blocked" "$message" "Provide a valid signed JWT identity token with OAH authorization group claims."
      return
    }
    Add-Check "live-browser-token" "Ready" "OAH_ID_TOKEN verified: subject=$($result.subject) groups=$($result.groups) issuer=$($result.issuer) alg=$($result.alg) kid=$($result.kid) signatureVerified=$($result.signatureVerified)."
  } catch {
    Add-Check "live-browser-token" "Blocked" "OAH_ID_TOKEN is not usable: $($_.Exception.Message)" "Provide a valid JWT identity token with OAH authorization group claims."
  }
}

function Add-Signature-TrustRoot-Check() {
  if ($CosignIdentity -and $CosignIssuer) {
    Add-Check "image-signature-trust-root" "Ready" "Keyless/OIDC trust root configured: identity=$CosignIdentity issuer=$CosignIssuer"
    return
  }
  if ($CosignKeyRef) {
    if (Test-LocalCosignKeyRef $CosignKeyRef) {
      if ($AllowDevKey -and -not $RequireProductionReady) {
        Add-Check "image-signature-trust-root" "Warning" "Local cosign key ref is allowed only for this non-production preflight: $CosignKeyRef" "Use keyless/OIDC or KMS-backed CosignKeyRef for production."
      } else {
        Add-Check "image-signature-trust-root" "Blocked" "Local cosign key ref is not an operating trust root: $CosignKeyRef" "Use keyless/OIDC or KMS-backed CosignKeyRef."
      }
    } else {
      Add-Check "image-signature-trust-root" "Ready" "KMS/remote cosign trust root configured: $CosignKeyRef"
    }
    return
  }
  if ($RequireSignedImages -or $RequireProductionReady) {
    Add-Check "image-signature-trust-root" "Blocked" "No cosign trust root is configured." "Provide -CosignIdentity and -CosignIssuer for keyless verification, or a KMS-backed -CosignKeyRef."
  } else {
    Add-Check "image-signature-trust-root" "Warning" "Image signature trust root is not configured for this audit preflight." "Run production preflight with -RequireProductionReady and keyless/OIDC or KMS-backed trust root."
  }
}

function Add-Image-Check([string]$Id, [string]$Image, [string]$NextAction) {
  if (-not $Image) {
    Add-Check $Id "Blocked" "Image is missing." $NextAction
  } elseif (Test-LocalImage $Image) {
    Add-Check $Id "Blocked" "Image uses local registry: $Image" $NextAction
  } elseif (Test-DigestImage $Image) {
    Add-Check $Id "Ready" "Image is remote digest pinned: $Image"
  } else {
    Add-Check $Id "Blocked" "Image is not digest pinned: $Image" $NextAction
  }
}

function Add-Deployment-Image-Checks($Deployment, [string]$Prefix) {
  if (-not $Deployment) { return }
  $name = $Deployment.metadata.name
  $containers = @()
  if ($Deployment.spec.template.spec.containers) { $containers = @($Deployment.spec.template.spec.containers) }
  foreach ($container in $containers) {
    Add-Image-Check "$Prefix-$name-container-$($container.name)" "$($container.image)" "Pin and sign every live container image before production release."
  }
  $initContainers = @()
  if ($Deployment.spec.template.spec.initContainers) { $initContainers = @($Deployment.spec.template.spec.initContainers) }
  foreach ($container in $initContainers) {
    Add-Image-Check "$Prefix-$name-init-$($container.name)" "$($container.image)" "Pin and sign every live initContainer image before production release."
  }
}

function Add-Dspa-Deployment-Image-Checks() {
  $deployments = Kube-Json @("get", "deploy", "-n", $Namespace)
  if (-not $deployments) {
    Add-Check "dspa-live-deployments-readable" "Blocked" "Unable to list deployments in namespace '$Namespace'." "Grant the release runner read access to deployments and rerun production preflight."
    return
  }
  if (-not $deployments.items) {
    Add-Check "dspa-live-deployments-readable" "Blocked" "Deployment list in namespace '$Namespace' did not include an items array." "Repair kubectl/API response and rerun production preflight."
    return
  }
  $matched = 0
  foreach ($deployment in @($deployments.items)) {
    $name = "$($deployment.metadata.name)"
    if ($name -like "ds-pipeline*" -or $name -like "*$DspaName*") {
      $matched++
      Add-Deployment-Image-Checks $deployment "dspa-live"
    }
  }
  if ($matched -eq 0) {
    Add-Check "dspa-live-deployments-present" "Blocked" "No DSPA runtime deployments matched 'ds-pipeline*' or '*$DspaName*' in namespace '$Namespace'." "Apply or repair the DSPA runtime before production release."
  }
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
  Add-Signature-TrustRoot-Check

  $packageText = Get-Content -Raw "uipluginpackage.yaml"
  $repositoryMatch = [regex]::Match($packageText, "(?m)^\s*repository:\s*(\S+)\s*$")
  $digestMatch = [regex]::Match($packageText, "(?m)^\s*digest:\s*(\S+)\s*$")
  $desiredImage = "unknown"
  if ($repositoryMatch.Success -and $digestMatch.Success) {
    $repo = $repositoryMatch.Groups[1].Value
    $digest = $digestMatch.Groups[1].Value
    $desiredImage = if ($digest.StartsWith("sha256:")) { "$repo@$digest" } else { "$repo`:$digest" }
  }

  Add-Image-Check "package-image-remote" $desiredImage "Promote the image with release:promote-images and update manifests to a remote digest."

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
    Add-Deployment-Image-Checks $ai "core"
  } else {
    Add-Check "cluster-ai-deployment" "Blocked" "$Namespace/$AiDeployment is not ready." "Restore the AI shell deployment before release verification."
  }

  $controller = Kube-Json @("get", "deploy", $ControllerDeployment, "-n", $Namespace)
  if ($controller -and $controller.status.readyReplicas -ge 1) {
    Add-Check "cluster-controller-deployment" "Ready" "$Namespace/$ControllerDeployment ready=$($controller.status.readyReplicas)/$($controller.spec.replicas) image=$($controller.spec.template.spec.containers[0].image)"
    Add-Deployment-Image-Checks $controller "core"
  } else {
    Add-Check "cluster-controller-deployment" "Blocked" "$Namespace/$ControllerDeployment is not ready." "Restore the DUPA registry controller before release verification."
  }

  $dspa = Kube-Json @("get", "dspa", $DspaName, "-n", $Namespace)
  if ($dspa) {
    Add-Image-Check "dspa-api-server-image" "$($dspa.spec.apiServer.image)" "Promote the DSPA API server image to a remote sha256 digest and reapply the DSPA manifest."
    Add-Image-Check "dspa-mlmd-grpc-image" "$($dspa.spec.mlmd.grpc.image)" "Promote the DSPA MLMD gRPC wrapper image to a remote sha256 digest and reapply the DSPA manifest."
    Add-Image-Check "dspa-mlmd-envoy-image" "$($dspa.spec.mlmd.envoy.image)" "Pin the DSPA MLMD envoy image to a remote sha256 digest and reapply the DSPA manifest."
    Add-Dspa-Deployment-Image-Checks
  } else {
    Add-Check "dspa-runtime" "Blocked" "$Namespace/$DspaName was not found." "Apply the OAH DSPA runtime before production release."
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

  Add-LiveBrowserToken-Check

  $blocked = @($Checks.ToArray() | Where-Object { $_.status -eq "Blocked" })
  $phase = if ($blocked.Count -eq 0) { "Ready" } else { "Blocked" }

  $resolvedReportDir = if ([System.IO.Path]::IsPathRooted($ReportDir)) { $ReportDir } else { Join-Path $Root $ReportDir }
  New-Item -ItemType Directory -Force -Path $resolvedReportDir | Out-Null
  $summary = [pscustomobject][ordered]@{
    generatedAt = $GeneratedAt.ToUniversalTime().ToString("o")
    phase = $phase
    requireProductionReady = [bool]$RequireProductionReady
    requireSignedImages = [bool]$RequireSignedImages
    cosignKeyRef = $CosignKeyRef
    cosignIdentity = $CosignIdentity
    cosignIssuer = $CosignIssuer
    requiredTokenIssuer = $RequiredTokenIssuer
    requiredTokenAudience = $RequiredTokenAudience
    allowDevKey = [bool]$AllowDevKey
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
