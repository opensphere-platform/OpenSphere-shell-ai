param(
  [switch]$RequireUpstream,
  [switch]$RequireLiveBrowser,
  [switch]$RequireRemoteImages,
  [switch]$RequireSignedImages,
  [switch]$AllowUnsignedImages,
  [switch]$AllowDevKey,
  [switch]$SkipLocalBuild,
  [string]$ReportDir = "release-reports",
  [string]$Namespace = "opensphere-system",
  [string]$CosignKeyRef = "",
  [string]$CosignIdentity = "",
  [string]$CosignIssuer = "",
  [string]$AiDeployment = "ai",
  [string]$ControllerDeployment = "dupa-registry-controller",
  [string]$DspaName = "oah-dspa"
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$GeneratedAt = Get-Date
$ReportStamp = $GeneratedAt.ToUniversalTime().ToString("yyyyMMdd-HHmmss")
$StepResults = New-Object System.Collections.Generic.List[object]

if (-not $PSBoundParameters.ContainsKey("RequireRemoteImages")) { $RequireRemoteImages = $true }
if (-not $PSBoundParameters.ContainsKey("RequireLiveBrowser")) { $RequireLiveBrowser = $true }
if ($AllowUnsignedImages) {
  $RequireSignedImages = $false
} elseif (-not $PSBoundParameters.ContainsKey("RequireSignedImages")) {
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

function Kube-JsonRequired([string]$Description, [string[]]$ArgsList) {
  $value = Kube-Json $ArgsList
  if (-not $value) {
    Fail "Unable to read $Description with kubectl $($ArgsList -join ' '). Release verification cannot continue without live cluster evidence."
  }
  return $value
}

function Test-LocalImage([string]$Image) {
  return $Image -match '^(localhost|127\.0\.0\.1|\[::1\])(:|/)'
}

function Test-DigestImage([string]$Image) {
  return $Image -match '@sha256:[a-fA-F0-9]{64}$'
}

function Add-ImageEntry([System.Collections.Generic.List[object]]$Images, [string]$Id, [string]$Image) {
  if (-not $Image) { return }
  $Images.Add([pscustomobject]@{ id = $Id; image = $Image }) | Out-Null
}

function Add-DeploymentImages([System.Collections.Generic.List[object]]$Images, $Deployment, [string]$Prefix) {
  if (-not $Deployment) { return }
  $name = $Deployment.metadata.name
  $containers = @()
  if ($Deployment.spec.template.spec.containers) { $containers = @($Deployment.spec.template.spec.containers) }
  for ($i = 0; $i -lt $containers.Count; $i++) {
    Add-ImageEntry $Images "$Prefix/$name/container/$($containers[$i].name)" "$($containers[$i].image)"
  }
  $initContainers = @()
  if ($Deployment.spec.template.spec.initContainers) { $initContainers = @($Deployment.spec.template.spec.initContainers) }
  for ($i = 0; $i -lt $initContainers.Count; $i++) {
    Add-ImageEntry $Images "$Prefix/$name/initContainer/$($initContainers[$i].name)" "$($initContainers[$i].image)"
  }
}

function Add-DspaDeploymentImages([System.Collections.Generic.List[object]]$Images) {
  $deployments = Kube-JsonRequired "$Namespace deployment list for DSPA runtime image policy" @("get", "deploy", "-n", $Namespace)
  if (-not $deployments.items) {
    Fail "Deployment list in namespace '$Namespace' did not include an items array. Release verification cannot prove DSPA runtime images."
  }
  $matched = 0
  foreach ($deployment in @($deployments.items)) {
    $name = "$($deployment.metadata.name)"
    if ($name -like "ds-pipeline*" -or $name -like "*$DspaName*") {
      $matched++
      Add-DeploymentImages $Images $deployment "dspa-live"
    }
  }
  if ($matched -eq 0) {
    Fail "No DSPA runtime deployments matched 'ds-pipeline*' or '*$DspaName*' in namespace '$Namespace'. Release verification cannot prove live DSPA sidecar images."
  }
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
    Fail "cosign was not found. Install cosign or run without -RequireSignedImages."
  }
  return $cmd
}

function Invoke-Cosign([string[]]$ArgsList) {
  Write-Output "[oah-release] cosign $($ArgsList -join ' ')"
  $cosign = Require-Cosign
  $psi = [System.Diagnostics.ProcessStartInfo]::new()
  $psi.FileName = $cosign
  $psi.Arguments = (($ArgsList | ForEach-Object {
    if ($_ -match '\s') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
  }) -join ' ')
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.UseShellExecute = $false
  $process = [System.Diagnostics.Process]::Start($psi)
  $stdout = $process.StandardOutput.ReadToEnd()
  $stderr = $process.StandardError.ReadToEnd()
  $process.WaitForExit()
  $exit = $process.ExitCode
  foreach ($line in (($stdout + "`n" + $stderr) -split "`r?`n")) {
    if ($line) { Write-Output $line }
  }
  if ($exit -ne 0) {
    Fail "cosign $($ArgsList -join ' ') failed with exit code $exit."
  }
}

function Test-LocalCosignKeyRef([string]$KeyRef) {
  if (-not $KeyRef) { return $false }
  if ($KeyRef -match '^(kms|awskms|azurekms|gcpkms|hashivault|k8s)://') { return $false }
  if ($KeyRef -match '^https?://') { return $false }
  return $true
}

function Verify-CosignSignature([string]$Image) {
  Require-Cosign
  if (-not $CosignKeyRef -and (-not $CosignIdentity -or -not $CosignIssuer)) {
    Fail "Signed image verification requires -CosignKeyRef or both -CosignIdentity and -CosignIssuer. Use -AllowUnsignedImages only for explicit non-production audit runs."
  }
  $args = New-Object System.Collections.Generic.List[string]
  $args.Add("verify")
  if ($CosignKeyRef) {
    if ((Test-LocalCosignKeyRef $CosignKeyRef) -and -not $AllowDevKey) {
      Fail "Local cosign key references are not accepted for production release verification. Use keyless -CosignIdentity/-CosignIssuer or a KMS-backed -CosignKeyRef, or pass -AllowDevKey only for explicit non-production audit runs."
    }
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
  $ai = Kube-JsonRequired "$Namespace/$AiDeployment deployment" @("get", "deploy", $AiDeployment, "-n", $Namespace)
  $controller = Kube-JsonRequired "$Namespace/$ControllerDeployment deployment" @("get", "deploy", $ControllerDeployment, "-n", $Namespace)
  $dspa = Kube-JsonRequired "$Namespace/$DspaName DSPA" @("get", "dspa", $DspaName, "-n", $Namespace)
  $images = New-Object System.Collections.Generic.List[object]
  Add-ImageEntry $images "package" $DesiredImage
  Add-DeploymentImages $images $ai "core"
  Add-DeploymentImages $images $controller "core"
  Add-ImageEntry $images "dspa-api-server" "$($dspa.spec.apiServer.image)"
  Add-ImageEntry $images "dspa-mlmd-grpc" "$($dspa.spec.mlmd.grpc.image)"
  Add-ImageEntry $images "dspa-spec/mlmd-envoy" "$($dspa.spec.mlmd.envoy.image)"
  Add-DspaDeploymentImages $images

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
    allowDevKey = [bool]$AllowDevKey
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
  $lines.Add("- Allow dev key: $AllowDevKey")
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
