param(
  [string]$Namespace = "opensphere-system",
  [string]$DspaName = "oah-dspa",
  [string]$OdhNamespace = "opendatahub",
  [string]$KserveNamespace = "kserve",
  [string]$KnativeNamespace = "knative-serving",
  [switch]$RequireAll
)

$ErrorActionPreference = "Stop"

function KubeJson([string[]]$ArgsList) {
  try {
    $output = & kubectl @ArgsList -o json 2>$null
  } catch {
    return $null
  }
  if ($LASTEXITCODE -ne 0 -or -not $output) {
    return $null
  }
  try {
    return $output | ConvertFrom-Json
  } catch {
    return $null
  }
}

function KubeText([string[]]$ArgsList) {
  try {
    $output = & kubectl @ArgsList 2>$null
  } catch {
    return $null
  }
  if ($LASTEXITCODE -ne 0) {
    return $null
  }
  return ($output -join "`n")
}

function HasApiResource([string]$Name) {
  $resources = KubeText @("api-resources", "--no-headers")
  if (-not $resources) {
    return $false
  }
  return $resources -match "(?m)^$([regex]::Escape($Name))\s"
}

function HasCrd([string]$Name) {
  $crd = KubeJson @("get", "crd", $Name)
  return $null -ne $crd
}

function PodsReady([string]$NamespaceName, [string]$LabelSelector = "") {
  $args = @("get", "pods", "-n", $NamespaceName)
  if ($LabelSelector) {
    $args += @("-l", $LabelSelector)
  }
  $pods = KubeJson $args
  if (-not $pods -or -not $pods.items) {
    return @{ Ready = $false; Count = 0; Detail = "no pods found" }
  }
  $items = @($pods.items)
  $notReady = @()
  foreach ($pod in $items) {
    $phase = [string]$pod.status.phase
    $readyCondition = @($pod.status.conditions | Where-Object { $_.type -eq "Ready" })[0]
    if ($phase -ne "Running" -or $readyCondition.status -ne "True") {
      $notReady += "$($pod.metadata.name):$phase/$($readyCondition.status)"
    }
  }
  return @{
    Ready = $notReady.Count -eq 0
    Count = $items.Count
    Detail = if ($notReady.Count) { $notReady -join ", " } else { "$($items.Count) pod(s) ready" }
  }
}

function ReadyCondition($Object) {
  if (-not $Object -or -not $Object.status -or -not $Object.status.conditions) {
    return $null
  }
  return @($Object.status.conditions | Where-Object { $_.type -eq "Ready" })[0]
}

function AddCheck([System.Collections.Generic.List[object]]$Checks, [string]$Id, [string]$Label, [string]$Status, [string]$Evidence, [string]$NextAction, [bool]$Required = $true) {
  $Checks.Add([pscustomobject]@{
    id = $Id
    label = $Label
    required = $Required
    status = $Status
    evidence = $Evidence
    nextAction = $NextAction
  })
}

$checks = [System.Collections.Generic.List[object]]::new()

$odhPods = PodsReady $OdhNamespace "app.kubernetes.io/name=data-science-pipelines-operator,pod-template-hash"
if ($odhPods.Count -gt 0) {
  AddCheck $checks "odh-namespace" "ODH/RHOAI operator namespace" ($(if ($odhPods.Ready) { "Ready" } else { "Warning" })) "$OdhNamespace namespace has $($odhPods.Detail)." "Keep operator pods healthy."
} else {
  AddCheck $checks "odh-namespace" "ODH/RHOAI operator namespace" "NotInstalled" "$OdhNamespace namespace or operator pods were not found." "Install ODH/RHOAI Operator or document native-only mode."
}

$hasDscCrd = HasCrd "datascienceclusters.datasciencecluster.opendatahub.io"
$dscItems = $null
if ($hasDscCrd) {
  $dscItems = KubeJson @("get", "datasciencecluster", "-A")
}
if ($hasDscCrd -and $dscItems -and @($dscItems.items).Count -gt 0) {
  $ready = @($dscItems.items | Where-Object { (ReadyCondition $_).status -eq "True" })
  AddCheck $checks "datasciencecluster" "DataScienceCluster" ($(if ($ready.Count -gt 0) { "Ready" } else { "Warning" })) "$($ready.Count)/$(@($dscItems.items).Count) DataScienceCluster resource(s) Ready." "Keep DataScienceCluster components aligned with OAH support services."
} elseif ($hasDscCrd) {
  AddCheck $checks "datasciencecluster" "DataScienceCluster" "Missing" "DataScienceCluster CRD exists but no instances were found." "Create a DataScienceCluster for upstream parity."
} else {
  AddCheck $checks "datasciencecluster" "DataScienceCluster" "NotInstalled" "DataScienceCluster CRD is not installed." "Install the ODH/RHOAI Operator and DataScienceCluster CRDs."
}

$hasDspaCrd = HasCrd "datasciencepipelinesapplications.datasciencepipelinesapplications.opendatahub.io"
$dspa = if ($hasDspaCrd) { KubeJson @("get", "dspa", $DspaName, "-n", $Namespace) } else { $null }
if ($dspa) {
  $readyCondition = ReadyCondition $dspa
  AddCheck $checks "dspa-kfp" "Data Science Pipelines / KFP" ($(if ($readyCondition.status -eq "True") { "Ready" } else { "Warning" })) "DSPA $Namespace/$DspaName Ready=$($readyCondition.status), MLMD image=$($dspa.spec.mlmd.grpc.image)." "Keep KFP API and PostgreSQL MLMD wrapper verified."
} elseif ($hasDspaCrd) {
  AddCheck $checks "dspa-kfp" "Data Science Pipelines / KFP" "Missing" "DSPA CRD exists but $Namespace/$DspaName was not found." "Create or repair the DSPA instance."
} else {
  AddCheck $checks "dspa-kfp" "Data Science Pipelines / KFP" "NotInstalled" "DSPA CRD is not installed." "Install Data Science Pipelines Operator."
}

$knativeCrdNames = @(
  "services.serving.knative.dev",
  "routes.serving.knative.dev",
  "revisions.serving.knative.dev"
)
$knativeMissing = @($knativeCrdNames | Where-Object { -not (HasCrd $_) })
$knativePods = PodsReady $KnativeNamespace
if ($knativeMissing.Count -eq 0 -and $knativePods.Ready) {
  AddCheck $checks "knative-serving" "Knative Serving" "Ready" "Knative CRDs are installed and $KnativeNamespace has $($knativePods.Detail)." "Run Route/Revision/Traffic checks for each served model."
} elseif ($knativeMissing.Count -eq 0) {
  AddCheck $checks "knative-serving" "Knative Serving" "Warning" "Knative CRDs are installed, but pods are not fully ready: $($knativePods.Detail)." "Repair Knative Serving control plane."
} else {
  AddCheck $checks "knative-serving" "Knative Serving" "NotInstalled" "Missing CRD(s): $($knativeMissing -join ', ')." "Install Knative Serving before upstream KServe validation."
}

$kserveCrdNames = @(
  "inferenceservices.serving.kserve.io",
  "servingruntimes.serving.kserve.io",
  "clusterservingruntimes.serving.kserve.io"
)
$kserveMissing = @($kserveCrdNames | Where-Object { -not (HasCrd $_) })
$kservePods = PodsReady $KserveNamespace
$inferenceServices = if ($kserveMissing.Count -eq 0) { KubeJson @("get", "inferenceservice", "-A") } else { $null }
$isvcReady = if ($inferenceServices -and $inferenceServices.items) { @($inferenceServices.items | Where-Object { (ReadyCondition $_).status -eq "True" }).Count } else { 0 }
$isvcTotal = if ($inferenceServices -and $inferenceServices.items) { @($inferenceServices.items).Count } else { 0 }
if ($kserveMissing.Count -eq 0 -and $kservePods.Ready -and $isvcReady -gt 0) {
  AddCheck $checks "kserve-serving" "KServe inference" "Ready" "KServe CRDs/control plane are ready and $isvcReady/$isvcTotal InferenceService resource(s) are Ready." "Keep storageUri, Route, Revision, and Traffic validation in e2e."
} elseif ($kserveMissing.Count -eq 0 -and $kservePods.Ready) {
  AddCheck $checks "kserve-serving" "KServe inference" "Warning" "KServe CRDs/control plane are ready, but no Ready InferenceService was found." "Create or repair an upstream InferenceService smoke workload."
} elseif ($kserveMissing.Count -eq 0) {
  AddCheck $checks "kserve-serving" "KServe inference" "Warning" "KServe CRDs exist, but control plane readiness is incomplete: $($kservePods.Detail)." "Repair KServe controller pods."
} else {
  AddCheck $checks "kserve-serving" "KServe inference" "NotInstalled" "Missing CRD(s): $($kserveMissing -join ', ')." "Install KServe before upstream inference parity."
}

$modelRegistryInstalled = HasApiResource "modelregistries"
if ($modelRegistryInstalled) {
  $registryResources = KubeJson @("get", "modelregistries", "-A")
  $count = if ($registryResources -and $registryResources.items) { @($registryResources.items).Count } else { 0 }
  AddCheck $checks "model-registry" "Upstream Model Registry" ($(if ($count -gt 0) { "Ready" } else { "Missing" })) "modelregistries API resource is installed with $count instance(s)." "Run upstream registry write/read sync validation."
} else {
  AddCheck $checks "model-registry" "Upstream Model Registry" "NotInstalled" "No modelregistries API resource was discovered." "Install or enable ODH/RHOAI Model Registry for upstream parity." $false
}

$trustyInstalled = HasApiResource "trustyaiservices"
if ($trustyInstalled) {
  $trustyResources = KubeJson @("get", "trustyaiservices", "-A")
  $count = if ($trustyResources -and $trustyResources.items) { @($trustyResources.items).Count } else { 0 }
  AddCheck $checks "trustyai" "TrustyAI monitoring" ($(if ($count -gt 0) { "Ready" } else { "Missing" })) "trustyaiservices API resource is installed with $count instance(s)." "Run model monitoring and explainability e2e."
} else {
  AddCheck $checks "trustyai" "TrustyAI monitoring" "NotInstalled" "No trustyaiservices API resource was discovered." "Install TrustyAI only when drift, bias, and explainability evidence are required." $false
}

$required = @($checks | Where-Object { $_.required })
$ready = @($checks | Where-Object { $_.status -eq "Ready" })
$missing = @($checks | Where-Object { $_.status -in @("Missing", "NotInstalled") })
$warnings = @($checks | Where-Object { $_.status -eq "Warning" })
$requiredMissing = @($required | Where-Object { $_.status -in @("Missing", "NotInstalled", "Warning") })
$phase = if ($requiredMissing.Count -eq 0) { "Ready" } elseif ($ready.Count -gt 0) { "Partial" } else { "NotReady" }

$report = [pscustomobject]@{
  generatedAt = (Get-Date).ToUniversalTime().ToString("o")
  namespace = $Namespace
  phase = $phase
  requireAll = [bool]$RequireAll
  summary = [pscustomobject]@{
    total = $checks.Count
    ready = $ready.Count
    warnings = $warnings.Count
    missing = $missing.Count
    required = $required.Count
    requiredMissing = $requiredMissing.Count
  }
  checks = $checks
}

Write-Output "[upstream-parity] phase=$($report.phase) ready=$($report.summary.ready)/$($report.summary.total) requiredMissing=$($report.summary.requiredMissing)"
foreach ($check in $checks) {
  Write-Output ("[upstream-parity] {0}: {1} - {2}" -f $check.id, $check.status, $check.evidence)
}
Write-Output "[upstream-parity] json=$($report | ConvertTo-Json -Depth 8 -Compress)"

if ($RequireAll -and $report.phase -ne "Ready") {
  Write-Error "[upstream-parity] RequireAll requested but upstream parity phase is $($report.phase)."
  exit 1
}
