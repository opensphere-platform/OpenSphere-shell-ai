param(
  [string]$Namespace = "opensphere-system",
  [string]$Deployment = "ai",
  [string]$Route = "https://console.opensphere.dev/p/ai/overview",
  [string]$PackagePath = "uipluginpackage.yaml",
  [string]$DspaName = "oah-dspa",
  [string]$TrainingJobName = "external-gpu-smoke-e2e",
  [string]$PipelineRunClaimName = "oah-kfp-smoke-run-v193",
  [string]$SeedPipelineName = "oah-kfp-smoke-pipeline",
  [string]$SmokeRunRecordName = "ospr-oah-kfp-smoke-run-v193-kfp-record",
  [string]$InferenceClaimName = "oah-serving-contract-smoke",
  [string]$ServingPromotionName = "oah-serving-smoke-promotion",
  [string]$ServingPromotionEvaluationName = "oah-model-registry-pg-smoke",
  [string]$MonitoringTargetName = "oah-default-model-monitoring"
)

$ErrorActionPreference = "Stop"

function Fail([string]$Message) {
  Write-Error "[oah-product-flow] $Message"
  exit 1
}

function Stage([string]$Name, [string]$Evidence) {
  Write-Output "[oah-product-flow] stage=$Name status=Ready evidence=$Evidence"
}

function KubeJson([string[]]$ArgsList) {
  $output = & kubectl @ArgsList -o json 2>$null
  if ($LASTEXITCODE -ne 0 -or -not $output) {
    return $null
  }
  try {
    return ($output -join "`n") | ConvertFrom-Json
  } catch {
    Fail "kubectl $($ArgsList -join ' ') returned invalid JSON. $_"
  }
}

function ReadyCondition($Object) {
  if (-not $Object -or -not $Object.status -or -not $Object.status.conditions) {
    return $null
  }
  return @($Object.status.conditions | Where-Object { $_.type -eq "Ready" })[0]
}

function IsReady($Object) {
  $condition = ReadyCondition $Object
  return $condition -and $condition.status -eq "True"
}

function ExecJson([string]$PodName, [string]$Url) {
  $output = & kubectl exec -n $Namespace $PodName -- wget -qO- $Url
  if ($LASTEXITCODE -ne 0 -or -not $output) {
    Fail "Pod endpoint $Url did not return JSON from $Namespace/$PodName."
  }
  try {
    return ($output -join "`n") | ConvertFrom-Json
  } catch {
    Fail "Pod endpoint $Url returned invalid JSON. $_"
  }
}

function EnsureServingPromotionFixture() {
  $promotion = KubeJson -ArgsList @("get", "modelpromotionclaim", $ServingPromotionName, "-n", $Namespace)
  if ($promotion) {
    return
  }
  $manifest = @"
apiVersion: ai.opensphere.io/v1alpha1
kind: ModelPromotionClaim
metadata:
  name: $ServingPromotionName
  namespace: $Namespace
  labels:
    app.kubernetes.io/part-of: opensphere-ai
spec:
  evaluationRef:
    apiVersion: eval.ai.opensphere.io/v1alpha1
    kind: EvaluationJob
    name: $ServingPromotionEvaluationName
    namespace: $Namespace
  modelRef:
    apiVersion: ai.opensphere.io/v1alpha1
    kind: TrainingJobClaim
    name: $TrainingJobName
    namespace: $Namespace
  stage: production
"@
  $manifest | kubectl apply -f - | Out-Null
  if ($LASTEXITCODE -ne 0) {
    Fail "Could not create serving promotion fixture $Namespace/$ServingPromotionName."
  }
}

function WaitForInferenceReady([string]$Name, [int]$Attempts = 12) {
  for ($i = 0; $i -lt $Attempts; $i += 1) {
    $item = KubeJson -ArgsList @("get", "inferenceclaim", $Name, "-n", $Namespace)
    if ($item -and (IsReady $item) -and $item.status.backendMode -eq "upstream") {
      return $item
    }
    Start-Sleep -Seconds 10
  }
  return KubeJson -ArgsList @("get", "inferenceclaim", $Name, "-n", $Namespace)
}

$deploy = KubeJson -ArgsList @("get", "deploy", $Deployment, "-n", $Namespace)
if (-not $deploy) {
  Fail "Deployment $Namespace/$Deployment could not be read."
}

$image = [string]$deploy.spec.template.spec.containers[0].image
$ready = "$($deploy.status.readyReplicas)/$($deploy.status.replicas)"
if ($ready -ne "1/1" -or [int]$deploy.status.updatedReplicas -lt 1 -or [int]$deploy.status.availableReplicas -lt 1) {
  Fail "Deployment $Namespace/$Deployment is not fully ready: ready=$ready updated=$($deploy.status.updatedReplicas) available=$($deploy.status.availableReplicas)."
}

if (Test-Path $PackagePath) {
  $packageText = Get-Content -Raw $PackagePath
  $repositoryMatch = [regex]::Match($packageText, "(?m)^\s*repository:\s*(\S+)\s*$")
  $digestMatch = [regex]::Match($packageText, "(?m)^\s*digest:\s*(\S+)\s*$")
  if ($repositoryMatch.Success -and $digestMatch.Success) {
    $digest = $digestMatch.Groups[1].Value
    $desiredImage = if ($digest.StartsWith("sha256:")) { "$($repositoryMatch.Groups[1].Value)@$digest" } else { "$($repositoryMatch.Groups[1].Value):$digest" }
    if ($image -ne $desiredImage) {
      Fail "Deployment image $image does not match desired image $desiredImage."
    }
  }
}

$routeStatus = & curl.exe -k -s -o NUL -w "%{http_code}" -I $Route
if ($routeStatus -ne "200") {
  Fail "Overview route $Route did not return HTTP 200; status=$routeStatus."
}
Stage "shell" "deployment image=$image ready=$ready route=$routeStatus"

$podJson = KubeJson -ArgsList @("get", "pods", "-n", $Namespace, "-l", "app=$Deployment")
if (-not $podJson -or -not $podJson.items) {
  Fail "No pods found for deployment $Namespace/$Deployment."
}
$running = @(
  $podJson.items |
    Where-Object {
      -not $_.metadata.deletionTimestamp -and
      $_.status.phase -eq "Running" -and
      @($_.status.containerStatuses | Where-Object { $_.ready }).Count -gt 0
    } |
    Sort-Object { [datetime]$_.metadata.creationTimestamp } -Descending
)
$currentPods = @($running | Where-Object { @($_.spec.containers | Where-Object { $_.image -eq $image }).Count -gt 0 })
if ($currentPods.Count -lt 1) {
  Fail "No active running $Deployment pod uses deployment image $image."
}
$podName = [string]$currentPods[0].metadata.name

$training = KubeJson -ArgsList @("get", "trainingjobclaim", $TrainingJobName, "-n", $Namespace)
if (-not $training) {
  Fail "TrainingJobClaim $Namespace/$TrainingJobName was not found."
}
$trainingReady = IsReady $training
$trainingPhase = [string]$training.status.phase
$externalJobPhase = [string]$training.status.externalJob.phase
$gpuEvidence = [string]$training.status.externalJobLogSummary.nvidiaSmi
if (-not $trainingReady -or $trainingPhase -ne "Succeeded" -or $externalJobPhase -ne "Succeeded" -or $gpuEvidence -notmatch "NVIDIA") {
  Fail "Training smoke did not prove a completed GPU-backed training path."
}
Stage "training" "$Namespace/$TrainingJobName phase=$trainingPhase externalJob=$externalJobPhase provider=$($training.status.provider)"

$pipelineBackend = ExecJson $podName "http://127.0.0.1:8080/pipelines/backend"
if ($pipelineBackend.phase -ne "Ready" -or -not $pipelineBackend.summary.kfpReady -or -not $pipelineBackend.summary.kfpApiReady) {
  Fail "Pipeline backend is not Ready with KFP API access."
}
$smokeRecord = @($pipelineBackend.records | Where-Object { $_.name -eq $SmokeRunRecordName })[0]
if (-not $smokeRecord -or $smokeRecord.state -ne "SUCCEEDED" -or -not $smokeRecord.runId) {
  Fail "Expected KFP smoke record $SmokeRunRecordName was not Succeeded."
}
$pipelineRun = KubeJson -ArgsList @("get", "pipelinerunclaim", $PipelineRunClaimName, "-n", $Namespace)
if (-not $pipelineRun -or -not (IsReady $pipelineRun) -or $pipelineRun.status.kfpState -ne "SUCCEEDED" -or -not $pipelineRun.status.kfpRunId) {
  Fail "PipelineRunClaim $Namespace/$PipelineRunClaimName is not a succeeded KFP run."
}
$seed = ExecJson $podName "http://ds-pipeline-$DspaName.$Namespace.svc.cluster.local:8888/apis/v2beta1/pipelines?page_size=100"
$seedPipeline = @($seed.pipelines | Where-Object { $_.display_name -eq $SeedPipelineName -or $_.name -eq $SeedPipelineName })[0]
if (-not $seedPipeline) {
  Fail "KFP seed pipeline $SeedPipelineName was not found."
}
Stage "pipelines" "backend=$($pipelineBackend.phase) run=$($pipelineRun.status.kfpRunId) seedPipeline=$($seedPipeline.pipeline_id)"

$vector = ExecJson $podName "http://127.0.0.1:8080/memory/vector?namespace=$Namespace"
if (-not $vector.extension.ready -or -not $vector.summary.ready -or [int]$vector.summary.collections -lt 1 -or [int]$vector.summary.chunks -lt 1) {
  Fail "Backbone pgvector memory is not ready with persisted collections and chunks."
}
Stage "vector-memory" "pgvector=$($vector.extension.version) collections=$($vector.summary.collections) chunks=$($vector.summary.chunks)"

$registry = ExecJson $podName "http://127.0.0.1:8080/models/registry/versions?namespace=$Namespace"
$registryItems = @($registry.items)
$registryPromotions = @($registry.promotions)
$registryAudit = @($registry.approvalAudit)
$registryMetrics = @($registry.evaluationMetrics)
$registryPgItems = @($registryItems | Where-Object { $_.backend -eq "opensphere-postgres" -and $_.registry -match "ai-hub-backbone-postgres" })
if ($registry.storage.type -ne "postgres" -or -not $registry.storage.ready -or $registry.source.type -ne "opensphere-postgres" -or $registryPgItems.Count -lt 1) {
  Fail "Model Registry is not backed by Backbone PostgreSQL."
}
if ($registryPromotions.Count -lt 1 -or $registryAudit.Count -lt 1 -or $registryMetrics.Count -lt 1) {
  Fail "Model Registry does not expose promotion, approval audit, and evaluation evidence."
}
Stage "model-registry" "storage=$($registry.storage.type) versions=$($registryItems.Count) promotions=$($registryPromotions.Count) audit=$($registryAudit.Count) metrics=$($registryMetrics.Count)"

EnsureServingPromotionFixture
kubectl annotate "inferenceclaim/$InferenceClaimName" -n $Namespace "opensphere.io/reconcile-at=$(Get-Date -Format o)" --overwrite | Out-Null
$inference = WaitForInferenceReady $InferenceClaimName
if (-not $inference -or -not (IsReady $inference) -or $inference.status.backendMode -ne "upstream") {
  Fail "InferenceClaim $Namespace/$InferenceClaimName is not Ready on the upstream KServe backend."
}
$runtimeName = [string]$inference.status.runtimeName
if (-not $runtimeName) {
  $runtimeName = "osinf-$InferenceClaimName"
}
$isvc = KubeJson -ArgsList @("get", "inferenceservice", $runtimeName, "-n", $Namespace)
if (-not $isvc -or -not (IsReady $isvc)) {
  Fail "KServe InferenceService $Namespace/$runtimeName is not Ready."
}
$predictor = $isvc.status.components.predictor
$trafficPercent = 0
foreach ($target in @($predictor.traffic)) {
  if ($null -ne $target.percent) {
    $trafficPercent += [int]$target.percent
  }
}
$revisionName = [string]$predictor.latestReadyRevision
$ksvcName = "$runtimeName-predictor"
$ksvc = KubeJson -ArgsList @("get", "ksvc", $ksvcName, "-n", $Namespace)
$revision = if ($revisionName) { KubeJson -ArgsList @("get", "revision", $revisionName, "-n", $Namespace) } else { $null }
if (-not $isvc.status.url -or $trafficPercent -ne 100 -or -not (IsReady $ksvc) -or -not (IsReady $revision)) {
  Fail "KServe/Knative route, revision, and traffic validation failed for $Namespace/$runtimeName."
}
$storageSecret = [string]$isvc.metadata.annotations.'serving.kserve.io/storageSecretName'
if ($storageSecret -ne "ai-hub-kserve-s3") {
  Fail "InferenceService $Namespace/$runtimeName is not using the Backbone KServe S3 secret."
}
Stage "serving" "inference=$runtimeName route=$([bool]$isvc.status.url) revision=$revisionName traffic=$trafficPercent% storageSecret=$storageSecret"

$monitoring = KubeJson -ArgsList @("get", "monitoringtarget", $MonitoringTargetName, "-n", $Namespace)
if (-not $monitoring -or [int]$monitoring.status.historySamples -lt 1) {
  Fail "MonitoringTarget $Namespace/$MonitoringTargetName is missing retained history."
}
$monitoringSource = [string]$monitoring.status.metricSource.type
$syntheticMetrics = @($monitoring.status.metrics | Where-Object { $_.synthetic -eq $true -or $_.status -eq "Unmeasured" })
if ($monitoringSource -eq "opensphere-fallback") {
  if ([string]$monitoring.status.phase -ne "Unmeasured" -or (IsReady $monitoring) -or $syntheticMetrics.Count -lt 3) {
    Fail "Fallback MonitoringTarget $Namespace/$MonitoringTargetName must be Unmeasured/NotReady with synthetic metrics."
  }
} elseif (-not (IsReady $monitoring) -or [int]$monitoring.status.summary.healthy -lt 3) {
  Fail "Measured MonitoringTarget $Namespace/$MonitoringTargetName is not healthy with retained history."
}
$trusty = ExecJson $podName "http://127.0.0.1:8080/monitoring/trustyai/metrics"
$trustyItems = @($trusty.items)
$trustyHistory = @($trusty.history)
if ($trustyItems.Count -lt 3 -or $trustyHistory.Count -lt 1) {
  Fail "TrustyAI-compatible metrics endpoint did not expose monitoring metrics and history."
}
Stage "monitoring" "target=$MonitoringTargetName metrics=$($trustyItems.Count) history=$($trustyHistory.Count) source=$monitoringSource phase=$($monitoring.status.phase)"

Write-Output "[oah-product-flow] checks passed"
