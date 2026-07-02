param(
  [string]$Namespace = "opensphere-system",
  [string]$Deployment = "ai",
  [string]$Route = "https://console.opensphere.dev/ai/cluster-settings/support-services",
  [string]$Api = "https://console.opensphere.dev/api/plugins/ai/admin/native/support-services",
  [string]$UpstreamParityApi = "https://console.opensphere.dev/api/plugins/ai/admin/native/upstream-parity",
  [string]$ModelRegistryConfigureApi = "https://console.opensphere.dev/api/plugins/ai/admin/native/support-services/model-registry/configure",
  [string]$ObservabilityConfigureApi = "https://console.opensphere.dev/api/plugins/ai/admin/native/support-services/observability/configure",
  [string]$FinalReadinessApi = "https://console.opensphere.dev/api/plugins/ai/admin/native/final-readiness",
  [string]$PluginManifest = "https://console.opensphere.dev/api/plugins/ai/plugins/ui-shell.manifest.json",
  [string]$PluginEntry = "https://console.opensphere.dev/api/plugins/ai/plugins/ui-shell.plugin.js",
  [string]$PluginAppBundle = "https://console.opensphere.dev/api/plugins/ai/app/main.js",
  [string]$PluginStyles = "https://console.opensphere.dev/api/plugins/ai/app/styles.css",
  [string]$PackagePath = "uipluginpackage.yaml",
  [string]$DspaName = "oah-dspa",
  [string]$ExpectedMlmdImage = "localhost:5000/oah-mlmd-grpc-postgres-wrapper:v1",
  [string]$SeedPipelineName = "oah-kfp-smoke-pipeline",
  [string]$SmokeRunName = "ospr-oah-kfp-smoke-run-v193-kfp-record",
  [string]$IdToken = $env:OAH_ID_TOKEN
)

$ErrorActionPreference = "Stop"

function Fail([string]$Message) {
  Write-Error "[support-services-live] $Message"
  exit 1
}

function Get-HttpText([string]$Url, [string]$Label) {
  $tmp = New-TemporaryFile
  try {
    $status = & curl.exe -k -s -o $tmp.FullName -w "%{http_code}" $Url
    $body = Get-Content -Raw $tmp.FullName
  } finally {
    Remove-Item -LiteralPath $tmp.FullName -ErrorAction SilentlyContinue
  }
  Write-Host "[support-services-live] $Label status=$status"
  if ($status -ne "200") {
    Fail "$Label did not return HTTP 200 from $Url."
  }
  return $body
}

function Convert-JsonArray([string]$Text) {
  if (-not $Text) {
    return @()
  }
  $parsed = ConvertFrom-Json -InputObject $Text
  if ($null -eq $parsed) {
    return @()
  }
  return @($parsed | ForEach-Object { $_ })
}

try {
  $deploy = kubectl get deploy $Deployment -n $Namespace -o json | ConvertFrom-Json
} catch {
  Fail "Deployment $Namespace/$Deployment could not be read. $_"
}

$image = $deploy.spec.template.spec.containers[0].image
$ready = "$($deploy.status.readyReplicas)/$($deploy.status.replicas)"
$updated = $deploy.status.updatedReplicas
$available = $deploy.status.availableReplicas
Write-Output "[support-services-live] deployment image=$image ready=$ready updated=$updated available=$available"

if (Test-Path $PackagePath) {
  $packageText = Get-Content -Raw $PackagePath
  $repositoryMatch = [regex]::Match($packageText, "(?m)^\s*repository:\s*(\S+)\s*$")
  $digestMatch = [regex]::Match($packageText, "(?m)^\s*digest:\s*(\S+)\s*$")
  if (-not $repositoryMatch.Success -or -not $digestMatch.Success) {
    Fail "Could not read desired image repository/digest from $PackagePath."
  }
  $repo = $repositoryMatch.Groups[1].Value
  $digest = $digestMatch.Groups[1].Value
  $desiredImage = if ($digest.StartsWith("sha256:")) { "$repo@$digest" } else { "$repo`:$digest" }
  Write-Output "[support-services-live] desired image=$desiredImage"
  if ($image -ne $desiredImage) {
    Fail "Deployment image $image does not match desired image $desiredImage."
  }
}

if ($ready -ne "1/1" -or $updated -lt 1 -or $available -lt 1) {
  Fail "Deployment is not fully ready."
}

$routeStatus = & curl.exe -k -s -o NUL -w "%{http_code}" -I $Route
Write-Output "[support-services-live] route $Route status=$routeStatus"
if ($routeStatus -ne "200") {
  Fail "Support services route did not return HTTP 200."
}

$manifestBody = Get-HttpText $PluginManifest "plugin manifest"
try {
  $manifest = $manifestBody | ConvertFrom-Json
} catch {
  Fail "Plugin manifest did not return valid JSON. $_"
}
if ($manifest.id -ne "ai" -or $manifest.entry -ne "ui-shell.plugin.js" -or $manifest.apiBase -ne "/api/plugins/ai") {
  Fail "Plugin manifest contract is not the expected AI subShell contract."
}

$pluginEntryBody = Get-HttpText $PluginEntry "plugin entry"
if ($pluginEntryBody -notmatch "/app/main\.js" -or $pluginEntryBody -notmatch "/app/styles\.css") {
  Fail "Plugin entry does not inject the AI app bundle and stylesheet."
}

$pluginStyleStatus = & curl.exe -k -s -o NUL -w "%{http_code}" -I $PluginStyles
Write-Output "[support-services-live] plugin styles status=$pluginStyleStatus"
if ($pluginStyleStatus -ne "200") {
  Fail "Plugin styles did not return HTTP 200."
}

$pluginAppBundleBody = Get-HttpText $PluginAppBundle "plugin app bundle"
foreach ($uiText in @(
  "OAH foundation services",
  "Backbone-backed service availability",
  "Configure Backbone foundation",
  "Apply OAH claim",
  "Bind issued Secrets",
  "Preview pipelines foundation",
  "Configure registry foundation",
  "Metadata credential bootstrap",
  "Object storage bootstrap",
  "Upstream parity inventory"
)) {
  if ($pluginAppBundleBody -notmatch [regex]::Escape($uiText)) {
    Fail "Deployed Support services UI bundle is missing '$uiText'."
  }
}
Write-Output "[support-services-live] deployed UI bundle contains required support-services controls"

$apiBody = & curl.exe -k -s $Api
Write-Output "[support-services-live] unauthenticated api response=$apiBody"
if ($apiBody -notmatch "Authentication required") {
  Fail "Unauthenticated support-services API did not enforce authentication."
}

$upstreamParityBody = & curl.exe -k -s $UpstreamParityApi
Write-Output "[support-services-live] unauthenticated upstream-parity response=$upstreamParityBody"
if ($upstreamParityBody -notmatch "Authentication required") {
  Fail "Unauthenticated upstream-parity API did not enforce authentication."
}

$modelRegistryConfigureBody = & curl.exe -k -s -X POST -H "content-type: application/json" -d "{}" $ModelRegistryConfigureApi
Write-Output "[support-services-live] unauthenticated model-registry configure response=$modelRegistryConfigureBody"
if ($modelRegistryConfigureBody -notmatch "Authentication required") {
  Fail "Unauthenticated model-registry configure API did not enforce authentication."
}

$observabilityBody = & curl.exe -k -s -X POST -H "content-type: application/json" -d "{}" $ObservabilityConfigureApi
Write-Output "[support-services-live] unauthenticated observability configure response=$observabilityBody"
if ($observabilityBody -notmatch "Authentication required") {
  Fail "Unauthenticated observability configure API did not enforce authentication."
}

if ($IdToken) {
  $tmp = New-TemporaryFile
  try {
    $finalStatus = & curl.exe -k -s -o $tmp.FullName -w "%{http_code}" -H "x-os-id-token: $IdToken" $FinalReadinessApi
    $finalBody = Get-Content -Raw $tmp.FullName
  } finally {
    Remove-Item -LiteralPath $tmp.FullName -ErrorAction SilentlyContinue
  }
  Write-Output "[support-services-live] authenticated final-readiness status=$finalStatus"
  if ($finalStatus -ne "200") {
    Fail "Authenticated final-readiness API did not return HTTP 200. Body=$finalBody"
  }
  try {
    $finalReadiness = $finalBody | ConvertFrom-Json
  } catch {
    Fail "Authenticated final-readiness API did not return valid JSON. $_"
  }
  $nativeReady = $finalReadiness.readinessModel.nativeReadiness.ready
  $nativePhase = $finalReadiness.readinessModel.nativeReadiness.phase
  $parityPhase = $finalReadiness.readinessModel.parityReadiness.phase
  Write-Output "[support-services-live] final-readiness nativePhase=$nativePhase nativeReady=$nativeReady parityPhase=$parityPhase upstreamPhase=$($finalReadiness.upstreamPhase)"
  if (-not $nativeReady) {
    Fail "Final readiness nativeReadiness is not ready."
  }
  if (-not $finalReadiness.readinessModel.parityReadiness.evidence) {
    Fail "Final readiness parity evidence is missing."
  }
} else {
  Write-Output "[support-services-live] authenticated final-readiness skipped; set OAH_ID_TOKEN or pass -IdToken to enable it"
}

$podJson = kubectl get pods -n $Namespace -l app=$Deployment -o json | ConvertFrom-Json
$running = @(
  $podJson.items |
    Where-Object {
      -not $_.metadata.deletionTimestamp -and
      $_.status.phase -eq "Running" -and
      @($_.status.containerStatuses | Where-Object { $_.ready }).Count -gt 0
    } |
    Sort-Object { [datetime]$_.metadata.creationTimestamp } -Descending
)
if ($running.Count -lt 1) {
  $seenPods = @($podJson.items | ForEach-Object { "$($_.metadata.name):phase=$($_.status.phase):deleting=$([bool]$_.metadata.deletionTimestamp)" }) -join ", "
  Fail "No active running $Deployment pod found. Seen: $seenPods"
}

$currentPods = @(
  $running |
    Where-Object { @($_.spec.containers | Where-Object { $_.image -eq $image }).Count -gt 0 }
)
if ($currentPods.Count -lt 1) {
  $runningPods = @($running | ForEach-Object {
    $podImages = @($_.spec.containers | ForEach-Object { $_.image }) -join "+"
    "$($_.metadata.name):images=$podImages"
  }) -join ", "
  Fail "No active running $Deployment pod uses deployment image $image. Running: $runningPods"
}

$podName = $currentPods[0].metadata.name
Write-Output "[support-services-live] running pod=$podName image=$image"

try {
  $dspa = kubectl get dspa $DspaName -n $Namespace -o json | ConvertFrom-Json
} catch {
  Fail "DSPA $Namespace/$DspaName could not be read. $_"
}

$dspaReady = @($dspa.status.conditions | Where-Object { $_.type -eq "Ready" })[0]
$dspaMlmdImage = $dspa.spec.mlmd.grpc.image
Write-Output "[support-services-live] dspa=$DspaName ready=$($dspaReady.status) mlmdImage=$dspaMlmdImage"
if ($dspaReady.status -ne "True") {
  Fail "DSPA $Namespace/$DspaName is not Ready."
}
if ($dspaMlmdImage -ne $ExpectedMlmdImage) {
  Fail "DSPA MLMD image $dspaMlmdImage does not match expected $ExpectedMlmdImage."
}

$mlmdDeployment = "ds-pipeline-metadata-grpc-$DspaName"
try {
  $mlmd = kubectl get deploy $mlmdDeployment -n $Namespace -o json | ConvertFrom-Json
} catch {
  Fail "MLMD deployment $Namespace/$mlmdDeployment could not be read. $_"
}
$mlmdImage = $mlmd.spec.template.spec.containers[0].image
$mlmdReady = "$($mlmd.status.readyReplicas)/$($mlmd.status.replicas)"
Write-Output "[support-services-live] mlmd deployment image=$mlmdImage ready=$mlmdReady"
if ($mlmdImage -ne $ExpectedMlmdImage) {
  Fail "MLMD deployment image $mlmdImage does not match expected $ExpectedMlmdImage."
}
if ($mlmdReady -ne "1/1") {
  Fail "MLMD deployment is not fully ready."
}

$pipelineBackendRaw = kubectl exec -n $Namespace $podName -- wget -qO- http://127.0.0.1:8080/pipelines/backend
$pipelineBackend = $pipelineBackendRaw | ConvertFrom-Json
Write-Output "[support-services-live] pipelines phase=$($pipelineBackend.phase) kfpReady=$($pipelineBackend.summary.kfpReady) kfpApiReady=$($pipelineBackend.summary.kfpApiReady) records=$($pipelineBackend.summary.runRecords)"
if ($pipelineBackend.phase -ne "Ready" -or -not $pipelineBackend.summary.kfpReady -or -not $pipelineBackend.summary.kfpApiReady) {
  Fail "Pipeline backend is not Ready with KFP API access."
}

$smokeRecord = @($pipelineBackend.records | Where-Object { $_.name -eq $SmokeRunName })[0]
if (-not $smokeRecord) {
  Fail "Expected KFP smoke record $SmokeRunName was not found."
}
Write-Output "[support-services-live] kfp smoke record=$($smokeRecord.name) state=$($smokeRecord.state) runId=$($smokeRecord.runId)"
if ($smokeRecord.state -ne "SUCCEEDED" -or -not $smokeRecord.runId) {
  Fail "KFP smoke record $SmokeRunName is not Succeeded."
}

$seedRaw = kubectl exec -n $Namespace $podName -- wget -qO- "http://ds-pipeline-$DspaName.$Namespace.svc.cluster.local:8888/apis/v2beta1/pipelines?page_size=100"
$seed = $seedRaw | ConvertFrom-Json
$seedPipeline = @($seed.pipelines | Where-Object { $_.display_name -eq $SeedPipelineName -or $_.name -eq $SeedPipelineName })[0]
Write-Output "[support-services-live] kfp seed pipeline=$($seedPipeline.display_name) id=$($seedPipeline.pipeline_id)"
if (-not $seedPipeline) {
  Fail "KFP seed pipeline $SeedPipelineName was not found."
}

$vectorRaw = kubectl exec -n $Namespace $podName -- wget -qO- "http://127.0.0.1:8080/memory/vector?namespace=$Namespace"
$vector = $vectorRaw | ConvertFrom-Json
Write-Output "[support-services-live] pgvector ready=$($vector.extension.ready) version=$($vector.extension.version) collections=$($vector.summary.collections) chunks=$($vector.summary.chunks)"
if (-not $vector.extension.ready -or -not $vector.summary.ready) {
  Fail "Backbone pgvector memory is not ready."
}

$registryRaw = kubectl exec -n $Namespace $podName -- wget -qO- "http://127.0.0.1:8080/models/registry/versions?namespace=$Namespace"
$registry = $registryRaw | ConvertFrom-Json
$registryItems = @($registry.items)
$registryPromotions = @($registry.promotions)
$registryAudit = @($registry.approvalAudit)
$registryMetrics = @($registry.evaluationMetrics)
$registryPgItems = @($registryItems | Where-Object { $_.backend -eq "opensphere-postgres" -and $_.registry -match "ai-hub-backbone-postgres" })
$registrySmoke = @($registryItems | Where-Object { $_.name -eq "oah-pg-smoke-model" -and $_.version -eq "oah-model-registry-pg-smoke" })[0]
Write-Output "[support-services-live] model registry storage=$($registry.storage.type) ready=$($registry.storage.ready) source=$($registry.source.type) versions=$($registryItems.Count) postgresVersions=$($registryPgItems.Count) promotions=$($registryPromotions.Count) audit=$($registryAudit.Count) metrics=$($registryMetrics.Count)"
if ($registry.storage.type -ne "postgres" -or -not $registry.storage.ready -or $registry.source.type -ne "opensphere-postgres") {
  Fail "Model Registry is not using the Backbone PostgreSQL store."
}
if ($registryItems.Count -lt 1 -or $registryPgItems.Count -lt 1 -or -not $registrySmoke) {
  Fail "Backbone PostgreSQL model registry does not expose the expected registered model versions."
}
if ($registryPromotions.Count -lt 1 -or $registryAudit.Count -lt 1 -or $registryMetrics.Count -lt 1) {
  Fail "Backbone PostgreSQL model registry does not expose promotion, audit, and evaluation evidence."
}

try {
  $registryCm = kubectl get cm ai-model-registry-versions -n $Namespace -o json | ConvertFrom-Json
} catch {
  Fail "Model Registry ConfigMap mirror $Namespace/ai-model-registry-versions could not be read. $_"
}
$mirrorVersions = @(Convert-JsonArray $registryCm.data.versions)
$mirrorPromotions = @(Convert-JsonArray $registryCm.data.promotions)
$mirrorAudit = @(Convert-JsonArray $registryCm.data.approvalAudit)
$mirrorMetrics = @(Convert-JsonArray $registryCm.data.evaluationMetrics)
$mirrorSmoke = @($mirrorVersions | Where-Object { $_.name -eq "oah-pg-smoke-model" -and $_.backend -eq "opensphere-postgres" })[0]
Write-Output "[support-services-live] model registry mirror versions=$($mirrorVersions.Count) promotions=$($mirrorPromotions.Count) audit=$($mirrorAudit.Count) metrics=$($mirrorMetrics.Count)"
if ($mirrorVersions.Count -lt 1 -or -not $mirrorSmoke -or $mirrorPromotions.Count -lt 1 -or $mirrorAudit.Count -lt 1 -or $mirrorMetrics.Count -lt 1) {
  Fail "Model Registry ConfigMap compatibility mirror is missing PostgreSQL-backed registry evidence."
}

try {
  $monitoringTargets = kubectl get monitoringtargets.ai.opensphere.io -A -o json | ConvertFrom-Json
} catch {
  Fail "MonitoringTarget resources could not be read. $_"
}
$monitoringTarget = @($monitoringTargets.items | Where-Object { $_.metadata.name -eq "oah-default-model-monitoring" -and $_.metadata.namespace -eq $Namespace })[0]
if (-not $monitoringTarget) {
  Fail "Default MonitoringTarget $Namespace/oah-default-model-monitoring was not found."
}
$monitoringReady = @($monitoringTarget.status.conditions | Where-Object { $_.type -eq "Ready" })[0]
$metricCount = @($monitoringTarget.status.metrics).Count
$historySamples = [int]($monitoringTarget.status.historySamples)
$metricSource = $monitoringTarget.status.metricSource.type
Write-Output "[support-services-live] monitoring target=$($monitoringTarget.metadata.name) ready=$($monitoringReady.status) phase=$($monitoringTarget.status.phase) source=$metricSource metrics=$metricCount history=$historySamples"
if ($monitoringReady.status -ne "True" -or $metricCount -lt 3 -or $historySamples -lt 1 -or -not $metricSource) {
  Fail "MonitoringTarget does not expose ready fallback metrics and retained history."
}

$trustyRaw = kubectl exec -n $Namespace $podName -- wget -qO- "http://127.0.0.1:8080/monitoring/trustyai/metrics"
$trusty = $trustyRaw | ConvertFrom-Json
$trustyItems = @($trusty.items)
$trustyHistory = @($trusty.history)
Write-Output "[support-services-live] monitoring metrics items=$($trustyItems.Count) alerts=$(@($trusty.alerts).Count) history=$($trustyHistory.Count) sources=$($trusty.sources -join ',')"
if ($trustyItems.Count -lt 3 -or $trustyHistory.Count -lt 1) {
  Fail "TrustyAI-compatible metrics endpoint did not return MonitoringTarget metrics and history."
}

Write-Output "[support-services-live] checks passed"
