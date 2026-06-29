param(
  [string]$Namespace = "opensphere-system",
  [string]$Deployment = "ai",
  [string]$Route = "https://console.opensphere.dev/ai/cluster-settings/support-services",
  [string]$Api = "https://console.opensphere.dev/api/plugins/ai/admin/native/support-services",
  [string]$PackagePath = "uipluginpackage.yaml"
)

$ErrorActionPreference = "Stop"

function Fail([string]$Message) {
  Write-Error "[support-services-live] $Message"
  exit 1
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
  $desiredImage = "$($repositoryMatch.Groups[1].Value):$($digestMatch.Groups[1].Value)"
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

$apiBody = & curl.exe -k -s $Api
Write-Output "[support-services-live] unauthenticated api response=$apiBody"
if ($apiBody -notmatch "Authentication required") {
  Fail "Unauthenticated support-services API did not enforce authentication."
}

$podJson = kubectl get pods -n $Namespace -l app=$Deployment --field-selector=status.phase=Running -o json | ConvertFrom-Json
$running = @($podJson.items)
if ($running.Count -lt 1) {
  Fail "No running $Deployment pod found."
}

Write-Output "[support-services-live] running pod=$($running[0].metadata.name)"
Write-Output "[support-services-live] checks passed"
