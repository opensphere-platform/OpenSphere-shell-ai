param(
  [string]$TargetRegistry = "ghcr.io",
  [string]$Username = "",
  [string]$Token = "",
  [switch]$CheckOnly
)

$ErrorActionPreference = "Stop"

function Fail([string]$Message) {
  Write-Error "[oah-registry-login] $Message"
  exit 1
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

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  Fail "docker was not found. Install Docker before registry login."
}

if (-not $Username) {
  if ($env:GHCR_USERNAME) { $Username = $env:GHCR_USERNAME }
  elseif ($env:GITHUB_ACTOR) { $Username = $env:GITHUB_ACTOR }
}
if (-not $Token) {
  if ($env:GHCR_TOKEN) { $Token = $env:GHCR_TOKEN }
  elseif ($env:GITHUB_TOKEN) { $Token = $env:GITHUB_TOKEN }
  elseif ($env:REGISTRY_TOKEN) { $Token = $env:REGISTRY_TOKEN }
}

if (Docker-Registry-Auth $TargetRegistry) {
  Write-Output "[oah-registry-login] registry-auth=Ready registry=$TargetRegistry"
  exit 0
}

if ($CheckOnly) {
  Write-Output "[oah-registry-login] registry-auth=Missing registry=$TargetRegistry"
  exit 1
}

if (-not $Username) {
  Fail "No registry username was provided. Set -Username, GHCR_USERNAME, or GITHUB_ACTOR."
}
if (-not $Token) {
  Fail "No registry token was provided. Set -Token, GHCR_TOKEN, GITHUB_TOKEN, or REGISTRY_TOKEN."
}

Write-Output "[oah-registry-login] docker login $TargetRegistry username=$Username token=***"
$Token | docker login $TargetRegistry --username $Username --password-stdin
if ($LASTEXITCODE -ne 0) {
  Fail "docker login $TargetRegistry failed."
}

if (Docker-Registry-Auth $TargetRegistry) {
  Write-Output "[oah-registry-login] registry-auth=Ready registry=$TargetRegistry"
} else {
  Fail "docker login completed but Docker config has no auth entry for $TargetRegistry."
}