const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const repoRoot = path.resolve(root, '..');

function read(rel) {
  return fs.readFileSync(path.resolve(root, rel), 'utf8');
}

function readRepo(rel) {
  return fs.readFileSync(path.resolve(repoRoot, rel), 'utf8');
}

function fail(message) {
  console.error(`[support-services] ${message}`);
  process.exitCode = 1;
}

function requireText(label, text, expected) {
  if (!text.includes(expected)) fail(`${label} is missing "${expected}".`);
}

function requirePattern(label, text, pattern) {
  if (!pattern.test(text)) fail(`${label} does not match ${pattern}.`);
}

const server = read('server.js');
const app = read('src/app/app.component.ts');
const liveVerifier = read('scripts/verify-live-support-services.ps1');
const productFlowVerifier = read('scripts/verify-oah-product-flow.ps1');
const releaseVerifier = read('scripts/verify-oah-release.ps1');
const productionPreflightVerifier = read('scripts/verify-production-preflight.ps1');
const promotionVerifier = read('scripts/promote-oah-images.ps1');
const registryLoginVerifier = read('scripts/login-release-registry.ps1');
const browserVerifier = read('scripts/verify-support-services-browser.js');
const liveBrowserVerifier = read('scripts/verify-live-support-services-browser.js');
const upstreamParityVerifier = read('scripts/verify-upstream-parity.ps1');
const packageJson = read('package.json');
const gitignore = read('.gitignore');
const pluginPackage = read('uipluginpackage.yaml');
const supportDoc = readRepo('_DOCS_/OAH-SUPPORT-SERVICES-INSTALLATION-MAP-2026-06-29.md');
const dupaController = readRepo('OpenSphere-console/backend/dupa-control/controller.js');
const dupaCrds = readRepo('OpenSphere-console/backend/dupa-control/ui-plugin-crds.yaml');

for (const endpoint of [
  '/admin/native/support-services',
  '/admin/native/foundation-services',
  '/admin/native/foundation-services/configure',
  '/admin/native/upstream-parity',
  '/admin/native/product-flow',
  '/admin/native/support-services/serving/preview',
  '/admin/native/support-services/pipelines/preview',
  '/admin/native/support-services/model-registry/preview',
  '/admin/native/support-services/model-registry/configure',
  '/admin/native/support-services/observability/preview',
  '/admin/native/support-services/metadata/preview',
  '/admin/native/support-services/metadata',
  '/admin/native/support-services/object-storage/preview',
  '/admin/native/support-services/object-storage',
  '/admin/native/support-services/backbone/claim/preview',
  '/admin/native/support-services/backbone/claim',
  '/admin/native/support-services/backbone/bindings/preview',
  '/admin/native/support-services/backbone/bindings',
]) {
  requireText('server support-services API', server, endpoint);
}

for (const id of [
  'backbone',
  'object-storage',
  'metadata-store',
  'compute-gpu',
  'odh-rhoai',
  'serving',
  'pipelines',
  'registry',
  'observability',
]) {
  requirePattern('server configurationPages map', server, new RegExp(`id:\\s*'${id}'`));
}

for (const uiText of [
  'Console Backbone provider',
  'OAH foundation services',
  'OAH product flow readiness',
  'training, KFP pipeline execution',
  'pgvector memory',
  'KServe serving',
  'Backbone-backed service availability',
  'Configure Backbone foundation',
  'Use Backbone defaults',
  'Preview OAH claim',
  'Apply OAH claim',
  'Bind issued Secrets',
  'Configuration pages',
  'Upstream parity inventory',
  'DataScienceCluster',
  'Native fallback readiness is intentionally reported separately',
  'OpenSphere-native fallback control plane',
  'Prepare native fallback',
  'Preview serving foundation',
  'Preview pipelines foundation',
  'Preview registry foundation',
  'Configure registry foundation',
  'Preview observability foundation',
  'Object storage bootstrap',
  'Metadata credential bootstrap',
]) {
  requireText('Support services UI', app, uiText);
}

for (const method of [
  'openConfigurationPage',
  'loadFoundationServices',
  'configureFoundationServices',
  'applyBackboneDefaults',
  'previewBackboneClaim',
  'applyBackboneClaim',
  'previewBackboneBindings',
  'applyBackboneBindings',
  'previewServingFoundation',
  'previewPipelinesFoundation',
  'previewModelRegistryFoundation',
  'configureModelRegistryFoundation',
  'previewObservabilityFoundation',
  'bootstrapMetadataStore',
  'bootstrapObjectStorage',
  'createNativeDataScienceCluster',
]) {
  requirePattern('Support services UI methods', app, new RegExp(`${method}\\(`));
}

for (const docText of [
  'OAH Support Services Installation Map',
  'Console Backbone Rule',
  'KServe / Knative Readiness Rule',
  'Object Storage Rule',
  'Metadata Rule',
  'Native Fallback Path',
  'Upstream Path',
]) {
  requireText('Support services documentation', supportDoc, docText);
}

requirePattern('Support services documentation', supportDoc, /Deployed image at writing:\s*`localhost:5000\/ai:v\d+`/);
requirePattern('server backbone inventory', server, /BACKBONE_NAMESPACE\s*=\s*'opensphere-backbone'/);
requirePattern('server backbone claim contract', server, /BACKBONE_CLAIM_NAME\s*=\s*'ai-hub'/);
requirePattern('server backbone object store secret', server, /BACKBONE_RUSTFS_SECRET\s*=\s*'ai-hub-backbone-rustfs'/);
requirePattern('server KServe S3 storage secret', server, /BACKBONE_KSERVE_S3_SECRET\s*=\s*'ai-hub-kserve-s3'/);
requirePattern('server KServe storage annotation', server, /serving\.kserve\.io\/storageSecretName/);
requirePattern('server DSPA manifest helper', server, /function backboneDspaManifest/);
requirePattern('server DSPA apiVersion', server, /datasciencepipelinesapplications\.opendatahub\.io\/v1/);
requirePattern('server DSPA external storage', server, /externalStorage:\s*\{/);
requirePattern('server DSPO public kube-rbac-proxy image', server, /quay\.io\/openshift\/origin-kube-rbac-proxy:latest/);
requirePattern('server DSPO public MLMD envoy image', server, /docker\.io\/envoyproxy\/envoy:v1\.31-latest/);
requirePattern('server DSPA TLS compatibility', server, /function ensureDspaTlsCompatibility/);
requirePattern('server DSPA network compatibility', server, /function ensureDspaNetworkCompatibility/);
requirePattern('server DSPO image compatibility', server, /function ensureDspoImageCompatibility/);
requirePattern('server upstream parity inventory', server, /async function upstreamParityInventory/);
requirePattern('server upstream parity route', server, /\/admin\/native\/upstream-parity/);
requirePattern('server upstream parity operator precision', server, /namespaceMatchingPodsReady/);
requireText('server upstream parity operator precision', server, 'Data Science Pipelines Operator only');
requirePattern('server product flow inventory', server, /async function productFlowInventory/);
requirePattern('server product flow route', server, /\/admin\/native\/product-flow/);
for (const productFlowServerText of [
  'GPU training smoke',
  'KFP pipeline execution',
  'Backbone pgvector memory',
  'Backbone PostgreSQL model registry',
  'KServe / Knative serving',
  'TrustyAI-compatible monitoring',
  'trafficPercent === 100',
  'BACKBONE_KSERVE_S3_SECRET',
]) {
  requireText('server product flow inventory', server, productFlowServerText);
}
requirePattern('server DSPA PostgreSQL runtime config verification', server, /async function verifyDspaPostgresRuntimeConfig/);
requirePattern('server Model Registry foundation configure', server, /async function configureModelRegistryFoundation/);
requirePattern('server shell token header', server, /headers\['x-shell-token'\]\s*=\s*process\.env\.SHELL_SERVICE_TOKEN/);
requirePattern('server backbone response', server, /backbone,\s*\n\s*upstreamParity,\s*\n\s*productFlow,\s*\n\s*setupPrerequisites/);
requireText('AI plugin package KFP pod label', pluginPackage, 'podLabels:');
requireText('AI plugin package KFP pod label', pluginPackage, 'pipelines.kubeflow.org/v2_component: "true"');
requireText('DUPA CRD podLabels schema', dupaCrds, 'podLabels:');
requirePattern('DUPA controller podLabels support', dupaController, /function podLabels\(pkg\)/);
requirePattern('DUPA controller podLabels merge', dupaController, /metadata:\s*\{\s*labels:\s*\{\s*\.\.\.podLabels\(pkg\),\s*app:\s*name\s*\}\s*\}/);

for (const verifierText of [
  'OAH_ID_TOKEN',
  'FinalReadinessApi',
  'PluginManifest',
  'ui-shell.manifest.json',
  'PluginAppBundle',
  'plugin app bundle',
  'deployed UI bundle contains required support-services controls',
  'Configure Backbone foundation',
  'Bind issued Secrets',
  'Preview pipelines foundation',
  'Configure registry foundation',
  'Unauthenticated upstream-parity API did not enforce authentication',
  'Unauthenticated model-registry configure API did not enforce authentication',
  'Unauthenticated observability configure API did not enforce authentication',
  'authenticated final-readiness',
  'nativeReadiness',
  'parityReadiness',
  'deletionTimestamp',
  'No active running',
  'deployment image',
  'ExpectedMlmdImage',
  'DSPA MLMD image',
  '/pipelines/backend',
  'KFP smoke record',
  'KFP seed pipeline',
  '/memory/vector',
  'pgvector',
  '/models/registry/versions',
  'model registry storage=',
  'model registry mirror versions=',
  'monitoring target=',
  '/monitoring/trustyai/metrics',
]) {
  requireText('live support-services verifier', liveVerifier, verifierText);
}

for (const browserVerifierText of [
  'osp-ai-shell',
  '/ai/cluster-settings/support-services',
  'OAH support services',
  'oah product flow readiness',
  'GPU training smoke',
  'Backbone pgvector memory',
  'KServe / Knative serving',
  'upstream parity inventory',
  'ODH/RHOAI operator',
  'Data Science Pipelines Operator only',
  'traffic=100%',
  'Use Backbone defaults',
  'Apply OAH claim',
  'Bind issued Secrets',
  'Preview pipelines foundation',
  'configure registry foundation',
  'Pipelines foundation preview generated',
  'browser render and click-through checks passed',
]) {
  requireText('browser support-services verifier', browserVerifier, browserVerifierText);
}

requireText('package scripts', packageJson, 'test:browser-support-services');
requireText('package scripts', packageJson, 'test:live-browser-support-services');
requireText('package scripts', packageJson, 'test:ui');
requirePattern('package test includes ui smoke', packageJson, /"test":\s*"npm run test:contracts && npm run test:ui"/);
requireText('package scripts', packageJson, 'test:upstream-parity');
requireText('package scripts', packageJson, 'test:product-flow');
requireText('package scripts', packageJson, 'test:release');
requireText('package scripts', packageJson, 'test:production-preflight');
requireText('package scripts', packageJson, 'release:promote-images');
requireText('package scripts', packageJson, 'release:login-registry');
requireText('browser support-services verifier', browserVerifier, '/usr/bin/chromium');
requireText('gitignore release reports', gitignore, 'release-reports/');



for (const registryLoginText of [
  'oah-registry-login',
  'TargetRegistry',
  'GHCR_TOKEN',
  'GITHUB_TOKEN',
  'REGISTRY_TOKEN',
  'GHCR_USERNAME',
  'GITHUB_ACTOR',
  '--password-stdin',
  'token=***',
  'Docker-Registry-Auth',
  'CheckOnly',
]) {
  requireText('OAH registry login verifier', registryLoginVerifier, registryLoginText);
}
for (const preflightText of [
  'oah-preflight',
  'RequireProductionReady',
  'TargetRegistry',
  'Docker-Registry-Auth',
  'package-image-remote',
  'registry-auth',
  'local-image-',
  'cluster-ai-deployment',
  'cluster-controller-deployment',
  'serving-contract',
  'live-browser-token',
  'OAH_ID_TOKEN',
  'oah-production-preflight-$Stamp.json',
  'phase=',
]) {
  requireText('OAH production preflight verifier', productionPreflightVerifier, preflightText);
}
for (const promotionText of [
  'oah-promote',
  'TargetRegistry',
  'TargetNamespace',
  'DryRun',
  'UpdateManifests',
  'Push-Image',
  'docker push',
  'sha256:',
  'oah-image-promotion-$Stamp.json',
  'aiPinned=',
  'controllerPinned=',
  'Replace-RegexFile',
  'SignImages',
  'VerifySignatures',
  'CosignKeyRef',
  'CosignIdentity',
  'CosignIssuer',
  'Resolve-CosignCommand',
  'Require-Cosign',
  'Sign-Image',
  'Verify-ImageSignature',
  'Invoke-Cosign @("sign"',
  '.Add("verify")',
  'Signatures',
  'verificationRequested',
]) {
  requireText('OAH image promotion verifier', promotionVerifier, promotionText);
}

for (const releaseText of [
  'oah-release',
  'RequireUpstream',
  'RequireLiveBrowser',
  'RequireRemoteImages',
  'RequireSignedImages',
  'SkipLocalBuild',
  'image-policy',
  'Test-LocalImage',
  'Test-DigestImage',
  'uses local registry',
  'not pinned to a sha256 digest',
  'CosignKeyRef',
  'CosignIdentity',
  'CosignIssuer',
  'Resolve-CosignCommand',
  'Require-Cosign',
  'Verify-CosignSignature',
  'cosign $($ArgsList -join',
  'npm.cmd test',
  'test:contracts',
  'verify-live-support-services.ps1',
  'verify-oah-product-flow.ps1',
  'test:live-browser-support-services',
  'verify-upstream-parity.ps1 -RequireAll',
  'ReportDir',
  'oah-release-$ReportStamp.json',
  'oah-release-$ReportStamp.md',
  'reportJson=',
  'reportMarkdown=',
  'checks passed',
]) {
  requireText('OAH release verifier', releaseVerifier, releaseText);
}

for (const liveBrowserText of [
  'support-services-live-browser',
  'OAH_ID_TOKEN',
  'OAH_LIVE_ROUTE',
  'Page.addScriptToEvaluateOnNewDocument',
  '__OPENSPHERE_ID_TOKEN__',
  'x-os-id-token',
  '/api/plugins/ai/',
  'oah product flow readiness',
  'gpu training smoke',
  'backbone pgvector memory',
  'kserve / knative serving',
  'traffic=100%',
  'checks passed',
]) {
  requireText('live browser support-services verifier', liveBrowserVerifier, liveBrowserText);
}

for (const productFlowText of [
  'oah-product-flow',
  'external-gpu-smoke-e2e',
  'oah-kfp-smoke-run-v193',
  'ospr-oah-kfp-smoke-run-v193-kfp-record',
  '/pipelines/backend',
  '/memory/vector',
  '/models/registry/versions',
  'oah-serving-contract-smoke',
  'serving.kserve.io/storageSecretName',
  'ai-hub-kserve-s3',
  'oah-default-model-monitoring',
  '/monitoring/trustyai/metrics',
  'Stage "training"',
  'Stage "vector-memory"',
  'Stage "model-registry"',
  'Stage "serving"',
  'Stage "monitoring"',
]) {
  requireText('product-flow verifier', productFlowVerifier, productFlowText);
}

for (const upstreamVerifierText of [
  'DataScienceCluster',
  'ODH/RHOAI operator',
  'Data Science Pipelines Operator only',
  'Data Science Pipelines / KFP',
  'Knative Serving',
  'KServe inference',
  'route/revision/traffic path',
  'latestReadyRevision',
  'Upstream Model Registry',
  'TrustyAI monitoring',
  'RequireAll',
  'requiredMissing',
  'upstream-parity',
]) {
  requireText('upstream parity verifier', upstreamParityVerifier, upstreamVerifierText);
}

if (!process.exitCode) console.log('[support-services] regression checks passed');

