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
const browserVerifier = read('scripts/verify-support-services-browser.js');
const upstreamParityVerifier = read('scripts/verify-upstream-parity.ps1');
const packageJson = read('package.json');
const supportDoc = readRepo('_DOCS_/OAH-SUPPORT-SERVICES-INSTALLATION-MAP-2026-06-29.md');

for (const endpoint of [
  '/admin/native/support-services',
  '/admin/native/foundation-services',
  '/admin/native/foundation-services/configure',
  '/admin/native/upstream-parity',
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
requirePattern('server DSPA PostgreSQL runtime config verification', server, /async function verifyDspaPostgresRuntimeConfig/);
requirePattern('server Model Registry foundation configure', server, /async function configureModelRegistryFoundation/);
requirePattern('server shell token header', server, /headers\['x-shell-token'\]\s*=\s*process\.env\.SHELL_SERVICE_TOKEN/);
requirePattern('server backbone response', server, /backbone,\s*\n\s*upstreamParity,\s*\n\s*setupPrerequisites/);

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
requireText('package scripts', packageJson, 'test:ui');
requirePattern('package test includes ui smoke', packageJson, /"test":\s*"npm run test:contracts && npm run test:ui"/);
requireText('package scripts', packageJson, 'test:upstream-parity');
requireText('browser support-services verifier', browserVerifier, '/usr/bin/chromium');

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
