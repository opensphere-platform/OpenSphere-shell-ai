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
const supportDoc = readRepo('_DOCS_/OAH-SUPPORT-SERVICES-INSTALLATION-MAP-2026-06-29.md');

for (const endpoint of [
  '/admin/native/support-services',
  '/admin/native/support-services/serving/preview',
  '/admin/native/support-services/pipelines/preview',
  '/admin/native/support-services/model-registry/preview',
  '/admin/native/support-services/observability/preview',
  '/admin/native/support-services/metadata/preview',
  '/admin/native/support-services/metadata',
  '/admin/native/support-services/object-storage/preview',
  '/admin/native/support-services/object-storage',
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
  'Use Backbone defaults',
  'Configuration pages',
  'OpenSphere-native fallback control plane',
  'Prepare native fallback',
  'Preview serving foundation',
  'Preview pipelines foundation',
  'Preview registry foundation',
  'Preview observability foundation',
  'Object storage bootstrap',
  'Metadata credential bootstrap',
]) {
  requireText('Support services UI', app, uiText);
}

for (const method of [
  'openConfigurationPage',
  'applyBackboneDefaults',
  'previewServingFoundation',
  'previewPipelinesFoundation',
  'previewModelRegistryFoundation',
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
requirePattern('server backbone response', server, /backbone,\s*\n\s*setupPrerequisites/);

if (!process.exitCode) console.log('[support-services] regression checks passed');
