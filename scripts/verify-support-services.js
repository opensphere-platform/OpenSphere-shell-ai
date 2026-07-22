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
const tokenVerifier = read('scripts/verify-oah-id-token.js');
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
  '/memory/vector/collections',
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
  'SAVE ACCESS',
  'vectorAclOwner',
  '/memory/vector/collections',
  'Requester',
  'Approver',
  'separationOfDuties',
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
requirePattern('server DSPA API image digest', server, /DSPA_API_SERVER_IMAGE[\s\S]*ghcr\.io\/opensphere-platform\/oah-ds-pipelines-api-server@sha256:[a-f0-9]{64}/);
requirePattern('server DSPA MLMD image digest', server, /DSPA_MLMD_GRPC_IMAGE[\s\S]*ghcr\.io\/opensphere-platform\/oah-mlmd-grpc-postgres-wrapper@sha256:[a-f0-9]{64}/);
requirePattern('server DSPO public kube-rbac-proxy image digest', server, /quay\.io\/openshift\/origin-kube-rbac-proxy@sha256:[a-f0-9]{64}/);
requirePattern('server DSPO public MLMD envoy image digest', server, /docker\.io\/envoyproxy\/envoy@sha256:[a-f0-9]{64}/);
requirePattern('server DSPO persistence agent image digest', server, /quay\.io\/opendatahub\/ds-pipelines-persistenceagent@sha256:[a-f0-9]{64}/);
requirePattern('server DSPO scheduled workflow image digest', server, /quay\.io\/opendatahub\/ds-pipelines-scheduledworkflow@sha256:[a-f0-9]{64}/);
requirePattern('server DSPO workflow controller image digest', server, /quay\.io\/opendatahub\/ds-pipelines-argo-workflowcontroller@sha256:[a-f0-9]{64}/);
requirePattern('server DSPA TLS compatibility', server, /function ensureDspaTlsCompatibility/);
requirePattern('server DSPA network compatibility', server, /function ensureDspaNetworkCompatibility/);
requirePattern('server DSPO image compatibility', server, /function ensureDspoImageCompatibility/);
requirePattern('server DSPA GHCR pull secret constant', server, /const GHCR_PULL_SECRET\s*=\s*'ghcr-pull'/);
requirePattern('server DSPA runtime image pull secret repair', server, /async function ensureDspaRuntimeImagePullSecrets/);
requirePattern('server KFP authenticated proxy fallback', server, /function kfpProxyFetchOptions[\s\S]*Authorization: `Bearer \$\{tok\(\)\}`[\s\S]*function kfpApiBases[\s\S]*https:\/\/ds-pipeline-\$\{name\}\.\$\{namespace\}\.svc\.cluster\.local:8443/);
requirePattern('server KFP api network policy compatibility', server, /function dspaApiCompatibilityNetworkPolicyManifest[\s\S]*allow-ai-runtime-kfp-api[\s\S]*app: 'ai'[\s\S]*port: 8888/);
requirePattern('server pipelines configure admin path', server, /\/admin\/native\/support-services\/pipelines\/configure/);
requirePattern('server pipelines configure audited controller apply', server, /async function configurePipelinesFoundation[\s\S]*const actor = await requestActor\(req\);[\s\S]*const applyReq = \{ _internal: true, _actor: actor \};[\s\S]*ensureDspaRuntimeImagePullSecrets\(applyReq\)/);
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
requirePattern('server serving approval gate', server, /async function servingApprovalGate/);
requirePattern('server inference approval enforcement', server, /UnapprovedModelArtifact/);
requirePattern('server vector bootstrap authz', server, /pathname === '\/memory\/vector\/bootstrap'[\s\S]*requireAdminAccess/);
requirePattern('server vector collection ownership schema', server, /oah_vector_collections[\s\S]*owner text not null default 'opensphere-ai-hub'[\s\S]*groups jsonb not null default '\[\]'::jsonb/);
requirePattern('server vector central policy schema', server, /create table if not exists oah_vector_access_policies[\s\S]*primary key \(namespace, collection\)/);
requirePattern('server vector list owner filter', server, /pathname === '\/memory\/vector'[\s\S]*requestActor\(req\)[\s\S]*vectorMemoryResponse\(req\.url, req\)/);
requirePattern('server vector owner group access', server, /function actorCanAccessVectorCollection[\s\S]*actorIsAdmin\(actor\)[\s\S]*vectorCollectionOwner[\s\S]*vectorCollectionGroups/);
requirePattern('server vector owner/admin manage access', server, /function actorCanManageVectorCollection[\s\S]*actorIsAdmin\(actor\)[\s\S]*vectorCollectionOwner/);
requirePattern('server vector group aliases', server, /function identityGroupAliases[\s\S]*replace\(\s*\/\^\\\/\+/);
requirePattern('server identity group claim extraction', server, /const IDENTITY_GROUP_CLAIM_KEYS[\s\S]*groups_name[\s\S]*function identityGroupsFromClaims[\s\S]*realm_access[\s\S]*resource_access/);
requirePattern('server admin group alias matching', server, /function actorIsAdmin[\s\S]*identityGroupAliases\(actor\?\.groups[\s\S]*identityGroupAliases\(ADMIN_GROUPS\)/);
requirePattern('server vector retrieval policy source', server, /const VECTOR_RETRIEVAL_CRD\s*=\s*'vectorretrievalclaims\.ai\.foundation\.opensphere\.io'[\s\S]*function vectorRetrievalAccessPolicy/);
requirePattern('server vector policy augments DB ACL', server, /async function vectorCollectionWithPolicy[\s\S]*vectorRetrievalPolicyFor[\s\S]*policySource/);
requirePattern('server vector backbone central policy source', server, /function vectorBackbonePolicySource[\s\S]*BackboneVectorAccessPolicy[\s\S]*async function upsertVectorBackboneAccessPolicy/);
requirePattern('server vector central policy batch load', server, /async function vectorBackboneAccessPolicyMap[\s\S]*oah_vector_access_policies[\s\S]*vectorMemoryState[\s\S]*vectorCollectionWithPolicy\(row, backbonePolicies\.get/);
requirePattern('server vector ACL writes policy CR', server, /async function upsertVectorRetrievalAccessPolicy[\s\S]*kind: 'VectorRetrievalClaim'[\s\S]*access:\s*\{[\s\S]*owner:[\s\S]*groups:/);
requirePattern('server vector ACL update API', server, /async function updateVectorCollectionAccess[\s\S]*update oah_vector_collections[\s\S]*owner = \$5[\s\S]*groups = \$6::jsonb/);
requirePattern('server vector ACL update syncs central policy', server, /async function updateVectorCollectionAccess[\s\S]*upsertVectorBackboneAccessPolicy\(client/);
requirePattern('server vector ACL update syncs policy', server, /async function updateVectorCollectionAccess[\s\S]*upsertVectorRetrievalAccessPolicy[\s\S]*policy/);
requirePattern('server vector query collection authz', server, /pathname === '\/memory\/vector\/query'[\s\S]*requireVectorCollectionAccess\(req, pathname, namespace, collection\)/);
requirePattern('server vector ACL route authz', server, /pathname === '\/memory\/vector\/collections'[\s\S]*requireVectorCollectionManageAccess\(req, pathname, namespace, collection\)/);
requirePattern('server append-only approval audit helper', server, /function appendApprovalAudit/);
requirePattern('server approval audit insert-only', server, /oah_model_registry_approval_audit[\s\S]*on conflict \(id\) do nothing/);
requirePattern('server promotion SoD helper', server, /function promotionSeparationOfDuties[\s\S]*SelfApprovalDenied[\s\S]*RequesterApproverSeparated/);
requirePattern('server promotion SoD enforcement', server, /approved && !separationOfDuties\.allowed[\s\S]*ApprovalSoDViolation[\s\S]*patchPromotionStatus/);
requirePattern('server serving blocks SoD violation', server, /function promotionAllowsServing[\s\S]*approvalsodviolation[\s\S]*separationOfDuties\.allowed !== true/);
requirePattern('server promotion requester annotation', server, /opensphere\.io\/requested-by[\s\S]*opensphere\.io\/requested-at/);
requirePattern('server promotion approver annotation', server, /opensphere\.io\/approved-by[\s\S]*opensphere\.io\/approved-at/);
requirePattern('server model registry app role secret', server, /BACKBONE_POSTGRES_APP_SECRET\s*=\s*'ai-hub-backbone-postgres-app'/);
requirePattern('server model registry app role migration', server, /async function ensureModelRegistryAppRole[\s\S]*grant select, insert on oah_model_registry_approval_audit[\s\S]*revoke update, delete, truncate on oah_model_registry_approval_audit/);
requirePattern('server model registry runtime app role preference', server, /async function modelRegistryRuntimeConfig[\s\S]*backbonePostgresAppConfig\(\)[\s\S]*owner-fallback/);
requirePattern('server model registry app role avoids delete prune', server, /async function upsertModelRegistryPgState[\s\S]*allowPrune = config\.role !== 'app'[\s\S]*if \(allowPrune\)[\s\S]*delete from oah_model_registry_versions[\s\S]*if \(allowPrune\)[\s\S]*delete from oah_model_registry_promotions/);
requirePattern('server model registry app role refresh helper', server, /async function refreshModelRegistryAppRole[\s\S]*_modelRegistryPgMigrationReady = false[\s\S]*ensureModelRegistryPgMigration\(\)[\s\S]*modelRegistryAppRoleUsable\(\)/);
requirePattern('server model registry configure refreshes app role', server, /async function configureModelRegistryFoundation[\s\S]*refreshModelRegistryAppRole\(\)[\s\S]*native-registry-postgres-app-role[\s\S]*Backbone PostgreSQL restricted app role/);
requirePattern('server monitoring synthetic fallback', server, /NoMeasuredMetricSource[\s\S]*syntheticMetrics/);
requirePattern('server TrustyAI metric fetch parser', server, /function trustyaiSamplesFromText[\s\S]*function trustyaiSamplesFromJson[\s\S]*function fetchTrustyaiMetricSamples/);
requirePattern('server TrustyAI measured coverage gate', server, /function trustyaiSamplesCoverMetrics[\s\S]*selectTrustyaiSample[\s\S]*if \(measured\.samples\.length && trustyaiSamplesCoverMetrics/);
requirePattern('server upstream parity TrustyAI measured evidence', server, /const trustySamples = trustyInfo\?\.ready \? await fetchTrustyaiMetricSamples[\s\S]*TrustyAIService[\s\S]*numeric metric sample/);
requirePattern('server backbone response', server, /backbone,\s*\n\s*upstreamParity,\s*\n\s*productFlow,\s*\n\s*setupPrerequisites/);
requireText('AI plugin package KFP pod label', pluginPackage, 'podLabels:');
requireText('AI plugin package KFP pod label', pluginPackage, 'pipelines.kubeflow.org/v2_component: "true"');
requireText('DUPA CRD podLabels schema', dupaCrds, 'podLabels:');
requirePattern('DUPA controller podLabels support', dupaController, /function podLabels\(pkg\)/);
requirePattern('DUPA controller podLabels merge', dupaController, /labels:\s*\{\s*\.\.\.podLabels\(pkg\),\s*app:\s*name\s*\}/);

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
  'ghcr.io/opensphere-platform/oah-mlmd-grpc-postgres-wrapper@sha256:',
  'DSPA MLMD image',
  '/pipelines/backend',
  'apiProbe=',
  'AbortSignal.timeout(10000)',
  'KFP smoke record',
  'KFP seed pipeline',
  '/memory/vector',
  'pgvector',
  '/models/registry/versions',
  'model registry storage=',
  'ds-pipeline-$DspaName.$Namespace.svc.cluster.local:8443',
  'sourceRole=',
  'restricted app role',
  'SodSmokePromotionName',
  'ApprovalSoDViolation',
  'SoD self-approval audit record',
  'model registry mirror versions=',
  'monitoring target=',
  '/monitoring/trustyai/metrics',
]) {
  requireText('live support-services verifier', liveVerifier, verifierText);
}

for (const releaseVerifierText of [
  'AllowUnsignedImages',
  'RequireRemoteImages = $true',
  'RequireLiveBrowser = $true',
  'dspa-api-server',
  'dspa-mlmd-grpc',
  'dspa-spec/mlmd-envoy',
  'Add-DspaDeploymentImages',
  'Kube-JsonRequired',
  'Release verification cannot continue without live cluster evidence',
  'No DSPA runtime deployments matched',
]) {
  requireText('release verifier strict gate', releaseVerifier, releaseVerifierText);
}

for (const preflightVerifierText of [
  'dspa-api-server-image',
  'dspa-mlmd-grpc-image',
  'dspa-mlmd-envoy-image',
  'Add-Dspa-Deployment-Image-Checks',
  'Add-Image-Check',
  'Add-Signature-TrustRoot-Check',
  'image-signature-trust-root',
  'RequireProductionReady',
  'RequireSignedImages',
  'OAH_COSIGN_KEY_REF',
  'OAH_COSIGN_IDENTITY',
  'OAH_COSIGN_ISSUER',
  'KMS-backed CosignKeyRef',
  'dspa-live-deployments-readable',
  'dspa-live-deployments-present',
]) {
  requireText('production preflight DSPA image gate', productionPreflightVerifier, preflightVerifierText);
}

for (const browserVerifierText of [
  'osp-ai-shell',
  '/p/ai/cluster-settings/support-services',
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
requirePattern('package test includes workspace integration and UI smoke', packageJson, /"test":\s*"npm run test:workspace-contracts && npm run test:ui"/);
requirePattern('package scripts keep standalone release contracts', packageJson, /"test:contracts":\s*"npm run test:standard && npm run test:rbac && node scripts\/verify-constitution-0003\.js"/);
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
  'verify-oah-id-token.js',
  '--use-system-ca',
  'Add-LiveBrowserToken-Check',
  'RequiredTokenIssuer',
  'RequiredTokenAudience',
  'OAH_REQUIRED_TOKEN_ISSUER',
  'OAH_REQUIRED_TOKEN_AUDIENCE',
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
  'OAH_COSIGN_KEY_REF',
  'OAH_COSIGN_IDENTITY',
  'OAH_COSIGN_ISSUER',
  'Resolve-CosignCommand',
  'Require-Cosign',
  'Test-LocalCosignKeyRef',
  'KMS-backed -CosignKeyRef',
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
  'verifyTokenWithHelper',
  'verify-oah-id-token.js',
  '--use-system-ca',
  'signatureVerified',
  'OAH_REQUIRED_TOKEN_ISSUER',
  'OAH_REQUIRED_TOKEN_AUDIENCE',
  'issuer mismatch',
  'audience mismatch',
  'decodeJwtHeader',
  'signed JWT with a signature segment',
  'alg=none is not accepted',
  'identityGroupClaimKeys',
  'groups_name',
  'realm_access',
  'resource_access',
  'OAH_ID_TOKEN does not contain any supported group claim',
  'Page.addScriptToEvaluateOnNewDocument',
  'awaitPromise: true',
  '__OPENSPHERE_ID_TOKEN__',
  'x-os-id-token',
  '/api/plugins/ai/admin/native/final-readiness',
  'authenticated final-readiness browser fetch',
  '/api/plugins/ai/memory/vector/collections',
  'authenticated vector owner/group browser smoke',
  'oah-live-browser-smoke',
  'Vector owner/group browser smoke failed',
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

for (const tokenVerifierText of [
  'OAH_ID_TOKEN',
  'OAH_REQUIRED_TOKEN_ISSUER',
  'OAH_REQUIRED_TOKEN_AUDIENCE',
  'OAH_SKIP_TOKEN_SIGNATURE_VERIFY',
  'OAH_ALLOW_UNSIGNED_ID_TOKEN_FOR_TESTS',
  'must not be used for production verification',
  '.well-known/openid-configuration',
  'jwks_uri',
  'crypto.createPublicKey',
  'joseEcdsaSignatureToDer',
  'ES256',
  'OAH_ID_TOKEN signature did not verify against issuer JWKS',
  'OAH_ID_TOKEN kid',
  'alg=none is not accepted',
  'groups_name',
  'realm_access',
  'resource_access',
  'signatureVerified',
]) {
  requireText('OAH ID token verifier', tokenVerifier, tokenVerifierText);
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
  'FetchTrustyMetricEvidence',
  'numeric metric sample',
  'measured metric evidence is missing',
  'RequireAll',
  'requiredMissing',
  'upstream-parity',
]) {
  requireText('upstream parity verifier', upstreamParityVerifier, upstreamVerifierText);
}

if (!process.exitCode) console.log('[support-services] regression checks passed');

