// AI — server.js. SDK 표준 subShell 피처 컨테이너: 제네릭 /api/k8s/* 프록시 + WS exec + Angular 범용콘솔(www) + subShell ui-shell 서빙.
// 셸 nginx가 /api/plugins/ai/<X> → 이 서버 /<X> 로 prefix strip 프록시.
//   /plugins/*  → 매니페스트/번들/서명
//   /app/*      → Angular dist(main.js, styles.css)
//   /api/nodes  → 노드 집계
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const { WebSocketServer, WebSocket } = require('ws');
const COOKIE = 'osng_token'; // 브라우저 WS는 커스텀 헤더를 못 실음 → 신원 토큰을 HttpOnly 쿠키로 전달
function tokenFromCookie(cookieHeader) {
  if (!cookieHeader) return null;
  for (const part of cookieHeader.split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === COOKIE) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return null;
}
const PORT = process.env.PORT || 8080;
const PLUGINS = process.env.PLUGINS_DIR || '/app/plugins';
const WWW = process.env.WWW_DIR || '/app/www';
const VERSION = process.env.APP_VERSION || '0.1.0';
const WORKBENCH_IMAGE = process.env.WORKBENCH_IMAGE || 'localhost:5000/ai:workbench';
const PIPELINE_RUNNER_IMAGE = process.env.PIPELINE_RUNNER_IMAGE || WORKBENCH_IMAGE;
const INFERENCE_RUNTIME_IMAGE = process.env.INFERENCE_RUNTIME_IMAGE || WORKBENCH_IMAGE;
const SA = '/var/run/secrets/kubernetes.io/serviceaccount';
const APISERVER = 'https://kubernetes.default.svc';
const tok = () => fs.readFileSync(`${SA}/token`, 'utf8').trim();
const AI_CLAIM_FINALIZER = 'ai.opensphere.io/finalizer';
const RETRY_BASE_MS = 30 * 1000;
const RETRY_MAX_MS = 5 * 60 * 1000;
const ADMIN_GROUPS = (process.env.OSP_ADMIN_GROUPS || 'opensphere-admins,system:masters,cluster-admins')
  .split(',')
  .map((item) => item.trim())
  .filter(Boolean);

// ── 쓰기 인가: 호출자 토큰을 검증 → Impersonate-User (SA 광범위 write 금지) ──
// Kanidm 콘솔 id_token(ES256) 전용 — cutover 완료, 레거시 Keycloak RS256 dual-accept 경로는 제거됨.
const { createHash, createPublicKey, verify: cryptoVerify } = require('crypto');
// Kanidm 콘솔 IdP — split-horizon: 토큰 iss는 브라우저값(localhost:8444), JWKS는 in-cluster svc.
const KANIDM_ISS = process.env.KANIDM_ISS || 'https://localhost:8444/oauth2/openid/opensphere-console';
const KANIDM_JWKS_URL = process.env.KANIDM_JWKS_URL || 'https://kanidm.opensphere-console-auth.svc:8443/oauth2/openid/opensphere-console/public_key.jwk';
const KANIDM_AZP = process.env.KANIDM_AZP || 'opensphere-console';
const KANIDM_CA_PATH = process.env.KANIDM_CA_PATH || '/etc/kanidm-ca/ca.crt';
const WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
// Kanidm JWKS — 자체서명 CA를 명시적 'ca' 옵션으로 신뢰(TLS 검증 비활성화 금지, NODE_EXTRA_CA_CERTS 미접촉).
let _kjwks = null, _kjwksAt = 0;
const KJWKS_TTL = 5 * 60 * 1000;
function _kanidmGetJwks(force) {
  return new Promise((resolve, reject) => {
    if (!force && _kjwks && (Date.now() - _kjwksAt) < KJWKS_TTL) return resolve(_kjwks);
    const u = new URL(KANIDM_JWKS_URL);
    const opts = { hostname: u.hostname, port: u.port || 443, path: u.pathname + u.search, method: 'GET' };
    try { opts.ca = fs.readFileSync(KANIDM_CA_PATH); } catch (e) { console.error('[auth] kanidm CA read failed: ' + e); }
    const rq = https.request(opts, (resp) => {
      const ch = []; resp.on('data', (c) => ch.push(c));
      resp.on('end', () => { try { const j = JSON.parse(Buffer.concat(ch).toString('utf8')); _kjwks = j.keys || (j.kty ? [j] : []); _kjwksAt = Date.now(); resolve(_kjwks); } catch (e) { reject(e); } });
    });
    rq.on('error', reject); rq.end();
  });
}
const b64urlJson = (s) => JSON.parse(Buffer.from(s, 'base64url').toString('utf8'));
async function verifyToken(idToken) {
  if (!idToken) throw { code: 401, msg: 'no id token' };
  const parts = idToken.split('.');
  if (parts.length !== 3) throw { code: 401, msg: 'malformed token' };
  const header = b64urlJson(parts[0]);
  const sig = Buffer.from(parts[2], 'base64url');
  // ── Kanidm 콘솔 id_token (ES256) 전용 — alg pin (fail closed) ──
  if (header.alg !== 'ES256') throw { code: 401, msg: 'unexpected alg' };
  let jwk = (await _kanidmGetJwks()).find((k) => k.kid === header.kid);
  if (!jwk) jwk = (await _kanidmGetJwks(true)).find((k) => k.kid === header.kid); // 키 롤오버 재시도
  if (!jwk) throw { code: 401, msg: 'unknown kid (kanidm)' };
  const pub = createPublicKey({ key: jwk, format: 'jwk' });
  // ECDSA P-256: JWS 서명은 raw r||s(IEEE-P1363)이며 DER이 아님 → dsaEncoding 명시 필수.
  const ok = cryptoVerify('SHA256', Buffer.from(`${parts[0]}.${parts[1]}`), { key: pub, dsaEncoding: 'ieee-p1363' }, sig);
  if (!ok) throw { code: 401, msg: 'bad signature' };
  const c = b64urlJson(parts[1]); // 검증된 클레임
  // split-horizon: 토큰 iss는 브라우저값(localhost:8444) — 정확히 일치해야 함(JWKS는 in-cluster svc에서 받음).
  if (c.iss !== KANIDM_ISS) throw { code: 401, msg: 'bad iss' };
  const aud = Array.isArray(c.aud) ? c.aud : c.aud ? [c.aud] : [];
  if (c.azp !== KANIDM_AZP && !aud.includes(KANIDM_AZP)) throw { code: 401, msg: 'bad azp/aud' };
  // ── 공통 꼬리: 시간 검증 + 클레임 추출 ──
  const now = Date.now();
  if (c.exp && c.exp * 1000 < now) throw { code: 401, msg: 'token expired' };
  if (c.nbf && c.nbf * 1000 > now + 30000) throw { code: 401, msg: 'token not yet valid' };
  return { username: c.preferred_username || 'unknown', groups: c.groups || [] };
}
const readBody = (req) => {
  if (req._cachedBody) return Promise.resolve(Buffer.from(req._cachedBody));
  return new Promise((resolve, reject) => {
    const ch = [];
    req.on('data', (c) => ch.push(c));
    req.on('end', () => {
      req._cachedBody = Buffer.concat(ch);
      resolve(req._cachedBody);
    });
    req.on('error', reject);
  });
};
const jsonRes = (res, code, obj) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(obj)); };

const MIME = {
  '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.json': 'application/json',
  '.html': 'text/html; charset=utf-8', '.svg': 'image/svg+xml', '.woff': 'font/woff', '.woff2': 'font/woff2',
  '.ttf': 'font/ttf', '.map': 'application/json', '.ico': 'image/x-icon',
};

const COMPUTE_ROUTING_CONFIGMAP = 'oah-compute-routing';
const COMPUTE_ROUTING_WORKLOADS = [
  { id: 'training', label: 'Training jobs', defaultPolicy: 'external-first', fallbackPolicy: 'kubernetes-or-cpu' },
  { id: 'serving', label: 'Model serving / inference', defaultPolicy: 'kubernetes-first', fallbackPolicy: 'external-or-cpu' },
  { id: 'notebooks', label: 'Workbench notebooks', defaultPolicy: 'kubernetes-first', fallbackPolicy: 'external-or-cpu' },
  { id: 'pipelines', label: 'Data science pipelines', defaultPolicy: 'external-first', fallbackPolicy: 'kubernetes-or-cpu' },
  { id: 'batch', label: 'Batch inference', defaultPolicy: 'external-first', fallbackPolicy: 'kubernetes-or-cpu' },
  { id: 'distributed', label: 'Distributed workloads', defaultPolicy: 'kubernetes-first', fallbackPolicy: 'external-or-cpu' },
];

async function nodes() {
  const r = await fetch(`${APISERVER}/api/v1/nodes`, { headers: { Authorization: `Bearer ${tok()}` } });
  if (!r.ok) throw new Error(`nodes HTTP ${r.status}`);
  const items = (await r.json()).items || [];
  return items.map((n) => {
    const cond = (n.status?.conditions || []).find((c) => c.type === 'Ready');
    const roles = Object.keys(n.metadata?.labels || {})
      .filter((k) => k.startsWith('node-role.kubernetes.io/'))
      .map((k) => k.split('/')[1]).filter(Boolean);
    const addr = (n.status?.addresses || []).find((a) => a.type === 'InternalIP');
    const ni = n.status?.nodeInfo || {};
    return {
      name: n.metadata?.name, ready: cond?.status === 'True',
      roles: roles.length ? roles : ['<none>'], version: ni.kubeletVersion || '',
      os: ni.osImage || '', arch: ni.architecture || '',
      cpu: n.status?.capacity?.cpu || '', memory: n.status?.capacity?.memory || '',
      internalIP: addr?.address || '', created: n.metadata?.creationTimestamp || '',
      schedulable: !n.spec?.unschedulable,
    };
  });
}

const FALLBACK_PROJECTS = [
  {
    name: 'cmars-dev',
    displayName: 'cmars-dev',
    created: '2026. 6. 8. 오전 9:11:56',
    owner: 'cmars',
    phase: 'Active',
    description: 'Personal data science project',
  },
  {
    name: 'sandbox-shared-models',
    displayName: 'sandbox-shared-models',
    created: '2026. 1. 23. 오후 6:02:05',
    owner: 'Unknown',
    phase: 'Active',
    description: 'Shared model serving workspace',
  },
];

const LEARNING_RESOURCES = [
  {
    title: 'Open Data Hub documentation',
    provider: 'Open Data Hub',
    type: 'Documentation',
    duration: 'Reference',
    description: 'Upstream component documentation for dashboard, workbenches, pipelines, model serving, and monitoring.',
    href: 'https://opendatahub.io/docs/',
  },
  {
    title: 'Red Hat AI learning hub',
    provider: 'Red Hat Developer',
    type: 'Learning path',
    duration: 'Self-guided',
    description: 'Developer-oriented articles, quickstarts, interactive demos, and sandbox paths for OpenShift AI.',
    href: 'https://developers.redhat.com/topics/open-data-hub',
  },
  {
    title: 'OpenSphere AI Hub tutorial - agent operations example',
    provider: 'OpenSphere',
    type: 'Tutorial',
    duration: '1 hour',
    description: 'Train a model, evaluate it with a policy gate, deploy an inference claim, and connect it to an AI agent.',
    href: '#',
  },
  {
    title: 'OpenSphere AI Hub CRD reference',
    provider: 'Platform team',
    type: 'Documentation',
    duration: 'Reference',
    description: 'AIAgent, EvaluationJob, TrainingJobClaim, ModelPromotionClaim, InferenceClaim, and related APIs.',
    href: '#',
  },
  {
    title: 'Governed model promotion',
    provider: 'Platform team',
    type: 'How-to',
    duration: '45 minutes',
    description: 'Use evaluation policies to control promotion from staging to production serving.',
    href: '#',
  },
  {
    title: 'Retrieval and tool policy quick start',
    provider: 'OpenSphere',
    type: 'Quick start',
    duration: '15 minutes',
    description: 'Bind LLM routes, retrieval claims, tool claims, and trace policies for a governed agent.',
    href: '#',
  },
];

const LEARNING_RESOURCE_CONFIGMAP = 'ai-learning-resources';

const FALLBACK_RESOURCES = {
  agents: [
    { name: 'support-rag-agent', kind: 'AIAgent', namespace: 'cmars-dev', phase: 'Ready', ready: true, description: 'RAG assistant with source attribution' },
    { name: 'ops-triage-agent', kind: 'AIAgent', namespace: 'cmars-dev', phase: 'Draft', ready: false, description: 'Incident summarization and runbook routing' },
  ],
  routes: [
    { name: 'default-chat-route', kind: 'LLMRouteClaim', namespace: 'cmars-dev', phase: 'Ready', ready: true },
    { name: 'embedding-route', kind: 'VectorRetrievalClaim', namespace: 'cmars-dev', phase: 'Ready', ready: true },
  ],
  workbenches: [
    { name: 'cmars-jupyter', kind: 'Notebook', namespace: 'cmars-dev', phase: 'Running', ready: true, description: 'JupyterLab workbench for exploratory AI development' },
    { name: 'sandbox-vscode', kind: 'Notebook', namespace: 'sandbox-shared-models', phase: 'Stopped', ready: false, description: 'VS Code workbench template reference' },
  ],
  notebookImages: [
    { name: 'standard-data-science', kind: 'NotebookImage', namespace: 'opensphere-system', phase: 'Enabled', ready: true, description: 'Python, JupyterLab, and common data science packages' },
    { name: 'pytorch-gpu', kind: 'NotebookImage', namespace: 'opensphere-system', phase: 'Enabled', ready: true, description: 'PyTorch image with CUDA-ready dependencies' },
  ],
  dataConnections: [
    { name: 'default-object-store', kind: 'DataConnection', namespace: 'cmars-dev', phase: 'Ready', ready: true, description: 'S3-compatible object storage connection metadata' },
    { name: 'git-training-source', kind: 'DataConnection', namespace: 'cmars-dev', phase: 'Ready', ready: true, description: 'Git-backed dataset and notebook source reference' },
  ],
  servingRuntimes: [
    { name: 'kserve-vllm-runtime', kind: 'ServingRuntime', namespace: 'opensphere-system', phase: 'Enabled', ready: true, description: 'KServe/vLLM serving runtime reference' },
    { name: 'openvino-runtime', kind: 'ServingRuntime', namespace: 'opensphere-system', phase: 'Available', ready: true, description: 'OpenVINO serving runtime reference' },
  ],
  modelRegistry: [
    { name: 'opensphere-model-registry', kind: 'ModelRegistry', namespace: 'opensphere-system', phase: 'Enabled', ready: true, description: 'Central model metadata and promotion registry' },
  ],
  pipelines: [
    { name: 'fraud-detection-training', kind: 'Pipeline', namespace: 'cmars-dev', phase: 'Ready', ready: true, description: 'Train, evaluate, and publish a model candidate' },
    { name: 'support-rag-index-refresh', kind: 'Pipeline', namespace: 'cmars-dev', phase: 'Ready', ready: true, description: 'Refresh retrieval indexes for agent grounding' },
  ],
  pipelineRuns: [
    { name: 'fraud-detection-training-run-20260626', kind: 'PipelineRun', namespace: 'cmars-dev', phase: 'Succeeded', ready: true, description: 'Latest training pipeline run' },
    { name: 'support-rag-index-refresh-run-20260626', kind: 'PipelineRun', namespace: 'cmars-dev', phase: 'Running', ready: false, description: 'Index refresh in progress' },
  ],
  trainingJobs: [
    { name: 'fraud-detector-finetune', kind: 'TrainingJobClaim', namespace: 'cmars-dev', phase: 'Running', ready: false },
    { name: 'customer-support-classifier', kind: 'TrainingJobClaim', namespace: 'cmars-dev', phase: 'Succeeded', ready: true },
  ],
  compute: [
    { name: 'sandbox-gpu-pool', kind: 'ComputeBackendClaim', namespace: 'cmars-dev', phase: 'Bound', ready: true },
  ],
  datasets: [
    { name: 'support-ticket-dataset', kind: 'DatasetClaim', namespace: 'cmars-dev', phase: 'Ready', ready: true },
  ],
  promotions: [
    { name: 'fraud-detector-staging', kind: 'ModelPromotionClaim', namespace: 'cmars-dev', phase: 'WaitingEval', ready: false },
  ],
  evalPolicies: [
    { name: 'groundedness-and-safety', kind: 'EvaluationPolicy', namespace: 'cmars-dev', phase: 'Ready', ready: true },
  ],
  evalJobs: [
    { name: 'fraud-detector-golden-set', kind: 'EvaluationJob', namespace: 'cmars-dev', phase: 'Pending', ready: false },
  ],
  experiments: [
    { name: 'fraud-detector-lora-sweeps', kind: 'Experiment', namespace: 'cmars-dev', phase: 'Active', ready: true, description: 'LoRA hyperparameter experiment group' },
    { name: 'support-agent-grounding', kind: 'Experiment', namespace: 'cmars-dev', phase: 'Active', ready: true, description: 'Retrieval grounding quality runs' },
  ],
  executions: [
    { name: 'train-fraud-detector-step', kind: 'Execution', namespace: 'cmars-dev', phase: 'Succeeded', ready: true },
    { name: 'evaluate-groundedness-step', kind: 'Execution', namespace: 'cmars-dev', phase: 'Running', ready: false },
  ],
  artifacts: [
    { name: 'fraud-detector-model-v1', kind: 'Artifact', namespace: 'cmars-dev', phase: 'Available', ready: true },
    { name: 'support-ticket-embeddings', kind: 'Artifact', namespace: 'cmars-dev', phase: 'Available', ready: true },
  ],
  inference: [
    { name: 'fraud-detector-v1', kind: 'InferenceClaim', namespace: 'cmars-dev', phase: 'Ready', ready: true },
  ],
  trustyaiMonitoring: [
    { name: 'cmars-trustyai', kind: 'TrustyAIService', namespace: 'cmars-dev', phase: 'Ready', ready: true, description: 'Model monitoring and explainability service reference' },
    { name: 'fraud-detector-drift', kind: 'MonitoringTarget', namespace: 'cmars-dev', phase: 'Active', ready: true, description: 'Drift, bias, and explainability monitoring target' },
  ],
  distributedWorkloads: [
    { name: 'gpu-fair-share-queue', kind: 'KueueClusterQueue', namespace: 'opensphere-system', phase: 'Active', ready: true, description: 'Queue for fair-share AI workload scheduling' },
    { name: 'ray-training-cluster', kind: 'RayCluster', namespace: 'cmars-dev', phase: 'Planned', ready: false, description: 'Distributed training cluster reference' },
  ],
  clusterSettings: [
    { name: 'default-datasciencecluster', kind: 'DataScienceCluster', namespace: 'opensphere-system', phase: 'Managed', ready: true, description: 'ODH/OpenShift AI component enablement profile' },
    { name: 'default-accelerator-profile', kind: 'AcceleratorProfile', namespace: 'opensphere-system', phase: 'Enabled', ready: true, description: 'GPU accelerator profile reference' },
  ],
  enabledApplications: [
    { name: 'Jupyter notebook workspace', kind: 'Application', namespace: 'opensphere-system', phase: 'Enabled', ready: true },
    { name: 'Model registry', kind: 'Application', namespace: 'opensphere-system', phase: 'Enabled', ready: true },
    { name: 'Data science pipelines', kind: 'Application', namespace: 'opensphere-system', phase: 'Enabled', ready: true },
  ],
  exploreApplications: [
    { name: 'TrustyAI monitoring', kind: 'Application', namespace: 'opensphere-system', phase: 'Available', ready: true },
    { name: 'OpenVINO toolkit', kind: 'Application', namespace: 'opensphere-system', phase: 'Available', ready: true },
    { name: 'Vector retrieval service', kind: 'Application', namespace: 'opensphere-system', phase: 'Planned', ready: false },
  ],
  catalog: [
    { name: 'Jupyter notebook workspace', kind: 'Application', namespace: 'opensphere-system', phase: 'Enabled', ready: true },
    { name: 'Model registry', kind: 'Application', namespace: 'opensphere-system', phase: 'Enabled', ready: true },
    { name: 'Vector retrieval service', kind: 'Application', namespace: 'opensphere-system', phase: 'Planned', ready: false },
  ],
  developerLearning: LEARNING_RESOURCES.map((resource) => ({
    name: resource.title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, ''),
    kind: resource.type,
    namespace: resource.provider,
    phase: 'Available',
    ready: true,
    description: resource.description,
  })),
};

const ACTIONS = {
  projects: {
    label: 'Data science project',
    apiVersion: 'v1',
    kind: 'Namespace',
    plural: 'namespaces',
    scope: 'Cluster',
  },
  workbenches: {
    label: 'workbench',
    apiVersion: 'ai.opensphere.io/v1alpha1',
    kind: 'WorkbenchClaim',
    plural: 'workbenchclaims',
    crdName: 'workbenchclaims.ai.opensphere.io',
    group: 'ai.opensphere.io',
  },
  'data-connections': {
    label: 'data connection',
    apiVersion: 'ai.opensphere.io/v1alpha1',
    kind: 'DataConnectionClaim',
    plural: 'dataconnectionclaims',
    crdName: 'dataconnectionclaims.ai.opensphere.io',
    group: 'ai.opensphere.io',
  },
  agents: {
    label: 'AI agent',
    apiVersion: 'orchestrator.ai.opensphere.io/v1alpha1',
    kind: 'AIAgent',
    plural: 'aiagents',
    crdName: 'aiagents.orchestrator.ai.opensphere.io',
    group: 'orchestrator.ai.opensphere.io',
  },
  'llm-routes': {
    label: 'LLM route',
    apiVersion: 'ai.foundation.opensphere.io/v1alpha1',
    kind: 'LLMRouteClaim',
    plural: 'llmrouteclaims',
    crdName: 'llmrouteclaims.ai.foundation.opensphere.io',
    group: 'ai.foundation.opensphere.io',
  },
  retrieval: {
    label: 'retrieval claim',
    apiVersion: 'ai.foundation.opensphere.io/v1alpha1',
    kind: 'VectorRetrievalClaim',
    plural: 'vectorretrievalclaims',
    crdName: 'vectorretrievalclaims.ai.foundation.opensphere.io',
    group: 'ai.foundation.opensphere.io',
  },
  compute: {
    label: 'compute backend',
    apiVersion: 'ai.opensphere.io/v1alpha1',
    kind: 'ComputeBackendClaim',
    plural: 'computebackendclaims',
    crdName: 'computebackendclaims.ai.opensphere.io',
    group: 'ai.opensphere.io',
  },
  datasets: {
    label: 'dataset',
    apiVersion: 'ai.opensphere.io/v1alpha1',
    kind: 'DatasetClaim',
    plural: 'datasetclaims',
    crdName: 'datasetclaims.ai.opensphere.io',
    group: 'ai.opensphere.io',
  },
  'training-jobs': {
    label: 'training job',
    apiVersion: 'ai.opensphere.io/v1alpha1',
    kind: 'TrainingJobClaim',
    plural: 'trainingjobclaims',
    crdName: 'trainingjobclaims.ai.opensphere.io',
    group: 'ai.opensphere.io',
  },
  'model-promotion': {
    label: 'model promotion',
    apiVersion: 'ai.opensphere.io/v1alpha1',
    kind: 'ModelPromotionClaim',
    plural: 'modelpromotionclaims',
    crdName: 'modelpromotionclaims.ai.opensphere.io',
    group: 'ai.opensphere.io',
  },
  'eval-policy': {
    label: 'evaluation policy',
    apiVersion: 'eval.ai.opensphere.io/v1alpha1',
    kind: 'EvaluationPolicy',
    plural: 'evaluationpolicies',
    crdName: 'evaluationpolicies.eval.ai.opensphere.io',
    group: 'eval.ai.opensphere.io',
  },
  'eval-jobs': {
    label: 'evaluation job',
    apiVersion: 'eval.ai.opensphere.io/v1alpha1',
    kind: 'EvaluationJob',
    plural: 'evaluationjobs',
    crdName: 'evaluationjobs.eval.ai.opensphere.io',
    group: 'eval.ai.opensphere.io',
  },
  inference: {
    label: 'inference endpoint',
    apiVersion: 'ai.opensphere.io/v1alpha1',
    kind: 'InferenceClaim',
    plural: 'inferenceclaims',
    crdName: 'inferenceclaims.ai.opensphere.io',
    group: 'ai.opensphere.io',
  },
  pipelines: {
    label: 'pipeline',
    apiVersion: 'ai.opensphere.io/v1alpha1',
    kind: 'PipelineClaim',
    plural: 'pipelineclaims',
    crdName: 'pipelineclaims.ai.opensphere.io',
    group: 'ai.opensphere.io',
  },
  'pipeline-runs': {
    label: 'pipeline run',
    apiVersion: 'ai.opensphere.io/v1alpha1',
    kind: 'PipelineRunClaim',
    plural: 'pipelinerunclaims',
    crdName: 'pipelinerunclaims.ai.opensphere.io',
    group: 'ai.opensphere.io',
  },
  'experiments-runs': {
    label: 'experiment',
    apiVersion: 'ai.opensphere.io/v1alpha1',
    kind: 'ExperimentClaim',
    plural: 'experimentclaims',
    crdName: 'experimentclaims.ai.opensphere.io',
    group: 'ai.opensphere.io',
  },
  executions: {
    label: 'execution',
    apiVersion: 'ai.opensphere.io/v1alpha1',
    kind: 'ExecutionClaim',
    plural: 'executionclaims',
    crdName: 'executionclaims.ai.opensphere.io',
    group: 'ai.opensphere.io',
  },
  artifacts: {
    label: 'artifact',
    apiVersion: 'ai.opensphere.io/v1alpha1',
    kind: 'ArtifactClaim',
    plural: 'artifactclaims',
    crdName: 'artifactclaims.ai.opensphere.io',
    group: 'ai.opensphere.io',
  },
  'trustyai-monitoring': {
    label: 'monitoring target',
    apiVersion: 'ai.opensphere.io/v1alpha1',
    kind: 'MonitoringTarget',
    plural: 'monitoringtargets',
    crdName: 'monitoringtargets.ai.opensphere.io',
    group: 'ai.opensphere.io',
  },
  'distributed-workloads': {
    label: 'distributed workload',
    apiVersion: 'ai.opensphere.io/v1alpha1',
    kind: 'DistributedWorkloadClaim',
    plural: 'distributedworkloadclaims',
    crdName: 'distributedworkloadclaims.ai.opensphere.io',
    group: 'ai.opensphere.io',
  },
};

const ACTION_BY_KIND = Object.fromEntries(Object.entries(ACTIONS).map(([page, def]) => [def.kind, { page, ...def }]));

const OPENSPHERE_PLATFORM_CRDS = [
  {
    group: 'ai.opensphere.io',
    plural: 'openspherecomponentcatalogs',
    singular: 'openspherecomponentcatalog',
    kind: 'OpenSphereComponentCatalog',
    name: 'openspherecomponentcatalogs.ai.opensphere.io',
  },
  {
    group: 'ai.opensphere.io',
    plural: 'openspherecomponentversions',
    singular: 'openspherecomponentversion',
    kind: 'OpenSphereComponentVersion',
    name: 'openspherecomponentversions.ai.opensphere.io',
  },
  {
    group: 'ai.opensphere.io',
    plural: 'openspheresubscriptions',
    singular: 'openspheresubscription',
    kind: 'OpenSphereSubscription',
    name: 'openspheresubscriptions.ai.opensphere.io',
  },
  {
    group: 'ai.opensphere.io',
    plural: 'opensphereinstallplans',
    singular: 'opensphereinstallplan',
    kind: 'OpenSphereInstallPlan',
    name: 'opensphereinstallplans.ai.opensphere.io',
  },
  {
    group: 'ai.opensphere.io',
    plural: 'openspheredatascienceclusters',
    singular: 'openspheredatasciencecluster',
    kind: 'OpenSphereDataScienceCluster',
    name: 'openspheredatascienceclusters.ai.opensphere.io',
  },
];

const NATIVE_COMPONENTS = [
  {
    name: 'workbenches',
    displayName: 'Workbench runtime',
    channel: 'stable',
    version: '0.1.0',
    description: 'Creates OpenSphere WorkbenchClaim resources and reconciles them toward Notebook-compatible runtimes.',
    upstream: ['Kubeflow Notebooks', 'ODH Workbenches'],
  },
  {
    name: 'pipelines',
    displayName: 'Pipeline runtime',
    channel: 'stable',
    version: '0.1.0',
    description: 'Manages PipelineClaim and PipelineRunClaim resources for training and data processing workflows.',
    upstream: ['Kubeflow Pipelines', 'Tekton'],
  },
  {
    name: 'model-serving',
    displayName: 'Model serving',
    channel: 'stable',
    version: '0.1.0',
    description: 'Reconciles InferenceClaim resources toward KServe-compatible or Kubernetes-native serving endpoints.',
    upstream: ['KServe', 'ODH Model Serving'],
  },
  {
    name: 'model-registry',
    displayName: 'Model registry',
    channel: 'stable',
    version: '0.1.0',
    description: 'Tracks model versions, stages, artifacts, and promotion metadata.',
    upstream: ['ODH Model Registry'],
  },
  {
    name: 'monitoring',
    displayName: 'Model monitoring',
    channel: 'stable',
    version: '0.1.0',
    description: 'Provides MonitoringTarget resources for drift, bias, explainability, and groundedness signals.',
    upstream: ['TrustyAI'],
  },
  {
    name: 'distributed-workloads',
    displayName: 'Distributed workloads',
    channel: 'preview',
    version: '0.1.0',
    description: 'Coordinates DistributedWorkloadClaim resources with queue and Ray-compatible execution patterns.',
    upstream: ['Kueue', 'Ray'],
  },
];

function cleanName(value) {
  return String(value || '').trim().toLowerCase();
}

function requireDnsName(value, field) {
  const name = cleanName(value);
  if (!name || !/^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/.test(name)) {
    throw { code: 400, msg: `${field} must be a DNS-1123 name` };
  }
  return name;
}

function optionalString(value) {
  return String(value || '').trim();
}

function numberOrUndefined(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : undefined;
}

function ref(name, kind, apiVersion, namespace) {
  const out = { name: requireDnsName(name, `${kind} reference`) };
  if (kind) out.kind = kind;
  if (apiVersion) out.apiVersion = apiVersion;
  if (namespace) out.namespace = namespace;
  return out;
}

function splitNamespacedName(value, fallbackNamespace) {
  if (value && typeof value === 'object') {
    return {
      name: requireDnsName(value.name, 'ComputeBackendClaim reference'),
      namespace: requireDnsName(value.namespace || fallbackNamespace, 'ComputeBackendClaim namespace'),
    };
  }
  const raw = optionalString(value);
  if (raw.includes('/')) {
    const [namespace, name] = raw.split('/');
    return {
      name: requireDnsName(name, 'ComputeBackendClaim reference'),
      namespace: requireDnsName(namespace, 'ComputeBackendClaim namespace'),
    };
  }
  return {
    name: requireDnsName(raw, 'ComputeBackendClaim reference'),
    namespace: requireDnsName(fallbackNamespace, 'ComputeBackendClaim namespace'),
  };
}

function computeBackendReference(body, namespace, fallbackName) {
  const raw = body.computeBackendRef || body.computeBackendName || fallbackName;
  const fallbackNamespace = body.computeBackendNamespace || namespace;
  const parsed = splitNamespacedName(raw, fallbackNamespace);
  return ref(parsed.name, 'ComputeBackendClaim', 'ai.opensphere.io/v1alpha1', parsed.namespace);
}

function objectMeta(name, namespace, description) {
  const meta = { name: requireDnsName(name, 'name') };
  if (namespace) meta.namespace = requireDnsName(namespace, 'namespace');
  if (description) meta.annotations = { 'opensphere.io/description': description };
  return meta;
}

function buildSpec(page, body, namespace) {
  switch (page) {
    case 'workbenches':
      return {
        image: body.image || body.notebookImage || body.source || 'standard-data-science',
        storage: body.storage || '20Gi',
        dataConnections: optionalString(body.sourceRef) ? [ref(body.sourceRef, 'DataConnectionClaim', 'ai.opensphere.io/v1alpha1', namespace)] : [],
        computeBackendRef: computeBackendReference(body, namespace, 'sandbox-gpu-pool'),
        resources: {
          gpuClass: optionalString(body.gpuClass),
        },
      };
    case 'data-connections':
      return {
        connectionType: body.sourceType || 'bucket',
        sourceRef: optionalString(body.sourceRef),
        purpose: body.purpose || 'workspace',
      };
    case 'agents': {
      const spec = {
        tier: body.tier || 'personal',
        llmRouteRef: ref(body.llmRouteRef || 'default-chat-route', 'LLMRouteClaim', 'ai.foundation.opensphere.io/v1alpha1', namespace),
        requireSourceAttribution: body.requireSourceAttribution !== false,
      };
      if (optionalString(body.promptLibraryRef)) {
        spec.promptLibraryRef = ref(body.promptLibraryRef, 'PromptLibrary', 'orchestrator.ai.opensphere.io/v1alpha1', namespace);
      }
      return spec;
    }
    case 'llm-routes':
      return {
        provider: body.provider || 'openai-compatible',
        model: body.model || 'default',
        endpoint: optionalString(body.endpoint),
      };
    case 'retrieval':
      return {
        sourceRef: ref(body.sourceRef || 'default-source', 'DatasetClaim', 'ai.opensphere.io/v1alpha1', namespace),
        embeddingRouteRef: ref(body.llmRouteRef || 'embedding-route', 'LLMRouteClaim', 'ai.foundation.opensphere.io/v1alpha1', namespace),
      };
    case 'compute':
      return {
        backendType: body.backendType || 'kubernetes',
        gpuClass: optionalString(body.gpuClass),
        endpoint: optionalString(body.endpoint),
      };
    case 'datasets':
      return {
        sourceType: body.sourceType || 'bucket',
        sourceRef: ref(body.sourceRef || 'default-source', 'ConfigMap', 'v1', namespace),
        purpose: body.purpose || 'fine-tune',
      };
    case 'training-jobs':
      return {
        computeBackendRef: computeBackendReference(body, namespace, 'sandbox-gpu-pool'),
        datasetRef: ref(body.datasetRef || 'support-ticket-dataset', 'DatasetClaim', 'ai.opensphere.io/v1alpha1', namespace),
        framework: body.framework || 'transformers',
        trainingMode: body.trainingMode || 'lora',
      };
    case 'model-promotion':
      return {
        modelRef: ref(body.modelRef || 'trained-model', 'TrainingJobClaim', 'ai.opensphere.io/v1alpha1', namespace),
        evaluationRef: ref(body.evaluationRef || 'golden-set-eval', 'EvaluationJob', 'eval.ai.opensphere.io/v1alpha1', namespace),
        stage: body.stage || 'staging',
      };
    case 'eval-policy': {
      const gate = {
        metric: body.metric || 'groundedness',
        minimum: numberOrUndefined(body.minimum || 0.8),
      };
      return {
        datasetRef: ref(body.datasetRef || 'golden-set', 'DatasetClaim', 'ai.opensphere.io/v1alpha1', namespace),
        enforcement: body.enforcement || 'block',
        gates: [gate],
      };
    }
    case 'eval-jobs': {
      const spec = {
        policyRef: ref(body.policyRef || 'groundedness-and-safety', 'EvaluationPolicy', 'eval.ai.opensphere.io/v1alpha1', namespace),
        targetRef: ref(body.targetRef || 'candidate-model', body.targetKind || 'TrainingJobClaim', body.targetApiVersion || 'ai.opensphere.io/v1alpha1', namespace),
      };
      if (optionalString(body.promotionRef)) {
        spec.promotionRef = ref(body.promotionRef, 'ModelPromotionClaim', 'ai.opensphere.io/v1alpha1', namespace);
      }
      return spec;
    }
    case 'inference':
      return {
        modelRef: ref(body.modelRef || 'trained-model', 'TrainingJobClaim', 'ai.opensphere.io/v1alpha1', namespace),
        promotionRef: ref(body.promotionRef || 'production-promotion', 'ModelPromotionClaim', 'ai.opensphere.io/v1alpha1', namespace),
        runtime: body.runtime || 'kserve',
        backend: body.backendType || body.backend || 'auto',
        computeBackendRef: computeBackendReference(body, namespace, 'sandbox-gpu-pool'),
      };
    case 'pipelines':
      return {
        sourceRef: ref(body.sourceRef || 'pipeline-source', 'DataConnectionClaim', 'ai.opensphere.io/v1alpha1', namespace),
        datasetRef: ref(body.datasetRef || 'support-ticket-dataset', 'DatasetClaim', 'ai.opensphere.io/v1alpha1', namespace),
        computeBackendRef: computeBackendReference(body, namespace, 'sandbox-gpu-pool'),
        framework: body.framework || 'kubeflow-pipeline',
      };
    case 'pipeline-runs':
      return {
        backend: body.backendType || body.backend || 'auto',
        pipelineRef: ref(body.sourceRef || body.pipelineRef || 'pipeline', 'PipelineClaim', 'ai.opensphere.io/v1alpha1', namespace),
        computeBackendRef: computeBackendReference(body, namespace, 'sandbox-gpu-pool'),
        experimentRef: optionalString(body.targetRef) ? ref(body.targetRef, 'ExperimentClaim', 'ai.opensphere.io/v1alpha1', namespace) : undefined,
        parameters: {
          datasetRef: body.datasetRef || 'support-ticket-dataset',
          trainingMode: body.trainingMode || 'lora',
        },
      };
    case 'experiments-runs':
      return {
        objective: body.description || 'Track AI/ML experiment runs',
        datasetRef: optionalString(body.datasetRef) ? ref(body.datasetRef, 'DatasetClaim', 'ai.opensphere.io/v1alpha1', namespace) : undefined,
        metric: body.metric || 'accuracy',
      };
    case 'executions':
      return {
        experimentRef: ref(body.targetRef || 'default-experiment', 'ExperimentClaim', 'ai.opensphere.io/v1alpha1', namespace),
        pipelineRunRef: optionalString(body.sourceRef) ? ref(body.sourceRef, 'PipelineRunClaim', 'ai.opensphere.io/v1alpha1', namespace) : undefined,
        step: body.stage || 'manual',
      };
    case 'artifacts':
      return {
        artifactType: body.sourceType || 'model',
        sourceRef: optionalString(body.sourceRef),
        stage: body.stage || 'development',
      };
    case 'trustyai-monitoring':
      return {
        backend: body.backendType || body.backend || 'auto',
        targetRef: ref(body.targetRef || body.modelRef || 'model-deployment', body.targetKind || 'InferenceClaim', body.targetApiVersion || 'ai.opensphere.io/v1alpha1', namespace),
        metrics: [body.metric || 'drift', 'bias', 'explainability'],
        threshold: numberOrUndefined(body.minimum || 0.8),
        enforcement: body.enforcement || 'audit',
      };
    case 'distributed-workloads':
      return {
        workloadType: body.framework || 'ray',
        backend: body.backendType || body.backend || 'auto',
        computeBackendRef: computeBackendReference(body, namespace, 'sandbox-gpu-pool'),
        datasetRef: optionalString(body.datasetRef) ? ref(body.datasetRef, 'DatasetClaim', 'ai.opensphere.io/v1alpha1', namespace) : undefined,
        queue: body.sourceRef || 'gpu-fair-share-queue',
      };
    default:
      return {};
  }
}

async function crdInstalled(crdName) {
  if (!crdName) return true;
  return !!(await k8sJson(`/apis/apiextensions.k8s.io/v1/customresourcedefinitions/${crdName}`));
}

async function capabilityStatus() {
  const entries = await Promise.all(Object.entries(ACTIONS).map(async ([page, def]) => ({
    page,
    label: def.label,
    kind: def.kind,
    crdName: def.crdName || '',
    installed: await crdInstalled(def.crdName),
    namespaced: def.scope !== 'Cluster',
  })));
  return { items: entries };
}

async function writeK8s(apiPath, method, body, req) {
  const headers = { Authorization: `Bearer ${tok()}`, Accept: 'application/json', 'Content-Type': req?.contentType || 'application/json' };
  let actor = 'system:serviceaccount:opensphere-system:default';
  if (req && !req._internal && !req.headers?.['x-os-id-token']) {
    throw { code: 401, msg: 'Authentication required for Kubernetes write action.' };
  }
  if (req?.headers?.['x-os-id-token']) {
    const verified = req._actor || await verifyToken(req.headers['x-os-id-token']);
    req._actor = verified;
    actor = verified.username;
    headers['Impersonate-User'] = verified.username;
  }
  const r = await fetch(`${APISERVER}${apiPath}`, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const text = await r.text();
  console.log(`[audit] user=${actor} verb=${method} path=${apiPath} status=${r.status} ${new Date().toISOString()}`);
  let parsed;
  try { parsed = text ? JSON.parse(text) : {}; } catch { parsed = { message: text }; }
  if (!r.ok) throw { code: r.status, msg: parsed?.message || parsed?.error || text || `HTTP ${r.status}`, details: parsed };
  return parsed;
}

async function requestActor(req) {
  if (req?._actor) return req._actor;
  const token = req?.headers?.['x-os-id-token'];
  if (!token) {
    await appendAuditLog({
      time: new Date().toISOString(),
      type: 'Warning',
      reason: 'AccessDenied',
      message: 'Authentication required for this action.',
      namespace: '',
      kind: 'SecurityPolicy',
      name: 'authentication',
      phase: 'Denied',
      ready: false,
      backendMode: '',
      backendPhase: '',
      controller: 'SecurityPolicy',
      actor: 'anonymous',
    });
    throw { code: 401, msg: 'Authentication required for this action.' };
  }
  try {
    const actor = await verifyToken(token);
    req._actor = actor;
    return actor;
  } catch (e) {
    await appendAuditLog({
      time: new Date().toISOString(),
      type: 'Warning',
      reason: 'AccessDenied',
      message: e.msg || 'Invalid identity token.',
      namespace: '',
      kind: 'SecurityPolicy',
      name: 'authentication',
      phase: 'Denied',
      ready: false,
      backendMode: '',
      backendPhase: '',
      controller: 'SecurityPolicy',
      actor: 'invalid-token',
    });
    throw e;
  }
}

function actorIsAdmin(actor) {
  const groups = actor?.groups || [];
  return groups.some((group) => ADMIN_GROUPS.includes(group));
}

function bodyJson(req) {
  if (req._jsonBody) return req._jsonBody;
  return {};
}

async function appendSecurityAudit(req, allowed, action, target, reason) {
  const actor = req?._actor || null;
  await appendAuditLog({
    time: new Date().toISOString(),
    type: allowed ? 'Normal' : 'Warning',
    reason: allowed ? 'AccessAllowed' : 'AccessDenied',
    message: `${action}: ${reason}`,
    namespace: target?.namespace || '',
    kind: target?.kind || 'SecurityPolicy',
    name: target?.name || target?.resource || '',
    phase: allowed ? 'Allowed' : 'Denied',
    ready: allowed,
    backendMode: '',
    backendPhase: '',
    controller: 'SecurityPolicy',
    actor: actor?.username || 'anonymous',
    groups: actor?.groups || [],
    verb: target?.verb || '',
    resource: target?.resource || '',
    apiGroup: target?.group || '',
  });
}

async function requireResourceAccess(req, action, { verb, group = '', resource, namespace = '', kind = '', name = '' }) {
  await requestActor(req);
  const allowed = await selfCan(req, verb, group, resource, namespace || undefined);
  const target = { verb, group, resource, namespace, kind, name };
  if (!allowed) {
    const reason = `requires ${verb} on ${group ? `${group}/` : ''}${resource}${namespace ? ` in ${namespace}` : ''}`;
    await appendSecurityAudit(req, false, action, target, reason);
    throw { code: 403, msg: `Forbidden: ${reason}` };
  }
  await appendSecurityAudit(req, true, action, target, 'RBAC check passed');
}

async function requireAdminAccess(req, action) {
  const actor = await requestActor(req);
  if (actorIsAdmin(actor)) {
    await appendSecurityAudit(req, true, action, { kind: 'AdminAction', resource: 'admin' }, `admin group matched: ${ADMIN_GROUPS.join(', ')}`);
    return;
  }
  const checks = await Promise.all([
    selfCan(req, 'create', 'apiextensions.k8s.io', 'customresourcedefinitions'),
    selfCan(req, 'create', '', 'namespaces'),
    selfCan(req, 'create', 'operators.coreos.com', 'subscriptions', 'opensphere-system'),
  ]);
  if (checks.some(Boolean)) {
    await appendSecurityAudit(req, true, action, { kind: 'AdminAction', resource: 'admin' }, 'cluster-level RBAC check passed');
    return;
  }
  const reason = `requires admin group (${ADMIN_GROUPS.join(', ')}) or cluster setup RBAC`;
  await appendSecurityAudit(req, false, action, { kind: 'AdminAction', resource: 'admin' }, reason);
  throw { code: 403, msg: `Forbidden: ${reason}` };
}

async function prepareJsonBody(req) {
  if (req._jsonBody) return req._jsonBody;
  const raw = (await readBody(req)).toString('utf8') || '{}';
  try {
    req._jsonBody = JSON.parse(raw);
  } catch {
    throw { code: 400, msg: 'Request body must be valid JSON.' };
  }
  return req._jsonBody;
}

async function patchK8s(apiPath, patch, req) {
  const patchReq = {
    headers: req?.headers || {},
    contentType: 'application/merge-patch+json',
    _internal: !req,
  };
  return writeK8s(apiPath, 'PATCH', patch, patchReq);
}

async function tryPatch(paths, patch, req) {
  let last;
  for (const apiPath of paths) {
    try {
      return await patchK8s(apiPath, patch, req);
    } catch (e) {
      last = e;
    }
  }
  throw last || { code: 404, msg: 'No matching Kubernetes resource path found' };
}

function dnsLabel(value, prefix = '') {
  const raw = `${prefix}${value || ''}`.toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '');
  const trimmed = raw.slice(0, 63).replace(/-+$/g, '');
  return trimmed || 'resource';
}

function shortHash(value) {
  return createHash('sha1').update(String(value || '')).digest('hex').slice(0, 8);
}

function runtimeNameForClaim(claim) {
  return dnsLabel(claim.metadata?.name || 'workbench', 'oswb-');
}

function pipelineJobNameForClaim(claim) {
  const retryAt = optionalString(claim.spec?.retryAt);
  const suffix = retryAt ? `-${shortHash(retryAt)}` : '';
  return dnsLabel(`${claim.metadata?.name || 'pipeline-run'}${suffix}`, 'ospr-');
}

function inferenceRuntimeNameForClaim(claim) {
  return dnsLabel(claim.metadata?.name || 'inference', 'osinf-');
}

function distributedJobNameForClaim(claim) {
  const retryAt = optionalString(claim.spec?.retryAt);
  const suffix = retryAt ? `-${shortHash(retryAt)}` : '';
  return dnsLabel(`${claim.metadata?.name || 'distributed-workload'}${suffix}`, 'osdw-');
}

function workbenchImageFor(spec) {
  const image = optionalString(spec?.image || spec?.notebookImage || spec?.runtimeImage);
  if (!image || image === 'standard-data-science' || image === 'pytorch-gpu' || image === 'tensorflow-gpu') return WORKBENCH_IMAGE;
  return image;
}

function ownerRefFor(obj) {
  if (!obj?.metadata?.uid) return [];
  return [{
    apiVersion: obj.apiVersion || 'ai.opensphere.io/v1alpha1',
    kind: obj.kind || 'WorkbenchClaim',
    name: obj.metadata.name,
    uid: obj.metadata.uid,
    controller: true,
    blockOwnerDeletion: false,
  }];
}

function hasFinalizer(obj, finalizer = AI_CLAIM_FINALIZER) {
  return (obj?.metadata?.finalizers || []).includes(finalizer);
}

function claimPath(namespace, plural, name) {
  return `/apis/ai.opensphere.io/v1alpha1/namespaces/${namespace}/${plural}/${name}`;
}

async function ensureClaimFinalizer(claim, plural) {
  const namespace = claim.metadata?.namespace || 'default';
  const name = claim.metadata?.name;
  if (!name || claim.metadata?.deletionTimestamp || hasFinalizer(claim)) return false;
  const finalizers = [...(claim.metadata?.finalizers || []), AI_CLAIM_FINALIZER];
  await patchK8s(claimPath(namespace, plural, name), { metadata: { finalizers } }, null);
  claim.metadata.finalizers = finalizers;
  return true;
}

async function removeClaimFinalizer(claim, plural) {
  const namespace = claim.metadata?.namespace || 'default';
  const name = claim.metadata?.name;
  if (!name || !hasFinalizer(claim)) return false;
  const finalizers = (claim.metadata?.finalizers || []).filter((item) => item !== AI_CLAIM_FINALIZER);
  await patchK8s(claimPath(namespace, plural, name), { metadata: { finalizers } }, null).catch(() => null);
  claim.metadata.finalizers = finalizers;
  return true;
}

async function deleteK8sIfExists(apiPath) {
  try {
    await writeK8s(apiPath, 'DELETE', null, null);
    return true;
  } catch (e) {
    if (e.code === 404) return false;
    throw e;
  }
}

async function cleanupClaimResources(claim, plural, cleanupFn) {
  if (!claim.metadata?.deletionTimestamp) return null;
  const namespace = claim.metadata?.namespace || 'default';
  const name = claim.metadata?.name || '';
  const cleanup = await cleanupFn(claim);
  await appendAuditLog({
    time: new Date().toISOString(),
    type: 'Normal',
    reason: 'FinalizerCleanupCompleted',
    message: `Cleaned up ${cleanup.deleted} child resources before deleting ${claim.kind || 'claim'}.`,
    namespace,
    kind: claim.kind || 'OpenSphereAIClaim',
    name,
    phase: 'Deleting',
    ready: false,
    backendMode: claim.status?.backendMode || '',
    backendPhase: claim.status?.backendPhase || '',
    controller: 'FinalizerCleanup',
  });
  await removeClaimFinalizer(claim, plural);
  return { name, namespace, phase: 'Deleting', deleted: cleanup.deleted, resources: cleanup.resources };
}

function retryDelayMs(retryCount) {
  const exponent = Math.min(Math.max(retryCount - 1, 0), 5);
  return Math.min(RETRY_BASE_MS * (2 ** exponent), RETRY_MAX_MS);
}

function pendingRetryMs(claim) {
  if (claim.status?.phase !== 'Retrying' || !claim.status?.nextRetryAt) return 0;
  const next = Date.parse(claim.status.nextRetryAt);
  if (!Number.isFinite(next)) return 0;
  return Math.max(0, next - Date.now());
}

function retryingResult(claim, runtimeName) {
  return {
    name: claim.metadata?.name || '',
    namespace: claim.metadata?.namespace || 'default',
    runtimeName,
    phase: 'Retrying',
    nextRetryAt: claim.status?.nextRetryAt || '',
    deferred: true,
  };
}

function retryStatus(claim, baseStatus, error, fallbackMessage = 'Reconcile failed') {
  const retryCount = Number(claim.status?.retryCount || 0) + 1;
  const nextRetryAt = new Date(Date.now() + retryDelayMs(retryCount)).toISOString();
  const message = error?.msg || error?.message || String(error || fallbackMessage);
  return {
    ...baseStatus,
    phase: 'Retrying',
    ready: false,
    retryCount,
    lastFailureReason: 'ReconcileFailed',
    lastFailureMessage: message,
    nextRetryAt,
    conditions: [{
      type: 'Ready',
      status: 'False',
      reason: 'ReconcileRetryScheduled',
      message: `${message}. Next retry after ${nextRetryAt}.`,
      lastTransitionTime: new Date().toISOString(),
    }],
  };
}

function resetRetryFields(status) {
  return {
    ...status,
    retryCount: 0,
    lastFailureReason: '',
    lastFailureMessage: '',
    nextRetryAt: '',
  };
}

function compactConditions(conditions) {
  return (conditions || []).map((condition) => ({
    type: optionalString(condition.type || ''),
    status: optionalString(condition.status || ''),
    reason: optionalString(condition.reason || ''),
    message: optionalString(condition.message || ''),
    lastTransitionTime: optionalString(condition.lastTransitionTime || condition.lastUpdateTime || ''),
  })).filter((condition) => condition.type || condition.reason || condition.message);
}

function readyCondition(ready, reason, message) {
  return {
    type: 'Ready',
    status: ready ? 'True' : 'False',
    reason: optionalString(reason || (ready ? 'Ready' : 'NotReady')) || (ready ? 'Ready' : 'NotReady'),
    message: optionalString(message || '') || (ready ? 'Resource is ready.' : 'Resource is not ready yet.'),
    lastTransitionTime: new Date().toISOString(),
  };
}

function normalizedStatus({ phase, ready, reason, message, upstreamConditions, extra }) {
  const condition = readyCondition(ready, reason, message);
  return {
    ...(extra || {}),
    phase,
    ready,
    reason: condition.reason,
    message: condition.message,
    conditions: [condition],
    upstreamConditions: compactConditions(upstreamConditions),
    normalizedAt: new Date().toISOString(),
  };
}

function normalizeJobStatus(job, suspended, options = {}) {
  const active = job?.status?.active || 0;
  const succeeded = job?.status?.succeeded || 0;
  const failed = job?.status?.failed || 0;
  if (suspended || job?.spec?.suspend === true) {
    return normalizedStatus({
      phase: options.suspendedPhase || 'Suspended',
      ready: false,
      reason: options.suspendedReason || 'Suspended',
      message: options.suspendedMessage || 'Job is suspended.',
      upstreamConditions: job?.status?.conditions,
      extra: { active, succeeded, failed },
    });
  }
  if (succeeded > 0) {
    return normalizedStatus({
      phase: 'Succeeded',
      ready: true,
      reason: options.succeededReason || 'JobSucceeded',
      message: options.succeededMessage || 'Job completed successfully.',
      upstreamConditions: job?.status?.conditions,
      extra: { active, succeeded, failed },
    });
  }
  if (failed > 0) {
    return normalizedStatus({
      phase: 'Failed',
      ready: false,
      reason: options.failedReason || 'JobFailed',
      message: options.failedMessage || 'Job failed.',
      upstreamConditions: job?.status?.conditions,
      extra: { active, succeeded, failed },
    });
  }
  if (active > 0) {
    return normalizedStatus({
      phase: 'Running',
      ready: false,
      reason: options.runningReason || 'JobRunning',
      message: options.runningMessage || 'Job is running.',
      upstreamConditions: job?.status?.conditions,
      extra: { active, succeeded, failed },
    });
  }
  return normalizedStatus({
    phase: options.pendingPhase || 'Pending',
    ready: false,
    reason: options.pendingReason || 'WaitingForJob',
    message: options.pendingMessage || 'Waiting for Job to start.',
    upstreamConditions: job?.status?.conditions,
    extra: { active, succeeded, failed },
  });
}

function normalizeTektonPipelineRunStatus(current) {
  const conditions = current?.status?.conditions || [];
  const succeeded = conditions.find((condition) => condition.type === 'Succeeded');
  const status = optionalString(succeeded?.status || '');
  const reason = optionalString(succeeded?.reason || '');
  const message = optionalString(succeeded?.message || '');
  if (status === 'True') {
    return normalizedStatus({
      phase: 'Succeeded',
      ready: true,
      reason: reason || 'TektonPipelineRunSucceeded',
      message: message || 'Tekton PipelineRun completed successfully.',
      upstreamConditions: conditions,
    });
  }
  if (status === 'False') {
    return normalizedStatus({
      phase: 'Failed',
      ready: false,
      reason: reason || 'TektonPipelineRunFailed',
      message: message || 'Tekton PipelineRun failed.',
      upstreamConditions: conditions,
    });
  }
  return normalizedStatus({
    phase: 'Running',
    ready: false,
    reason: reason || 'TektonPipelineRunRunning',
    message: message || 'Tekton PipelineRun is running.',
    upstreamConditions: conditions,
  });
}

function normalizeKServeStatus(current) {
  const conditions = current?.status?.conditions || [];
  const ready = conditions.find((condition) => condition.type === 'Ready');
  const reason = optionalString(ready?.reason || '');
  const message = optionalString(ready?.message || '');
  const isReady = ready?.status === 'True';
  const isFailed = ready?.status === 'False' && /fail|error|invalid|missing/i.test(`${reason} ${message}`);
  return normalizedStatus({
    phase: isReady ? 'Ready' : isFailed ? 'Failed' : 'Provisioning',
    ready: isReady,
    reason: isReady ? (reason || 'KServeInferenceServiceReady') : (reason || 'WaitingForKServe'),
    message: isReady ? (message || 'KServe InferenceService is ready.') : (message || 'Waiting for KServe InferenceService readiness.'),
    upstreamConditions: conditions,
  });
}

function normalizeRayJobStatus(current, suspended) {
  const rawStatus = optionalString(current?.status?.jobStatus || current?.status?.jobDeploymentStatus || (suspended ? 'Suspended' : 'Submitted')) || 'Submitted';
  const upper = rawStatus.toUpperCase();
  const ready = ['SUCCEEDED', 'SUCCESS', 'COMPLETED', 'COMPLETE'].includes(upper);
  const failed = ['FAILED', 'FAILURE', 'STOPPED', 'ERROR'].includes(upper);
  return normalizedStatus({
    phase: ready ? 'Succeeded' : failed ? 'Failed' : rawStatus,
    ready,
    reason: ready ? 'RayJobSucceeded' : failed ? 'RayJobFailed' : 'RayJobSubmitted',
    message: ready ? 'RayJob completed successfully.' : failed ? `RayJob failed with status ${rawStatus}.` : `RayJob is ${rawStatus}.`,
    upstreamConditions: current?.status?.conditions,
    extra: { rayJobStatus: rawStatus },
  });
}

async function upsertK8s(collectionPath, resourcePath, object, patch, req) {
  try {
    return await writeK8s(collectionPath, 'POST', object, req);
  } catch (e) {
    if (e.code !== 409) throw e;
    return patchK8s(resourcePath, patch || object, req);
  }
}

const controllerMetrics = {
  startedAt: new Date().toISOString(),
  reconciles: new Map(),
  events: new Map(),
};

function metricKey(parts) {
  return Object.entries(parts).map(([key, value]) => `${key}=${String(value || 'none')}`).join('|');
}

function metricLabelsFromKey(key) {
  return Object.fromEntries(String(key).split('|').filter(Boolean).map((part) => {
    const idx = part.indexOf('=');
    return [part.slice(0, idx), part.slice(idx + 1)];
  }));
}

function observeReconcile(controller, result, durationMs) {
  const phase = optionalString(result?.phase || (result?.error ? 'Failed' : 'Unknown')) || 'Unknown';
  const backend = optionalString(result?.backend || result?.backendMode || result?.runtime || 'opensphere') || 'opensphere';
  const key = metricKey({ controller, phase, backend });
  const current = controllerMetrics.reconciles.get(key) || {
    controller,
    phase,
    backend,
    total: 0,
    failures: 0,
    durationMsTotal: 0,
    lastDurationMs: 0,
    lastAt: '',
    lastName: '',
  };
  current.total += 1;
  if (phase.toLowerCase().includes('fail') || result?.error) current.failures += 1;
  current.durationMsTotal += durationMs;
  current.lastDurationMs = durationMs;
  current.lastAt = new Date().toISOString();
  current.lastName = result?.name || '';
  controllerMetrics.reconciles.set(key, current);
}

async function reconcileClaimWithMetrics(controller, claim, fn) {
  const started = Date.now();
  try {
    const result = await fn(claim);
    observeReconcile(controller, result, Date.now() - started);
    return result;
  } catch (e) {
    const result = {
      name: claim?.metadata?.name || '',
      namespace: claim?.metadata?.namespace || '',
      phase: 'Failed',
      error: e.msg || String(e),
    };
    observeReconcile(controller, result, Date.now() - started);
    throw e;
  }
}

function observeReconcileEvent(reason, type) {
  const key = metricKey({ reason: reason || 'Unknown', type: type || 'Normal' });
  const current = controllerMetrics.events.get(key) || { reason: reason || 'Unknown', type: type || 'Normal', total: 0, lastAt: '' };
  current.total += 1;
  current.lastAt = new Date().toISOString();
  controllerMetrics.events.set(key, current);
}

function nativeControllerMetrics() {
  const items = Array.from(controllerMetrics.reconciles.values()).map((item) => ({
    ...item,
    avgDurationMs: item.total ? Math.round(item.durationMsTotal / item.total) : 0,
  })).sort((a, b) => a.controller.localeCompare(b.controller) || a.phase.localeCompare(b.phase));
  const events = Array.from(controllerMetrics.events.values()).sort((a, b) => a.reason.localeCompare(b.reason));
  const summary = {
    controllers: new Set(items.map((item) => item.controller)).size,
    reconciles: items.reduce((sum, item) => sum + item.total, 0),
    failures: items.reduce((sum, item) => sum + item.failures, 0),
    events: events.reduce((sum, item) => sum + item.total, 0),
  };
  return { startedAt: controllerMetrics.startedAt, source: 'process', summary, items, events };
}

function controllerNameForAuditEntry(entry) {
  if (entry?.controller) return entry.controller;
  const kind = entry?.kind || '';
  const byKind = {
    AIAgent: 'agent-controller',
    ComputeBackendClaim: 'compute-controller',
    DataConnectionClaim: 'data-connection-controller',
    DatasetClaim: 'dataset-controller',
    DistributedWorkloadClaim: 'distributed-workload-controller',
    ArtifactClaim: 'experiment-controller',
    EvaluationJob: 'evaluation-controller',
    EvaluationPolicy: 'evaluation-policy-controller',
    ExecutionClaim: 'experiment-controller',
    ExperimentClaim: 'experiment-controller',
    InferenceClaim: 'inference-controller',
    LLMRouteClaim: 'llm-route-controller',
    ModelPromotionClaim: 'model-promotion-controller',
    MonitoringTarget: 'monitoring-controller',
    MonitoringTargetClaim: 'monitoring-controller',
    PipelineClaim: 'pipeline-controller',
    PipelineRunClaim: 'pipeline-run-controller',
    RetrievalClaim: 'retrieval-controller',
    VectorRetrievalClaim: 'retrieval-controller',
    TrainingJobClaim: 'training-controller',
    WorkbenchClaim: 'workbench-controller',
  };
  return byKind[kind] || '';
}

function auditResourceKey(kind, namespace, name) {
  return `${kind || ''}/${namespace || ''}/${name || ''}`;
}

const AUDIT_RESOURCE_SOURCES = [
  { path: '/apis/orchestrator.ai.opensphere.io/v1alpha1/aiagents', kind: 'AIAgent' },
  { path: '/apis/ai.opensphere.io/v1alpha1/workbenchclaims', kind: 'WorkbenchClaim' },
  { path: '/apis/ai.opensphere.io/v1alpha1/dataconnectionclaims', kind: 'DataConnectionClaim' },
  { path: '/apis/ai.foundation.opensphere.io/v1alpha1/llmrouteclaims', kind: 'LLMRouteClaim' },
  { path: '/apis/ai.foundation.opensphere.io/v1alpha1/vectorretrievalclaims', kind: 'VectorRetrievalClaim' },
  { path: '/apis/ai.opensphere.io/v1alpha1/pipelineclaims', kind: 'PipelineClaim' },
  { path: '/apis/ai.opensphere.io/v1alpha1/pipelinerunclaims', kind: 'PipelineRunClaim' },
  { path: '/apis/ai.opensphere.io/v1alpha1/computebackendclaims', kind: 'ComputeBackendClaim' },
  { path: '/apis/ai.opensphere.io/v1alpha1/datasetclaims', kind: 'DatasetClaim' },
  { path: '/apis/ai.opensphere.io/v1alpha1/trainingjobclaims', kind: 'TrainingJobClaim' },
  { path: '/apis/ai.opensphere.io/v1alpha1/modelpromotionclaims', kind: 'ModelPromotionClaim' },
  { path: '/apis/eval.ai.opensphere.io/v1alpha1/evaluationpolicies', kind: 'EvaluationPolicy' },
  { path: '/apis/eval.ai.opensphere.io/v1alpha1/evaluationjobs', kind: 'EvaluationJob' },
  { path: '/apis/ai.opensphere.io/v1alpha1/experimentclaims', kind: 'ExperimentClaim' },
  { path: '/apis/ai.opensphere.io/v1alpha1/executionclaims', kind: 'ExecutionClaim' },
  { path: '/apis/ai.opensphere.io/v1alpha1/artifactclaims', kind: 'ArtifactClaim' },
  { path: '/apis/ai.opensphere.io/v1alpha1/inferenceclaims', kind: 'InferenceClaim' },
  { path: '/apis/ai.opensphere.io/v1alpha1/monitoringtargets', kind: 'MonitoringTarget' },
  { path: '/apis/ai.opensphere.io/v1alpha1/distributedworkloadclaims', kind: 'DistributedWorkloadClaim' },
];

function statusTransitionTime(item) {
  return optionalString(
    item?.status?.lastReconciledAt
      || item?.status?.normalizedAt
      || item?.status?.conditions?.[0]?.lastTransitionTime
      || item?.metadata?.annotations?.['opensphere.io/reconciled-at']
      || item?.metadata?.creationTimestamp
      || new Date().toISOString(),
  );
}

function activeAuditEntryFromResource(item, fallbackKind) {
  const status = item?.status || {};
  const annotations = item?.metadata?.annotations || {};
  const annotatedPhase = optionalString(annotations['opensphere.io/reconcile-phase']);
  const annotatedReason = optionalString(annotations['opensphere.io/reconcile-reason']);
  const annotatedMessage = optionalString(annotations['opensphere.io/reconcile-message']);
  const annotatedBackend = optionalString(annotations['opensphere.io/backend-mode']);
  const phase = optionalString(status.phase || annotatedPhase || (status.ready === true ? 'Ready' : status.ready === false ? 'NotReady' : 'Observed')) || 'Observed';
  const reason = optionalString(status.reason || status.conditions?.[0]?.reason || annotatedReason || phase) || phase;
  const warning = status.ready === false
    || /fail|error|blocked|degraded|notready/i.test(`${phase} ${reason}`);
  return {
    id: `snapshot-${shortHash(auditResourceKey(item?.kind || fallbackKind, item?.metadata?.namespace || '', item?.metadata?.name || ''))}`,
    type: warning ? 'Warning' : 'Normal',
    reason,
    message: optionalString(status.message || status.conditions?.[0]?.message || annotatedMessage || `Current resource state is ${phase}.`),
    phase,
    ready: status.ready ?? (!!annotatedPhase && !warning),
    backendMode: optionalString(status.backendMode || status.backend || annotatedBackend || 'opensphere') || 'opensphere',
    apiVersion: optionalString(item?.apiVersion || ''),
    kind: item?.kind || fallbackKind,
    namespace: item?.metadata?.namespace || '',
    name: item?.metadata?.name || '',
    controller: controllerNameForAuditEntry({ kind: item?.kind || fallbackKind }),
    time: statusTransitionTime(item),
    source: 'cluster',
    snapshot: true,
    activeResource: true,
    resourceState: 'active',
  };
}

async function activeAuditResourceEntries() {
  const entries = [];
  await Promise.all(AUDIT_RESOURCE_SOURCES.map(async (source) => {
    const json = await k8sJson(source.path);
    for (const item of json?.items || []) {
      entries.push(activeAuditEntryFromResource(item, source.kind));
    }
  }));
  return entries;
}

async function activeAuditResourceIds() {
  const ids = new Set();
  for (const entry of await activeAuditResourceEntries()) {
    ids.add(auditResourceKey(entry.kind, entry.namespace, entry.name));
  }
  return ids;
}

async function nativeControllerMetricsWithAuditFallback() {
  const live = nativeControllerMetrics();
  if (live.summary.reconciles > 0 || live.summary.events > 0) return live;
  const [entries, activeIds] = await Promise.all([
    auditLogEntries().catch(() => []),
    activeAuditResourceIds().catch(() => new Set()),
  ]);
  const reconcileMap = new Map();
  const eventMap = new Map();
  for (const entry of entries) {
    const controller = controllerNameForAuditEntry(entry);
    if (!controller) continue;
    const phase = optionalString(entry.phase || 'Recorded') || 'Recorded';
    const backend = optionalString(entry.backendMode || 'opensphere') || 'opensphere';
    const active = activeIds.has(auditResourceKey(entry.kind, entry.namespace, entry.name));
    const key = metricKey({ controller, phase, backend });
    const current = reconcileMap.get(key) || {
      controller,
      phase,
      backend,
      total: 0,
      failures: 0,
      historicalFailures: 0,
      durationMsTotal: 0,
      lastDurationMs: 0,
      lastAt: '',
      lastName: '',
    };
    current.total += 1;
    if (phase.toLowerCase().includes('fail')) {
      if (active) current.failures += 1;
      else current.historicalFailures += 1;
    }
    if (!current.lastAt || String(entry.time || '').localeCompare(current.lastAt) > 0) {
      current.lastAt = entry.time || '';
      current.lastName = entry.name || '';
    }
    reconcileMap.set(key, current);

    const eventKey = metricKey({ reason: entry.reason || 'Recorded', type: entry.type || 'Normal' });
    const event = eventMap.get(eventKey) || { reason: entry.reason || 'Recorded', type: entry.type || 'Normal', total: 0, lastAt: '' };
    event.total += 1;
    if (!event.lastAt || String(entry.time || '').localeCompare(event.lastAt) > 0) event.lastAt = entry.time || '';
    eventMap.set(eventKey, event);
  }
  const items = Array.from(reconcileMap.values()).map((item) => ({
    ...item,
    avgDurationMs: item.total ? Math.round(item.durationMsTotal / item.total) : 0,
  })).sort((a, b) => a.controller.localeCompare(b.controller) || a.phase.localeCompare(b.phase));
  const events = Array.from(eventMap.values()).sort((a, b) => a.reason.localeCompare(b.reason));
  const summary = {
    controllers: new Set(items.map((item) => item.controller)).size,
    reconciles: items.reduce((sum, item) => sum + item.total, 0),
    failures: items.reduce((sum, item) => sum + item.failures, 0),
    historicalFailures: items.reduce((sum, item) => sum + (item.historicalFailures || 0), 0),
    events: events.reduce((sum, item) => sum + item.total, 0),
  };
  return { startedAt: controllerMetrics.startedAt, source: 'audit-log', summary, items, events };
}

function prometheusMetricsText() {
  const lines = [
    '# HELP opensphere_ai_controller_reconcile_total Total OpenSphere AI Hub claim reconciliations.',
    '# TYPE opensphere_ai_controller_reconcile_total counter',
  ];
  for (const [key, item] of controllerMetrics.reconciles.entries()) {
    const labels = metricLabelsFromKey(key);
    lines.push(`opensphere_ai_controller_reconcile_total{controller="${labels.controller}",phase="${labels.phase}",backend="${labels.backend}"} ${item.total}`);
  }
  lines.push('# HELP opensphere_ai_controller_reconcile_failures_total Total failed OpenSphere AI Hub claim reconciliations.');
  lines.push('# TYPE opensphere_ai_controller_reconcile_failures_total counter');
  for (const [key, item] of controllerMetrics.reconciles.entries()) {
    const labels = metricLabelsFromKey(key);
    lines.push(`opensphere_ai_controller_reconcile_failures_total{controller="${labels.controller}",phase="${labels.phase}",backend="${labels.backend}"} ${item.failures}`);
  }
  lines.push('# HELP opensphere_ai_controller_reconcile_duration_ms_total Total reconcile duration in milliseconds.');
  lines.push('# TYPE opensphere_ai_controller_reconcile_duration_ms_total counter');
  for (const [key, item] of controllerMetrics.reconciles.entries()) {
    const labels = metricLabelsFromKey(key);
    lines.push(`opensphere_ai_controller_reconcile_duration_ms_total{controller="${labels.controller}",phase="${labels.phase}",backend="${labels.backend}"} ${item.durationMsTotal}`);
  }
  lines.push('# HELP opensphere_ai_controller_events_total Total Kubernetes Events emitted by OpenSphere AI Hub controller.');
  lines.push('# TYPE opensphere_ai_controller_events_total counter');
  for (const [key, item] of controllerMetrics.events.entries()) {
    const labels = metricLabelsFromKey(key);
    lines.push(`opensphere_ai_controller_events_total{reason="${labels.reason}",type="${labels.type}"} ${item.total}`);
  }
  lines.push('');
  return lines.join('\n');
}

const AUDIT_LOG_CONFIGMAP = 'ai-controller-audit-log';
const AUDIT_LOG_LIMIT = 200;
const MONITORING_HISTORY_CONFIGMAP = 'ai-monitoring-metric-history';
const MONITORING_HISTORY_LIMIT = 500;

async function auditLogEntries() {
  const cm = await k8sJson(`/api/v1/namespaces/opensphere-system/configmaps/${AUDIT_LOG_CONFIGMAP}`);
  if (!cm?.data?.entries) return [];
  try {
    const parsed = JSON.parse(cm.data.entries || '[]');
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

async function saveAuditLogEntries(entries) {
  const capped = entries.slice(-AUDIT_LOG_LIMIT);
  const cm = {
    apiVersion: 'v1',
    kind: 'ConfigMap',
    metadata: {
      name: AUDIT_LOG_CONFIGMAP,
      namespace: 'opensphere-system',
      labels: {
        'app.kubernetes.io/part-of': 'opensphere-ai',
        'ai.opensphere.io/audit-log': 'true',
      },
    },
    data: {
      entries: JSON.stringify(capped),
    },
  };
  try {
    await writeK8s('/api/v1/namespaces/opensphere-system/configmaps', 'POST', cm, null);
  } catch (e) {
    if (e.code !== 409) throw e;
    await patchK8s(`/api/v1/namespaces/opensphere-system/configmaps/${AUDIT_LOG_CONFIGMAP}`, { metadata: { labels: cm.metadata.labels }, data: cm.data }, null);
  }
  return capped;
}

async function appendAuditLog(entry) {
  const current = await auditLogEntries();
  const next = [...current, { id: shortHash(JSON.stringify(entry) + Date.now()), ...entry }].slice(-AUDIT_LOG_LIMIT);
  await saveAuditLogEntries(next).catch(() => null);
  return next;
}

async function nativeAuditLog() {
  const [currentEntries, durableEntries] = await Promise.all([
    activeAuditResourceEntries().catch(() => []),
    auditLogEntries().catch(() => []),
  ]);
  const currentKeys = new Set(currentEntries.map((entry) => auditResourceKey(entry.kind, entry.namespace, entry.name)));
  const historicalEntries = durableEntries.slice().reverse().map((entry) => {
    const hasResourceIdentity = !!entry.kind && !!entry.name && entry.kind !== 'SecurityPolicy';
    const activeResource = hasResourceIdentity && currentKeys.has(auditResourceKey(entry.kind, entry.namespace, entry.name));
    return {
      ...entry,
      activeResource,
      resourceState: hasResourceIdentity ? activeResource ? 'active' : 'historical' : 'system',
    };
  }).filter((entry) => !(entry.activeResource && currentKeys.has(auditResourceKey(entry.kind, entry.namespace, entry.name))));
  const entries = [...currentEntries, ...historicalEntries].sort((a, b) => {
    const bt = Date.parse(b.time || '') || 0;
    const at = Date.parse(a.time || '') || 0;
    return bt - at;
  });
  const summary = {
    total: entries.length,
    warnings: entries.filter((entry) => entry.type === 'Warning').length,
    namespaces: new Set(entries.map((entry) => entry.namespace).filter(Boolean)).size,
    kinds: new Set(entries.map((entry) => entry.kind).filter(Boolean)).size,
    activeEntries: entries.filter((entry) => entry.resourceState === 'active').length,
    historicalEntries: entries.filter((entry) => entry.resourceState === 'historical').length,
    systemEntries: entries.filter((entry) => entry.resourceState === 'system').length,
    activeWarnings: entries.filter((entry) => entry.type === 'Warning' && entry.resourceState === 'active').length,
    historicalWarnings: entries.filter((entry) => entry.type === 'Warning' && entry.resourceState === 'historical').length,
    systemWarnings: entries.filter((entry) => entry.type === 'Warning' && entry.resourceState === 'system').length,
  };
  return { summary, items: entries };
}

const PASSIVE_RECONCILE_TARGETS = [
  { path: '/apis/orchestrator.ai.opensphere.io/v1alpha1/aiagents', plural: 'aiagents', kind: 'AIAgent', controller: 'agent-controller', phase: 'Ready', reason: 'AgentConfigured', message: 'Agent declaration is accepted by the OpenSphere internal controller.' },
  { path: '/apis/ai.opensphere.io/v1alpha1/dataconnectionclaims', plural: 'dataconnectionclaims', kind: 'DataConnectionClaim', controller: 'data-connection-controller', phase: 'Ready', reason: 'ConnectionConfigured', message: 'Data connection metadata is configured for workspace use.' },
  { path: '/apis/ai.foundation.opensphere.io/v1alpha1/llmrouteclaims', plural: 'llmrouteclaims', kind: 'LLMRouteClaim', controller: 'llm-route-controller', phase: 'Ready', reason: 'RouteConfigured', message: 'LLM route is registered for OpenSphere AI Hub consumers.' },
  { path: '/apis/ai.foundation.opensphere.io/v1alpha1/vectorretrievalclaims', plural: 'vectorretrievalclaims', kind: 'VectorRetrievalClaim', controller: 'retrieval-controller', phase: 'Ready', reason: 'RetrievalConfigured', message: 'Retrieval route is registered for RAG workflows.' },
  { path: '/apis/ai.opensphere.io/v1alpha1/pipelineclaims', plural: 'pipelineclaims', kind: 'PipelineClaim', controller: 'pipeline-controller', phase: 'Ready', reason: 'PipelineRegistered', message: 'Pipeline definition is registered and can be used by pipeline runs.' },
  { path: '/apis/ai.opensphere.io/v1alpha1/computebackendclaims', plural: 'computebackendclaims', kind: 'ComputeBackendClaim', controller: 'compute-controller', phase: 'Ready', reason: 'BackendConfigured', message: 'Compute backend claim is available for AI workloads.' },
  { path: '/apis/ai.opensphere.io/v1alpha1/datasetclaims', plural: 'datasetclaims', kind: 'DatasetClaim', controller: 'dataset-controller', phase: 'Ready', reason: 'DatasetRegistered', message: 'Dataset claim is registered for training and evaluation workflows.' },
  { path: '/apis/ai.opensphere.io/v1alpha1/trainingjobclaims', plural: 'trainingjobclaims', kind: 'TrainingJobClaim', controller: 'training-controller', phase: 'Ready', reason: 'TrainingJobPrepared', message: 'Training job claim is prepared for an OpenSphere internal or external trainer.' },
  { path: '/apis/eval.ai.opensphere.io/v1alpha1/evaluationpolicies', plural: 'evaluationpolicies', kind: 'EvaluationPolicy', controller: 'evaluation-policy-controller', phase: 'Ready', reason: 'PolicyActive', message: 'Evaluation policy is active and available to evaluation jobs.' },
  { path: '/apis/ai.opensphere.io/v1alpha1/experimentclaims', plural: 'experimentclaims', kind: 'ExperimentClaim', controller: 'experiment-controller', phase: 'Ready', reason: 'ExperimentActive', message: 'Experiment is active for runs, executions, and artifacts.' },
  { path: '/apis/ai.opensphere.io/v1alpha1/executionclaims', plural: 'executionclaims', kind: 'ExecutionClaim', controller: 'experiment-controller', phase: 'Ready', reason: 'ExecutionTracked', message: 'Execution is tracked by the OpenSphere experiment controller.' },
  { path: '/apis/ai.opensphere.io/v1alpha1/artifactclaims', plural: 'artifactclaims', kind: 'ArtifactClaim', controller: 'experiment-controller', phase: 'Ready', reason: 'ArtifactRegistered', message: 'Artifact metadata is registered for lineage and experiment tracking.' },
];

function passiveStatus(claim, target) {
  const now = new Date().toISOString();
  return {
    phase: target.phase,
    ready: true,
    reason: target.reason,
    message: target.message,
    backendMode: 'opensphere',
    controller: target.controller,
    observedGeneration: claim?.metadata?.generation || 1,
    lastReconciledAt: now,
    conditions: [{
      type: 'Ready',
      status: 'True',
      reason: target.reason,
      message: target.message,
      lastTransitionTime: now,
    }],
  };
}

function namespacedResourcePath(collectionPath, namespace, plural, name, suffix = '') {
  return `${collectionPath.replace(`/${plural}`, '')}/namespaces/${namespace}/${plural}/${name}${suffix}`;
}

async function patchPassiveStatus(claim, target, status) {
  const namespace = claim.metadata?.namespace || 'default';
  const name = claim.metadata?.name;
  if (!name) return;
  const path = namespacedResourcePath(target.path, namespace, target.plural, name);
  try {
    await patchK8s(`${path}/status`, { status }, null);
  } catch (e) {
    await patchK8s(path, {
      metadata: {
        annotations: {
          'opensphere.io/reconcile-phase': status.phase,
          'opensphere.io/reconcile-reason': status.reason,
          'opensphere.io/reconcile-message': status.message,
          'opensphere.io/backend-mode': status.backendMode,
          'opensphere.io/reconciled-at': status.lastReconciledAt,
        },
      },
    }, null).catch(() => null);
  }
  await recordReconcileEvent(claim, status, target.reason);
}

async function reconcilePassiveClaim(target, claim) {
  if (target.kind === 'TrainingJobClaim') return reconcileTrainingJobClaim(target, claim);
  const status = passiveStatus(claim, target);
  await patchPassiveStatus(claim, target, status);
  return {
    name: claim.metadata?.name || '',
    namespace: claim.metadata?.namespace || '',
    phase: status.phase,
    backendMode: status.backendMode,
  };
}

function refNamespace(refObj, fallback) {
  return optionalString(refObj?.namespace || fallback || 'default') || 'default';
}

async function computeBackendForTrainingClaim(claim) {
  const spec = claim.spec || {};
  const backendRef = spec.computeBackendRef || spec.computeBackend || {};
  const name = optionalString(backendRef.name || spec.computeBackendName || spec.computeBackendRefName);
  if (!name) return null;
  const namespace = refNamespace(backendRef, claim.metadata?.namespace || 'default');
  return k8sJson(`/apis/ai.opensphere.io/v1alpha1/namespaces/${encodeURIComponent(namespace)}/computebackendclaims/${encodeURIComponent(name)}`);
}

function isExternalComputeBackend(backend) {
  const spec = backend?.spec || {};
  const type = optionalString(spec.backendType || spec.backend || backend?.status?.backendType || '').toLowerCase();
  return type === 'external' || type === 'notebook-bridge' || (!!spec.endpoint && type !== 'kubernetes');
}

function requestedTrainingJobType(claim) {
  const spec = claim.spec || {};
  return optionalString(spec.jobType || spec.trainingMode || spec.framework || 'smoke').toLowerCase();
}

function externalTrainingStatus(claim, backend, patch) {
  const now = new Date().toISOString();
  const provider = optionalString(backend?.spec?.provider || backend?.status?.provider || 'external') || 'external';
  const resourceName = optionalString(backend?.spec?.resourceName || backend?.status?.resourceName || '');
  return {
    backendMode: 'external',
    backendType: backend?.spec?.backendType || 'external',
    provider,
    resourceName,
    controller: 'training-controller',
    observedGeneration: claim?.metadata?.generation || 1,
    lastReconciledAt: now,
    ...patch,
    conditions: [{
      type: 'Ready',
      status: patch.ready ? 'True' : 'False',
      reason: patch.reason,
      message: patch.message,
      lastTransitionTime: now,
    }],
  };
}

function bridgeLogLineValue(entry) {
  if (!entry) return '';
  if (typeof entry === 'string') return entry;
  return optionalString(entry.line || entry.message || '');
}

function bridgeLogSummary(logs) {
  const lines = (logs?.lines || []).map(bridgeLogLineValue).filter(Boolean);
  const meaningful = lines.filter((line) => {
    const trimmed = line.trim();
    return trimmed
      && !/^[+\-|=\s]+$/.test(trimmed)
      && !/^Sat |^Sun |^Mon |^Tue |^Wed |^Thu |^Fri /.test(trimmed)
      && !/^Processes:|^GPU\s+GI|^ID\s+ID/i.test(trimmed);
  });
  const smi = meaningful.find((line) => line.includes('NVIDIA-SMI')) || '';
  const gpu = meaningful.find((line) => /NVIDIA|RTX|A100|L4|H100|GeForce|Quadro|Tesla/i.test(line) && !line.includes('NVIDIA-SMI')) || '';
  const usage = meaningful.find((line) => /MiB\s*\/|W\s*\/|Default/.test(line)) || '';
  const latest = usage || gpu || smi || meaningful[meaningful.length - 1] || '';
  return {
    latest,
    nvidiaSmi: smi,
    gpu,
    usage,
    lineCount: lines.length,
  };
}

async function reconcileExternalTrainingJobClaim(target, claim, backend) {
  const generation = claim.metadata?.generation || 1;
  const previous = claim.status || {};
  if (previous.phase === 'Succeeded' && previous.observedGeneration === generation && previous.externalJob?.phase === 'Succeeded') {
    return {
      name: claim.metadata?.name || '',
      namespace: claim.metadata?.namespace || '',
      phase: previous.phase,
      backendMode: 'external',
    };
  }
  const spec = claim.spec || {};
  const endpoint = optionalString(backend.spec?.endpoint || backend.status?.endpoint);
  const credentialSecret = optionalString(backend.spec?.credentialSecretRef || backend.spec?.credentialSecret || 'oah-external-gpu-credentials');
  const namespace = claim.metadata?.namespace || backend.metadata?.namespace || 'default';
  const jobType = requestedTrainingJobType(claim);
  const supported = backend.spec?.supportedJobTypes || backend.status?.supportedJobTypes || ['smoke'];
  if (!endpoint || !validHttpEndpoint(endpoint)) {
    const status = externalTrainingStatus(claim, backend, {
      phase: 'Blocked',
      ready: false,
      reason: 'ExternalEndpointMissing',
      message: 'External ComputeBackend endpoint is missing or invalid.',
    });
    await patchPassiveStatus(claim, target, status);
    return { name: claim.metadata?.name || '', namespace, phase: status.phase, backendMode: status.backendMode };
  }
  if (jobType !== 'smoke' || !supported.includes('smoke')) {
    const status = externalTrainingStatus(claim, backend, {
      phase: 'Blocked',
      ready: false,
      reason: 'UnsupportedExternalJobType',
      message: `External bridge MVP supports smoke jobs only. Requested ${jobType || 'unknown'}.`,
      supportedJobTypes: supported,
    });
    await patchPassiveStatus(claim, target, status);
    return { name: claim.metadata?.name || '', namespace, phase: status.phase, backendMode: status.backendMode };
  }
  const token = await readGpuBridgeToken(refNamespace({ namespace: backend.metadata?.namespace }, namespace), credentialSecret);
  const headers = { ...gpuBridgeAuthHeaders(token), 'content-type': 'application/json' };
  const submitted = await fetchGpuBridge(endpoint, '/jobs', {
    method: 'POST',
    headers,
    body: JSON.stringify({
      jobType: 'smoke',
      metadata: {
        claim: `${claim.metadata?.namespace || namespace}/${claim.metadata?.name || ''}`,
        framework: optionalString(spec.framework),
        trainingMode: optionalString(spec.trainingMode),
      },
    }),
  });
  const id = submitted.id || submitted.jobId;
  let job = submitted;
  for (let i = 0; id && i < 12; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 500));
    job = await fetchGpuBridge(endpoint, `/jobs/${encodeURIComponent(id)}`, { headers: gpuBridgeAuthHeaders(token) });
    if (['Succeeded', 'Failed', 'Cancelled'].includes(job.phase)) break;
  }
  let externalJobLogs = null;
  if (id) {
    try {
      externalJobLogs = await fetchGpuBridge(endpoint, `/jobs/${encodeURIComponent(id)}/logs`, { headers: gpuBridgeAuthHeaders(token) });
    } catch {
      externalJobLogs = null;
    }
  }
  const status = externalTrainingStatus(claim, backend, {
    phase: job.phase === 'Succeeded' ? 'Succeeded' : job.phase || 'Submitted',
    ready: job.phase === 'Succeeded',
    reason: job.phase === 'Succeeded' ? 'ExternalGpuSmokeSucceeded' : 'ExternalGpuJobSubmitted',
    message: job.summary || `External bridge job ${id || ''} is ${job.phase || 'submitted'}.`,
    externalJob: job,
    externalJobLogs,
    externalJobLogSummary: bridgeLogSummary(externalJobLogs),
    endpoint,
    supportedJobTypes: supported,
  });
  await patchPassiveStatus(claim, target, status);
  return {
    name: claim.metadata?.name || '',
    namespace,
    phase: status.phase,
    backendMode: status.backendMode,
  };
}

async function reconcileTrainingJobClaim(target, claim) {
  const backend = await computeBackendForTrainingClaim(claim);
  if (backend && isExternalComputeBackend(backend)) {
    return reconcileExternalTrainingJobClaim(target, claim, backend);
  }
  const status = passiveStatus(claim, target);
  await patchPassiveStatus(claim, target, status);
  return {
    name: claim.metadata?.name || '',
    namespace: claim.metadata?.namespace || '',
    phase: status.phase,
    backendMode: status.backendMode,
  };
}

async function reconcilePassiveResources() {
  const results = [];
  for (const target of PASSIVE_RECONCILE_TARGETS) {
    const list = await k8sJson(target.path);
    for (const item of list?.items || []) {
      results.push(await reconcileClaimWithMetrics(target.controller, item, (claim) => reconcilePassiveClaim(target, claim)));
    }
  }
  return { reconciled: results.length, items: results };
}

function shouldRecordReconcileEvent(claim, status) {
  const previous = claim?.status || {};
  if (!previous.phase && previous.ready === undefined && !previous.backendMode) return true;
  return previous.phase !== status.phase || previous.ready !== status.ready || previous.backendMode !== status.backendMode;
}

async function recordReconcileEvent(claim, status, fallbackReason) {
  if (!claim?.metadata?.name || !shouldRecordReconcileEvent(claim, status)) return;
  const namespace = claim.metadata.namespace || 'default';
  const now = new Date().toISOString();
  const reason = optionalString(status.conditions?.[0]?.reason || fallbackReason || status.phase || 'Reconciled') || 'Reconciled';
  const warning = String(status.phase || '').toLowerCase().includes('fail') || status.ready === false && reason.toLowerCase().includes('failed');
  const event = {
    apiVersion: 'v1',
    kind: 'Event',
    metadata: {
      generateName: dnsLabel(`${claim.metadata.name}-${reason}`, 'osai-').slice(0, 52) + '-',
      namespace,
      labels: {
        'app.kubernetes.io/part-of': 'opensphere-ai',
        'ai.opensphere.io/reconcile-event': 'true',
      },
    },
    involvedObject: {
      apiVersion: claim.apiVersion || 'ai.opensphere.io/v1alpha1',
      kind: claim.kind || 'OpenSphereAIClaim',
      name: claim.metadata.name,
      namespace,
      uid: claim.metadata.uid,
      resourceVersion: claim.metadata.resourceVersion,
    },
    reason,
    message: optionalString(status.conditions?.[0]?.message || status.backendMessage || `Reconciled to ${status.phase || 'Unknown'}`),
    source: { component: 'opensphere-ai-controller' },
    firstTimestamp: now,
    lastTimestamp: now,
    count: 1,
    type: warning ? 'Warning' : 'Normal',
  };
  await appendAuditLog({
    time: now,
    type: event.type,
    reason,
    message: event.message,
    namespace,
    kind: event.involvedObject.kind,
    name: event.involvedObject.name,
    phase: status.phase || '',
    ready: status.ready === true,
    backendMode: status.backendMode || '',
    backendPhase: status.backendPhase || '',
    controller: fallbackReason || '',
  });
  await writeK8s(`/api/v1/namespaces/${namespace}/events`, 'POST', event, null).then(() => {
    observeReconcileEvent(reason, event.type);
  }).catch(() => null);
}

function workbenchResources(claim) {
  const spec = claim.spec || {};
  const namespace = claim.metadata?.namespace || 'default';
  const name = runtimeNameForClaim(claim);
  const labels = {
    'app.kubernetes.io/name': name,
    'app.kubernetes.io/part-of': 'opensphere-ai',
    'ai.opensphere.io/workbench-claim': claim.metadata?.name || '',
  };
  const storage = optionalString(spec.storage || spec.storageSize || '10Gi') || '10Gi';
  const image = workbenchImageFor(spec);
  const stopped = spec.suspended === true || spec.stopped === true;
  const ownerReferences = ownerRefFor(claim);
  const pvc = {
    apiVersion: 'v1',
    kind: 'PersistentVolumeClaim',
    metadata: { name: `${name}-workspace`, namespace, labels, ownerReferences },
    spec: {
      accessModes: ['ReadWriteOnce'],
      resources: { requests: { storage } },
    },
  };
  const deployment = {
    apiVersion: 'apps/v1',
    kind: 'Deployment',
    metadata: { name, namespace, labels, ownerReferences },
    spec: {
      replicas: stopped ? 0 : 1,
      selector: { matchLabels: labels },
      template: {
        metadata: { labels },
        spec: {
          containers: [{
            name: 'workbench',
            image,
            imagePullPolicy: image.includes('localhost:5000/') ? 'IfNotPresent' : 'IfNotPresent',
            ports: [{ name: 'http', containerPort: 8080 }],
            env: [
              { name: 'OPENSPHERE_WORKBENCH_CLAIM', value: claim.metadata?.name || '' },
              { name: 'OPENSPHERE_WORKSPACE_PATH', value: '/workspace' },
            ],
            volumeMounts: [{ name: 'workspace', mountPath: '/workspace' }],
            readinessProbe: { httpGet: { path: '/healthz', port: 'http' }, initialDelaySeconds: 5, periodSeconds: 10 },
          }],
          volumes: [{ name: 'workspace', persistentVolumeClaim: { claimName: `${name}-workspace` } }],
        },
      },
    },
  };
  const service = {
    apiVersion: 'v1',
    kind: 'Service',
    metadata: { name, namespace, labels, ownerReferences },
    spec: {
      selector: labels,
      ports: [{ name: 'http', port: 80, targetPort: 'http' }],
    },
  };
  return { name, namespace, labels, image, stopped, pvc, deployment, service };
}

async function cleanupWorkbenchResources(claim) {
  const resources = workbenchResources(claim);
  const targets = [
    { kind: 'Deployment', path: `/apis/apps/v1/namespaces/${resources.namespace}/deployments/${resources.name}` },
    { kind: 'Service', path: `/api/v1/namespaces/${resources.namespace}/services/${resources.name}` },
    { kind: 'PersistentVolumeClaim', path: `/api/v1/namespaces/${resources.namespace}/persistentvolumeclaims/${resources.pvc.metadata.name}` },
  ];
  let deleted = 0;
  const names = [];
  for (const target of targets) {
    if (await deleteK8sIfExists(target.path)) {
      deleted += 1;
      names.push(target.kind);
    }
  }
  return { deleted, resources: names };
}

async function patchWorkbenchStatus(claim, status) {
  const namespace = claim.metadata?.namespace || 'default';
  const name = claim.metadata?.name;
  if (!name) return;
  try {
    await patchK8s(`/apis/ai.opensphere.io/v1alpha1/namespaces/${namespace}/workbenchclaims/${name}/status`, { status }, null);
  } catch (e) {
    await patchK8s(`/apis/ai.opensphere.io/v1alpha1/namespaces/${namespace}/workbenchclaims/${name}`, {
      metadata: {
        annotations: {
          'opensphere.io/reconcile-phase': status.phase,
          'opensphere.io/runtime-service': status.serviceName || '',
        },
      },
    }, null).catch(() => null);
  }
  await recordReconcileEvent(claim, status, 'WorkbenchReconciled');
}

async function reconcileWorkbenchClaim(claim) {
  const resources = workbenchResources(claim);
  const { name, namespace, pvc, deployment, service, image, stopped } = resources;
  const cleanup = await cleanupClaimResources(claim, 'workbenchclaims', cleanupWorkbenchResources);
  if (cleanup) return cleanup;
  await ensureClaimFinalizer(claim, 'workbenchclaims');
  if (pendingRetryMs(claim) > 0) return retryingResult(claim, name);
  const baseStatus = {
    runtimeName: name,
    serviceName: name,
    image,
    url: `http://${name}.${namespace}.svc.cluster.local`,
    observedGeneration: claim.metadata?.generation || 0,
    lastReconciledAt: new Date().toISOString(),
  };
  try {
    await upsertK8s(
      `/api/v1/namespaces/${namespace}/persistentvolumeclaims`,
      `/api/v1/namespaces/${namespace}/persistentvolumeclaims/${pvc.metadata.name}`,
      pvc,
      { metadata: { labels: pvc.metadata.labels }, spec: pvc.spec },
      null,
    );
    await upsertK8s(
      `/apis/apps/v1/namespaces/${namespace}/deployments`,
      `/apis/apps/v1/namespaces/${namespace}/deployments/${name}`,
      deployment,
      { metadata: { labels: deployment.metadata.labels }, spec: deployment.spec },
      null,
    );
    await upsertK8s(
      `/api/v1/namespaces/${namespace}/services`,
      `/api/v1/namespaces/${namespace}/services/${name}`,
      service,
      { metadata: { labels: service.metadata.labels }, spec: service.spec },
      null,
    );
    const deployed = await k8sJson(`/apis/apps/v1/namespaces/${namespace}/deployments/${name}`);
    const available = deployed?.status?.availableReplicas || 0;
    const normalized = normalizedStatus({
      phase: stopped ? 'Stopped' : available > 0 ? 'Ready' : 'Provisioning',
      ready: stopped || available > 0,
      reason: stopped ? 'Stopped' : available > 0 ? 'RuntimeAvailable' : 'WaitingForDeployment',
      message: stopped ? 'Workbench is stopped by spec.suspended.' : available > 0 ? 'Workbench runtime is available.' : 'Deployment exists but is not available yet.',
      upstreamConditions: deployed?.status?.conditions,
      extra: { availableReplicas: available },
    });
    await patchWorkbenchStatus(claim, resetRetryFields({
      ...baseStatus,
      backendResource: `apps/v1/Deployment/${namespace}/${name}`,
      ...normalized,
    }));
    return { name: claim.metadata?.name, namespace, runtimeName: name, phase: normalized.phase };
  } catch (e) {
    const status = retryStatus(claim, baseStatus, e);
    await patchWorkbenchStatus(claim, status);
    return { name: claim.metadata?.name, namespace, runtimeName: name, phase: 'Retrying', error: e.msg || String(e), nextRetryAt: status.nextRetryAt };
  }
}

let _workbenchReconciling = false;
async function reconcileWorkbenches() {
  if (_workbenchReconciling) return { skipped: true, reason: 'already running' };
  _workbenchReconciling = true;
  try {
    if (!(await crdInstalled('workbenchclaims.ai.opensphere.io'))) return { reconciled: 0, items: [] };
    const list = await k8sJson('/apis/ai.opensphere.io/v1alpha1/workbenchclaims');
    const items = list?.items || [];
    const results = [];
    for (const claim of items) {
      results.push(await reconcileClaimWithMetrics('workbenches', claim, reconcileWorkbenchClaim));
    }
    return { reconciled: results.length, items: results };
  } finally {
    _workbenchReconciling = false;
  }
}

function pipelineRunResources(claim) {
  const spec = claim.spec || {};
  const namespace = claim.metadata?.namespace || 'default';
  const name = pipelineJobNameForClaim(claim);
  const pipelineName = spec.pipelineRef?.name || spec.pipeline || 'pipeline';
  const parameters = spec.parameters || {};
  const suspended = spec.suspended === true;
  const labels = {
    'app.kubernetes.io/name': name,
    'app.kubernetes.io/part-of': 'opensphere-ai',
    'ai.opensphere.io/pipeline-run-claim': claim.metadata?.name || '',
  };
  const ownerReferences = ownerRefFor(claim);
  const script = [
    "const env=process.env;",
    "const params=JSON.parse(env.OPENSPHERE_PIPELINE_PARAMETERS||'{}');",
    "console.log(`[pipeline] starting ${env.OPENSPHERE_PIPELINE_RUN} for ${env.OPENSPHERE_PIPELINE}`);",
    "console.log(`[pipeline] parameters ${JSON.stringify(params)}`);",
    "console.log('[pipeline] resolving inputs');",
    "console.log('[pipeline] running execution steps');",
    "console.log('[pipeline] publishing artifacts');",
    "console.log('[pipeline] completed successfully');",
  ].join('');
  const job = {
    apiVersion: 'batch/v1',
    kind: 'Job',
    metadata: { name, namespace, labels, ownerReferences },
    spec: {
      suspend: suspended,
      backoffLimit: 0,
      ttlSecondsAfterFinished: 3600,
      template: {
        metadata: { labels },
        spec: {
          restartPolicy: 'Never',
          containers: [{
            name: 'runner',
            image: optionalString(spec.runnerImage) || PIPELINE_RUNNER_IMAGE,
            imagePullPolicy: 'IfNotPresent',
            command: ['node', '-e', script],
            env: [
              { name: 'OPENSPHERE_PIPELINE_RUN', value: claim.metadata?.name || '' },
              { name: 'OPENSPHERE_PIPELINE', value: pipelineName },
              { name: 'OPENSPHERE_PIPELINE_PARAMETERS', value: JSON.stringify(parameters) },
            ],
          }],
        },
      },
    },
  };
  return { name, namespace, labels, job, suspended, pipelineName, parameters };
}

function tektonPipelineRunForClaim(claim, resources) {
  const spec = claim.spec || {};
  const pipelineRefName = optionalString(spec.pipelineRef?.name || spec.pipeline || resources.pipelineName);
  const params = Object.entries(resources.parameters || {}).map(([name, value]) => ({
    name,
    value: typeof value === 'string' ? value : JSON.stringify(value),
  }));
  const pipelineSpec = {
    params: params.map((param) => ({ name: param.name, type: 'string' })),
    tasks: [{
      name: 'opensphere-run',
      taskSpec: {
        params: params.map((param) => ({ name: param.name, type: 'string' })),
        steps: [{
          name: 'runner',
          image: optionalString(spec.runnerImage) || PIPELINE_RUNNER_IMAGE,
          script: [
            '#!/usr/bin/env sh',
            'set -eu',
            `echo "[pipeline] starting ${claim.metadata?.name || resources.name}"`,
            `echo "[pipeline] pipeline ${pipelineRefName || 'inline'}"`,
            `echo "[pipeline] parameters ${JSON.stringify(resources.parameters || {}).replace(/"/g, '\\"')}"`,
            'echo "[pipeline] completed successfully"',
          ].join('\n'),
        }],
      },
    }],
  };
  const tektonSpec = {
    params,
    timeouts: { pipeline: optionalString(spec.timeout || '1h') || '1h' },
  };
  if (pipelineRefName && spec.usePipelineRef === true) {
    tektonSpec.pipelineRef = { name: pipelineRefName };
  } else {
    tektonSpec.pipelineSpec = pipelineSpec;
  }
  return {
    apiVersion: 'tekton.dev/v1',
    kind: 'PipelineRun',
    metadata: {
      name: resources.name,
      namespace: resources.namespace,
      labels: resources.labels,
      ownerReferences: ownerRefFor(claim),
      annotations: {
        'ai.opensphere.io/pipeline-run-claim': claim.metadata?.name || '',
        'ai.opensphere.io/backend': 'tekton',
      },
    },
    spec: tektonSpec,
  };
}

async function kfpBackendInfo(namespace) {
  const dspaPaths = [
    `/apis/datasciencepipelinesapplications.opendatahub.io/v1/namespaces/${namespace}/datasciencepipelinesapplications`,
    `/apis/datasciencepipelinesapplications.opendatahub.io/v1alpha1/namespaces/${namespace}/datasciencepipelinesapplications`,
    '/apis/datasciencepipelinesapplications.opendatahub.io/v1/datasciencepipelinesapplications',
    '/apis/datasciencepipelinesapplications.opendatahub.io/v1alpha1/datasciencepipelinesapplications',
  ];
  for (const path of dspaPaths) {
    const list = await k8sJson(path);
    const item = list?.items?.[0];
    if (item) {
      const conditions = item.status?.conditions || [];
      const readyCondition = conditions.find((condition) => condition.type === 'Ready' || condition.type === 'Available');
      const ready = readyCondition?.status === 'True' || !readyCondition;
      return {
        ready,
        kind: 'DataSciencePipelinesApplication',
        apiVersion: item.apiVersion || 'datasciencepipelinesapplications.opendatahub.io/v1',
        name: item.metadata?.name || 'default-dspa',
        namespace: item.metadata?.namespace || namespace,
        endpoint: item.status?.apiServerRoute || item.status?.url || item.status?.externalUrl || item.spec?.apiServer?.deploy || '',
        conditions,
      };
    }
  }
  const [kfpGroup, dspaCrd] = await Promise.all([
    k8sJson('/apis/pipelines.kubeflow.org'),
    crdInstalled('datasciencepipelinesapplications.datasciencepipelinesapplications.opendatahub.io'),
  ]);
  if (kfpGroup || dspaCrd) {
    return {
      ready: true,
      kind: kfpGroup ? 'KubeflowPipelinesAPI' : 'DataSciencePipelinesApplication',
      apiVersion: kfpGroup ? 'pipelines.kubeflow.org' : 'datasciencepipelinesapplications.opendatahub.io',
      name: 'detected-kfp-backend',
      namespace,
      endpoint: '',
      conditions: [],
    };
  }
  return { ready: false, kind: '', apiVersion: '', name: '', namespace, endpoint: '', conditions: [] };
}

function kfpRunIdForClaim(claim) {
  return `kfp-${shortHash(`${claim.metadata?.namespace || 'default'}/${claim.metadata?.name || 'run'}/${claim.metadata?.uid || ''}`)}`;
}

async function kfpRunRecordForClaim(claim, resources, info) {
  const spec = claim.spec || {};
  const record = {
    apiVersion: 'v1',
    kind: 'ConfigMap',
    metadata: {
      name: `${resources.name}-kfp-record`,
      namespace: resources.namespace,
      labels: {
        'app.kubernetes.io/part-of': 'opensphere-ai',
        'ai.opensphere.io/pipeline-run-claim': claim.metadata?.name || '',
        'ai.opensphere.io/backend': 'kubeflow-pipelines',
      },
      ownerReferences: ownerRefFor(claim),
    },
    data: {
      runId: kfpRunIdForClaim(claim),
      pipelineName: resources.pipelineName,
      parameters: JSON.stringify(resources.parameters || {}),
      experiment: spec.experimentRef?.name || spec.experiment || 'default',
      backend: JSON.stringify(info),
      submittedAt: new Date().toISOString(),
    },
  };
  await upsertK8s(
    `/api/v1/namespaces/${resources.namespace}/configmaps`,
    `/api/v1/namespaces/${resources.namespace}/configmaps/${record.metadata.name}`,
    record,
    { metadata: { labels: record.metadata.labels }, data: record.data },
    null,
  );
  return record;
}

function normalizeKfpPipelineRunStatus(record, info) {
  return normalizedStatus({
    phase: 'Submitted',
    ready: false,
    reason: 'KubeflowPipelineRunSubmitted',
    message: info.endpoint
      ? `Kubeflow Pipelines run ${record.data.runId} submitted through ${info.endpoint}.`
      : `Kubeflow Pipelines run ${record.data.runId} submitted to ${info.kind}.`,
    upstreamConditions: info.conditions,
    extra: {
      kfpRunId: record.data.runId,
      kfpExperiment: record.data.experiment,
      kfpApplication: info.name,
      kfpEndpoint: info.endpoint,
    },
  });
}

async function cleanupPipelineRunResources(claim) {
  const resources = pipelineRunResources(claim);
  const targets = [
    { kind: 'Job', path: `/apis/batch/v1/namespaces/${resources.namespace}/jobs/${resources.name}` },
    { kind: 'PipelineRun', path: `/apis/tekton.dev/v1/namespaces/${resources.namespace}/pipelineruns/${resources.name}` },
    { kind: 'ConfigMap', path: `/api/v1/namespaces/${resources.namespace}/configmaps/${resources.name}-kfp-record` },
  ];
  let deleted = 0;
  const names = [];
  for (const target of targets) {
    if (await deleteK8sIfExists(target.path)) {
      deleted += 1;
      names.push(target.kind);
    }
  }
  return { deleted, resources: names };
}

async function patchPipelineRunStatus(claim, status) {
  const namespace = claim.metadata?.namespace || 'default';
  const name = claim.metadata?.name;
  if (!name) return;
  try {
    await patchK8s(`/apis/ai.opensphere.io/v1alpha1/namespaces/${namespace}/pipelinerunclaims/${name}/status`, { status }, null);
  } catch (e) {
    await patchK8s(`/apis/ai.opensphere.io/v1alpha1/namespaces/${namespace}/pipelinerunclaims/${name}`, {
      metadata: {
        annotations: {
          'opensphere.io/reconcile-phase': status.phase,
          'opensphere.io/runtime-job': status.jobName || '',
        },
      },
    }, null).catch(() => null);
  }
  await recordReconcileEvent(claim, status, 'PipelineRunReconciled');
}

function jobPhase(job, suspended) {
  if (suspended || job?.spec?.suspend === true) return { phase: 'Suspended', ready: false, reason: 'Suspended' };
  if (job?.status?.succeeded > 0) return { phase: 'Succeeded', ready: true, reason: 'JobSucceeded' };
  if (job?.status?.failed > 0) return { phase: 'Failed', ready: false, reason: 'JobFailed' };
  if (job?.status?.active > 0) return { phase: 'Running', ready: false, reason: 'JobRunning' };
  return { phase: 'Pending', ready: false, reason: 'WaitingForJob' };
}

async function reconcilePipelineRunClaim(claim) {
  const resources = pipelineRunResources(claim);
  const { name, namespace, job, suspended, pipelineName, parameters } = resources;
  const cleanup = await cleanupClaimResources(claim, 'pipelinerunclaims', cleanupPipelineRunResources);
  if (cleanup) return cleanup;
  await ensureClaimFinalizer(claim, 'pipelinerunclaims');
  if (pendingRetryMs(claim) > 0) return retryingResult(claim, name);
  const backend = await selectBackend('pipelines', claim.spec || {});
  const baseStatus = {
    jobName: name,
    pipelineName,
    parameters,
    backendMode: backend.mode,
    backendRequested: backend.requested,
    backendPhase: backend.phase,
    backendMessage: backend.message,
    observedGeneration: claim.metadata?.generation || 0,
    lastReconciledAt: new Date().toISOString(),
  };
  try {
    if (!backend.ready) throw { code: 409, msg: backend.message };
    if (backend.mode === 'upstream') {
      const preferKfp = ['kubeflow', 'kfp', 'kubeflow-pipelines'].includes(backend.requestedType);
      const hasTekton = await crdInstalled('pipelineruns.tekton.dev');
      const kfpInfo = await kfpBackendInfo(namespace);
      if (preferKfp || !hasTekton) {
        if (!kfpInfo.ready) {
          if (preferKfp) throw { code: 409, msg: 'Kubeflow Pipelines backend requested but no DataSciencePipelinesApplication or Kubeflow Pipelines API was found.' };
        } else {
          const record = await kfpRunRecordForClaim(claim, resources, kfpInfo);
          const normalized = normalizeKfpPipelineRunStatus(record, kfpInfo);
          await patchPipelineRunStatus(claim, resetRetryFields({
            ...baseStatus,
            backendMode: 'upstream',
            backendType: 'kubeflow-pipelines',
            backendResource: `${kfpInfo.apiVersion}/${kfpInfo.kind}/${kfpInfo.namespace}/${kfpInfo.name}`,
            ...normalized,
          }));
          return { name: claim.metadata?.name, namespace, jobName: name, backend: 'kubeflow-pipelines', phase: normalized.phase };
        }
      }
      const tektonRun = tektonPipelineRunForClaim(claim, resources);
      await upsertK8s(
        `/apis/tekton.dev/v1/namespaces/${namespace}/pipelineruns`,
        `/apis/tekton.dev/v1/namespaces/${namespace}/pipelineruns/${name}`,
        tektonRun,
        { metadata: { labels: tektonRun.metadata.labels, annotations: tektonRun.metadata.annotations }, spec: tektonRun.spec },
        null,
      );
      const current = await k8sJson(`/apis/tekton.dev/v1/namespaces/${namespace}/pipelineruns/${name}`);
      const normalized = normalizeTektonPipelineRunStatus(current);
      await patchPipelineRunStatus(claim, resetRetryFields({
        ...baseStatus,
        backendResource: `tekton.dev/v1/PipelineRun/${namespace}/${name}`,
        ...normalized,
      }));
      return { name: claim.metadata?.name, namespace, jobName: name, backend: 'tekton', phase: normalized.phase };
    }
    await upsertK8s(
      `/apis/batch/v1/namespaces/${namespace}/jobs`,
      `/apis/batch/v1/namespaces/${namespace}/jobs/${name}`,
      job,
      { metadata: { labels: job.metadata.labels }, spec: { suspend: suspended } },
      null,
    );
    const current = await k8sJson(`/apis/batch/v1/namespaces/${namespace}/jobs/${name}`);
    const normalized = normalizeJobStatus(current, suspended, {
      succeededMessage: 'Pipeline run job completed successfully.',
      pendingMessage: 'Pipeline run job is Pending.',
      runningMessage: 'Pipeline run job is Running.',
      suspendedMessage: 'Pipeline run job is Suspended.',
      failedMessage: 'Pipeline run job failed.',
    });
    await patchPipelineRunStatus(claim, resetRetryFields({
      ...baseStatus,
      backendResource: `batch/v1/Job/${namespace}/${name}`,
      ...normalized,
    }));
    return { name: claim.metadata?.name, namespace, jobName: name, phase: normalized.phase };
  } catch (e) {
    const status = retryStatus(claim, baseStatus, e);
    await patchPipelineRunStatus(claim, status);
    return { name: claim.metadata?.name, namespace, jobName: name, phase: 'Retrying', error: e.msg || String(e), nextRetryAt: status.nextRetryAt };
  }
}

let _pipelineRunReconciling = false;
async function reconcilePipelineRuns() {
  if (_pipelineRunReconciling) return { skipped: true, reason: 'already running' };
  _pipelineRunReconciling = true;
  try {
    if (!(await crdInstalled('pipelinerunclaims.ai.opensphere.io'))) return { reconciled: 0, items: [] };
    const list = await k8sJson('/apis/ai.opensphere.io/v1alpha1/pipelinerunclaims');
    const items = list?.items || [];
    const results = [];
    for (const claim of items) {
      results.push(await reconcileClaimWithMetrics('pipeline-runs', claim, reconcilePipelineRunClaim));
    }
    return { reconciled: results.length, items: results };
  } finally {
    _pipelineRunReconciling = false;
  }
}

function inferenceResources(claim) {
  const spec = claim.spec || {};
  const namespace = claim.metadata?.namespace || 'default';
  const name = inferenceRuntimeNameForClaim(claim);
  const modelName = spec.modelRef?.name || spec.model || claim.metadata?.name || 'model';
  const runtime = optionalString(spec.runtime || 'kubernetes-deployment') || 'kubernetes-deployment';
  const image = optionalString(spec.runtimeImage || spec.servingImage || spec.image) || INFERENCE_RUNTIME_IMAGE;
  const suspended = spec.suspended === true;
  const labels = {
    'app.kubernetes.io/name': name,
    'app.kubernetes.io/part-of': 'opensphere-ai',
    'ai.opensphere.io/inference-claim': claim.metadata?.name || '',
  };
  const ownerReferences = ownerRefFor(claim);
  const script = [
    "const http=require('http');",
    "const model=process.env.OPENSPHERE_MODEL_NAME||'model';",
    "const runtime=process.env.OPENSPHERE_INFERENCE_RUNTIME||'runtime';",
    "const claim=process.env.OPENSPHERE_INFERENCE_CLAIM||'inference';",
    "function send(res,code,obj){res.writeHead(code,{'content-type':'application/json'});res.end(JSON.stringify(obj));}",
    "http.createServer((req,res)=>{",
    " if(req.url==='/healthz') return send(res,200,{ok:true,model,runtime,claim});",
    " let body=''; req.on('data',c=>body+=c);",
    " req.on('end',()=>{",
    "  let input=null; try{input=body?JSON.parse(body):null;}catch{input=body;}",
    "  if(req.url.includes('/predict')||req.url==='/infer') return send(res,200,{model,runtime,claim,predictions:[{label:'opensphere-ready',score:1}], input});",
    "  return send(res,200,{model,runtime,claim,endpoints:['/healthz','/v1/models/'+model+'/predict','/infer']});",
    " });",
    "}).listen(8080,'0.0.0.0',()=>console.log('[inference] '+claim+' serving '+model+' with '+runtime));",
  ].join('');
  const deployment = {
    apiVersion: 'apps/v1',
    kind: 'Deployment',
    metadata: { name, namespace, labels, ownerReferences },
    spec: {
      replicas: suspended ? 0 : 1,
      selector: { matchLabels: labels },
      template: {
        metadata: { labels },
        spec: {
          containers: [{
            name: 'inference',
            image,
            imagePullPolicy: 'IfNotPresent',
            command: ['node', '-e', script],
            ports: [{ name: 'http', containerPort: 8080 }],
            env: [
              { name: 'OPENSPHERE_INFERENCE_CLAIM', value: claim.metadata?.name || '' },
              { name: 'OPENSPHERE_MODEL_NAME', value: modelName },
              { name: 'OPENSPHERE_INFERENCE_RUNTIME', value: runtime },
            ],
            readinessProbe: { httpGet: { path: '/healthz', port: 'http' }, initialDelaySeconds: 3, periodSeconds: 5 },
          }],
        },
      },
    },
  };
  const service = {
    apiVersion: 'v1',
    kind: 'Service',
    metadata: { name, namespace, labels, ownerReferences },
    spec: {
      selector: labels,
      ports: [{ name: 'http', port: 80, targetPort: 'http' }],
    },
  };
  return { name, namespace, labels, image, modelName, runtime, suspended, deployment, service };
}

function kserveInferenceServiceForClaim(claim, resources) {
  const spec = claim.spec || {};
  const modelUri = optionalString(spec.modelUri || spec.storageUri || spec.artifactUri || spec.sourceRef || spec.source);
  const modelFormat = optionalString(spec.modelFormat || spec.format || 'sklearn') || 'sklearn';
  const runtime = optionalString(spec.servingRuntime || spec.runtime);
  const predictor = {
    model: {
      modelFormat: { name: modelFormat },
      storageUri: modelUri,
    },
  };
  if (runtime) predictor.model.runtime = runtime;
  if (spec.serviceAccountName) predictor.serviceAccountName = spec.serviceAccountName;
  return {
    apiVersion: 'serving.kserve.io/v1beta1',
    kind: 'InferenceService',
    metadata: {
      name: resources.name,
      namespace: resources.namespace,
      labels: resources.labels,
      ownerReferences: ownerRefFor(claim),
      annotations: {
        'ai.opensphere.io/inference-claim': claim.metadata?.name || '',
      },
    },
    spec: { predictor },
  };
}

async function cleanupInferenceResources(claim) {
  const resources = inferenceResources(claim);
  const targets = [
    { kind: 'Deployment', path: `/apis/apps/v1/namespaces/${resources.namespace}/deployments/${resources.name}` },
    { kind: 'Service', path: `/api/v1/namespaces/${resources.namespace}/services/${resources.name}` },
    { kind: 'InferenceService', path: `/apis/serving.kserve.io/v1beta1/namespaces/${resources.namespace}/inferenceservices/${resources.name}` },
  ];
  let deleted = 0;
  const names = [];
  for (const target of targets) {
    if (await deleteK8sIfExists(target.path)) {
      deleted += 1;
      names.push(target.kind);
    }
  }
  return { deleted, resources: names };
}

async function patchInferenceStatus(claim, status) {
  const namespace = claim.metadata?.namespace || 'default';
  const name = claim.metadata?.name;
  if (!name) return;
  try {
    await patchK8s(`/apis/ai.opensphere.io/v1alpha1/namespaces/${namespace}/inferenceclaims/${name}/status`, { status }, null);
  } catch (e) {
    await patchK8s(`/apis/ai.opensphere.io/v1alpha1/namespaces/${namespace}/inferenceclaims/${name}`, {
      metadata: {
        annotations: {
          'opensphere.io/reconcile-phase': status.phase,
          'opensphere.io/runtime-service': status.serviceName || '',
        },
      },
    }, null).catch(() => null);
  }
  await recordReconcileEvent(claim, status, 'InferenceReconciled');
}

async function reconcileInferenceClaim(claim) {
  const resources = inferenceResources(claim);
  const { name, namespace, deployment, service, image, modelName, runtime, suspended } = resources;
  const cleanup = await cleanupClaimResources(claim, 'inferenceclaims', cleanupInferenceResources);
  if (cleanup) return cleanup;
  await ensureClaimFinalizer(claim, 'inferenceclaims');
  if (pendingRetryMs(claim) > 0) return retryingResult(claim, name);
  let backend = await selectBackend('model-serving', claim.spec || {});
  const modelUri = optionalString(claim.spec?.modelUri || claim.spec?.storageUri || claim.spec?.artifactUri || claim.spec?.sourceRef || claim.spec?.source);
  if (backend.mode === 'upstream' && !modelUri && backend.requested === 'auto') {
    backend = {
      ...backend,
      mode: 'opensphere',
      phase: 'FallbackReady',
      message: 'KServe is available, but this claim has no model artifact URI; auto-selected OpenSphere fallback runtime.',
    };
  }
  const baseStatus = {
    runtimeName: name,
    serviceName: name,
    image,
    modelName,
    runtime,
    backendMode: backend.mode,
    backendRequested: backend.requested,
    backendPhase: backend.phase,
    backendMessage: backend.message,
    url: `http://${name}.${namespace}.svc.cluster.local`,
    predictUrl: `http://${name}.${namespace}.svc.cluster.local/v1/models/${modelName}/predict`,
    observedGeneration: claim.metadata?.generation || 0,
    lastReconciledAt: new Date().toISOString(),
  };
  try {
    if (!backend.ready) throw { code: 409, msg: backend.message };
    if (backend.mode === 'upstream') {
      if (!modelUri) {
        if (backend.requested === 'upstream') throw { code: 400, msg: 'KServe upstream backend requires spec.modelUri, spec.storageUri, spec.artifactUri, spec.sourceRef, or spec.source' };
      } else {
        const inferenceService = kserveInferenceServiceForClaim(claim, resources);
        await upsertK8s(
          `/apis/serving.kserve.io/v1beta1/namespaces/${namespace}/inferenceservices`,
          `/apis/serving.kserve.io/v1beta1/namespaces/${namespace}/inferenceservices/${name}`,
          inferenceService,
          { metadata: { labels: inferenceService.metadata.labels, annotations: inferenceService.metadata.annotations }, spec: inferenceService.spec },
          null,
        );
        const current = await k8sJson(`/apis/serving.kserve.io/v1beta1/namespaces/${namespace}/inferenceservices/${name}`);
        const normalized = normalizeKServeStatus(current);
        const url = current?.status?.url || current?.status?.address?.url || baseStatus.url;
        await patchInferenceStatus(claim, resetRetryFields({
          ...baseStatus,
          serviceName: name,
          url,
          predictUrl: `${String(url).replace(/\/$/, '')}/v1/models/${modelName}/predict`,
          backendResource: `serving.kserve.io/v1beta1/InferenceService/${namespace}/${name}`,
          ...normalized,
        }));
        return { name: claim.metadata?.name, namespace, runtimeName: name, backend: 'upstream', phase: normalized.phase };
      }
    }
    await upsertK8s(
      `/apis/apps/v1/namespaces/${namespace}/deployments`,
      `/apis/apps/v1/namespaces/${namespace}/deployments/${name}`,
      deployment,
      { metadata: { labels: deployment.metadata.labels }, spec: deployment.spec },
      null,
    );
    await upsertK8s(
      `/api/v1/namespaces/${namespace}/services`,
      `/api/v1/namespaces/${namespace}/services/${name}`,
      service,
      { metadata: { labels: service.metadata.labels }, spec: service.spec },
      null,
    );
    const deployed = await k8sJson(`/apis/apps/v1/namespaces/${namespace}/deployments/${name}`);
    const available = deployed?.status?.availableReplicas || 0;
    const normalized = normalizedStatus({
      phase: suspended ? 'Suspended' : available > 0 ? 'Ready' : 'Provisioning',
      ready: suspended || available > 0,
      reason: suspended ? 'Suspended' : available > 0 ? 'RuntimeAvailable' : 'WaitingForDeployment',
      message: suspended ? 'Inference endpoint is suspended by spec.suspended.' : available > 0 ? 'Inference endpoint is available.' : 'Deployment exists but is not available yet.',
      upstreamConditions: deployed?.status?.conditions,
      extra: { availableReplicas: available },
    });
    await patchInferenceStatus(claim, resetRetryFields({
      ...baseStatus,
      backendResource: `apps/v1/Deployment/${namespace}/${name}`,
      ...normalized,
    }));
    return { name: claim.metadata?.name, namespace, runtimeName: name, phase: normalized.phase };
  } catch (e) {
    const status = retryStatus(claim, baseStatus, e);
    await patchInferenceStatus(claim, status);
    return { name: claim.metadata?.name, namespace, runtimeName: name, phase: 'Retrying', error: e.msg || String(e), nextRetryAt: status.nextRetryAt };
  }
}

let _inferenceReconciling = false;
async function reconcileInferences() {
  if (_inferenceReconciling) return { skipped: true, reason: 'already running' };
  _inferenceReconciling = true;
  try {
    if (!(await crdInstalled('inferenceclaims.ai.opensphere.io'))) return { reconciled: 0, items: [] };
    const list = await k8sJson('/apis/ai.opensphere.io/v1alpha1/inferenceclaims');
    const items = list?.items || [];
    const results = [];
    for (const claim of items) {
      results.push(await reconcileClaimWithMetrics('inference', claim, reconcileInferenceClaim));
    }
    return { reconciled: results.length, items: results };
  } finally {
    _inferenceReconciling = false;
  }
}

async function createAction(req) {
  const body = JSON.parse((await readBody(req)).toString('utf8') || '{}');
  const page = body.page;
  const def = ACTIONS[page];
  if (!def) throw { code: 400, msg: 'unsupported create action' };

  if (page === 'projects') {
    const name = requireDnsName(body.name, 'project name');
    const description = optionalString(body.description);
    const displayName = optionalString(body.displayName) || name;
    const ns = {
      apiVersion: 'v1',
      kind: 'Namespace',
      metadata: {
        name,
        labels: { 'opensphere.io/project': 'true' },
        annotations: {
          'opensphere.io/display-name': displayName,
          'opensphere.io/description': description,
        },
      },
    };
    const created = await writeK8s('/api/v1/namespaces', 'POST', ns, req);
    return { created: itemFromK8s(created, 'Namespace'), raw: created };
  }

  if (!(await crdInstalled(def.crdName))) {
    throw { code: 409, msg: `${def.kind} CRD is not installed`, details: { crdName: def.crdName } };
  }

  const namespace = requireDnsName(body.namespace || 'default', 'namespace');
  const description = optionalString(body.description);
  const routed = await applyComputeRoutingDefaults(page, body, namespace);
  const effectiveBody = routed.body;
  const metadata = objectMeta(effectiveBody.name, namespace, description);
  if (routed.routedBackend) {
    metadata.annotations = {
      ...(metadata.annotations || {}),
      'opensphere.io/compute-routing-workload': workloadIdForCreatePage(page),
      'opensphere.io/compute-routing-backend': routed.routedBackend.key,
      'opensphere.io/compute-routing-applied-at': new Date().toISOString(),
    };
  }
  const obj = {
    apiVersion: def.apiVersion,
    kind: def.kind,
    metadata,
    spec: buildSpec(page, effectiveBody, namespace),
  };
  const created = await writeK8s(`/apis/${def.group}/v1alpha1/namespaces/${namespace}/${def.plural}`, 'POST', obj, req);
  return { created: itemFromK8s(created, def.kind), raw: created, routedBackend: routed.routedBackend };
}

async function deleteAction(req) {
  const body = JSON.parse((await readBody(req)).toString('utf8') || '{}');
  const kindDef = body.kind ? ACTION_BY_KIND[body.kind] : null;
  const def = kindDef || ACTIONS[body.page];
  if (!def || def.scope === 'Cluster') throw { code: 400, msg: 'unsupported delete action' };
  if (!(await crdInstalled(def.crdName))) {
    throw { code: 409, msg: `${def.kind} CRD is not installed`, details: { crdName: def.crdName } };
  }
  const namespace = requireDnsName(body.namespace || 'default', 'namespace');
  const name = requireDnsName(body.name, 'name');
  await writeK8s(`/apis/${def.group}/v1alpha1/namespaces/${namespace}/${def.plural}/${name}`, 'DELETE', null, req);
  return { deleted: { name, namespace, kind: def.kind } };
}

const FALLBACK_DETAILS = {
  pipelineLogs: [
    '[pipeline] resolving dataset support-ticket-dataset',
    '[pipeline] launching training step fraud-detector-finetune',
    '[pipeline] running evaluation gate groundedness-and-safety',
    '[pipeline] publishing candidate artifact fraud-detector-model-v1',
  ],
  lineage: [
    { from: 'support-ticket-dataset', to: 'train-fraud-detector-step', type: 'input' },
    { from: 'train-fraud-detector-step', to: 'fraud-detector-model-v1', type: 'output' },
    { from: 'fraud-detector-model-v1', to: 'evaluate-groundedness-step', type: 'evaluation' },
  ],
  metrics: [
    { metric: 'drift', value: 0.12, threshold: 0.3, status: 'Healthy' },
    { metric: 'bias', value: 0.08, threshold: 0.2, status: 'Healthy' },
    { metric: 'explainability', value: 0.91, threshold: 0.8, status: 'Ready' },
    { metric: 'groundedness', value: 0.86, threshold: 0.8, status: 'Ready' },
  ],
  modelVersions: [
    { name: 'fraud-detector', version: '1.0.0', stage: 'staging', source: 'fraud-detector-model-v1' },
    { name: 'support-rag-ranker', version: '0.3.2', stage: 'development', source: 'support-agent-grounding' },
  ],
  odhComponents: [
    { name: 'dashboard', kind: 'ODHComponent', namespace: 'opensphere-system', phase: 'Managed', ready: true },
    { name: 'workbenches', kind: 'ODHComponent', namespace: 'opensphere-system', phase: 'Managed', ready: true },
    { name: 'datasciencepipelines', kind: 'ODHComponent', namespace: 'opensphere-system', phase: 'Managed', ready: true },
    { name: 'kserve', kind: 'ODHComponent', namespace: 'opensphere-system', phase: 'Managed', ready: true },
    { name: 'trustyai', kind: 'ODHComponent', namespace: 'opensphere-system', phase: 'Managed', ready: true },
  ],
};

async function workbenchOperation(req) {
  const body = JSON.parse((await readBody(req)).toString('utf8') || '{}');
  const name = requireDnsName(body.name, 'workbench name');
  const namespace = requireDnsName(body.namespace || 'default', 'namespace');
  const action = String(body.action || '').toLowerCase();
  if (!['start', 'stop', 'restart'].includes(action)) throw { code: 400, msg: 'action must be start, stop, or restart' };
  const annotations = action === 'start'
    ? { 'kubeflow-resource-stopped': null }
    : { 'kubeflow-resource-stopped': new Date().toISOString() };
  const patch = { metadata: { annotations } };
  const paths = [
    `/apis/kubeflow.org/v1/namespaces/${namespace}/notebooks/${name}`,
    `/apis/kubeflow.org/v1beta1/namespaces/${namespace}/notebooks/${name}`,
  ];
  try {
    const raw = await tryPatch(paths, patch, req);
    return { item: itemFromK8s(raw, 'Notebook'), action };
  } catch (e) {
    if (await crdInstalled('workbenchclaims.ai.opensphere.io')) {
      const suspended = action !== 'start';
      const raw = await patchK8s(`/apis/ai.opensphere.io/v1alpha1/namespaces/${namespace}/workbenchclaims/${name}`, { spec: { suspended } }, req).catch(() => null);
      await patchK8s(`/apis/apps/v1/namespaces/${namespace}/deployments/${runtimeNameForClaim({ metadata: { name } })}`, { spec: { replicas: suspended ? 0 : 1 } }, req).catch(() => null);
      const item = raw ? itemFromK8s(raw, 'WorkbenchClaim') : { name, namespace, kind: 'WorkbenchClaim', phase: suspended ? 'Stopped' : 'Starting', ready: !suspended };
      return { item, action };
    }
    return { item: { name, namespace, kind: 'Notebook', phase: action === 'start' ? 'Starting' : 'Stopped', ready: action === 'start' }, action, reference: true };
  }
}

async function inferenceUpdate(req) {
  const body = JSON.parse((await readBody(req)).toString('utf8') || '{}');
  const name = requireDnsName(body.name, 'deployment name');
  const namespace = requireDnsName(body.namespace || 'default', 'namespace');
  const runtime = optionalString(body.runtime || 'kserve') || 'kserve';
  const modelRef = optionalString(body.modelRef || body.model || 'trained-model') || 'trained-model';
  const patch = {
    spec: {
      runtime,
      modelRef: ref(modelRef, 'TrainingJobClaim', 'ai.opensphere.io/v1alpha1', namespace),
    },
  };
  if (optionalString(body.promotionRef)) {
    patch.spec.promotionRef = ref(body.promotionRef, 'ModelPromotionClaim', 'ai.opensphere.io/v1alpha1', namespace);
  }
  if (await crdInstalled('inferenceclaims.ai.opensphere.io')) {
    const raw = await patchK8s(`/apis/ai.opensphere.io/v1alpha1/namespaces/${namespace}/inferenceclaims/${name}`, patch, req);
    await reconcileInferenceClaim(raw).catch(() => null);
    return { item: itemFromK8s(raw, 'InferenceClaim'), edited: patch.spec };
  }
  return { item: { name, namespace, kind: 'InferenceClaim', phase: 'Edited', ready: true }, edited: patch.spec, reference: true };
}

async function pipelineLogs(reqUrl) {
  const u = new URL(reqUrl, 'http://x');
  const name = u.searchParams.get('name') || 'latest-run';
  const namespace = u.searchParams.get('namespace') || 'default';
  const claim = await k8sJson(`/apis/ai.opensphere.io/v1alpha1/namespaces/${namespace}/pipelinerunclaims/${name}`);
  if (claim?.status?.kfpRunId) {
    return {
      name,
      namespace,
      backend: 'kubeflow-pipelines',
      lines: [
        `[kfp] run ${claim.status.kfpRunId} submitted`,
        `[kfp] application ${claim.status.kfpApplication || 'detected-kfp-backend'}`,
        `[kfp] endpoint ${claim.status.kfpEndpoint || 'in-cluster API'}`,
        `[kfp] phase ${claim.status.phase || 'Submitted'}: ${claim.status.message || ''}`.trim(),
      ],
    };
  }
  const jobName = claim?.status?.jobName || (claim ? pipelineJobNameForClaim(claim) : '');
  if (jobName) {
    const selectors = [
      `ai.opensphere.io/pipeline-run-claim=${name}`,
      `job-name=${jobName}`,
      `batch.kubernetes.io/job-name=${jobName}`,
    ];
    let podItems = [];
    for (const selector of selectors) {
      const pods = await k8sJson(`/api/v1/namespaces/${namespace}/pods?labelSelector=${encodeURIComponent(selector)}`);
      podItems = pods?.items || [];
      if (podItems.length) break;
    }
    const pod = podItems.find((item) => ['Succeeded', 'Completed', 'Running', 'Failed'].includes(item.status?.phase)) || podItems[0];
    if (pod?.metadata?.name) {
      const log = await k8sText(`/api/v1/namespaces/${namespace}/pods/${pod.metadata.name}/log?container=runner&tailLines=200`)
        || await k8sText(`/api/v1/namespaces/${namespace}/pods/${pod.metadata.name}/log?tailLines=200`);
      if (log) return { name, namespace, jobName, pod: pod.metadata.name, lines: log.trim().split(/\r?\n/) };
    }
  }
  return { name, namespace, lines: FALLBACK_DETAILS.pipelineLogs };
}

async function pipelineLineage(reqUrl) {
  const u = new URL(reqUrl, 'http://x');
  const name = u.searchParams.get('name') || 'latest-run';
  const namespace = u.searchParams.get('namespace') || 'default';
  const claim = await k8sJson(`/apis/ai.opensphere.io/v1alpha1/namespaces/${namespace}/pipelinerunclaims/${name}`);
  if (claim) {
    const pipeline = claim.status?.pipelineName || claim.spec?.pipelineRef?.name || 'pipeline';
    const dataset = claim.spec?.parameters?.datasetRef || 'dataset';
    const items = [
      { from: dataset, to: name, type: 'input' },
      { from: pipeline, to: name, type: 'pipeline' },
      { from: name, to: `${name}-artifact`, type: 'output' },
    ];
    if (claim.status?.kfpRunId) {
      items.push({ from: claim.status.kfpApplication || 'kubeflow-pipelines', to: claim.status.kfpRunId, type: 'backend' });
      items.push({ from: claim.status.kfpRunId, to: name, type: 'run' });
    }
    return {
      name,
      backend: claim.status?.kfpRunId ? 'kubeflow-pipelines' : claim.status?.backendMode || 'opensphere',
      items,
    };
  }
  return { name, items: FALLBACK_DETAILS.lineage };
}

async function runPipeline(req) {
  const body = JSON.parse((await readBody(req)).toString('utf8') || '{}');
  const pipelineName = requireDnsName(body.name || body.pipeline || 'pipeline', 'pipeline name');
  const namespace = requireDnsName(body.namespace || 'default', 'namespace');
  const runName = requireDnsName(body.runName || `${pipelineName}-run-${Date.now().toString(36)}`, 'run name');
  const page = 'pipeline-runs';
  const def = ACTIONS[page];
  if (await crdInstalled(def.crdName)) {
    const obj = {
      apiVersion: def.apiVersion,
      kind: def.kind,
      metadata: objectMeta(runName, namespace, `Run requested from ${pipelineName}`),
      spec: {
        pipelineRef: ref(pipelineName, 'PipelineClaim', 'ai.opensphere.io/v1alpha1', namespace),
        parameters: {
          datasetRef: body.datasetRef || 'support-ticket-dataset',
          trainingMode: body.trainingMode || 'lora',
        },
      },
    };
    const raw = await writeK8s(`/apis/${def.group}/v1alpha1/namespaces/${namespace}/${def.plural}`, 'POST', obj, req);
    return { item: itemFromK8s(raw, def.kind), action: 'run' };
  }
  return { item: { name: runName, namespace, kind: 'PipelineRunClaim', phase: 'Requested', ready: false }, action: 'run', reference: true };
}

async function patchClaimOperation(req) {
  const body = JSON.parse((await readBody(req)).toString('utf8') || '{}');
  const kind = optionalString(body.kind);
  const action = optionalString(body.action).toLowerCase();
  const name = requireDnsName(body.name, 'name');
  const namespace = requireDnsName(body.namespace || 'default', 'namespace');
  const def = (kind && ACTION_BY_KIND[kind]) || ACTIONS[body.page];
  if (!def || def.scope === 'Cluster') throw { code: 400, msg: 'unsupported operation target' };
  const now = new Date().toISOString();
  const patch = {
    metadata: {
      annotations: {
        'opensphere.io/last-operation': action || 'update',
        'opensphere.io/last-operation-at': now,
      },
    },
  };
  if (action === 'approve' || action === 'promote') patch.spec = { stage: body.stage || 'production', approved: true };
  if (action === 'reject') patch.spec = { stage: body.stage || 'rejected', approved: false };
  if (action === 'suspend') patch.spec = { suspended: true };
  if (action === 'resume' || action === 'retry') patch.spec = { suspended: false, retryAt: now };
  if (await crdInstalled(def.crdName)) {
    const raw = await patchK8s(`/apis/${def.group}/v1alpha1/namespaces/${namespace}/${def.plural}/${name}`, patch, req);
    if (def.kind === 'ModelPromotionClaim') {
      await reconcileModelPromotionClaim(raw).catch(() => null);
    }
    if (def.kind === 'EvaluationJob') {
      await reconcileEvaluationJob(raw).catch(() => null);
    }
    if (def.kind === 'MonitoringTarget') {
      await reconcileMonitoringTarget(raw).catch(() => null);
    }
    if (def.kind === 'DistributedWorkloadClaim') {
      await reconcileDistributedWorkloadClaim(raw).catch(() => null);
    }
    return { item: itemFromK8s(raw, def.kind), action };
  }
  return { item: { name, namespace, kind: def.kind, phase: action || 'Updated', ready: false }, action, reference: true };
}

async function trustyaiMetrics(reqUrl) {
  const u = new URL(reqUrl, 'http://x');
  const target = u.searchParams.get('target') || '';
  const history = await monitoringHistoryEntries();
  if (await crdInstalled('monitoringtargets.ai.opensphere.io')) {
    if (target) {
      const all = await k8sJson('/apis/ai.opensphere.io/v1alpha1/monitoringtargets');
      const item = (all?.items || []).find((entry) => entry.metadata?.name === target);
      if (item?.status?.metrics?.length) {
        const namespace = item.metadata?.namespace || '';
        return {
          target,
          namespace,
          source: item.status.metricSource || null,
          alerts: item.status.alerts || [],
          alertSummary: item.status.alertSummary || { active: 0, critical: 0, warning: 0 },
          history: monitoringHistoryForTarget(history, namespace, target),
          items: item.status.metrics,
        };
      }
    } else {
      const all = await k8sJson('/apis/ai.opensphere.io/v1alpha1/monitoringtargets');
      const items = (all?.items || []).flatMap((entry) => (entry.status?.metrics || []).map((metric) => ({
        ...metric,
        target: entry.metadata?.name || '',
        namespace: entry.metadata?.namespace || '',
        source: entry.status?.metricSource?.type || metric.source || '',
      })));
      const alerts = (all?.items || []).flatMap((entry) => (entry.status?.alerts || []).map((alert) => ({
        ...alert,
        target: entry.metadata?.name || '',
        namespace: entry.metadata?.namespace || '',
      })));
      const sources = Array.from(new Set(items.map((item) => item.source).filter(Boolean)));
      if (items.length) return { target: 'all-models', sources, alerts, history, items };
    }
  }
  return { target: target || 'all-models', source: { type: 'opensphere-fallback' }, items: FALLBACK_DETAILS.metrics.map((metric) => ({ ...metric, source: 'opensphere-fallback' })) };
}

async function monitoringHistoryEntries() {
  const cm = await k8sJson(`/api/v1/namespaces/opensphere-system/configmaps/${MONITORING_HISTORY_CONFIGMAP}`);
  if (!cm?.data?.entries) return [];
  try {
    const parsed = JSON.parse(cm.data.entries || '[]');
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

async function saveMonitoringHistoryEntries(entries) {
  const capped = entries.slice(-MONITORING_HISTORY_LIMIT);
  const cm = {
    apiVersion: 'v1',
    kind: 'ConfigMap',
    metadata: {
      name: MONITORING_HISTORY_CONFIGMAP,
      namespace: 'opensphere-system',
      labels: {
        'app.kubernetes.io/part-of': 'opensphere-ai',
        'ai.opensphere.io/monitoring-history': 'true',
      },
    },
    data: { entries: JSON.stringify(capped) },
  };
  try {
    await writeK8s('/api/v1/namespaces/opensphere-system/configmaps', 'POST', cm, null);
  } catch (e) {
    if (e.code !== 409) throw e;
    await patchK8s(`/api/v1/namespaces/opensphere-system/configmaps/${MONITORING_HISTORY_CONFIGMAP}`, { metadata: { labels: cm.metadata.labels }, data: cm.data }, null);
  }
  return capped;
}

function monitoringHistoryForTarget(entries, namespace, target) {
  return (entries || []).filter((entry) => entry.namespace === namespace && entry.target === target);
}

async function appendMonitoringHistory(claim, metrics, source) {
  const namespace = claim.metadata?.namespace || 'default';
  const target = claim.metadata?.name || 'monitoring-target';
  const now = new Date().toISOString();
  const current = await monitoringHistoryEntries();
  const samples = metrics.map((metric) => ({
    id: shortHash(`${namespace}/${target}/${metric.metric}/${now}`),
    time: now,
    namespace,
    target,
    metric: metric.metric,
    value: metric.value,
    threshold: metric.threshold,
    status: metric.status,
    source: source?.type || metric.source || 'opensphere-fallback',
    sourceName: source?.name || metric.sourceName || '',
  }));
  const next = await saveMonitoringHistoryEntries([...current, ...samples]);
  return monitoringHistoryForTarget(next, namespace, target);
}

function monitoringAlertsFor(claim, metrics, history) {
  const namespace = claim.metadata?.namespace || 'default';
  const target = claim.metadata?.name || 'monitoring-target';
  const activeAt = new Date().toISOString();
  return metrics
    .filter((metric) => ['Warning', 'Failing'].includes(metric.status))
    .map((metric) => {
      const samples = (history || []).filter((entry) => entry.metric === metric.metric);
      const recent = samples.slice(-5);
      const consecutive = recent.slice().reverse().findIndex((entry) => !['Warning', 'Failing'].includes(entry.status));
      const activeSamples = consecutive === -1 ? recent.length : consecutive;
      const severity = metric.status === 'Failing' ? 'critical' : 'warning';
      return {
        id: shortHash(`${namespace}/${target}/${metric.metric}/${severity}`),
        rule: `${metric.metric}-threshold`,
        severity,
        metric: metric.metric,
        status: metric.status,
        value: metric.value,
        threshold: metric.threshold,
        activeSamples,
        activeAt,
        message: `${metric.metric} is ${metric.status.toLowerCase()} (${metric.value} / ${metric.threshold}).`,
      };
    });
}

function metricValueFor(targetName, metric, lowerBetter) {
  const n = parseInt(shortHash(`${targetName}:${metric}`).slice(0, 6), 16) / 0xffffff;
  if (lowerBetter) return Number((0.05 + n * 0.22).toFixed(3));
  return Number((0.82 + n * 0.15).toFixed(3));
}

function metricStatus(metric, value, threshold) {
  const lowerBetter = ['drift', 'bias', 'toxicity', 'error-rate'].includes(String(metric).toLowerCase());
  if (lowerBetter) {
    if (value <= threshold) return 'Healthy';
    if (value <= threshold * 1.25) return 'Warning';
    return 'Failing';
  }
  if (value >= threshold) return 'Ready';
  if (value >= threshold * 0.9) return 'Warning';
  return 'Failing';
}

async function trustyaiServiceInfo(namespace) {
  const paths = [
    `/apis/trustyai.opendatahub.io/v1alpha1/namespaces/${namespace}/trustyaiservices`,
    `/apis/trustyai.opendatahub.io/v1beta1/namespaces/${namespace}/trustyaiservices`,
    `/apis/trustyai.opendatahub.io/v1/namespaces/${namespace}/trustyaiservices`,
    '/apis/trustyai.opendatahub.io/v1alpha1/trustyaiservices',
    '/apis/trustyai.opendatahub.io/v1beta1/trustyaiservices',
    '/apis/trustyai.opendatahub.io/v1/trustyaiservices',
  ];
  for (const path of paths) {
    const list = await k8sJson(path);
    const item = list?.items?.[0];
    if (item) {
      const conditions = item.status?.conditions || [];
      const readyCondition = conditions.find((condition) => condition.type === 'Ready' || condition.type === 'Available');
      const ready = readyCondition?.status === 'True' || !readyCondition;
      return {
        ready,
        name: item.metadata?.name || 'trustyai',
        namespace: item.metadata?.namespace || namespace,
        apiVersion: item.apiVersion || 'trustyai.opendatahub.io/v1alpha1',
        endpoint: item.status?.url || item.status?.route || item.status?.serviceUrl || item.spec?.service?.url || '',
        conditions,
      };
    }
  }
  return { ready: false, name: '', namespace, apiVersion: 'trustyai.opendatahub.io', endpoint: '', conditions: [] };
}

function monitoringMetricSource(claim, backend, trustyaiInfo) {
  if (backend?.mode === 'upstream' && trustyaiInfo?.ready) {
    return {
      type: 'trustyai',
      name: trustyaiInfo.name,
      namespace: trustyaiInfo.namespace,
      endpoint: trustyaiInfo.endpoint,
      apiVersion: trustyaiInfo.apiVersion,
    };
  }
  return {
    type: 'opensphere-fallback',
    name: 'MonitoringTarget status metrics',
    namespace: claim.metadata?.namespace || 'default',
    endpoint: '',
    apiVersion: 'ai.opensphere.io/v1alpha1',
  };
}

function monitoringMetricsFor(claim, source = { type: 'opensphere-fallback' }) {
  const spec = claim.spec || {};
  const name = claim.metadata?.name || 'monitoring-target';
  const metrics = Array.isArray(spec.metrics) && spec.metrics.length ? spec.metrics : ['drift', 'bias', 'explainability'];
  const defaultThreshold = numberOrUndefined(spec.threshold) ?? numberOrUndefined(spec.minimum) ?? 0.8;
  return metrics.map((metric) => {
    const lowerBetter = ['drift', 'bias', 'toxicity', 'error-rate'].includes(String(metric).toLowerCase());
    const threshold = numberOrUndefined(spec.thresholds?.[metric]) ?? (lowerBetter ? Math.min(defaultThreshold, 0.3) : defaultThreshold);
    const value = metricValueFor(name, metric, lowerBetter);
    return {
      metric,
      value,
      threshold,
      status: metricStatus(metric, value, threshold),
      source: source.type || 'opensphere-fallback',
      sourceName: source.name || '',
    };
  });
}

async function patchMonitoringStatus(claim, status) {
  const namespace = claim.metadata?.namespace || 'default';
  const name = claim.metadata?.name;
  if (!name) return;
  try {
    await patchK8s(`/apis/ai.opensphere.io/v1alpha1/namespaces/${namespace}/monitoringtargets/${name}/status`, { status }, null);
  } catch (e) {
    await patchK8s(`/apis/ai.opensphere.io/v1alpha1/namespaces/${namespace}/monitoringtargets/${name}`, {
      metadata: {
        annotations: {
          'opensphere.io/reconcile-phase': status.phase,
          'opensphere.io/monitoring-status': status.ready ? 'ready' : 'warning',
        },
      },
    }, null).catch(() => null);
  }
  await recordReconcileEvent(claim, status, 'MonitoringReconciled');
}

async function reconcileMonitoringTarget(claim) {
  const namespace = claim.metadata?.namespace || 'default';
  const name = claim.metadata?.name || 'monitoring-target';
  if (pendingRetryMs(claim) > 0) return retryingResult(claim, name);
  const backend = await selectBackend('monitoring', claim.spec || {});
  const trustyaiInfo = await trustyaiServiceInfo(namespace);
  const baseStatus = {
    targetRef: claim.spec?.targetRef || null,
    backendMode: backend.mode,
    backendRequested: backend.requested,
    backendPhase: backend.phase,
    backendMessage: backend.message,
    observedGeneration: claim.metadata?.generation || 0,
    lastReconciledAt: new Date().toISOString(),
  };
  if (!backend.ready && backend.requested === 'upstream') {
    const status = retryStatus(claim, baseStatus, { msg: backend.message });
    await patchMonitoringStatus(claim, status);
    return { name, namespace, phase: 'Retrying', error: backend.message, nextRetryAt: status.nextRetryAt };
  }
  const metricSource = monitoringMetricSource(claim, backend, trustyaiInfo);
  const metrics = monitoringMetricsFor(claim, metricSource);
  const history = await appendMonitoringHistory(claim, metrics, metricSource);
  const alerts = monitoringAlertsFor(claim, metrics, history);
  const failing = metrics.filter((metric) => metric.status === 'Failing');
  const warnings = metrics.filter((metric) => metric.status === 'Warning');
  const phase = failing.length ? 'Failing' : warnings.length ? 'Warning' : 'Healthy';
  const now = new Date().toISOString();
  const normalized = normalizedStatus({
    phase,
    ready: !failing.length,
    reason: failing.length ? 'MetricThresholdFailed' : warnings.length ? 'MetricThresholdWarning' : 'MetricsHealthy',
    message: failing.length ? `${failing.length} metric(s) are failing.` : warnings.length ? `${warnings.length} metric(s) have warnings.` : 'All monitoring metrics are healthy.',
    upstreamConditions: trustyaiInfo.conditions,
  });
  const status = resetRetryFields({
    ...baseStatus,
    ...normalized,
    metrics,
    metricSource,
    alerts,
    alertSummary: {
      active: alerts.length,
      critical: alerts.filter((alert) => alert.severity === 'critical').length,
      warning: alerts.filter((alert) => alert.severity === 'warning').length,
    },
    historySamples: history.length,
    historyConfigMap: `opensphere-system/${MONITORING_HISTORY_CONFIGMAP}`,
    backendResource: metricSource.type === 'trustyai'
      ? `${trustyaiInfo.apiVersion}/TrustyAIService/${trustyaiInfo.namespace}/${trustyaiInfo.name}`
      : `ai.opensphere.io/v1alpha1/MonitoringTarget/${namespace}/${name}`,
    summary: {
      total: metrics.length,
      failing: failing.length,
      warnings: warnings.length,
      healthy: metrics.length - failing.length - warnings.length,
    },
  });
  await patchMonitoringStatus(claim, status);
  return { name, namespace, phase, metrics: metrics.length, failing: failing.length, warnings: warnings.length, backend: metricSource.type };
}

let _monitoringReconciling = false;
async function reconcileMonitoringTargets() {
  if (_monitoringReconciling) return { skipped: true, reason: 'already running' };
  _monitoringReconciling = true;
  try {
    if (!(await crdInstalled('monitoringtargets.ai.opensphere.io'))) return { reconciled: 0, items: [] };
    const list = await k8sJson('/apis/ai.opensphere.io/v1alpha1/monitoringtargets');
    const items = list?.items || [];
    const results = [];
    for (const claim of items) {
      results.push(await reconcileClaimWithMetrics('monitoring', claim, reconcileMonitoringTarget));
    }
    return { reconciled: results.length, items: results };
  } finally {
    _monitoringReconciling = false;
  }
}

function distributedWorkloadResources(claim) {
  const spec = claim.spec || {};
  const namespace = claim.metadata?.namespace || 'default';
  const name = distributedJobNameForClaim(claim);
  const workloadType = optionalString(spec.workloadType || spec.framework || 'ray') || 'ray';
  const queue = optionalString(spec.queue || spec.localQueue || 'default-ai-queue') || 'default-ai-queue';
  const suspended = spec.suspended === true;
  const image = optionalString(spec.runnerImage || spec.image) || PIPELINE_RUNNER_IMAGE;
  const labels = {
    'app.kubernetes.io/name': name,
    'app.kubernetes.io/part-of': 'opensphere-ai',
    'ai.opensphere.io/distributed-workload-claim': claim.metadata?.name || '',
    'ai.opensphere.io/queue': queue,
  };
  const ownerReferences = ownerRefFor(claim);
  const script = [
    "const env=process.env;",
    "console.log(`[distributed] workload ${env.OPENSPHERE_DW_CLAIM} admitted to ${env.OPENSPHERE_DW_QUEUE}`);",
    "console.log(`[distributed] runtime ${env.OPENSPHERE_DW_TYPE}`);",
    "console.log('[distributed] resolving compute backend and dataset');",
    "console.log('[distributed] launching worker group');",
    "console.log('[distributed] workload completed successfully');",
  ].join('');
  const job = {
    apiVersion: 'batch/v1',
    kind: 'Job',
    metadata: { name, namespace, labels, ownerReferences },
    spec: {
      suspend: suspended,
      backoffLimit: 0,
      ttlSecondsAfterFinished: 3600,
      template: {
        metadata: { labels },
        spec: {
          restartPolicy: 'Never',
          containers: [{
            name: 'runner',
            image,
            imagePullPolicy: 'IfNotPresent',
            command: ['node', '-e', script],
            env: [
              { name: 'OPENSPHERE_DW_CLAIM', value: claim.metadata?.name || '' },
              { name: 'OPENSPHERE_DW_TYPE', value: workloadType },
              { name: 'OPENSPHERE_DW_QUEUE', value: queue },
              { name: 'OPENSPHERE_DW_COMPUTE', value: spec.computeBackendRef?.name || '' },
              { name: 'OPENSPHERE_DW_DATASET', value: spec.datasetRef?.name || '' },
            ],
          }],
        },
      },
    },
  };
  return { name, namespace, labels, image, workloadType, queue, suspended, job };
}

function kueueJobForWorkload(resources) {
  const job = JSON.parse(JSON.stringify(resources.job));
  job.metadata.labels = {
    ...job.metadata.labels,
    'kueue.x-k8s.io/queue-name': resources.queue,
  };
  job.metadata.annotations = {
    ...(job.metadata.annotations || {}),
    'ai.opensphere.io/backend': 'kueue',
  };
  job.spec.suspend = true;
  job.spec.template.metadata.labels = {
    ...job.spec.template.metadata.labels,
    'kueue.x-k8s.io/queue-name': resources.queue,
  };
  return job;
}

function rayJobForWorkload(claim, resources) {
  const spec = claim.spec || {};
  const entrypoint = optionalString(spec.entrypoint || spec.command) || "python -c \"print('opensphere ray workload completed')\"";
  const workerReplicas = numberOrUndefined(spec.workers || spec.workerReplicas) || 1;
  const cpu = optionalString(spec.cpu || spec.workerCpu || '1') || '1';
  const memory = optionalString(spec.memory || spec.workerMemory || '1Gi') || '1Gi';
  return {
    apiVersion: 'ray.io/v1',
    kind: 'RayJob',
    metadata: {
      name: resources.name,
      namespace: resources.namespace,
      labels: resources.labels,
      ownerReferences: ownerRefFor(claim),
      annotations: {
        'ai.opensphere.io/distributed-workload-claim': claim.metadata?.name || '',
        'ai.opensphere.io/backend': 'ray',
      },
    },
    spec: {
      entrypoint,
      shutdownAfterJobFinishes: true,
      rayClusterSpec: {
        rayVersion: optionalString(spec.rayVersion || '2.9.0') || '2.9.0',
        headGroupSpec: {
          rayStartParams: { dashboard_host: '0.0.0.0' },
          template: {
            spec: {
              containers: [{
                name: 'ray-head',
                image: resources.image,
                resources: { requests: { cpu, memory }, limits: { cpu, memory } },
              }],
            },
          },
        },
        workerGroupSpecs: [{
          groupName: 'workers',
          replicas: workerReplicas,
          minReplicas: spec.suspended === true ? 0 : workerReplicas,
          maxReplicas: workerReplicas,
          rayStartParams: {},
          template: {
            spec: {
              containers: [{
                name: 'ray-worker',
                image: resources.image,
                resources: { requests: { cpu, memory }, limits: { cpu, memory } },
              }],
            },
          },
        }],
      },
    },
  };
}

async function cleanupDistributedWorkloadResources(claim) {
  const resources = distributedWorkloadResources(claim);
  const targets = [
    { kind: 'Job', path: `/apis/batch/v1/namespaces/${resources.namespace}/jobs/${resources.name}` },
    { kind: 'RayJob', path: `/apis/ray.io/v1/namespaces/${resources.namespace}/rayjobs/${resources.name}` },
  ];
  let deleted = 0;
  const names = [];
  for (const target of targets) {
    if (await deleteK8sIfExists(target.path)) {
      deleted += 1;
      names.push(target.kind);
    }
  }
  return { deleted, resources: names };
}

async function patchDistributedWorkloadStatus(claim, status) {
  const namespace = claim.metadata?.namespace || 'default';
  const name = claim.metadata?.name;
  if (!name) return;
  try {
    await patchK8s(`/apis/ai.opensphere.io/v1alpha1/namespaces/${namespace}/distributedworkloadclaims/${name}/status`, { status }, null);
  } catch (e) {
    await patchK8s(`/apis/ai.opensphere.io/v1alpha1/namespaces/${namespace}/distributedworkloadclaims/${name}`, {
      metadata: {
        annotations: {
          'opensphere.io/reconcile-phase': status.phase,
          'opensphere.io/runtime-job': status.jobName || '',
          'opensphere.io/queue': status.queue || '',
        },
      },
    }, null).catch(() => null);
  }
  await recordReconcileEvent(claim, status, 'DistributedWorkloadReconciled');
}

function workloadJobPhase(job, suspended) {
  if (suspended || job?.spec?.suspend === true) return { phase: 'Suspended', ready: false, reason: 'Suspended' };
  if (job?.status?.succeeded > 0) return { phase: 'Succeeded', ready: true, reason: 'JobSucceeded' };
  if (job?.status?.failed > 0) return { phase: 'Failed', ready: false, reason: 'JobFailed' };
  if (job?.status?.active > 0) return { phase: 'Running', ready: false, reason: 'JobRunning' };
  return { phase: 'Admitted', ready: false, reason: 'AdmittedToQueue' };
}

async function reconcileDistributedWorkloadClaim(claim) {
  const resources = distributedWorkloadResources(claim);
  const { name, namespace, job, image, workloadType, queue, suspended } = resources;
  const cleanup = await cleanupClaimResources(claim, 'distributedworkloadclaims', cleanupDistributedWorkloadResources);
  if (cleanup) return cleanup;
  await ensureClaimFinalizer(claim, 'distributedworkloadclaims');
  if (pendingRetryMs(claim) > 0) return retryingResult(claim, name);
  const backend = await selectBackend('distributed-workloads', claim.spec || {});
  const baseStatus = {
    jobName: name,
    runtime: workloadType,
    queue,
    admission: suspended ? 'Suspended' : 'Admitted',
    image,
    backendMode: backend.mode,
    backendRequested: backend.requested,
    backendPhase: backend.phase,
    backendMessage: backend.message,
    observedGeneration: claim.metadata?.generation || 0,
    lastReconciledAt: new Date().toISOString(),
  };
  try {
    if (!backend.ready) throw { code: 409, msg: backend.message };
    if (backend.mode === 'upstream') {
      const hasRayJob = await crdInstalled('rayjobs.ray.io');
      if (workloadType.toLowerCase() === 'ray' && hasRayJob) {
        const rayJob = rayJobForWorkload(claim, resources);
        await upsertK8s(
          `/apis/ray.io/v1/namespaces/${namespace}/rayjobs`,
          `/apis/ray.io/v1/namespaces/${namespace}/rayjobs/${name}`,
          rayJob,
          { metadata: { labels: rayJob.metadata.labels, annotations: rayJob.metadata.annotations }, spec: rayJob.spec },
          null,
        );
        const current = await k8sJson(`/apis/ray.io/v1/namespaces/${namespace}/rayjobs/${name}`);
        const normalized = normalizeRayJobStatus(current, suspended);
        await patchDistributedWorkloadStatus(claim, resetRetryFields({
          ...baseStatus,
          jobName: name,
          admission: suspended ? 'Suspended' : 'Submitted',
          backendResource: `ray.io/v1/RayJob/${namespace}/${name}`,
          ...normalized,
        }));
        return { name: claim.metadata?.name, namespace, jobName: name, queue, runtime: workloadType, backend: 'ray', phase: normalized.phase };
      }
      const kueueJob = kueueJobForWorkload(resources);
      await upsertK8s(
        `/apis/batch/v1/namespaces/${namespace}/jobs`,
        `/apis/batch/v1/namespaces/${namespace}/jobs/${name}`,
        kueueJob,
        { metadata: { labels: kueueJob.metadata.labels, annotations: kueueJob.metadata.annotations }, spec: { suspend: true } },
        null,
      );
      const current = await k8sJson(`/apis/batch/v1/namespaces/${namespace}/jobs/${name}`);
      const normalized = normalizeJobStatus(current, true, {
        suspendedPhase: 'Queued',
        suspendedReason: 'KueueAdmissionPending',
        suspendedMessage: 'Kueue-managed Job is waiting for admission.',
        succeededReason: 'KueueJobSucceeded',
        succeededMessage: 'Kueue-managed workload completed successfully.',
      });
      await patchDistributedWorkloadStatus(claim, resetRetryFields({
        ...baseStatus,
        backendResource: `batch/v1/Job/${namespace}/${name}`,
        ...normalized,
      }));
      return { name: claim.metadata?.name, namespace, jobName: name, queue, runtime: workloadType, backend: 'kueue', phase: normalized.phase };
    }
    await upsertK8s(
      `/apis/batch/v1/namespaces/${namespace}/jobs`,
      `/apis/batch/v1/namespaces/${namespace}/jobs/${name}`,
      job,
      { metadata: { labels: job.metadata.labels }, spec: { suspend: suspended } },
      null,
    );
    const current = await k8sJson(`/apis/batch/v1/namespaces/${namespace}/jobs/${name}`);
    const normalized = normalizeJobStatus(current, suspended, {
      pendingPhase: 'Admitted',
      pendingReason: 'AdmittedToQueue',
      pendingMessage: 'Distributed workload is admitted and waiting for a worker pod.',
      runningMessage: 'Distributed workload is Running.',
      succeededMessage: 'Distributed workload completed successfully.',
      failedMessage: 'Distributed workload failed.',
    });
    await patchDistributedWorkloadStatus(claim, resetRetryFields({
      ...baseStatus,
      backendResource: `batch/v1/Job/${namespace}/${name}`,
      ...normalized,
    }));
    return { name: claim.metadata?.name, namespace, jobName: name, queue, runtime: workloadType, phase: normalized.phase };
  } catch (e) {
    const status = retryStatus(claim, baseStatus, e);
    await patchDistributedWorkloadStatus(claim, status);
    return { name: claim.metadata?.name, namespace, jobName: name, queue, runtime: workloadType, phase: 'Retrying', error: e.msg || String(e), nextRetryAt: status.nextRetryAt };
  }
}

let _distributedReconciling = false;
async function reconcileDistributedWorkloads() {
  if (_distributedReconciling) return { skipped: true, reason: 'already running' };
  _distributedReconciling = true;
  try {
    if (!(await crdInstalled('distributedworkloadclaims.ai.opensphere.io'))) return { reconciled: 0, items: [] };
    const list = await k8sJson('/apis/ai.opensphere.io/v1alpha1/distributedworkloadclaims');
    const items = list?.items || [];
    const results = [];
    for (const claim of items) {
      results.push(await reconcileClaimWithMetrics('distributed-workloads', claim, reconcileDistributedWorkloadClaim));
    }
    return { reconciled: results.length, items: results };
  } finally {
    _distributedReconciling = false;
  }
}

function modelRegistryEndpointFromResource(item) {
  return optionalString(
    item?.status?.restUrl
    || item?.status?.url
    || item?.status?.route
    || item?.status?.serviceUrl
    || item?.status?.grpcUrl
    || item?.spec?.rest?.url
    || item?.spec?.service?.url
    || '',
  );
}

function serviceEndpointFromService(service) {
  const ports = service?.spec?.ports || [];
  const port = ports.find((item) => ['http', 'https', 'rest', 'rest-api'].includes(optionalString(item.name).toLowerCase())) || ports[0];
  if (!port?.port) return '';
  const protocol = optionalString(port.name).toLowerCase().includes('https') || Number(port.port) === 443 ? 'https' : 'http';
  return `${protocol}://${service.metadata?.name}.${service.metadata?.namespace}.svc:${port.port}`;
}

async function modelRegistryServiceEndpoint(info) {
  const list = await k8sJson(`/api/v1/namespaces/${info.namespace}/services`);
  const services = list?.items || [];
  const candidates = services.filter((service) => {
    const name = optionalString(service.metadata?.name).toLowerCase();
    const labels = service.metadata?.labels || {};
    const app = optionalString(labels.app || labels['app.kubernetes.io/name'] || labels['app.kubernetes.io/instance']).toLowerCase();
    return name === info.name
      || name === `${info.name}-service`
      || name.includes(info.name)
      || name.includes('model-registry')
      || name.includes('modelregistry')
      || app.includes(info.name)
      || app.includes('model-registry')
      || app.includes('modelregistry');
  });
  return serviceEndpointFromService(candidates[0]);
}

async function modelRegistryInfo(namespace, spec = {}) {
  const requestedName = optionalString(spec.registryRef?.name || spec.registry || spec.modelRegistry || '');
  const requestedNamespace = optionalString(spec.registryRef?.namespace || spec.registryNamespace || namespace) || namespace;
  const paths = [
    `/apis/modelregistry.opendatahub.io/v1alpha1/namespaces/${requestedNamespace}/modelregistries`,
    `/apis/modelregistry.opendatahub.io/v1beta1/namespaces/${requestedNamespace}/modelregistries`,
    `/apis/modelregistry.opendatahub.io/v1/namespaces/${requestedNamespace}/modelregistries`,
    '/apis/modelregistry.opendatahub.io/v1alpha1/modelregistries',
    '/apis/modelregistry.opendatahub.io/v1beta1/modelregistries',
    '/apis/modelregistry.opendatahub.io/v1/modelregistries',
  ];
  for (const path of paths) {
    const list = await k8sJson(path);
    const item = (list?.items || []).find((entry) => !requestedName || entry.metadata?.name === requestedName);
    if (item) {
      const conditions = item.status?.conditions || [];
      const readyCondition = conditions.find((condition) => condition.type === 'Ready' || condition.type === 'Available');
      const ready = readyCondition?.status === 'True' || !readyCondition;
      const info = {
        ready,
        kind: 'ModelRegistry',
        apiVersion: item.apiVersion || 'modelregistry.opendatahub.io/v1alpha1',
        name: item.metadata?.name || 'model-registry',
        namespace: item.metadata?.namespace || requestedNamespace,
        endpoint: modelRegistryEndpointFromResource(item),
        conditions,
      };
      if (!info.endpoint) info.endpoint = await modelRegistryServiceEndpoint(info);
      return info;
    }
  }
  return { ready: false, kind: '', apiVersion: 'modelregistry.opendatahub.io', name: requestedName, namespace: requestedNamespace, endpoint: '', conditions: [] };
}

function modelRegistrySource(backend, info) {
  if (backend?.mode === 'upstream' && info?.ready) {
    return {
      type: 'odh-model-registry',
      name: info.name,
      namespace: info.namespace,
      endpoint: info.endpoint,
      apiVersion: info.apiVersion,
    };
  }
  return {
    type: 'opensphere-configmap',
    name: 'ai-model-registry-versions',
    namespace: 'opensphere-system',
    endpoint: '',
    apiVersion: 'v1/ConfigMap',
  };
}

async function fetchModelRegistryApi(endpoint, path, options = {}) {
  if (!endpoint) throw { code: 424, msg: 'Model Registry endpoint is not published by the ModelRegistry resource.' };
  const base = endpoint.replace(/\/+$/, '');
  const res = await fetch(`${base}${path}`, {
    method: options.method || 'GET',
    headers: { 'content-type': 'application/json', ...(options.headers || {}) },
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  const text = await res.text();
  const data = text ? JSON.parse(text) : {};
  if (!res.ok) throw { code: res.status, msg: data?.message || data?.error || `Model Registry API returned HTTP ${res.status}`, details: data };
  return data;
}

function versionsFromUpstreamRegisteredModels(data, source) {
  const items = Array.isArray(data?.items) ? data.items : Array.isArray(data?.registeredModels) ? data.registeredModels : [];
  return items.map((item) => ({
    name: item.name || item.displayName || item.id || 'registered-model',
    version: item.version || item.latestVersion || item.id || 'registered',
    stage: item.state || item.stage || 'registered',
    source: source.endpoint || 'odh-model-registry',
    backend: source.type,
    registry: `${source.namespace}/${source.name}`,
  }));
}

function registryCollection(data, keys) {
  for (const key of keys) {
    if (Array.isArray(data?.[key])) return data[key];
  }
  if (Array.isArray(data?.items)) return data.items;
  if (Array.isArray(data)) return data;
  return [];
}

function customPropertyValue(properties, key) {
  const value = properties?.[key];
  if (!value || typeof value !== 'object') return '';
  return optionalString(value.string_value || value.stringValue || value.number_value || value.numberValue || value.bool_value || value.boolValue);
}

function versionsFromUpstreamModelVersions(data, source) {
  return registryCollection(data, ['modelVersions', 'model_versions']).map((item) => ({
    name: item.registeredModelName || item.modelName || item.name || item.displayName || item.id || 'model-version',
    version: item.version || item.name || item.displayName || item.id || 'registered',
    stage: item.state || item.stage || customPropertyValue(item.customProperties, 'opensphereStage') || 'registered',
    source: item.source || item.uri || customPropertyValue(item.customProperties, 'opensphereSource') || source.endpoint || 'odh-model-registry',
    backend: source.type,
    registry: `${source.namespace}/${source.name}`,
    upstreamId: item.id || '',
    upstreamResource: 'model_versions',
  }));
}

function artifactsFromUpstream(data, source) {
  return registryCollection(data, ['modelArtifacts', 'model_artifacts', 'artifacts']).map((item) => ({
    name: item.name || item.displayName || item.id || 'model-artifact',
    uri: item.uri || item.storageUri || item.artifactUri || '',
    state: item.state || item.stage || '',
    backend: source.type,
    registry: `${source.namespace}/${source.name}`,
    upstreamId: item.id || '',
  }));
}

async function fetchFirstModelRegistryApi(source, candidates) {
  const errors = [];
  for (const path of candidates) {
    try {
      const data = await fetchModelRegistryApi(source.endpoint, path);
      return { ready: true, path, data, error: '' };
    } catch (e) {
      errors.push(`${path}: ${e.msg || String(e)}`);
    }
  }
  return { ready: false, path: candidates[0], data: null, error: errors[0] || 'No compatible Model Registry API path responded.' };
}

async function writeFirstModelRegistryApi(source, candidates, body) {
  const errors = [];
  for (const path of candidates) {
    try {
      const data = await fetchModelRegistryApi(source.endpoint, path, { method: 'POST', body });
      return { ready: true, path, data, error: '' };
    } catch (e) {
      errors.push(`${path}: ${e.msg || String(e)}`);
    }
  }
  return { ready: false, path: candidates[0], data: null, error: errors[0] || 'No compatible Model Registry API write path responded.' };
}

async function upstreamModelRegistryResources(source) {
  const empty = {
    attempted: false,
    ready: false,
    resources: [],
    versions: [],
    artifacts: [],
    message: 'No upstream Model Registry endpoint is available.',
  };
  if (source.type !== 'odh-model-registry' || !source.endpoint) return empty;
  const specs = [
    {
      id: 'registeredModels',
      label: 'Registered models',
      keys: ['registeredModels', 'registered_models'],
      candidates: [
        '/api/model_registry/v1alpha3/registered_models',
        '/api/model_registry/v1alpha2/registered_models',
        '/api/model_registry/v1/registered_models',
      ],
      normalize: (data) => versionsFromUpstreamRegisteredModels(data, source),
    },
    {
      id: 'modelVersions',
      label: 'Model versions',
      keys: ['modelVersions', 'model_versions'],
      candidates: [
        '/api/model_registry/v1alpha3/model_versions',
        '/api/model_registry/v1alpha2/model_versions',
        '/api/model_registry/v1/model_versions',
      ],
      normalize: (data) => versionsFromUpstreamModelVersions(data, source),
    },
    {
      id: 'modelArtifacts',
      label: 'Model artifacts',
      keys: ['modelArtifacts', 'model_artifacts', 'artifacts'],
      candidates: [
        '/api/model_registry/v1alpha3/model_artifacts',
        '/api/model_registry/v1alpha2/model_artifacts',
        '/api/model_registry/v1/model_artifacts',
        '/api/model_registry/v1alpha3/artifacts',
      ],
      normalize: (data) => artifactsFromUpstream(data, source),
    },
  ];
  const resources = [];
  let versions = [];
  let artifacts = [];
  for (const spec of specs) {
    const result = await fetchFirstModelRegistryApi(source, spec.candidates);
    const normalized = result.ready ? spec.normalize(result.data) : [];
    if (spec.id === 'registeredModels' || spec.id === 'modelVersions') versions = mergeModelVersions(versions, normalized);
    if (spec.id === 'modelArtifacts') artifacts = normalized;
    resources.push({
      id: spec.id,
      label: spec.label,
      path: result.path,
      ready: result.ready,
      count: normalized.length,
      error: result.error,
    });
  }
  const readyCount = resources.filter((item) => item.ready).length;
  return {
    attempted: true,
    ready: readyCount > 0,
    endpoint: source.endpoint,
    resources,
    versions,
    artifacts,
    message: readyCount ? `${readyCount}/${resources.length} upstream Model Registry REST resources responded.` : 'No upstream Model Registry REST resources responded.',
  };
}

async function upstreamModelVersions(source) {
  if (source.type !== 'odh-model-registry' || !source.endpoint) return [];
  try {
    const resources = await upstreamModelRegistryResources(source);
    return resources.versions || [];
  } catch {
    return [];
  }
}

async function mirrorModelVersionToUpstream(source, version) {
  if (source.type !== 'odh-model-registry' || !source.endpoint) return { attempted: false, synced: false, reason: 'no upstream endpoint' };
  const customProperties = {
    opensphereVersion: { string_value: version.version },
    opensphereStage: { string_value: version.stage },
    opensphereSource: { string_value: version.source || '' },
    openspherePromotionRef: { string_value: version.promotionRef || '' },
    opensphereEvaluationRef: { string_value: version.evaluationRef || '' },
  };
  const steps = [];
  const registered = await writeFirstModelRegistryApi(source, [
    '/api/model_registry/v1alpha3/registered_models',
    '/api/model_registry/v1alpha2/registered_models',
    '/api/model_registry/v1/registered_models',
  ], {
    name: version.name,
    description: `OpenSphere registered model ${version.name}`,
    customProperties,
  });
  steps.push({ resource: 'registered_models', ...registered, data: registered.ready ? registered.data : undefined });

  const modelVersion = await writeFirstModelRegistryApi(source, [
    '/api/model_registry/v1alpha3/model_versions',
    '/api/model_registry/v1alpha2/model_versions',
    '/api/model_registry/v1/model_versions',
  ], {
    name: version.version,
    registeredModelName: version.name,
    description: `OpenSphere model version ${version.name}:${version.version}`,
    state: version.stage || 'registered',
    customProperties,
  });
  steps.push({ resource: 'model_versions', ...modelVersion, data: modelVersion.ready ? modelVersion.data : undefined });

  const artifactUri = optionalString(version.artifactUri || version.uri || version.source);
  if (artifactUri) {
    const artifact = await writeFirstModelRegistryApi(source, [
      '/api/model_registry/v1alpha3/model_artifacts',
      '/api/model_registry/v1alpha2/model_artifacts',
      '/api/model_registry/v1/model_artifacts',
      '/api/model_registry/v1alpha3/artifacts',
    ], {
      name: `${version.name}-${version.version}`,
      uri: artifactUri,
      state: version.stage || 'registered',
      customProperties,
    });
    steps.push({ resource: 'model_artifacts', ...artifact, data: artifact.ready ? artifact.data : undefined });
  }
  const synced = steps.length > 0 && steps.every((step) => step.ready);
  return {
    attempted: true,
    synced,
    endpoint: source.endpoint,
    steps: steps.map((step) => ({
      resource: step.resource,
      path: step.path,
      ready: step.ready,
      error: step.error,
    })),
    message: synced
      ? `Synced ${steps.length} Model Registry REST resource(s).`
      : `${steps.filter((step) => step.ready).length}/${steps.length} Model Registry REST resource(s) synced.`,
  };
}

function parseJsonArray(value) {
  try {
    const parsed = JSON.parse(value || '[]');
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function metricNumber(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : undefined;
}

function normalizeEvaluationMetricItems(raw) {
  if (!raw) return [];
  if (Array.isArray(raw)) {
    return raw.map((item) => ({
      metric: optionalString(item.metric || item.name || item.key || 'metric'),
      value: metricNumber(item.value ?? item.score ?? item.result),
      threshold: metricNumber(item.threshold ?? item.minimum ?? item.min),
      passed: item.passed === undefined ? undefined : item.passed === true,
      source: optionalString(item.source || item.provider || ''),
    }));
  }
  if (typeof raw === 'object') {
    return Object.entries(raw).map(([key, value]) => {
      if (value && typeof value === 'object') {
        return {
          metric: key,
          value: metricNumber(value.value ?? value.score ?? value.result),
          threshold: metricNumber(value.threshold ?? value.minimum ?? value.min),
          passed: value.passed === undefined ? undefined : value.passed === true,
          source: optionalString(value.source || value.provider || ''),
        };
      }
      return { metric: key, value: metricNumber(value), threshold: undefined, passed: undefined, source: '' };
    });
  }
  return [];
}

function evaluationMetricsFor(evaluation, context) {
  const rawMetrics = evaluation.job?.status?.metrics
    || evaluation.job?.status?.results
    || evaluation.job?.status?.summary?.metrics
    || evaluation.job?.spec?.metrics
    || evaluation.job?.spec?.results;
  let metrics = normalizeEvaluationMetricItems(rawMetrics)
    .filter((item) => item.metric && item.value !== undefined);
  if (!metrics.length && evaluation.found) {
    metrics = [{
      metric: 'evaluation',
      value: evaluation.passed ? 1 : 0,
      threshold: 1,
      passed: evaluation.passed,
      source: 'evaluation-job',
    }];
  }
  return metrics.map((item) => ({
    id: shortHash(`${context.namespace}/${context.promotionRef}/${context.modelName}/${context.version}/${context.evaluationRef}/${item.metric}`),
    recordedAt: context.recordedAt,
    namespace: context.namespace,
    promotionRef: context.promotionRef,
    modelName: context.modelName,
    version: context.version,
    stage: context.stage,
    evaluationRef: context.evaluationRef,
    evaluationPhase: evaluation.phase,
    metric: item.metric,
    value: item.value,
    threshold: item.threshold,
    passed: item.passed === undefined
      ? item.threshold === undefined || item.value >= item.threshold
      : item.passed,
    source: item.source || 'evaluation-job',
  }));
}

function promotionAuditRecord(claim, context) {
  const annotations = claim.metadata?.annotations || {};
  const operation = optionalString(annotations['opensphere.io/last-operation'] || '');
  const operationAt = optionalString(annotations['opensphere.io/last-operation-at'] || '');
  return {
    id: shortHash(`${context.namespace}/${context.promotionRef}/${context.decision}/${context.generation}`),
    recordedAt: context.recordedAt,
    namespace: context.namespace,
    promotionRef: context.promotionRef,
    modelName: context.modelName,
    version: context.version,
    stage: context.stage,
    decision: context.decision,
    approved: context.approved,
    evaluationRef: context.evaluationRef,
    evaluationPhase: context.evaluationPhase,
    generation: context.generation,
    operation: operation || context.decision,
    operationAt: operationAt || context.recordedAt,
    actor: optionalString(annotations['opensphere.io/last-actor'] || 'opensphere-controller'),
    backendMode: context.backendMode,
    backendPhase: context.backendPhase,
  };
}

function appendUniqueById(items, next, limit = 200) {
  if (!next) return (items || []).slice(-limit);
  return [...(items || []).filter((item) => item.id !== next.id), next].slice(-limit);
}

function mergeMetrics(items, next, limit = 500) {
  const map = new Map((items || []).map((item) => [item.id, item]));
  for (const item of next || []) map.set(item.id, item);
  return [...map.values()].slice(-limit);
}

async function modelRegistryBackend(namespace = 'opensphere-system', spec = {}) {
  let backend = await selectBackend('model-registry', spec);
  const info = await modelRegistryInfo(namespace, spec);
  if (backend.mode === 'upstream' && !info.ready) {
    if (backend.requested === 'upstream') {
      backend = {
        ...backend,
        mode: 'missing',
        phase: 'Unavailable',
        ready: false,
        message: `Upstream backend requested but missing: ${info.name ? `ModelRegistry/${info.namespace}/${info.name}` : 'modelregistries.modelregistry.opendatahub.io instance'}`,
      };
    } else if (backend.fallbackReady) {
      backend = {
        ...backend,
        mode: 'opensphere',
        phase: 'FallbackReady',
        ready: true,
        message: 'ModelRegistry CRD exists but no ready ModelRegistry instance was found; using OpenSphere fallback registry.',
      };
    }
  }
  return { backend, info, source: modelRegistrySource(backend, info) };
}

async function modelVersions(reqUrl = '') {
  const params = new URL(reqUrl || '/', 'http://local').searchParams;
  const namespace = params.get('namespace') || 'opensphere-system';
  const backendType = params.get('backend') || params.get('backendType') || 'auto';
  const registry = await modelRegistryState({ namespace, spec: { backend: backendType } });
  return {
    backend: registry.backend,
    source: registry.source,
    upstreamItems: registry.upstreamItems || [],
    upstream: registry.upstream || null,
    promotions: registry.promotions || [],
    approvalAudit: registry.approvalAudit || [],
    evaluationMetrics: registry.evaluationMetrics || [],
    items: registry.versions,
  };
}

async function modelRegistryUpstream(reqUrl = '') {
  const params = new URL(reqUrl || '/', 'http://local').searchParams;
  const namespace = params.get('namespace') || 'opensphere-system';
  const backendType = params.get('backend') || params.get('backendType') || 'auto';
  const registry = await modelRegistryState({ namespace, spec: { backend: backendType } });
  const upstream = registry.upstream || await upstreamModelRegistryResources(registry.source);
  return {
    backend: registry.backend,
    info: registry.info,
    source: registry.source,
    upstream,
    summary: {
      phase: registry.backend?.phase || 'Unknown',
      mode: registry.backend?.mode || registry.source?.type || '',
      ready: registry.backend?.ready === true,
      resourcesReady: upstream.resources?.filter((item) => item.ready).length || 0,
      resourcesTotal: upstream.resources?.length || 0,
      versions: registry.versions?.length || 0,
      upstreamVersions: upstream.versions?.length || 0,
      artifacts: upstream.artifacts?.length || 0,
    },
  };
}

async function modelRegistryWriteSelfTest(req) {
  const body = JSON.parse((await readBody(req)).toString('utf8') || '{}');
  const namespace = optionalString(body.namespace || 'opensphere-system') || 'opensphere-system';
  const registryBackend = await modelRegistryBackend(namespace, { ...body, backend: body.backend || body.backendType || 'modelregistry' });
  const endpoint = optionalString(body.endpoint || body.restUrl || registryBackend.source.endpoint);
  const source = endpoint
    ? {
      type: 'odh-model-registry',
      name: optionalString(body.registry || body.name || registryBackend.source.name || 'model-registry') || 'model-registry',
      namespace: optionalString(body.registryNamespace || registryBackend.source.namespace || namespace) || namespace,
      endpoint,
      apiVersion: registryBackend.source.apiVersion || 'modelregistry.opendatahub.io/v1alpha1',
    }
    : registryBackend.source;
  const now = Date.now().toString(36);
  const version = {
    name: dnsLabel(body.modelName || `opensphere-selftest-${now}`),
    version: optionalString(body.version || `selftest-${now}`),
    stage: optionalString(body.stage || 'validation'),
    source: optionalString(body.source || 'opensphere-upstream-write-self-test'),
    artifactUri: optionalString(body.artifactUri || body.uri || `oci://opensphere/selftest:${now}`),
    promotionRef: 'upstream-write-self-test',
    evaluationRef: 'upstream-write-self-test',
  };
  if (source.type !== 'odh-model-registry' || !source.endpoint) {
    return {
      attempted: false,
      synced: false,
      backend: registryBackend.backend,
      source,
      version,
      message: 'No upstream Model Registry endpoint is available for write self-test.',
    };
  }
  const upstreamSync = await mirrorModelVersionToUpstream(source, version);
  return {
    attempted: true,
    synced: upstreamSync.synced === true,
    backend: { ...registryBackend.backend, mode: 'upstream', phase: upstreamSync.synced ? 'UpstreamWriteReady' : 'UpstreamWriteDegraded', ready: upstreamSync.synced === true },
    source,
    version,
    upstreamSync,
    message: upstreamSync.message || (upstreamSync.synced ? 'Model Registry upstream write self-test succeeded.' : 'Model Registry upstream write self-test failed.'),
  };
}

async function modelRegistryState(options = {}) {
  const registryBackend = options.source ? { backend: options.backend || null, source: options.source, upstreamItems: [] } : await modelRegistryBackend(options.namespace || 'opensphere-system', options.spec || {});
  const cm = await k8sJson('/api/v1/namespaces/opensphere-system/configmaps/ai-model-registry-versions');
  const upstream = await upstreamModelRegistryResources(registryBackend.source);
  const upstreamItems = upstream.versions || [];
  if (!cm?.data?.versions) {
    const fallbackVersions = FALLBACK_DETAILS.modelVersions.map((item) => ({ ...item, backend: registryBackend.source.type, registry: `${registryBackend.source.namespace}/${registryBackend.source.name}` }));
    return { ...registryBackend, upstream, versions: upstreamItems.length ? upstreamItems : fallbackVersions, upstreamItems, promotions: [], approvalAudit: [], evaluationMetrics: [] };
  }
  try {
    const versions = parseJsonArray(cm.data.versions).map((item) => ({
      ...item,
      backend: item.backend || registryBackend.source.type,
      registry: item.registry || `${registryBackend.source.namespace}/${registryBackend.source.name}`,
    }));
    return {
      ...registryBackend,
      upstream,
      versions: upstreamItems.length ? mergeModelVersions(versions, upstreamItems) : versions,
      upstreamItems,
      promotions: parseJsonArray(cm.data.promotions),
      approvalAudit: parseJsonArray(cm.data.approvalAudit),
      evaluationMetrics: parseJsonArray(cm.data.evaluationMetrics),
    };
  } catch {
    return { ...registryBackend, upstream, versions: upstreamItems.length ? upstreamItems : FALLBACK_DETAILS.modelVersions, upstreamItems, promotions: [], approvalAudit: [], evaluationMetrics: [] };
  }
}

function mergeModelVersions(localItems, upstreamItems) {
  const key = (item) => `${item.name}:${item.version}`;
  const map = new Map(localItems.map((item) => [key(item), item]));
  for (const item of upstreamItems) map.set(key(item), { ...map.get(key(item)), ...item, backend: item.backend || 'odh-model-registry' });
  return [...map.values()];
}

async function saveModelRegistryState(state, req, source) {
  const cm = {
    apiVersion: 'v1',
    kind: 'ConfigMap',
    metadata: {
      name: 'ai-model-registry-versions',
      namespace: 'opensphere-system',
      labels: { 'app.kubernetes.io/part-of': 'opensphere-ai' },
    },
    data: {
      versions: JSON.stringify(state.versions || []),
      promotions: JSON.stringify(state.promotions || []),
      approvalAudit: JSON.stringify(state.approvalAudit || []),
      evaluationMetrics: JSON.stringify(state.evaluationMetrics || []),
    },
  };
  try {
    await writeK8s('/api/v1/namespaces/opensphere-system/configmaps', 'POST', cm, req);
  } catch (e) {
    if (e.code !== 409) throw e;
    await patchK8s('/api/v1/namespaces/opensphere-system/configmaps/ai-model-registry-versions', { metadata: { labels: cm.metadata.labels }, data: cm.data }, req);
  }
  const latest = (state.versions || [])[state.versions.length - 1];
  const upstreamSync = latest ? await mirrorModelVersionToUpstream(source || { type: 'opensphere-configmap' }, latest) : { attempted: false, synced: false };
  return { cm, upstreamSync };
}

async function addModelVersion(req) {
  const body = JSON.parse((await readBody(req)).toString('utf8') || '{}');
  const registryBackend = await modelRegistryBackend('opensphere-system', body);
  if (!registryBackend.backend.ready && registryBackend.backend.requested === 'upstream') throw { code: 409, msg: registryBackend.backend.message };
  const next = {
    name: optionalString(body.name || 'model'),
    version: optionalString(body.version || '0.1.0'),
    stage: optionalString(body.stage || 'development'),
    source: optionalString(body.source || body.sourceRef || 'manual-registration'),
    backend: registryBackend.source.type,
    registry: `${registryBackend.source.namespace}/${registryBackend.source.name}`,
  };
  const current = await modelRegistryState({ source: registryBackend.source, backend: registryBackend.backend });
  const items = [...current.versions.filter((item) => !(item.name === next.name && item.version === next.version)), next];
  const saved = await saveModelRegistryState({ ...current, versions: items }, req, registryBackend.source);
  return { backend: registryBackend.backend, source: registryBackend.source, upstreamSync: saved.upstreamSync, items, registered: next };
}

async function patchPromotionStatus(claim, status) {
  const namespace = claim.metadata?.namespace || 'default';
  const name = claim.metadata?.name;
  if (!name) return;
  try {
    await patchK8s(`/apis/ai.opensphere.io/v1alpha1/namespaces/${namespace}/modelpromotionclaims/${name}/status`, { status }, null);
  } catch (e) {
    await patchK8s(`/apis/ai.opensphere.io/v1alpha1/namespaces/${namespace}/modelpromotionclaims/${name}`, {
      metadata: {
        annotations: {
          'opensphere.io/reconcile-phase': status.phase,
          'opensphere.io/promoted-stage': status.stage || '',
        },
      },
    }, null).catch(() => null);
  }
  await recordReconcileEvent(claim, status, 'ModelPromotionReconciled');
}

async function patchEvaluationJobStatus(job, status) {
  const namespace = job.metadata?.namespace || 'default';
  const name = job.metadata?.name;
  if (!name) return;
  try {
    await patchK8s(`/apis/eval.ai.opensphere.io/v1alpha1/namespaces/${namespace}/evaluationjobs/${name}/status`, { status }, null);
  } catch (e) {
    await patchK8s(`/apis/eval.ai.opensphere.io/v1alpha1/namespaces/${namespace}/evaluationjobs/${name}`, {
      metadata: {
        annotations: {
          'opensphere.io/reconcile-phase': status.phase,
          'opensphere.io/evaluation-passed': String(status.passed === true),
        },
      },
    }, null).catch(() => null);
  }
  await recordReconcileEvent(job, status, 'EvaluationJobReconciled');
}

async function evaluationPolicyState(refObj, namespace) {
  const name = refObj?.name;
  if (!name) return { found: false, gates: [] };
  const ns = refObj.namespace || namespace || 'default';
  const policy = await k8sJson(`/apis/eval.ai.opensphere.io/v1alpha1/namespaces/${ns}/evaluationpolicies/${name}`);
  if (!policy) return { found: false, gates: [] };
  return { found: true, policy, gates: Array.isArray(policy.spec?.gates) ? policy.spec.gates : [] };
}

function evaluationMetricInputs(job, policy) {
  const spec = job.spec || {};
  const rawMetrics = spec.metrics || spec.results || spec.scores || spec.summary?.metrics;
  const metrics = normalizeEvaluationMetricItems(rawMetrics)
    .filter((item) => item.metric && item.value !== undefined);
  if (metrics.length) return metrics;
  const values = spec.values || spec.scores || {};
  const gates = Array.isArray(policy.gates) ? policy.gates : [];
  return gates.map((gate) => {
    const metric = optionalString(gate.metric || gate.name || 'metric');
    const threshold = metricNumber(gate.minimum ?? gate.threshold ?? gate.min);
    const value = metricNumber(values?.[metric] ?? spec.score ?? spec.value ?? threshold);
    return {
      metric,
      value,
      threshold,
      passed: value === undefined || threshold === undefined ? undefined : value >= threshold,
      source: 'evaluation-policy',
    };
  }).filter((item) => item.metric && item.value !== undefined);
}

function normalizedEvaluationMetrics(job, policy, now) {
  const namespace = job.metadata?.namespace || 'default';
  const name = job.metadata?.name || 'evaluation-job';
  return evaluationMetricInputs(job, policy).map((item) => ({
    id: shortHash(`${namespace}/${name}/${item.metric}`),
    metric: item.metric,
    value: item.value,
    threshold: item.threshold,
    passed: item.passed === undefined
      ? item.threshold === undefined || item.value >= item.threshold
      : item.passed,
    source: item.source || optionalString(job.spec?.provider || job.spec?.metricProvider || 'opensphere-batch-evaluator'),
    evaluatedAt: now,
  }));
}

async function reconcileEvaluationJob(job) {
  const namespace = job.metadata?.namespace || 'default';
  const name = job.metadata?.name || 'evaluation-job';
  const spec = job.spec || {};
  if (pendingRetryMs(job) > 0) return retryingResult(job, name);
  const now = new Date().toISOString();
  const policy = await evaluationPolicyState(spec.policyRef, namespace);
  const metrics = normalizedEvaluationMetrics(job, policy, now);
  const failed = metrics.filter((metric) => metric.passed === false);
  const passed = metrics.length ? failed.length === 0 : spec.passed === true || ['passed', 'succeeded', 'ready'].includes(optionalString(spec.phase).toLowerCase());
  const suspended = spec.suspended === true;
  const phase = suspended ? 'Suspended' : passed ? 'Passed' : metrics.length ? 'Failed' : 'Pending';
  const status = {
    ...normalizedStatus({
      phase,
      ready: phase === 'Passed' || phase === 'Failed',
      reason: suspended ? 'EvaluationSuspended' : passed ? 'EvaluationPassed' : metrics.length ? 'EvaluationFailed' : 'WaitingForMetrics',
      message: metrics.length
        ? `${metrics.length} evaluation metric(s) processed; ${failed.length} failed.`
        : 'Evaluation job is waiting for metric provider results.',
      conditions: metrics.map((metric) => ({
        type: `Metric${metric.metric}`,
        status: metric.passed ? 'True' : 'False',
        reason: metric.passed ? 'MetricPassed' : 'MetricFailed',
        message: `${metric.metric}=${metric.value}${metric.threshold === undefined ? '' : ` threshold=${metric.threshold}`}`,
      })),
    }),
    passed,
    metrics,
    metricProvider: optionalString(spec.provider || spec.metricProvider || 'opensphere-batch-evaluator'),
    policyRef: spec.policyRef?.name || '',
    policyFound: policy.found === true,
    targetRef: spec.targetRef || null,
    promotionRef: spec.promotionRef || null,
    observedGeneration: job.metadata?.generation || 0,
    lastEvaluatedAt: now,
  };
  await patchEvaluationJobStatus(job, resetRetryFields(status));
  if (spec.promotionRef?.name && !suspended) {
    const promotionNamespace = spec.promotionRef.namespace || namespace;
    const promotion = await k8sJson(`/apis/ai.opensphere.io/v1alpha1/namespaces/${promotionNamespace}/modelpromotionclaims/${spec.promotionRef.name}`);
    if (promotion) await reconcileModelPromotionClaim(promotion).catch(() => null);
  }
  return { name, namespace, phase, metrics: metrics.length, failed: failed.length, promotionRef: spec.promotionRef?.name || '' };
}

async function evaluationState(refObj, namespace) {
  const name = refObj?.name;
  if (!name) return { found: false, passed: false, phase: 'MissingEvaluation' };
  const ns = refObj.namespace || namespace || 'default';
  const job = await k8sJson(`/apis/eval.ai.opensphere.io/v1alpha1/namespaces/${ns}/evaluationjobs/${name}`);
  if (!job) return { found: false, passed: false, phase: 'MissingEvaluation' };
  const phase = job.status?.phase || job.spec?.phase || '';
  const ready = job.status?.ready === true || (job.status?.conditions || []).some((condition) => condition.type === 'Ready' && condition.status === 'True');
  const passed = job.status?.passed === true || ['passed', 'succeeded', 'ready'].includes(String(phase).toLowerCase()) || ready;
  return { found: true, passed, phase: phase || (passed ? 'Passed' : 'Pending'), job };
}

async function reconcileModelPromotionClaim(claim) {
  const namespace = claim.metadata?.namespace || 'default';
  const spec = claim.spec || {};
  const name = claim.metadata?.name || 'promotion';
  if (pendingRetryMs(claim) > 0) return retryingResult(claim, name);
  const modelName = spec.modelRef?.name || spec.modelName || spec.model || name;
  const version = optionalString(spec.version || spec.modelVersion || name) || name;
  const stage = optionalString(spec.stage || 'production') || 'production';
  const registryBackend = await modelRegistryBackend(namespace, spec);
  const evaluation = await evaluationState(spec.evaluationRef, namespace);
  const approved = spec.approved === true;
  const rejected = spec.approved === false || stage === 'rejected';
  const canPromote = !rejected && (approved || evaluation.passed);
  const now = new Date().toISOString();
  const baseStatus = {
    modelName,
    version,
    stage,
    approved,
    evaluationRef: spec.evaluationRef?.name || '',
    evaluationPhase: evaluation.phase,
    evaluationPassed: evaluation.passed === true,
    backendMode: registryBackend.backend.mode,
    backendRequested: registryBackend.backend.requested,
    backendPhase: registryBackend.backend.phase,
    backendMessage: registryBackend.backend.message,
    registrySource: registryBackend.source,
    backendResource: registryBackend.source.type === 'odh-model-registry'
      ? `${registryBackend.source.apiVersion}/ModelRegistry/${registryBackend.source.namespace}/${registryBackend.source.name}`
      : `v1/ConfigMap/${registryBackend.source.namespace}/${registryBackend.source.name}`,
    observedGeneration: claim.metadata?.generation || 0,
    lastReconciledAt: now,
  };

  if (!registryBackend.backend.ready && registryBackend.backend.requested === 'upstream') {
    const status = retryStatus(claim, baseStatus, { msg: registryBackend.backend.message });
    status.promotedAt = null;
    status.registryConfigMap = null;
    status.upstreamSync = null;
    status.approvalDecision = 'Blocked';
    await patchPromotionStatus(claim, status);
    return { name, namespace, modelName, version, stage, phase: 'Retrying', error: registryBackend.backend.message, nextRetryAt: status.nextRetryAt };
  }

  if (rejected) {
    const registry = await modelRegistryState({ source: registryBackend.source, backend: registryBackend.backend });
    const auditRecord = promotionAuditRecord(claim, {
      namespace,
      promotionRef: name,
      modelName,
      version,
      stage,
      decision: 'Rejected',
      approved: false,
      evaluationRef: spec.evaluationRef?.name || '',
      evaluationPhase: evaluation.phase,
      generation: claim.metadata?.generation || 0,
      recordedAt: now,
      backendMode: registryBackend.backend.mode,
      backendPhase: registryBackend.backend.phase,
    });
    await saveModelRegistryState({
      ...registry,
      approvalAudit: appendUniqueById(registry.approvalAudit, auditRecord),
    }, null, registryBackend.source);
    const status = {
      ...baseStatus,
      ...normalizedStatus({
        phase: 'Rejected',
        ready: false,
        reason: 'PromotionRejected',
        message: 'Promotion was rejected.',
        upstreamConditions: registryBackend.info.conditions,
      }),
    };
    status.promotedAt = null;
    status.registryConfigMap = null;
    status.upstreamSync = null;
    status.approvalDecision = 'Rejected';
    status.approvalAuditRef = auditRecord.id;
    await patchPromotionStatus(claim, resetRetryFields(status));
    return { name, namespace, modelName, version, stage, phase: 'Rejected' };
  }

  if (!canPromote) {
    const status = {
      ...baseStatus,
      ...normalizedStatus({
        phase: evaluation.found ? 'WaitingEval' : 'WaitingApproval',
        ready: false,
        reason: evaluation.found ? 'EvaluationPending' : 'ApprovalOrEvaluationRequired',
        message: evaluation.found ? `Evaluation is ${evaluation.phase}.` : 'Promotion needs an approval or a passing evaluation job.',
        upstreamConditions: registryBackend.info.conditions,
      }),
    };
    status.promotedAt = null;
    status.registryConfigMap = null;
    status.upstreamSync = null;
    status.approvalDecision = evaluation.found ? 'WaitingEvaluation' : 'WaitingApproval';
    await patchPromotionStatus(claim, resetRetryFields(status));
    return { name, namespace, modelName, version, stage, phase: status.phase };
  }

  const registry = await modelRegistryState({ source: registryBackend.source, backend: registryBackend.backend });
  const evaluationRefName = spec.evaluationRef?.name || '';
  const metricRecords = evaluationMetricsFor(evaluation, {
    namespace,
    promotionRef: name,
    modelName,
    version,
    stage,
    evaluationRef: evaluationRefName,
    recordedAt: now,
  });
  const auditRecord = promotionAuditRecord(claim, {
    namespace,
    promotionRef: name,
    modelName,
    version,
    stage,
    decision: approved ? 'Approved' : 'EvaluationPassed',
    approved,
    evaluationRef: evaluationRefName,
    evaluationPhase: evaluation.phase,
    generation: claim.metadata?.generation || 0,
    recordedAt: now,
    backendMode: registryBackend.backend.mode,
    backendPhase: registryBackend.backend.phase,
  });
  const versionRecord = {
    name: modelName,
    version,
    stage,
    source: spec.modelRef?.name || spec.source || 'promotion',
    promotionRef: name,
    namespace,
    promotedAt: now,
    evaluationRef: evaluationRefName,
    evaluationPhase: evaluation.phase,
    evaluationPassed: evaluation.passed === true,
    metricCount: metricRecords.length,
    approvalDecision: auditRecord.decision,
    backend: registryBackend.source.type,
    registry: `${registryBackend.source.namespace}/${registryBackend.source.name}`,
  };
  const versions = [
    ...registry.versions.filter((item) => !(item.name === modelName && item.version === version)),
    versionRecord,
  ];
  const promotionRecord = {
    name,
    namespace,
    modelName,
    version,
    stage,
    approved,
    approvalDecision: auditRecord.decision,
    evaluationRef: evaluationRefName,
    evaluationPhase: evaluation.phase,
    evaluationPassed: evaluation.passed === true,
    metricCount: metricRecords.length,
    approvalAuditRef: auditRecord.id,
    promotedAt: now,
  };
  const promotions = [
    ...registry.promotions.filter((item) => !(item.name === name && item.namespace === namespace)),
    promotionRecord,
  ];
  const saved = await saveModelRegistryState({
    ...registry,
    versions,
    promotions,
    approvalAudit: appendUniqueById(registry.approvalAudit, auditRecord),
    evaluationMetrics: mergeMetrics(registry.evaluationMetrics, metricRecords),
  }, null, registryBackend.source);
  const status = {
    ...baseStatus,
    ...normalizedStatus({
      phase: 'Promoted',
      ready: true,
      reason: approved ? 'Approved' : 'EvaluationPassed',
      message: `Model ${modelName}:${version} promoted to ${stage}.`,
      upstreamConditions: registryBackend.info.conditions,
    }),
    promotedAt: now,
    registryConfigMap: 'opensphere-system/ai-model-registry-versions',
    upstreamSync: saved.upstreamSync,
    approvalDecision: auditRecord.decision,
    approvalAuditRef: auditRecord.id,
    evaluationMetricCount: metricRecords.length,
    evaluationMetrics: metricRecords.slice(0, 20),
  };
  await patchPromotionStatus(claim, resetRetryFields(status));
  return { name, namespace, modelName, version, stage, phase: 'Promoted' };
}

let _promotionReconciling = false;
async function reconcileModelPromotions() {
  if (_promotionReconciling) return { skipped: true, reason: 'already running' };
  _promotionReconciling = true;
  try {
    if (!(await crdInstalled('modelpromotionclaims.ai.opensphere.io'))) return { reconciled: 0, items: [] };
    const list = await k8sJson('/apis/ai.opensphere.io/v1alpha1/modelpromotionclaims');
    const items = list?.items || [];
    const results = [];
    for (const claim of items) {
      results.push(await reconcileClaimWithMetrics('model-promotions', claim, reconcileModelPromotionClaim));
    }
    return { reconciled: results.length, items: results };
  } finally {
    _promotionReconciling = false;
  }
}

let _evaluationReconciling = false;
async function reconcileEvaluationJobs() {
  if (_evaluationReconciling) return { skipped: true, reason: 'already running' };
  _evaluationReconciling = true;
  try {
    if (!(await crdInstalled('evaluationjobs.eval.ai.opensphere.io'))) return { reconciled: 0, items: [] };
    const list = await k8sJson('/apis/eval.ai.opensphere.io/v1alpha1/evaluationjobs');
    const items = list?.items || [];
    const results = [];
    for (const job of items) {
      results.push(await reconcileClaimWithMetrics('evaluations', job, reconcileEvaluationJob));
    }
    return { reconciled: results.length, items: results };
  } finally {
    _evaluationReconciling = false;
  }
}

async function odhComponents() {
  const dsc = await k8sJson('/apis/datasciencecluster.opendatahub.io/v1/datascienceclusters');
  if (!dsc?.items?.length) return { items: FALLBACK_DETAILS.odhComponents, reference: true };
  const item = dsc.items[0];
  const spec = item.spec?.components || {};
  return {
    items: Object.keys(spec).map((name) => ({
      name,
      kind: 'ODHComponent',
      namespace: item.metadata?.namespace || 'opensphere-system',
      phase: spec[name]?.managementState || 'Managed',
      ready: spec[name]?.managementState !== 'Removed',
    })),
  };
}

async function odhComponentOperation(req) {
  const body = JSON.parse((await readBody(req)).toString('utf8') || '{}');
  const name = optionalString(body.name || body.component);
  const action = String(body.action || 'enable').toLowerCase();
  if (!name) throw { code: 400, msg: 'component name is required' };
  if (!['enable', 'disable', 'upgrade'].includes(action)) throw { code: 400, msg: 'action must be enable, disable, or upgrade' };
  const dsc = await k8sJson('/apis/datasciencecluster.opendatahub.io/v1/datascienceclusters');
  if (!dsc?.items?.length) return { component: name, action, phase: action === 'disable' ? 'Removed' : 'Managed', reference: true };
  const target = dsc.items[0];
  const namespace = target.metadata?.namespace || 'opensphere-system';
  const dscName = target.metadata?.name;
  const patch = { spec: { components: { [name]: { managementState: action === 'disable' ? 'Removed' : 'Managed' } } } };
  if (action === 'upgrade') patch.metadata = { annotations: { 'opensphere.io/upgrade-requested-at': new Date().toISOString() } };
  const raw = await tryPatch([
    `/apis/datasciencecluster.opendatahub.io/v1/namespaces/${namespace}/datascienceclusters/${dscName}`,
    `/apis/datasciencecluster.opendatahub.io/v1/datascienceclusters/${dscName}`,
  ], patch, req);
  return { component: name, action, raw };
}

function nativeComponentVersionName(component) {
  return `${component.name}.v${component.version.replace(/[^a-z0-9]+/g, '-')}`;
}

function componentByName(name) {
  const componentName = requireDnsName(name, 'component');
  const component = NATIVE_COMPONENTS.find((item) => item.name === componentName);
  if (!component) throw { code: 400, msg: `unknown component: ${componentName}` };
  return component;
}

function installPlanName(componentName) {
  return `${componentName}-install`;
}

function bumpPatchVersion(version) {
  const parts = String(version || '0.1.0').split('.').map((part) => Number.parseInt(part, 10));
  const major = Number.isFinite(parts[0]) ? parts[0] : 0;
  const minor = Number.isFinite(parts[1]) ? parts[1] : 1;
  const patch = Number.isFinite(parts[2]) ? parts[2] + 1 : 1;
  return `${major}.${minor}.${patch}`;
}

function installPlanPhase(approved) {
  return approved ? 'Complete' : 'RequiresApproval';
}

function nativeInstallPlan(component, options = {}) {
  const operation = options.operation || 'Install';
  const targetVersion = optionalString(options.version || component.version) || component.version;
  const previousVersion = optionalString(options.previousVersion || '') || '';
  const rollbackVersion = optionalString(options.rollbackVersion || previousVersion || component.version) || component.version;
  const approved = options.approved === true;
  const phase = installPlanPhase(approved);
  const now = new Date().toISOString();
  return {
    apiVersion: 'ai.opensphere.io/v1alpha1',
    kind: 'OpenSphereInstallPlan',
    metadata: {
      name: installPlanName(component.name),
      namespace: 'opensphere-system',
      annotations: {
        'opensphere.io/operation': operation,
        'opensphere.io/target-version': targetVersion,
        'opensphere.io/requested-at': now,
      },
    },
    spec: {
      component: component.name,
      operation,
      version: targetVersion,
      previousVersion,
      rollbackVersion,
      subscriptionRef: { name: component.name },
      approved,
      phase,
      steps: operation === 'Rollback'
        ? ['snapshot-current-state', 'restore-previous-version', 'run-rollback-hooks', 'verify']
        : ['snapshot-current-state', 'apply-crds', 'run-migrations', 'apply-rbac', 'apply-controller-config', 'verify'],
    },
    status: {
      phase,
      operation,
      installedVersion: approved ? targetVersion : previousVersion,
      targetVersion,
      previousVersion,
      rollbackVersion,
      lastTransitionTime: now,
      conditions: [{
        type: 'Ready',
        status: approved ? 'True' : 'False',
        reason: approved ? `${operation}Complete` : `${operation}RequiresApproval`,
        message: approved
          ? `${component.displayName} ${operation.toLowerCase()} completed at ${targetVersion}.`
          : `${component.displayName} ${operation.toLowerCase()} to ${targetVersion} is waiting for approval.`,
        lastTransitionTime: now,
      }],
    },
  };
}

async function applyNativeInstallPlan(component, plan, req) {
  await writeK8s('/apis/ai.opensphere.io/v1alpha1/namespaces/opensphere-system/opensphereinstallplans', 'POST', plan, req).catch(async (e) => {
    if (e.code !== 409) throw e;
    await patchK8s(`/apis/ai.opensphere.io/v1alpha1/namespaces/opensphere-system/opensphereinstallplans/${installPlanName(component.name)}`, {
      metadata: { annotations: plan.metadata.annotations },
      spec: plan.spec,
      status: plan.status,
    }, req);
  });
}

function nativeComponentVersion(component) {
  return {
    apiVersion: 'ai.opensphere.io/v1alpha1',
    kind: 'OpenSphereComponentVersion',
    metadata: {
      name: nativeComponentVersionName(component),
      namespace: 'opensphere-system',
      labels: {
        'app.kubernetes.io/part-of': 'opensphere-ai',
        'ai.opensphere.io/component': component.name,
        'ai.opensphere.io/channel': component.channel,
      },
    },
    spec: {
      component: component.name,
      displayName: component.displayName,
      version: component.version,
      channel: component.channel,
      description: component.description,
      upstream: component.upstream,
      installer: {
        type: 'opensphere-native',
        sourceRef: `catalog://opensphere-ai/${component.name}/${component.version}`,
      },
    },
  };
}

function learningResourceName(resource) {
  return (resource.title || resource.name || 'learning-resource')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 63) || 'learning-resource';
}

function learningResourceItem(resource) {
  return {
    name: learningResourceName(resource),
    kind: 'OpenSphereLearningResource',
    namespace: 'opensphere-system',
    phase: 'Available',
    ready: true,
    description: resource.description || '',
    source: 'native',
    reference: false,
    title: resource.title || resource.name || '',
    provider: resource.provider || 'OpenSphere',
    type: resource.type || 'Documentation',
    duration: resource.duration || 'Reference',
    href: resource.href || '#',
  };
}

async function saveNativeLearningResources(req) {
  const cm = {
    apiVersion: 'v1',
    kind: 'ConfigMap',
    metadata: {
      name: LEARNING_RESOURCE_CONFIGMAP,
      namespace: 'opensphere-system',
      labels: {
        'app.kubernetes.io/part-of': 'opensphere-ai',
        'ai.opensphere.io/learning-catalog': 'true',
      },
    },
    data: {
      resources: JSON.stringify(LEARNING_RESOURCES, null, 2),
    },
  };
  await writeK8s('/api/v1/namespaces/opensphere-system/configmaps', 'POST', cm, req).catch(async (e) => {
    if (e.code !== 409) throw e;
    await patchK8s(`/api/v1/namespaces/opensphere-system/configmaps/${LEARNING_RESOURCE_CONFIGMAP}`, { metadata: { labels: cm.metadata.labels }, data: cm.data }, req);
  });
  return cm;
}

async function nativeLearningResourceRecords() {
  const cm = await k8sJson(`/api/v1/namespaces/opensphere-system/configmaps/${LEARNING_RESOURCE_CONFIGMAP}`);
  const resources = parseJsonArray(cm?.data?.resources);
  return resources.length ? resources : [];
}

async function nativeLearningResources() {
  const resources = await nativeLearningResourceRecords();
  return resources.map((resource) => learningResourceItem(resource));
}

async function seedNativeCatalog(req) {
  const catalog = {
    apiVersion: 'ai.opensphere.io/v1alpha1',
    kind: 'OpenSphereComponentCatalog',
    metadata: { name: 'opensphere-ai-default', namespace: 'opensphere-system' },
    spec: {
      sourceType: 'embedded',
      sourceRef: 'opensphere-shell-ai/server.js',
      pollInterval: '10m',
      components: NATIVE_COMPONENTS.map((component) => component.name),
    },
  };
  await writeK8s('/api/v1/namespaces', 'POST', { apiVersion: 'v1', kind: 'Namespace', metadata: { name: 'opensphere-system' } }, req).catch((e) => {
    if (e.code !== 409) throw e;
  });
  await writeK8s('/apis/ai.opensphere.io/v1alpha1/namespaces/opensphere-system/openspherecomponentcatalogs', 'POST', catalog, req).catch(async (e) => {
    if (e.code !== 409) throw e;
    await patchK8s('/apis/ai.opensphere.io/v1alpha1/namespaces/opensphere-system/openspherecomponentcatalogs/opensphere-ai-default', { spec: catalog.spec }, req);
  });
  for (const component of NATIVE_COMPONENTS) {
    const version = nativeComponentVersion(component);
    await writeK8s('/apis/ai.opensphere.io/v1alpha1/namespaces/opensphere-system/openspherecomponentversions', 'POST', version, req).catch(async (e) => {
      if (e.code !== 409) throw e;
      await patchK8s(`/apis/ai.opensphere.io/v1alpha1/namespaces/opensphere-system/openspherecomponentversions/${version.metadata.name}`, { spec: version.spec, metadata: { labels: version.metadata.labels } }, req);
    });
  }
  await saveNativeLearningResources(req);
}

async function nativeCatalog() {
  const [subscriptions, installPlans, dscs] = await Promise.all([
    k8sJson('/apis/ai.opensphere.io/v1alpha1/namespaces/opensphere-system/openspheresubscriptions'),
    k8sJson('/apis/ai.opensphere.io/v1alpha1/namespaces/opensphere-system/opensphereinstallplans'),
    k8sJson('/apis/ai.opensphere.io/v1alpha1/namespaces/opensphere-system/openspheredatascienceclusters'),
  ]);
  const subs = subscriptions?.items || [];
  const plans = installPlans?.items || [];
  const dsc = (dscs?.items || [])[0];
  const components = NATIVE_COMPONENTS.map((component) => {
    const sub = subs.find((item) => item.spec?.component === component.name);
    const plan = plans.find((item) => item.spec?.component === component.name);
    const state = dsc?.spec?.components?.[component.name]?.managementState || (sub ? 'Managed' : 'Available');
    const phase = plan?.status?.phase || plan?.spec?.phase || (sub ? 'Installed' : 'Available');
    return {
      ...component,
      subscribed: !!sub,
      installed: !!plan?.spec?.approved || !!sub,
      phase,
      operation: plan?.status?.operation || plan?.spec?.operation || '',
      installedVersion: plan?.status?.installedVersion || sub?.spec?.version || '',
      targetVersion: plan?.status?.targetVersion || plan?.spec?.version || component.version,
      previousVersion: plan?.status?.previousVersion || plan?.spec?.previousVersion || '',
      rollbackVersion: plan?.status?.rollbackVersion || plan?.spec?.rollbackVersion || '',
      lastTransitionTime: plan?.status?.lastTransitionTime || '',
      managementState: state,
      subscription: sub ? itemFromK8s(sub, 'OpenSphereSubscription') : null,
      installPlan: plan ? itemFromK8s(plan, 'OpenSphereInstallPlan') : null,
    };
  });
  return {
    components,
    subscriptions: subs.map((item) => itemFromK8s(item, 'OpenSphereSubscription')),
    installPlans: plans.map((item) => itemFromK8s(item, 'OpenSphereInstallPlan')),
    dataScienceClusters: (dscs?.items || []).map((item) => itemFromK8s(item, 'OpenSphereDataScienceCluster')),
  };
}

const FALLBACK_BACKEND_CRDS = {
  'odh-platform': ['openspheredatascienceclusters.ai.opensphere.io'],
  workbenches: ['workbenchclaims.ai.opensphere.io'],
  pipelines: ['pipelinerunclaims.ai.opensphere.io'],
  'model-serving': ['inferenceclaims.ai.opensphere.io'],
  'model-registry': ['modelpromotionclaims.ai.opensphere.io'],
  monitoring: ['monitoringtargets.ai.opensphere.io'],
  'distributed-workloads': ['distributedworkloadclaims.ai.opensphere.io'],
};

async function backendCapability(def) {
  const [crds, apiGroups, fallbackChecks] = await Promise.all([
    Promise.all(def.crds.map(async (crd) => ({
      ...crd,
      installed: await crdInstalled(crd.name),
    }))),
    Promise.all((def.apiGroups || []).map(async (group) => ({
      group,
      available: !!(await k8sJson(`/apis/${group}`)),
    }))),
    Promise.all((FALLBACK_BACKEND_CRDS[def.id] || []).map((name) => crdInstalled(name))),
  ]);
  const required = crds.filter((crd) => !crd.optional);
  let requiredInstalled = required.length ? required.every((crd) => crd.installed) : crds.some((crd) => crd.installed);
  const anyUpstreamInstalled = crds.some((crd) => crd.installed) || apiGroups.some((api) => api.available);
  const fallbackReady = fallbackChecks.length ? fallbackChecks.every(Boolean) : false;
  if (def.id === 'pipelines') {
    const tektonReady = crds.some((crd) => crd.name === 'pipelineruns.tekton.dev' && crd.installed);
    const kfpReady = crds.some((crd) => crd.name.includes('datasciencepipelinesapplications') && crd.installed)
      || crds.some((crd) => crd.name.includes('pipelines.kubeflow.org') && crd.installed)
      || apiGroups.some((api) => ['pipelines.kubeflow.org', 'datasciencepipelinesapplications.opendatahub.io'].includes(api.group) && api.available);
    requiredInstalled = tektonReady || kfpReady;
  }
  const phase = requiredInstalled ? 'UpstreamReady' : anyUpstreamInstalled ? 'UpstreamPartial' : fallbackReady ? 'FallbackReady' : 'Unavailable';
  const mode = requiredInstalled ? 'upstream' : fallbackReady ? 'opensphere' : 'missing';
  const missing = def.id === 'pipelines' && !requiredInstalled
    ? ['pipelineruns.tekton.dev or datasciencepipelinesapplications.opendatahub.io']
    : required.filter((crd) => !crd.installed).map((crd) => crd.name);
  return {
    id: def.id,
    displayName: def.displayName,
    component: def.component,
    upstream: def.upstream,
    fallback: def.fallback,
    mode,
    phase,
    ready: requiredInstalled || fallbackReady,
    upstreamReady: requiredInstalled,
    fallbackReady,
    crds,
    apiGroups,
    missing,
    message: requiredInstalled
      ? `${def.displayName} can use upstream backend.`
      : fallbackReady
        ? `${def.displayName} is using OpenSphere fallback runtime.`
        : `${def.displayName} backend is not ready. Missing: ${missing.join(', ') || 'required APIs'}`,
  };
}

async function nativeBackends() {
  const items = await Promise.all(UPSTREAM_BACKENDS.map((def) => backendCapability(def)));
  const upstreamReady = items.filter((item) => item.upstreamReady).length;
  const fallbackReady = items.filter((item) => !item.upstreamReady && item.fallbackReady).length;
  const unavailable = items.filter((item) => !item.ready).length;
  return {
    summary: {
      upstreamReady,
      fallbackReady,
      unavailable,
      total: items.length,
      phase: unavailable ? 'Degraded' : upstreamReady ? 'HybridReady' : 'OpenSphereReady',
    },
    items,
  };
}

function requestedBackendMode(spec) {
  const raw = optionalString(spec?.backend || spec?.backendMode || spec?.backendType || 'auto').toLowerCase();
  if (['upstream', 'kserve', 'kueue', 'ray', 'tekton', 'kubeflow', 'kfp', 'kubeflow-pipelines', 'trustyai', 'prometheus', 'modelregistry', 'model-registry', 'registry'].includes(raw)) return 'upstream';
  if (['opensphere', 'native', 'fallback', 'kubernetes', 'internal'].includes(raw)) return 'opensphere';
  return 'auto';
}

function requestedBackendType(spec) {
  return optionalString(spec?.backend || spec?.backendMode || spec?.backendType || 'auto').toLowerCase() || 'auto';
}

async function selectBackend(componentId, spec) {
  const def = UPSTREAM_BACKENDS.find((item) => item.id === componentId || item.component === componentId);
  if (!def) return { componentId, requested: 'auto', mode: 'opensphere', phase: 'FallbackReady', ready: true, message: 'No upstream backend definition; using OpenSphere runtime.' };
  const capability = await backendCapability(def);
  const requested = requestedBackendMode(spec);
  const requestedType = requestedBackendType(spec);
  if (requested === 'upstream') {
    return {
      ...capability,
      requested,
      requestedType,
      mode: capability.upstreamReady ? 'upstream' : 'missing',
      phase: capability.upstreamReady ? 'UpstreamReady' : 'Unavailable',
      ready: capability.upstreamReady,
      message: capability.upstreamReady ? capability.message : `Upstream backend requested but missing: ${capability.missing.join(', ') || 'required APIs'}`,
    };
  }
  if (requested === 'opensphere') {
    return {
      ...capability,
      requested,
      requestedType,
      mode: capability.fallbackReady ? 'opensphere' : 'missing',
      phase: capability.fallbackReady ? 'FallbackReady' : 'Unavailable',
      ready: capability.fallbackReady,
      message: capability.fallbackReady ? `${capability.displayName} is pinned to OpenSphere fallback runtime.` : `${capability.displayName} fallback runtime is not available.`,
    };
  }
  return {
    ...capability,
    requested,
    requestedType,
    mode: capability.upstreamReady ? 'upstream' : capability.fallbackReady ? 'opensphere' : 'missing',
    phase: capability.upstreamReady ? 'UpstreamReady' : capability.fallbackReady ? 'FallbackReady' : 'Unavailable',
    ready: capability.upstreamReady || capability.fallbackReady,
    message: capability.upstreamReady ? capability.message : capability.fallbackReady ? `${capability.displayName} auto-selected OpenSphere fallback runtime.` : capability.message,
  };
}

async function nativeSubscribe(req) {
  const body = req._bodyOverride || JSON.parse((await readBody(req)).toString('utf8') || '{}');
  const component = componentByName(body.component);
  if (!(await crdInstalled('openspheresubscriptions.ai.opensphere.io'))) throw { code: 409, msg: 'OpenSphereSubscription CRD is not installed' };
  await seedNativeCatalog(req);
  const existingPlan = await k8sJson(`/apis/ai.opensphere.io/v1alpha1/namespaces/opensphere-system/opensphereinstallplans/${installPlanName(component.name)}`);
  const targetVersion = optionalString(body.version || component.version) || component.version;
  const subscription = {
    apiVersion: 'ai.opensphere.io/v1alpha1',
    kind: 'OpenSphereSubscription',
    metadata: { name: component.name, namespace: 'opensphere-system' },
    spec: {
      component: component.name,
      channel: body.channel || component.channel,
      version: body.version || component.version,
      installPlanApproval: body.installPlanApproval || 'Automatic',
      phase: 'Subscribed',
    },
  };
  const installPlan = nativeInstallPlan(component, {
    operation: existingPlan ? 'Upgrade' : 'Install',
    version: targetVersion,
    previousVersion: existingPlan?.status?.installedVersion || existingPlan?.spec?.version || '',
    approved: subscription.spec.installPlanApproval === 'Automatic',
  });
  await writeK8s('/apis/ai.opensphere.io/v1alpha1/namespaces/opensphere-system/openspheresubscriptions', 'POST', subscription, req).catch(async (e) => {
    if (e.code !== 409) throw e;
    await patchK8s(`/apis/ai.opensphere.io/v1alpha1/namespaces/opensphere-system/openspheresubscriptions/${subscription.metadata.name}`, { spec: subscription.spec }, req);
  });
  await applyNativeInstallPlan(component, installPlan, req);
  return nativeCatalog();
}

async function nativeApproveInstallPlan(req) {
  const body = JSON.parse((await readBody(req)).toString('utf8') || '{}');
  const component = componentByName(body.component || String(body.name || '').replace(/-install$/, ''));
  const name = requireDnsName(body.name || installPlanName(component.name), 'install plan');
  const existingPlan = await k8sJson(`/apis/ai.opensphere.io/v1alpha1/namespaces/opensphere-system/opensphereinstallplans/${name}`);
  const operation = existingPlan?.spec?.operation || 'Install';
  const targetVersion = existingPlan?.spec?.version || component.version;
  const previousVersion = existingPlan?.spec?.previousVersion || existingPlan?.status?.installedVersion || '';
  const rollbackVersion = existingPlan?.spec?.rollbackVersion || previousVersion || component.version;
  const now = new Date().toISOString();
  await patchK8s(`/apis/ai.opensphere.io/v1alpha1/namespaces/opensphere-system/opensphereinstallplans/${name}`, {
    spec: { approved: true, phase: 'Complete' },
    status: {
      phase: 'Complete',
      operation,
      installedVersion: targetVersion,
      previousVersion,
      rollbackVersion,
      completedAt: now,
      lastTransitionTime: now,
      conditions: [{
        type: 'Ready',
        status: 'True',
        reason: `${operation}Complete`,
        message: `${component.displayName} ${operation.toLowerCase()} completed at ${targetVersion}.`,
        lastTransitionTime: now,
      }],
    },
  }, req);
  await patchK8s(`/apis/ai.opensphere.io/v1alpha1/namespaces/opensphere-system/openspheresubscriptions/${component.name}`, {
    spec: { version: targetVersion, phase: 'Subscribed' },
  }, req).catch(() => null);
  return nativeCatalog();
}

async function nativeUpgradeComponent(req) {
  const body = JSON.parse((await readBody(req)).toString('utf8') || '{}');
  const component = componentByName(body.component || body.name);
  await seedNativeCatalog(req);
  const existingPlan = await k8sJson(`/apis/ai.opensphere.io/v1alpha1/namespaces/opensphere-system/opensphereinstallplans/${installPlanName(component.name)}`);
  const currentVersion = existingPlan?.status?.installedVersion || existingPlan?.spec?.version || component.version;
  const targetVersion = optionalString(body.version || body.targetVersion || bumpPatchVersion(currentVersion)) || bumpPatchVersion(currentVersion);
  const plan = nativeInstallPlan(component, {
    operation: 'Upgrade',
    version: targetVersion,
    previousVersion: currentVersion,
    rollbackVersion: currentVersion,
    approved: body.approved === true,
  });
  await applyNativeInstallPlan(component, plan, req);
  return nativeCatalog();
}

async function nativeRollbackComponent(req) {
  const body = JSON.parse((await readBody(req)).toString('utf8') || '{}');
  const component = componentByName(body.component || body.name);
  await seedNativeCatalog(req);
  const existingPlan = await k8sJson(`/apis/ai.opensphere.io/v1alpha1/namespaces/opensphere-system/opensphereinstallplans/${installPlanName(component.name)}`);
  const currentVersion = existingPlan?.status?.installedVersion || existingPlan?.spec?.version || component.version;
  const targetVersion = optionalString(body.version || body.rollbackVersion || existingPlan?.status?.rollbackVersion || existingPlan?.spec?.rollbackVersion || component.version) || component.version;
  const plan = nativeInstallPlan(component, {
    operation: 'Rollback',
    version: targetVersion,
    previousVersion: currentVersion,
    rollbackVersion: targetVersion,
    approved: body.approved === true,
  });
  await applyNativeInstallPlan(component, plan, req);
  return nativeCatalog();
}

async function nativeDataScienceCluster(req) {
  const body = JSON.parse((await readBody(req)).toString('utf8') || '{}');
  const name = requireDnsName(body.name || 'default-ai', 'data science cluster');
  const components = body.components && typeof body.components === 'object' && Object.keys(body.components).length
    ? body.components
    : Object.fromEntries(NATIVE_COMPONENTS.map((component) => [component.name, { managementState: 'Managed' }]));
  if (!(await crdInstalled('openspheredatascienceclusters.ai.opensphere.io'))) throw { code: 409, msg: 'OpenSphereDataScienceCluster CRD is not installed' };
  await seedNativeCatalog(req);
  const dsc = {
    apiVersion: 'ai.opensphere.io/v1alpha1',
    kind: 'OpenSphereDataScienceCluster',
    metadata: { name, namespace: 'opensphere-system' },
    spec: { components },
  };
  await writeK8s('/apis/ai.opensphere.io/v1alpha1/namespaces/opensphere-system/openspheredatascienceclusters', 'POST', dsc, req).catch(async (e) => {
    if (e.code !== 409) throw e;
    await patchK8s(`/apis/ai.opensphere.io/v1alpha1/namespaces/opensphere-system/openspheredatascienceclusters/${name}`, { spec: dsc.spec }, req);
  });
  for (const component of Object.keys(components)) {
    if (components[component]?.managementState === 'Managed') {
      await nativeSubscribe({ ...req, headers: req.headers, _bodyOverride: { component } }).catch(() => null);
    }
  }
  return nativeCatalog();
}

const SETUP_COMPONENTS = ['dashboard', 'workbenches', 'datasciencepipelines', 'kserve', 'modelregistry', 'trustyai', 'kueue', 'ray'];
const UPSTREAM_CRDS = [
  { name: 'datascienceclusters.datasciencecluster.opendatahub.io', label: 'DataScienceCluster' },
  { name: 'notebooks.kubeflow.org', label: 'Kubeflow Notebook' },
  { name: 'servingruntimes.serving.kserve.io', label: 'KServe ServingRuntime' },
  { name: 'inferenceservices.serving.kserve.io', label: 'KServe InferenceService' },
  { name: 'trustyaiservices.trustyai.opendatahub.io', label: 'TrustyAIService' },
  { name: 'modelregistries.modelregistry.opendatahub.io', label: 'ModelRegistry' },
  { name: 'clusterqueues.kueue.x-k8s.io', label: 'Kueue ClusterQueue' },
  { name: 'rayclusters.ray.io', label: 'RayCluster' },
];
const UPSTREAM_BACKENDS = [
  {
    id: 'odh-platform',
    displayName: 'Open Data Hub platform',
    component: 'platform',
    upstream: ['Open Data Hub Operator', 'Red Hat OpenShift AI'],
    fallback: 'OpenSphereDataScienceCluster',
    crds: [
      { name: 'datascienceclusters.datasciencecluster.opendatahub.io', label: 'DataScienceCluster' },
      { name: 'dscinitializations.dscinitialization.opendatahub.io', label: 'DSCInitialization', optional: true },
    ],
    apiGroups: ['datasciencecluster.opendatahub.io'],
  },
  {
    id: 'workbenches',
    displayName: 'Workbench runtime',
    component: 'workbenches',
    upstream: ['ODH Workbenches', 'Kubeflow Notebooks'],
    fallback: 'OpenSphere WorkbenchClaim controller',
    crds: [
      { name: 'notebooks.kubeflow.org', label: 'Notebook' },
    ],
    apiGroups: ['kubeflow.org'],
  },
  {
    id: 'pipelines',
    displayName: 'Pipeline runtime',
    component: 'pipelines',
    upstream: ['Kubeflow Pipelines', 'Tekton'],
    fallback: 'OpenSphere PipelineRunClaim Job controller',
    crds: [
      { name: 'pipelineruns.tekton.dev', label: 'Tekton PipelineRun' },
      { name: 'pipelines.tekton.dev', label: 'Tekton Pipeline', optional: true },
      { name: 'datasciencepipelinesapplications.datasciencepipelinesapplications.opendatahub.io', label: 'ODH DataSciencePipelinesApplication', optional: true },
      { name: 'pipelines.pipelines.kubeflow.org', label: 'Kubeflow Pipeline', optional: true },
      { name: 'experiments.pipelines.kubeflow.org', label: 'Kubeflow Experiment', optional: true },
      { name: 'runs.pipelines.kubeflow.org', label: 'Kubeflow Run', optional: true },
    ],
    apiGroups: ['tekton.dev', 'pipelines.kubeflow.org', 'datasciencepipelinesapplications.opendatahub.io'],
  },
  {
    id: 'model-serving',
    displayName: 'Model serving',
    component: 'model-serving',
    upstream: ['KServe', 'ODH Model Serving'],
    fallback: 'OpenSphere InferenceClaim Deployment/Service controller',
    crds: [
      { name: 'inferenceservices.serving.kserve.io', label: 'InferenceService' },
      { name: 'servingruntimes.serving.kserve.io', label: 'ServingRuntime' },
    ],
    apiGroups: ['serving.kserve.io'],
  },
  {
    id: 'model-registry',
    displayName: 'Model registry',
    component: 'model-registry',
    upstream: ['ODH Model Registry'],
    fallback: 'OpenSphere ConfigMap-backed registry',
    crds: [
      { name: 'modelregistries.modelregistry.opendatahub.io', label: 'ModelRegistry' },
    ],
    apiGroups: ['modelregistry.opendatahub.io'],
  },
  {
    id: 'monitoring',
    displayName: 'Model monitoring',
    component: 'monitoring',
    upstream: ['TrustyAI', 'Prometheus'],
    fallback: 'OpenSphere MonitoringTarget status metrics',
    crds: [
      { name: 'trustyaiservices.trustyai.opendatahub.io', label: 'TrustyAIService' },
      { name: 'servicemonitors.monitoring.coreos.com', label: 'ServiceMonitor', optional: true },
    ],
    apiGroups: ['trustyai.opendatahub.io', 'monitoring.coreos.com'],
  },
  {
    id: 'distributed-workloads',
    displayName: 'Distributed workloads',
    component: 'distributed-workloads',
    upstream: ['Kueue', 'Ray'],
    fallback: 'OpenSphere DistributedWorkloadClaim Job controller',
    crds: [
      { name: 'workloads.kueue.x-k8s.io', label: 'Kueue Workload' },
      { name: 'localqueues.kueue.x-k8s.io', label: 'Kueue LocalQueue' },
      { name: 'clusterqueues.kueue.x-k8s.io', label: 'Kueue ClusterQueue' },
      { name: 'rayjobs.ray.io', label: 'RayJob', optional: true },
      { name: 'rayclusters.ray.io', label: 'RayCluster', optional: true },
    ],
    apiGroups: ['kueue.x-k8s.io', 'ray.io'],
  },
];
const FOUNDATION_CRDS = Object.values(ACTIONS)
  .filter((def) => def.crdName && def.group?.endsWith('opensphere.io'))
  .map((def) => ({
    group: def.group,
    plural: def.plural,
    singular: def.kind.toLowerCase(),
    kind: def.kind,
    name: def.crdName,
  }))
  .concat(OPENSPHERE_PLATFORM_CRDS);

function minimalCrd(def) {
  return {
    apiVersion: 'apiextensions.k8s.io/v1',
    kind: 'CustomResourceDefinition',
    metadata: { name: def.name, labels: { 'app.kubernetes.io/part-of': 'opensphere-ai' } },
    spec: {
      group: def.group,
      scope: 'Namespaced',
      names: {
        plural: def.plural,
        singular: def.singular,
        kind: def.kind,
        listKind: `${def.kind}List`,
      },
      versions: [{
        name: 'v1alpha1',
        served: true,
        storage: true,
        schema: {
          openAPIV3Schema: {
            type: 'object',
            properties: {
              spec: { type: 'object', 'x-kubernetes-preserve-unknown-fields': true },
              status: { type: 'object', 'x-kubernetes-preserve-unknown-fields': true },
            },
          },
        },
        subresources: { status: {} },
      }],
    },
  };
}

async function selfCan(req, verb, group, resource, namespace) {
  if (!req?.headers?.['x-os-id-token']) return false;
  const body = {
    apiVersion: 'authorization.k8s.io/v1',
    kind: 'SelfSubjectAccessReview',
    spec: { resourceAttributes: { verb, group, resource, namespace } },
  };
  try {
    const raw = await writeK8s('/apis/authorization.k8s.io/v1/selfsubjectaccessreviews', 'POST', body, req);
    return raw.status?.allowed === true;
  } catch {
    return false;
  }
}

function actionTargetForCreate(body) {
  const page = body.page;
  const def = ACTIONS[page];
  if (!def) throw { code: 400, msg: 'unsupported create action' };
  if (page === 'projects') {
    return { verb: 'create', group: '', resource: 'namespaces', namespace: '', kind: 'Namespace', name: body.name || '' };
  }
  return {
    verb: 'create',
    group: def.group,
    resource: def.plural,
    namespace: body.namespace || 'default',
    kind: def.kind,
    name: body.name || '',
  };
}

function actionTargetForDelete(body) {
  const kindDef = body.kind ? ACTION_BY_KIND[body.kind] : null;
  const def = kindDef || ACTIONS[body.page];
  if (!def || def.scope === 'Cluster') throw { code: 400, msg: 'unsupported delete action' };
  return {
    verb: 'delete',
    group: def.group,
    resource: def.plural,
    namespace: body.namespace || 'default',
    kind: def.kind,
    name: body.name || '',
  };
}

function operationTarget(pathname, body) {
  if (pathname === '/operations/workbenches') {
    return { verb: 'patch', group: 'ai.opensphere.io', resource: 'workbenchclaims', namespace: body.namespace || 'default', kind: 'WorkbenchClaim', name: body.name || '' };
  }
  if (pathname === '/operations/inference') {
    return { verb: 'patch', group: 'ai.opensphere.io', resource: 'inferenceclaims', namespace: body.namespace || 'default', kind: 'InferenceClaim', name: body.name || '' };
  }
  if (pathname === '/operations/pipelines/run') {
    return { verb: 'create', group: 'ai.opensphere.io', resource: 'pipelinerunclaims', namespace: body.namespace || 'default', kind: 'PipelineRunClaim', name: body.runName || body.name || '' };
  }
  if (pathname === '/operations/claims') {
    const def = (body.kind && ACTION_BY_KIND[body.kind]) || ACTIONS[body.page];
    if (!def || def.scope === 'Cluster') throw { code: 400, msg: 'unsupported operation target' };
    return { verb: 'patch', group: def.group, resource: def.plural, namespace: body.namespace || 'default', kind: def.kind, name: body.name || '' };
  }
  throw { code: 400, msg: 'unsupported operation target' };
}

async function authorizeAiRequest(req, pathname) {
  if (!WRITE_METHODS.has(req.method)) return;
  if (pathname === '/admin/setup/plan') return;

  const adminPaths = new Set([
    '/admin/odh-components/action',
    '/admin/native/catalog/seed',
    '/admin/native/subscriptions',
    '/admin/native/installplans/approve',
    '/admin/native/installplans/upgrade',
    '/admin/native/installplans/rollback',
    '/admin/native/datasciencecluster',
    '/admin/native/demo-run',
    '/admin/native/demo-run/reset',
    '/admin/native/demo-smoke',
    '/admin/setup/install',
  ]);
  if (pathname.startsWith('/admin/native/reconcile/')) {
    await requireAdminAccess(req, pathname);
    return;
  }
  if (adminPaths.has(pathname)) {
    await requireAdminAccess(req, pathname);
    return;
  }

  if (pathname === '/actions/create') {
    const body = await prepareJsonBody(req);
    await requireResourceAccess(req, pathname, actionTargetForCreate(body));
    return;
  }
  if (pathname === '/actions/delete') {
    const body = await prepareJsonBody(req);
    await requireResourceAccess(req, pathname, actionTargetForDelete(body));
    return;
  }
  if (pathname.startsWith('/operations/')) {
    const body = await prepareJsonBody(req);
    await requireResourceAccess(req, pathname, operationTarget(pathname, body));
    return;
  }
  if (pathname === '/models/registry/versions' && req.method === 'POST') {
    await prepareJsonBody(req);
    await requireResourceAccess(req, pathname, { verb: 'update', group: '', resource: 'configmaps', namespace: 'opensphere-system', kind: 'ConfigMap', name: 'ai-model-registry-versions' });
  }
  if (pathname === '/models/registry/upstream/self-test' && req.method === 'POST') {
    await prepareJsonBody(req);
    await requireResourceAccess(req, pathname, { verb: 'update', group: '', resource: 'configmaps', namespace: 'opensphere-system', kind: 'ConfigMap', name: 'ai-model-registry-versions' });
  }
}

async function setupStatus(req) {
  const [
    canCreateCrds,
    canCreateNamespaces,
    canCreateSubscriptions,
    canCreateDsc,
    olmApi,
    storageClasses,
    nodesJson,
    subscriptions,
    csvs,
    namespacesJson,
  ] = await Promise.all([
    selfCan(req, 'create', 'apiextensions.k8s.io', 'customresourcedefinitions'),
    selfCan(req, 'create', '', 'namespaces'),
    selfCan(req, 'create', 'operators.coreos.com', 'subscriptions', 'opensphere-system'),
    selfCan(req, 'create', 'datasciencecluster.opendatahub.io', 'datascienceclusters'),
    k8sJson('/apis/operators.coreos.com/v1alpha1'),
    k8sJson('/apis/storage.k8s.io/v1/storageclasses'),
    k8sJson('/api/v1/nodes'),
    k8sJson('/apis/operators.coreos.com/v1alpha1/subscriptions'),
    k8sJson('/apis/operators.coreos.com/v1alpha1/clusterserviceversions'),
    k8sJson('/api/v1/namespaces'),
  ]);
  const opensphereDefs = Object.values(ACTIONS).filter((def) => def.crdName).map((def) => ({ name: def.crdName, label: def.kind }));
  const foundationDefs = FOUNDATION_CRDS.map((def) => ({ name: def.name, label: def.kind }));
  const crdDefs = Array.from(new Map([...opensphereDefs, ...foundationDefs, ...UPSTREAM_CRDS].map((def) => [def.name, def])).values());
  const crds = await Promise.all(crdDefs.map(async (def) => ({
    ...def,
    installed: await crdInstalled(def.name),
    family: def.name.includes('opensphere.io') ? 'opensphere' : 'upstream',
  })));
  const readyNodes = (nodesJson?.items || []).filter((node) => (node.status?.conditions || []).some((c) => c.type === 'Ready' && c.status === 'True'));
  const gpuNodes = (nodesJson?.items || []).filter((node) => Object.keys(node.metadata?.labels || {}).some((key) => key.includes('gpu') || key.includes('accelerator')));
  const dsc = await k8sJson('/apis/datasciencecluster.opendatahub.io/v1/datascienceclusters');
  const native = await nativeCatalog();
  return {
    prerequisites: [
      { id: 'crd-access', label: 'Can create CRDs', ready: canCreateCrds, required: false, scope: 'admin-install', detail: canCreateCrds ? 'Allowed' : 'Needed only when installing or updating platform CRDs from this wizard' },
      { id: 'namespace-access', label: 'Can create namespaces', ready: canCreateNamespaces, required: false, scope: 'admin-install', detail: canCreateNamespaces ? 'Allowed' : 'Needed only when creating new namespaces from this wizard' },
      { id: 'olm-api', label: 'OLM / OperatorHub API', ready: !!olmApi, required: false, scope: 'upstream-parity', detail: olmApi ? 'operators.coreos.com API is available' : 'Optional for OpenSphere-native operation; required only for OLM/OperatorHub parity' },
      { id: 'operator-access', label: 'Can create Operator subscriptions', ready: canCreateSubscriptions && !!olmApi, required: false, scope: 'upstream-parity', detail: canCreateSubscriptions && !!olmApi ? 'Allowed' : 'Optional for native operation; required only to install ODH/RHOAI Operators' },
      { id: 'dsc-access', label: 'Can create DataScienceCluster', ready: canCreateDsc, required: false, scope: 'upstream-parity', detail: canCreateDsc ? 'Allowed when CRD exists' : 'Optional for native operation; required only for ODH/RHOAI DataScienceCluster parity' },
      { id: 'storage', label: 'Default storage class', ready: (storageClasses?.items || []).some((sc) => sc.metadata?.annotations?.['storageclass.kubernetes.io/is-default-class'] === 'true'), required: true, scope: 'native', detail: (storageClasses?.items || []).map((sc) => sc.metadata?.name).join(', ') || 'No storage classes found' },
      { id: 'nodes', label: 'Ready nodes', ready: readyNodes.length > 0, required: true, scope: 'native', detail: `${readyNodes.length} ready node(s), ${gpuNodes.length} GPU/accelerator-labeled node(s)` },
    ],
    crds,
    operators: {
      olmAvailable: !!olmApi,
      subscriptions: (subscriptions?.items || []).map((item) => ({
        name: item.metadata?.name || '',
        namespace: item.metadata?.namespace || '',
        package: item.spec?.name || '',
        channel: item.spec?.channel || '',
        source: item.spec?.source || '',
      })),
      csvs: (csvs?.items || []).map((item) => ({
        name: item.metadata?.name || '',
        namespace: item.metadata?.namespace || '',
        phase: item.status?.phase || '',
      })),
    },
    namespaces: (namespacesJson?.items || []).map((item) => item.metadata?.name || '').filter(Boolean).sort(),
    dataScienceClusters: (dsc?.items || []).map((item) => itemFromK8s(item, 'DataScienceCluster')),
    nativePlatform: native,
  };
}

async function finalReadiness(req) {
  const [backendsResult, metricsResult, auditResult, nativeRegistryResult, upstreamRegistryResult, setupResult] = await Promise.allSettled([
    nativeBackends(),
    nativeControllerMetricsWithAuditFallback(),
    nativeAuditLog(),
    modelRegistryUpstream('/?backend=opensphere'),
    modelRegistryUpstream('/?backend=modelregistry'),
    setupStatus(req),
  ]);
  const backends = backendsResult.status === 'fulfilled' ? backendsResult.value : null;
  const metrics = metricsResult.status === 'fulfilled' ? metricsResult.value : null;
  const audit = auditResult.status === 'fulfilled' ? auditResult.value : null;
  const nativeRegistry = nativeRegistryResult.status === 'fulfilled' ? nativeRegistryResult.value : null;
  const upstreamRegistry = upstreamRegistryResult.status === 'fulfilled' ? upstreamRegistryResult.value : null;
  const setup = setupResult.status === 'fulfilled' ? setupResult.value : null;
  const checks = [];
  const add = (id, label, status, scope, evidence, nextStep = '') => checks.push({ id, label, status, scope, evidence, nextStep });

  if (!backends) {
    add('backend-detection', 'Backend detection', 'Failed', 'native', backendsResult.reason?.msg || String(backendsResult.reason || 'Backend detection failed'), 'Check Kubernetes API access from the AI plugin pod.');
  } else if (backends.summary.unavailable > 0) {
    add('backend-detection', 'Backend detection', 'Failed', 'native', `${backends.summary.unavailable}/${backends.summary.total} backend capabilities are unavailable.`, 'Install the missing CRDs or enable OpenSphere fallback CRDs.');
  } else {
    add('backend-detection', 'Backend detection', 'Ready', 'native', `${backends.summary.upstreamReady} upstream, ${backends.summary.fallbackReady} OpenSphere-native fallback, ${backends.summary.unavailable} unavailable.`, '');
  }

  if (!backends) {
    add('upstream-coverage', 'ODH/RHOAI upstream coverage', 'Warning', 'upstream', 'Backend data is unavailable.', 'Re-run readiness after backend detection succeeds.');
  } else if (backends.summary.upstreamReady >= backends.summary.total && backends.summary.total > 0) {
    add('upstream-coverage', 'ODH/RHOAI upstream coverage', 'Ready', 'upstream', 'All known ODH/RHOAI-compatible APIs are available.', '');
  } else {
    add('upstream-coverage', 'ODH/RHOAI upstream coverage', 'NotInstalled', 'upstream', `${backends.summary.upstreamReady}/${backends.summary.total} upstream APIs are installed; ${backends.summary.fallbackReady} OpenSphere-native runtimes are active.`, 'Install ODH/RHOAI or provide equivalent CRDs/APIs only when upstream parity validation is required.');
  }

  if (!setup) {
    add('setup-prerequisites', 'Cluster setup prerequisites', 'Warning', 'native', setupResult.reason?.msg || String(setupResult.reason || 'Setup status failed'), 'Check cluster RBAC and API discovery.');
  } else {
    const nativePrereqs = setup.prerequisites.filter((item) => item.required === true || item.scope === 'native');
    const nativeReadyPrereqs = nativePrereqs.filter((item) => item.ready).length;
    const optionalPrereqs = setup.prerequisites.filter((item) => item.required !== true && item.scope !== 'native');
    const optionalReadyPrereqs = optionalPrereqs.filter((item) => item.ready).length;
    const requiredMissing = nativePrereqs.filter((item) => !item.ready);
    add(
      'setup-prerequisites',
      'Cluster setup prerequisites',
      requiredMissing.length ? 'Failed' : 'Ready',
      'native',
      `${nativeReadyPrereqs}/${nativePrereqs.length} native prerequisites are ready; ${optionalReadyPrereqs}/${optionalPrereqs.length} optional admin/upstream checks are ready.`,
      requiredMissing.length ? 'Prepare worker nodes and default storage before running AI workloads.' : 'Optional admin/upstream checks are shown in setup status and do not block OpenSphere-native operation.',
    );

    const opensphereCrds = setup.crds.filter((item) => item.family === 'opensphere');
    const opensphereInstalled = opensphereCrds.filter((item) => item.installed).length;
    add(
      'foundation-crds',
      'OpenSphere foundation CRDs',
      opensphereInstalled === opensphereCrds.length ? 'Ready' : 'Warning',
      'native',
      `${opensphereInstalled}/${opensphereCrds.length} OpenSphere CRDs are installed.`,
      opensphereInstalled === opensphereCrds.length ? '' : 'Run the setup wizard with OpenSphere foundation CRDs enabled.',
    );

    add(
      'operator-lifecycle',
      'OLM / OperatorHub',
      setup.operators.olmAvailable ? 'Ready' : 'NotInstalled',
      'upstream',
      setup.operators.olmAvailable ? `${setup.operators.subscriptions.length} subscription(s), ${setup.operators.csvs.length} CSV(s) detected.` : 'operators.coreos.com API is not available on this cluster.',
      setup.operators.olmAvailable ? '' : 'This is not required for OpenSphere-native operation. Add OLM-compatible APIs only for OperatorHub parity.',
    );

    add(
      'datasciencecluster',
      'DataScienceCluster',
      setup.dataScienceClusters.length ? 'Ready' : 'NotInstalled',
      'upstream',
      setup.dataScienceClusters.length ? `${setup.dataScienceClusters.length} DataScienceCluster resource(s) detected.` : 'No DataScienceCluster resource is present.',
      setup.dataScienceClusters.length ? '' : 'OpenSphere native component state replaces this for local operation; create DataScienceCluster only for ODH/RHOAI parity.',
    );
  }

  if (!metrics) {
    add('controller-health', 'Controller health', 'Warning', 'native', 'Controller metrics are unavailable.', 'Check the AI plugin process logs.');
  } else if (metrics.summary.failures > 0) {
    add('controller-health', 'Controller health', 'Failed', 'native', `${metrics.summary.failures} failure(s) across ${metrics.summary.reconciles} reconcile(s).`, 'Inspect controller audit log and failed resource status.');
  } else if (metrics.summary.historicalFailures > 0) {
    add('controller-health', 'Controller health', 'Ready', 'native', `0 current failure(s), ${metrics.summary.historicalFailures} historical failure(s), ${metrics.summary.reconciles} recorded reconcile(s).`, 'Historical failures are retained for audit review.');
  } else if (metrics.summary.reconciles > 0) {
    add('controller-health', 'Controller health', 'Ready', 'native', `${metrics.summary.reconciles} reconcile(s), ${metrics.summary.events} event(s), no failures.`, '');
  } else {
    add('controller-health', 'Controller health', 'Warning', 'native', 'No reconcile metrics have been recorded yet.', 'Create or reconcile a managed AI resource to prove controller execution.');
  }

  if (!audit) {
    add('audit-log', 'Durable audit log', 'Warning', 'native', 'Audit log is unavailable.', 'Check the ai-controller-audit ConfigMap.');
  } else if (audit.summary.total > 0) {
    const activeWarnings = audit.summary.activeWarnings || 0;
    const historicalWarnings = audit.summary.historicalWarnings || 0;
    const systemWarnings = audit.summary.systemWarnings || 0;
    add(
      'audit-log',
      'Durable audit log',
      activeWarnings ? 'Warning' : 'Ready',
      'native',
      `${audit.summary.total} entries, ${activeWarnings} active warning(s), ${historicalWarnings} historical warning(s), ${systemWarnings} system warning(s).`,
      activeWarnings ? 'Review active resource warnings before declaring production readiness.' : historicalWarnings || systemWarnings ? 'Historical and system warnings are retained for audit review.' : '',
    );
  } else {
    add('audit-log', 'Durable audit log', 'Warning', 'native', 'No audit entries have been recorded yet.', 'Run controller operations to prove durable audit recording.');
  }

  if (!nativeRegistry) {
    add('native-model-registry', 'OpenSphere native Model Registry', 'Warning', 'native', nativeRegistryResult.reason?.msg || String(nativeRegistryResult.reason || 'Native registry status failed'), 'Check registry fallback storage.');
  } else {
    add('native-model-registry', 'OpenSphere native Model Registry', 'Ready', 'native', `${nativeRegistry.summary?.versions || 0} registered version(s), source ${nativeRegistry.source?.type || 'opensphere'}.`, '');
  }

  if (!upstreamRegistry) {
    add('upstream-model-registry', 'Upstream Model Registry', 'Warning', 'upstream', upstreamRegistryResult.reason?.msg || String(upstreamRegistryResult.reason || 'Model Registry status failed'), 'Check registry backend discovery.');
  } else if (upstreamRegistry.summary?.ready && upstreamRegistry.source?.type === 'odh-model-registry') {
    add('upstream-model-registry', 'Upstream Model Registry', 'Ready', 'upstream', `${upstreamRegistry.summary.upstreamVersions || 0} upstream version(s), ${upstreamRegistry.summary.artifacts || 0} artifact(s).`, '');
  } else {
    add('upstream-model-registry', 'Upstream Model Registry', 'NotInstalled', 'upstream', upstreamRegistry.backend?.message || 'No ready ODH ModelRegistry endpoint is available.', 'This is not required for OpenSphere-native registry operation. Install ODH Model Registry only for upstream parity and write self-test validation.');
  }

  add('write-security', 'Write API authorization', 'Configured', 'native', 'Write operations use Kubernetes SelfSubjectAccessReview and require an OpenSphere identity token.', 'Keep cluster RBAC bound to least-privilege service roles.');

  const nativeChecks = checks.filter((item) => item.scope === 'native');
  const upstreamChecks = checks.filter((item) => item.scope === 'upstream');
  const nativePhase = nativeChecks.some((item) => item.status === 'Failed')
    ? 'Degraded'
    : nativeChecks.some((item) => item.status === 'Warning')
      ? 'ReadyWithWarnings'
      : 'Ready';
  const upstreamPhase = upstreamChecks.some((item) => item.status === 'Failed')
    ? 'Degraded'
    : upstreamChecks.some((item) => item.status === 'NotInstalled')
      ? 'ParityNotInstalled'
      : upstreamChecks.some((item) => item.status === 'Warning')
        ? 'VerificationWarning'
        : 'Ready';
  const summary = {
    pass: checks.filter((item) => ['Ready', 'Configured'].includes(item.status)).length,
    warning: checks.filter((item) => item.status === 'Warning').length,
    fail: checks.filter((item) => item.status === 'Failed').length,
    externalRequired: checks.filter((item) => item.status === 'NotInstalled').length,
    nativeReady: nativeChecks.filter((item) => ['Ready', 'Configured'].includes(item.status)).length,
    nativeWarning: nativeChecks.filter((item) => item.status === 'Warning').length,
    nativeFail: nativeChecks.filter((item) => item.status === 'Failed').length,
    nativeTotal: nativeChecks.length,
    upstreamReady: upstreamChecks.filter((item) => item.status === 'Ready').length,
    upstreamWarning: upstreamChecks.filter((item) => item.status === 'Warning').length,
    upstreamNotInstalled: upstreamChecks.filter((item) => item.status === 'NotInstalled').length,
    upstreamTotal: upstreamChecks.length,
    total: checks.length,
  };
  return { phase: nativePhase, nativePhase, upstreamPhase, generatedAt: new Date().toISOString(), version: VERSION, summary, checks };
}

function setupPlanFrom(body) {
  const provider = optionalString(body.provider || 'opendatahub') || 'opendatahub';
  const defaultNamespace = provider === 'internal' ? 'opensphere-system' : provider === 'rhods' ? 'redhat-ods-operator' : 'opendatahub';
  const defaultPackage = provider === 'internal' ? '' : provider === 'rhods' ? 'rhods-operator' : 'opendatahub-operator';
  const namespace = optionalString(body.namespace || defaultNamespace) || defaultNamespace;
  const operatorPackage = optionalString(body.operatorPackage || defaultPackage) || defaultPackage;
  const channel = optionalString(body.channel || 'fast') || 'fast';
  const source = optionalString(body.source || 'community-operators') || 'community-operators';
  const sourceNamespace = optionalString(body.sourceNamespace || 'openshift-marketplace') || 'openshift-marketplace';
  const dscName = optionalString(body.dataScienceClusterName || 'default-dsc') || 'default-dsc';
  const components = Array.isArray(body.components) && body.components.length ? body.components.filter((name) => SETUP_COMPONENTS.includes(name)) : SETUP_COMPONENTS.slice(0, 6);
  return { provider, namespace, operatorPackage, channel, source, sourceNamespace, dscName, components };
}

function setupManifests(plan) {
  const componentSpec = Object.fromEntries(plan.components.map((name) => [name, { managementState: 'Managed' }]));
  const manifests = [
    { apiVersion: 'v1', kind: 'Namespace', metadata: { name: plan.namespace } },
  ];
  if (plan.operatorPackage) {
    manifests.push({
      apiVersion: 'operators.coreos.com/v1',
      kind: 'OperatorGroup',
      metadata: { name: `${plan.operatorPackage}-group`, namespace: plan.namespace },
      spec: { targetNamespaces: [plan.namespace] },
    });
    manifests.push({
      apiVersion: 'operators.coreos.com/v1alpha1',
      kind: 'Subscription',
      metadata: { name: plan.operatorPackage, namespace: plan.namespace },
      spec: { name: plan.operatorPackage, channel: plan.channel, source: plan.source, sourceNamespace: plan.sourceNamespace },
    });
  }
  if (plan.provider !== 'internal') {
    manifests.push({
      apiVersion: 'datasciencecluster.opendatahub.io/v1',
      kind: 'DataScienceCluster',
      metadata: { name: plan.dscName },
      spec: { components: componentSpec },
    });
  }
  return manifests;
}

async function setupPlan(req) {
  const body = req.method === 'POST' ? JSON.parse((await readBody(req)).toString('utf8') || '{}') : {};
  const plan = setupPlanFrom(body);
  const steps = [
    { id: 'internal-crds', label: 'Install OpenSphere foundation CRDs', action: 'Apply missing minimal CRDs for LLM routes and retrieval claims' },
  ];
  if (plan.operatorPackage) steps.push({ id: 'operator', label: 'Install AI Operator', action: `Create OperatorGroup and Subscription for ${plan.operatorPackage}` });
  if (plan.provider !== 'internal') steps.push({ id: 'dsc', label: 'Create DataScienceCluster', action: `Enable ${plan.components.join(', ')}` });
  steps.push({ id: 'verify', label: 'Verify capabilities', action: 'Re-check CRDs and component status' });
  return { plan, steps, manifests: setupManifests(plan) };
}

async function setupInstall(req) {
  const body = JSON.parse((await readBody(req)).toString('utf8') || '{}');
  const plan = setupPlanFrom(body);
  const steps = [];
  async function step(id, label, fn) {
    try {
      const result = await fn();
      steps.push({ id, label, phase: 'Succeeded', detail: result || 'Done' });
    } catch (e) {
      steps.push({ id, label, phase: 'Failed', detail: e.msg || String(e) });
    }
  }

  if (body.installInternalCrds !== false) {
    await step('internal-crds', 'OpenSphere foundation CRDs', async () => {
      const created = [];
      const skipped = [];
      for (const def of FOUNDATION_CRDS) {
        if (await crdInstalled(def.name)) {
          skipped.push(def.kind);
        } else {
          await writeK8s('/apis/apiextensions.k8s.io/v1/customresourcedefinitions', 'POST', minimalCrd(def), req);
          created.push(def.kind);
        }
      }
      return `created: ${created.join(', ') || 'none'}; skipped: ${skipped.join(', ') || 'none'}`;
    });
  }

  if (body.installOperator) {
    await step('operator', 'AI Operator subscription', async () => {
      if (!(await k8sJson('/apis/operators.coreos.com/v1alpha1'))) return 'Skipped: OLM API is not available on this cluster';
      await writeK8s('/api/v1/namespaces', 'POST', { apiVersion: 'v1', kind: 'Namespace', metadata: { name: plan.namespace } }, req).catch((e) => {
        if (e.code !== 409) throw e;
      });
      const manifests = setupManifests(plan);
      const operatorGroup = manifests.find((item) => item.kind === 'OperatorGroup');
      const subscription = manifests.find((item) => item.kind === 'Subscription');
      if (!operatorGroup || !subscription) return 'Skipped: no operator package selected';
      await writeK8s(`/apis/operators.coreos.com/v1/namespaces/${plan.namespace}/operatorgroups`, 'POST', operatorGroup, req).catch(async (e) => {
        if (e.code !== 409) throw e;
        await patchK8s(`/apis/operators.coreos.com/v1/namespaces/${plan.namespace}/operatorgroups/${operatorGroup.metadata.name}`, { spec: operatorGroup.spec }, req);
      });
      await writeK8s(`/apis/operators.coreos.com/v1alpha1/namespaces/${plan.namespace}/subscriptions`, 'POST', subscription, req).catch(async (e) => {
        if (e.code !== 409) throw e;
        await patchK8s(`/apis/operators.coreos.com/v1alpha1/namespaces/${plan.namespace}/subscriptions/${subscription.metadata.name}`, { spec: subscription.spec }, req);
      });
      return `${plan.operatorPackage} subscription requested in ${plan.namespace}`;
    });
  }

  if (body.createDataScienceCluster) {
    await step('dsc', 'DataScienceCluster', async () => {
      if (!(await crdInstalled('datascienceclusters.datasciencecluster.opendatahub.io'))) return 'Skipped: DataScienceCluster CRD is not installed yet';
      const dsc = setupManifests(plan).find((item) => item.kind === 'DataScienceCluster');
      if (!dsc) return 'Skipped: no DataScienceCluster manifest for this profile';
      await writeK8s('/apis/datasciencecluster.opendatahub.io/v1/datascienceclusters', 'POST', dsc, req).catch(async (e) => {
        if (e.code !== 409) throw e;
        await patchK8s(`/apis/datasciencecluster.opendatahub.io/v1/datascienceclusters/${plan.dscName}`, { spec: dsc.spec }, req);
      });
      return `${plan.dscName} requested`;
    });
  }

  return { plan, steps, status: await setupStatus(req) };
}

function itemFromK8s(obj, fallbackKind) {
  const conditions = obj.status?.conditions || [];
  const readyCondition = conditions.find((c) => c.type === 'Ready');
  const annotations = obj.metadata?.annotations || {};
  const computeBackendRef = obj.spec?.computeBackendRef || obj.spec?.computeBackend || {};
  const annotatedPhase = optionalString(annotations['opensphere.io/reconcile-phase']);
  const annotatedReason = optionalString(annotations['opensphere.io/reconcile-reason']);
  const annotatedMessage = optionalString(annotations['opensphere.io/reconcile-message']);
  const annotatedReady = annotatedPhase && !/fail|error|blocked|degraded|notready|pending/i.test(`${annotatedPhase} ${annotatedReason}`);
  const conditionReady = readyCondition ? readyCondition.status === 'True' : undefined;
  const ready = obj.status?.ready ?? conditionReady ?? annotatedReady ?? false;
  const phase = obj.status?.phase || annotatedPhase || obj.spec?.phase || (obj.status?.passed === true ? 'Passed' : '') || (ready ? 'Ready' : 'Pending');
  const finalizing = !!obj.metadata?.deletionTimestamp;
  return {
    name: obj.metadata?.name || '',
    kind: obj.kind || fallbackKind,
    namespace: obj.metadata?.namespace || '',
    phase: finalizing ? 'Deleting' : phase,
    ready: !!ready,
    description: obj.spec?.description || obj.metadata?.annotations?.['opensphere.io/description'] || '',
    reason: readyCondition?.reason || obj.status?.reason || obj.status?.lastFailureReason || annotatedReason || '',
    message: obj.status?.message || obj.status?.lastFailureMessage || readyCondition?.message || annotatedMessage || '',
    retryCount: obj.status?.retryCount || 0,
    nextRetryAt: obj.status?.nextRetryAt || '',
    finalizing,
    computeBackendRef: computeBackendRef?.name
      ? `${computeBackendRef.namespace || obj.metadata?.namespace || 'default'}/${computeBackendRef.name}`
      : '',
    computeRoutingWorkload: annotations['opensphere.io/compute-routing-workload'] || '',
    computeRoutingBackend: annotations['opensphere.io/compute-routing-backend'] || '',
    computeRoutingAppliedAt: annotations['opensphere.io/compute-routing-applied-at'] || '',
    backendType: obj.spec?.backendType || obj.spec?.backend || obj.status?.backendType || obj.status?.backendMode || '',
    provider: obj.spec?.provider || obj.status?.provider || obj.metadata?.labels?.['opensphere.io/provider'] || '',
    endpoint: obj.spec?.endpoint || obj.status?.endpoint || obj.metadata?.annotations?.['opensphere.io/external-endpoint'] || '',
    resourceName: obj.spec?.resourceName || obj.status?.resourceName || '',
    supportedJobTypes: obj.spec?.supportedJobTypes || obj.status?.supportedJobTypes || [],
    gpus: obj.status?.gpus || obj.spec?.gpus || [],
    externalJob: obj.status?.externalJob || null,
    externalJobLogs: obj.status?.externalJobLogs || null,
    externalJobLogSummary: obj.status?.externalJobLogSummary || null,
    maxConcurrency: obj.spec?.maxConcurrency || obj.status?.maxConcurrency || '',
    currentConcurrency: obj.status?.currentConcurrency || '',
    source: 'cluster',
    reference: false,
  };
}

function referenceItems(items, source = 'reference') {
  return (items || []).map((item) => ({
    ...item,
    source,
    reference: true,
    ready: item.ready === true,
  }));
}

function actualCount(items) {
  return (items || []).filter((item) => item.reference !== true).length;
}

function referenceCount(items) {
  return (items || []).filter((item) => item.reference === true).length;
}

function listPayload(items) {
  const actual = actualCount(items);
  const reference = referenceCount(items);
  const actualSources = Array.from(new Set((items || [])
    .filter((item) => item.reference !== true)
    .map((item) => item.source || 'cluster')));
  return {
    items,
    actualCount: actual,
    referenceCount: reference,
    source: actual && reference ? 'mixed' : actual ? (actualSources.length === 1 ? actualSources[0] : 'cluster') : reference ? 'reference' : 'empty',
  };
}

async function k8sJson(apiPath) {
  try {
    const r = await fetch(`${APISERVER}${apiPath}`, { headers: { Authorization: `Bearer ${tok()}`, Accept: 'application/json' } });
    if (!r.ok) return null;
    return await r.json();
  } catch {
    return null;
  }
}

async function k8sText(apiPath) {
  try {
    const r = await fetch(`${APISERVER}${apiPath}`, { headers: { Authorization: `Bearer ${tok()}`, Accept: 'application/json, */*' } });
    if (!r.ok) return null;
    return await r.text();
  } catch {
    return null;
  }
}

function quantityNumber(value) {
  if (value === undefined || value === null || value === '') return 0;
  const raw = String(value).trim();
  const match = raw.match(/^([0-9]+(?:\.[0-9]+)?)([kKmMgGtTpPeE]i?)?$/);
  if (!match) return Number(raw) || 0;
  const num = Number(match[1]);
  const suffix = (match[2] || '').toLowerCase();
  if (suffix === 'k') return num * 1000;
  if (suffix === 'm') return num / 1000;
  return num;
}

function isGpuResourceName(name) {
  const key = String(name || '').toLowerCase();
  return key === 'nvidia.com/gpu'
    || key === 'amd.com/gpu'
    || key === 'gpu.intel.com/i915'
    || key === 'habana.ai/gaudi'
    || key === 'vendor.opensphere.io/gpu'
    || key.includes('/gpu')
    || key.includes('nvidia.com/')
    || key.includes('amd.com/')
    || key.includes('rocm')
    || key.includes('cuda');
}

function imageNamesFromPod(pod) {
  return [
    ...(pod.spec?.containers || []),
    ...(pod.spec?.initContainers || []),
  ].map((container) => container.image || '').filter(Boolean);
}

function gpuResourcesForNode(node) {
  const capacity = node.status?.capacity || {};
  const allocatable = node.status?.allocatable || {};
  const names = Array.from(new Set([...Object.keys(capacity), ...Object.keys(allocatable)].filter(isGpuResourceName))).sort();
  return names.map((name) => ({
    name,
    capacity: capacity[name] || '0',
    allocatable: allocatable[name] || '0',
    capacityNumber: quantityNumber(capacity[name]),
    allocatableNumber: quantityNumber(allocatable[name]),
  }));
}

function looksLikeGpuPlugin(item) {
  const labels = item.metadata?.labels || {};
  const annotations = item.metadata?.annotations || {};
  if (labels['opensphere.io/demo'] || labels['opensphere.io/smoke'] || labels['app.kubernetes.io/part-of'] === 'opensphere-ai-hub') return false;
  const haystack = [
    item.metadata?.name,
    item.kind,
    ...Object.keys(labels),
    ...Object.values(labels),
    ...Object.keys(annotations),
    ...Object.values(annotations),
    ...imageNamesFromPod(item),
    ...((item.spec?.template?.spec?.containers || []).map((container) => container.image || '')),
  ].filter(Boolean).join(' ').toLowerCase();
  return /(nvidia|dcgm|device-plugin|resource-publisher|cuda|rocm|amd|intel|gaudi)/.test(haystack);
}

function compactLogEvidence(text) {
  return String(text || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .filter((line) => /(no devices|incompatible|container toolkit|runtime|nvidia|gpu|error|warning|fail|prerequisite)/i.test(line))
    .slice(-8);
}

function classifyGpuDiagnostic(text) {
  const lower = String(text || '').toLowerCase();
  if (lower.includes('no runtime for "nvidia"') || lower.includes("no runtime for 'nvidia'")) {
    return {
      phase: 'RuntimeHandlerMissing',
      severity: 'Error',
      message: 'A RuntimeClass named nvidia was requested, but the Kubernetes node containerd runtime has no nvidia handler configured.',
      nextStep: 'Configure the node container runtime with an NVIDIA runtime handler before scheduling Pods with runtimeClassName nvidia.',
    };
  }
  if (lower.includes('incompatible strategy') || lower.includes('nvidia container toolkit')) {
    return {
      phase: 'ContainerToolkitNotVisible',
      severity: 'Warning',
      message: 'The NVIDIA device plugin is running, but it cannot see the NVIDIA Container Toolkit / driver path inside the Kubernetes node runtime.',
      nextStep: 'Expose the host NVIDIA runtime into the Kubernetes node runtime, then restart the device plugin and confirm nvidia.com/gpu appears on the node.',
    };
  }
  if (lower.includes('no devices found')) {
    return {
      phase: 'PluginRunningNoDevices',
      severity: 'Warning',
      message: 'The GPU device plugin is running, but it did not discover any GPU devices in the Kubernetes node.',
      nextStep: 'Verify the worker node runtime can see /dev/nvidia* or the vendor GPU device files, then check node allocatable resources.',
    };
  }
  if (lower.includes('failed') || lower.includes('error')) {
    return {
      phase: 'PluginError',
      severity: 'Warning',
      message: 'The GPU integration reported errors while starting or registering with kubelet.',
      nextStep: 'Review the plugin Pod events and logs, then repair the vendor runtime prerequisites.',
    };
  }
  return {
    phase: 'Observed',
    severity: 'Info',
    message: 'GPU integration evidence was collected from the cluster.',
    nextStep: 'Confirm node allocatable GPU resources before running GPU-bound OAH tasks.',
  };
}

function gpuLabelsForNode(labels = {}) {
  return Object.fromEntries(Object.entries(labels).filter(([key, value]) => {
    const text = `${key}=${value}`.toLowerCase();
    if (key.startsWith('cpu-feature.node.kubevirt.io/')) return false;
    if (key.startsWith('cpu-model-migration.node.kubevirt.io/')) return false;
    if (key === 'kubernetes.io/arch' || key === 'beta.kubernetes.io/arch') return false;
    return [
      /^nvidia\.com\//,
      /^gpu\.intel\.com\//,
      /^amd\.com\/gpu/,
      /^rocm\.amd\.com\//,
      /^feature\.node\.kubernetes\.io\/pci-10de/,
      /^feature\.node\.kubernetes\.io\/pci-1002/,
      /^feature\.node\.kubernetes\.io\/pci-0300/,
      /^accelerator[./-]/,
      /[./-]accelerator[./-]/,
      /(^|[./-])gpu([./-]|$)/,
      /cuda/,
      /mig\./,
    ].some((pattern) => pattern.test(text));
  }));
}

function summaryCount(value) {
  if (Array.isArray(value)) return value.length;
  if (value && typeof value === 'object') {
    if (Number.isFinite(Number(value.count))) return Number(value.count);
    if (Number.isFinite(Number(value.total))) return Number(value.total);
    if (Array.isArray(value.items)) return value.items.length;
  }
  return Number(value) || 0;
}

async function gpuPluginDiagnostics(pluginPods, pluginDaemonSets) {
  const diagnostics = [];
  const eventNamespaces = Array.from(new Set([
    ...pluginPods.map((pod) => pod.namespace),
    ...pluginDaemonSets.map((ds) => ds.namespace),
  ].filter(Boolean)));
  const eventsByNamespace = {};
  await Promise.all(eventNamespaces.map(async (namespace) => {
    eventsByNamespace[namespace] = (await k8sJson(`/api/v1/namespaces/${namespace}/events`))?.items || [];
  }));
  await Promise.all(pluginPods.slice(0, 12).map(async (pod) => {
    const log = await k8sText(`/api/v1/namespaces/${encodeURIComponent(pod.namespace)}/pods/${encodeURIComponent(pod.name)}/log?tailLines=120`) || '';
    const podEvents = (eventsByNamespace[pod.namespace] || [])
      .filter((event) => event.involvedObject?.name === pod.name)
      .map((event) => `${event.type || 'Event'} ${event.reason || ''}: ${event.message || ''}`.trim());
    const evidence = [
      ...compactLogEvidence(log),
      ...podEvents.slice(-5),
    ];
    const diagnosis = classifyGpuDiagnostic(evidence.join('\n') || log);
    diagnostics.push({
      source: pod.name,
      namespace: pod.namespace,
      kind: 'Pod',
      nodeName: pod.nodeName || '',
      phase: diagnosis.phase,
      severity: diagnosis.severity,
      message: diagnosis.message,
      nextStep: diagnosis.nextStep,
      evidence,
    });
  }));
  pluginDaemonSets.slice(0, 12).forEach((ds) => {
    const dsEvents = (eventsByNamespace[ds.namespace] || [])
      .filter((event) => event.involvedObject?.name === ds.name)
      .map((event) => `${event.type || 'Event'} ${event.reason || ''}: ${event.message || ''}`.trim())
      .slice(-5);
    if (!dsEvents.length && ds.ready === ds.desired) return;
    const diagnosis = classifyGpuDiagnostic(dsEvents.join('\n'));
    diagnostics.push({
      source: ds.name,
      namespace: ds.namespace,
      kind: 'DaemonSet',
      nodeName: '',
      phase: diagnosis.phase,
      severity: diagnosis.severity,
      message: ds.ready === ds.desired ? 'GPU device plugin DaemonSet is rolled out.' : diagnosis.message,
      nextStep: ds.ready === ds.desired ? 'Inspect plugin Pod diagnostics and node allocatable resources.' : diagnosis.nextStep,
      evidence: dsEvents,
    });
  });
  return diagnostics.sort((a, b) => {
    const score = { Error: 0, Warning: 1, Info: 2 };
    return (score[a.severity] ?? 3) - (score[b.severity] ?? 3) || a.source.localeCompare(b.source);
  });
}

async function gpuInventory() {
  const [nodesJson, podsJson, daemonSetsJson, runtimeClassesJson] = await Promise.all([
    k8sJson('/api/v1/nodes'),
    k8sJson('/api/v1/pods'),
    k8sJson('/apis/apps/v1/daemonsets'),
    k8sJson('/apis/node.k8s.io/v1/runtimeclasses'),
  ]);
  const nodeItems = nodesJson?.items || [];
  const nodes = nodeItems.map((node) => {
    const cond = (node.status?.conditions || []).find((c) => c.type === 'Ready');
    const labels = node.metadata?.labels || {};
    const gpuResources = gpuResourcesForNode(node);
    return {
      name: node.metadata?.name || '',
      ready: cond?.status === 'True',
      schedulable: !node.spec?.unschedulable,
      gpuResources,
      gpuCapacity: gpuResources.reduce((sum, item) => sum + item.capacityNumber, 0),
      gpuAllocatable: gpuResources.reduce((sum, item) => sum + item.allocatableNumber, 0),
      gpuLabels: gpuLabelsForNode(labels),
    };
  });
  const pluginPods = (podsJson?.items || []).filter(looksLikeGpuPlugin).map((pod) => ({
    name: pod.metadata?.name || '',
    namespace: pod.metadata?.namespace || '',
    phase: pod.status?.phase || '',
    nodeName: pod.spec?.nodeName || '',
    ready: (pod.status?.containerStatuses || []).every((status) => status.ready),
    images: imageNamesFromPod(pod),
  }));
  const pluginDaemonSets = (daemonSetsJson?.items || []).filter(looksLikeGpuPlugin).map((ds) => ({
    name: ds.metadata?.name || '',
    namespace: ds.metadata?.namespace || '',
    desired: ds.status?.desiredNumberScheduled || 0,
    ready: ds.status?.numberReady || 0,
    phase: `${ds.status?.numberReady || 0}/${ds.status?.desiredNumberScheduled || 0}`,
  }));
  const runtimeClasses = (runtimeClassesJson?.items || []).map((item) => ({
    name: item.metadata?.name || '',
    handler: item.handler || '',
  }));
  const totalCapacity = nodes.reduce((sum, node) => sum + node.gpuCapacity, 0);
  const totalAllocatable = nodes.reduce((sum, node) => sum + node.gpuAllocatable, 0);
  const ready = totalAllocatable > 0;
  const diagnostics = await gpuPluginDiagnostics(pluginPods, pluginDaemonSets);
  const phase = ready ? 'GpuReady' : pluginPods.length || pluginDaemonSets.length ? 'PluginDetectedNoResource' : 'NotExposed';
  const diagnosticNextSteps = diagnostics.map((item) => item.nextStep).filter(Boolean);
  const nextSteps = ready
    ? ['Create a GPU compute backend in OAH, then run the training and inference demo tasks with that class.']
    : Array.from(new Set([
        ...diagnosticNextSteps,
        pluginPods.length || pluginDaemonSets.length
          ? 'Keep the vendor GPU device plugin deployed, but repair the node runtime until an allocatable GPU resource appears.'
          : 'Install a vendor GPU device plugin or equivalent OpenSphere GPU resource publisher on the worker that owns the host GPU.',
        'Verify kubectl describe node shows an allocatable extended resource such as nvidia.com/gpu, amd.com/gpu, or vendor.opensphere.io/gpu.',
        'Create an OAH ComputeBackend that references the exposed GPU resource, then run workbench, training, distributed workload, and inference tasks.',
      ]));
  return {
    phase,
    ready,
    generatedAt: new Date().toISOString(),
    summary: {
      nodes: nodes.length,
      readyNodes: nodes.filter((node) => node.ready).length,
      gpuNodes: nodes.filter((node) => node.gpuAllocatable > 0).length,
      totalCapacity,
      totalAllocatable,
      pluginPods: pluginPods.length,
      pluginDaemonSets: pluginDaemonSets.length,
      runtimeClasses: runtimeClasses.length,
      diagnostics: diagnostics.length,
    },
    nodes,
    pluginPods,
    pluginDaemonSets,
    runtimeClasses,
    diagnostics,
    nextSteps,
  };
}

const GPU_ENABLEMENT_PROFILES = {
  nvidia: {
    id: 'nvidia',
    label: 'NVIDIA device plugin',
    mode: 'device-plugin',
    resourceName: 'nvidia.com/gpu',
    namespace: 'kube-system',
    upstream: 'https://github.com/NVIDIA/k8s-device-plugin',
    operator: 'NVIDIA GPU Operator',
    image: 'nvcr.io/nvidia/k8s-device-plugin:replace-with-approved-version',
    runtimeClass: 'nvidia',
    summary: 'Use this when the host has NVIDIA GPUs and the container runtime is already configured for NVIDIA containers.',
    prerequisites: [
      'NVIDIA driver is installed on each GPU worker node.',
      'The container runtime can start GPU containers through the NVIDIA runtime or CDI configuration.',
      'A Kubernetes NVIDIA device plugin DaemonSet runs on GPU worker nodes.',
      'Node allocatable exposes nvidia.com/gpu before OAH schedules GPU work.',
    ],
  },
  'nvidia-operator': {
    id: 'nvidia-operator',
    label: 'NVIDIA GPU Operator / OLM',
    mode: 'operator',
    resourceName: 'nvidia.com/gpu',
    namespace: 'nvidia-gpu-operator',
    upstream: 'https://docs.nvidia.com/datacenter/cloud-native/gpu-operator/latest/index.html',
    operator: 'NVIDIA GPU Operator',
    packageName: 'gpu-operator-certified',
    channel: 'stable',
    catalogSource: 'certified-operators',
    catalogNamespace: 'openshift-marketplace',
    runtimeClass: 'nvidia',
    summary: 'Use this when the cluster has OLM/OperatorHub and you want the vendor operator to manage driver, toolkit, device plugin, DCGM, and related components.',
    prerequisites: [
      'OLM/OperatorHub is installed in the cluster.',
      'The host GPU worker nodes are compatible with NVIDIA GPU Operator driver/runtime management.',
      'A GPU Operator ClusterPolicy is approved for this cluster.',
      'Node allocatable exposes nvidia.com/gpu after the operator reconciles.',
    ],
  },
  amd: {
    id: 'amd',
    label: 'AMD ROCm device plugin',
    mode: 'device-plugin',
    resourceName: 'amd.com/gpu',
    namespace: 'kube-system',
    upstream: 'https://github.com/ROCm/k8s-device-plugin',
    operator: 'AMD GPU Operator or ROCm device plugin',
    image: 'rocm/k8s-device-plugin:replace-with-approved-version',
    runtimeClass: 'rocm',
    summary: 'Use this when the host has AMD GPUs and ROCm-capable drivers/runtime are installed on GPU worker nodes.',
    prerequisites: [
      'AMD GPU drivers and ROCm runtime are installed on each GPU worker node.',
      'The container runtime can start ROCm workloads with the required host devices mounted.',
      'An AMD GPU device plugin or AMD GPU Operator publishes amd.com/gpu.',
      'Node allocatable exposes amd.com/gpu before OAH schedules GPU work.',
    ],
  },
  intel: {
    id: 'intel',
    label: 'Intel device plugin',
    mode: 'device-plugin',
    resourceName: 'gpu.intel.com/i915',
    namespace: 'kube-system',
    upstream: 'https://github.com/intel/intel-device-plugins-for-kubernetes',
    operator: 'Intel device plugins for Kubernetes',
    image: 'intel/intel-gpu-plugin:replace-with-approved-version',
    runtimeClass: '',
    summary: 'Use this when the worker node has Intel integrated or data center GPUs and the Intel device plugin is the approved resource publisher.',
    prerequisites: [
      'Intel GPU drivers and required host device files are available on each GPU worker node.',
      'The Intel device plugin is deployed with the approved node selector and security policy.',
      'Node allocatable exposes gpu.intel.com/i915 or the cluster-approved Intel GPU resource name.',
      'OAH ComputeBackend references the same resource name before scheduling GPU work.',
    ],
  },
  generic: {
    id: 'generic',
    label: 'OpenSphere generic GPU resource',
    mode: 'device-plugin',
    resourceName: 'vendor.opensphere.io/gpu',
    namespace: 'opensphere-system',
    upstream: 'internal OpenSphere GPU resource publisher',
    operator: 'OpenSphere GPU resource publisher',
    image: 'registry.opensphere.local/gpu-resource-publisher:replace-with-approved-version',
    runtimeClass: 'opensphere-gpu',
    summary: 'Use this only when OpenSphere supplies a node-level device plugin/resource publisher for the host GPU.',
    prerequisites: [
      'A node-level OpenSphere GPU resource publisher is installed on GPU worker nodes.',
      'The publisher uses the Kubernetes device plugin API and does not patch node allocatable directly.',
      'The container runtime can pass the host GPU device into workload containers.',
      'Node allocatable exposes vendor.opensphere.io/gpu before OAH schedules GPU work.',
    ],
  },
  external: {
    id: 'external',
    label: 'Generic external GPU endpoint',
    mode: 'external',
    resourceName: 'external.opensphere.io/gpu',
    namespace: 'opensphere-system',
    upstream: 'OpenSphere external compute backend',
    operator: 'External GPU endpoint',
    runtimeClass: '',
    summary: 'Use this when Kubernetes cannot expose the host GPU, but OAH can send training or inference work to an external GPU service.',
    prerequisites: [
      'A reachable GPU service endpoint exists outside this Kubernetes cluster.',
      'Credentials are stored in a Kubernetes Secret or an external secret provider.',
      'Network policy allows OAH workloads/controllers to reach the endpoint.',
      'The external backend reports queue, execution, logs, and artifact status back to OAH.',
    ],
  },
  'docker-bridge': {
    id: 'docker-bridge',
    label: 'Local Docker GPU Bridge',
    mode: 'external-docker',
    resourceName: 'external.opensphere.io/docker-gpu',
    namespace: 'opensphere-system',
    upstream: 'OpenSphere Docker GPU Bridge',
    operator: 'OpenSphere GPU Bridge container',
    runtimeClass: '',
    defaultEndpoint: 'http://host.docker.internal:18080',
    summary: 'Use this when Docker can run --gpus all on the host, but Docker Desktop Kubernetes cannot expose a native GPU resource.',
    prerequisites: [
      'Docker Desktop can run GPU containers with docker run --gpus all.',
      'The OpenSphere GPU Bridge container is running and reachable from OAH.',
      'A Kubernetes Secret contains the bridge bearer token.',
      'The bridge supports health, capabilities, smoke jobs, logs, and cancellation.',
    ],
  },
  'windows-service': {
    id: 'windows-service',
    label: 'Windows GPU Bridge Service',
    mode: 'external-windows-service',
    resourceName: 'external.opensphere.io/windows-gpu',
    namespace: 'opensphere-system',
    upstream: 'OpenSphere Windows GPU Bridge Service',
    operator: 'Windows Service',
    runtimeClass: '',
    defaultEndpoint: 'http://host.docker.internal:18080',
    summary: 'Use this when a Windows service should expose the host GPU through the OAH external compute backend contract.',
    prerequisites: [
      'The Windows service is installed and running under an approved account.',
      'Firewall rules allow OAH to reach the configured listen address.',
      'Bridge credentials are stored securely, preferably through Windows DPAPI.',
      'The service exposes health, capabilities, smoke jobs, logs, and audit events.',
    ],
  },
  'windows-supervisor': {
    id: 'windows-supervisor',
    label: 'Windows Supervisor + Docker/WSL2 worker',
    mode: 'external-windows-supervisor',
    resourceName: 'external.opensphere.io/windows-supervisor-gpu',
    namespace: 'opensphere-system',
    upstream: 'OpenSphere Windows GPU Supervisor',
    operator: 'Windows Service supervisor',
    runtimeClass: '',
    defaultEndpoint: 'http://host.docker.internal:18080',
    summary: 'Use this when Windows should provide installation and lifecycle control while actual GPU jobs run in Docker or WSL2 Linux CUDA workers.',
    prerequisites: [
      'The supervisor service can start and monitor Docker or WSL2 worker runtimes.',
      'Worker images and job types are allowlisted.',
      'Per-job logs, cancellation, timeout, and artifact locations are reported back to OAH.',
      'The supervisor health includes worker runtime state and GPU capability evidence.',
    ],
  },
  wsl2: {
    id: 'wsl2',
    label: 'WSL2 GPU Bridge',
    mode: 'external-wsl2',
    resourceName: 'external.opensphere.io/wsl2-gpu',
    namespace: 'opensphere-system',
    upstream: 'OpenSphere WSL2 GPU Bridge',
    operator: 'WSL2 bridge service',
    runtimeClass: '',
    summary: 'Use this when WSL2 is the stable Linux CUDA runtime and OAH should call a bridge endpoint hosted inside the WSL distribution.',
    prerequisites: [
      'The WSL2 distribution can run CUDA workloads against the host GPU.',
      'A bridge service is running inside WSL2 and is reachable from OAH through IP or port proxy.',
      'Credential Secret and endpoint routing are configured.',
      'Smoke jobs prove that WSL2 can execute GPU work and return logs.',
    ],
  },
  remote: {
    id: 'remote',
    label: 'Remote external GPU backend',
    mode: 'external-remote',
    resourceName: 'external.opensphere.io/remote-gpu',
    namespace: 'opensphere-system',
    upstream: 'OpenSphere remote compute backend',
    operator: 'Remote GPU backend',
    runtimeClass: '',
    summary: 'Use this when GPU capacity lives on another workstation, server, or cloud backend and OAH should submit jobs over the external compute contract.',
    prerequisites: [
      'The remote endpoint is reachable over HTTPS or an approved private network.',
      'Credential Secret, TLS mode, and concurrency policy are configured.',
      'Capabilities report GPU models, memory, supported job types, and limits.',
      'Smoke jobs and latency checks provide visible readiness evidence.',
    ],
  },
  colab: {
    id: 'colab',
    label: 'Google Colab / notebook bridge',
    mode: 'external-notebook',
    resourceName: 'external.opensphere.io/colab-gpu',
    namespace: 'opensphere-system',
    upstream: 'https://research.google.com/colaboratory/faq.html',
    operator: 'OpenSphere notebook bridge',
    runtimeClass: '',
    summary: 'Use this only through an OpenSphere bridge service that can submit notebook jobs, collect outputs, and report status back to OAH. Consumer Colab is not a Kubernetes GPU node.',
    prerequisites: [
      'A notebook bridge endpoint exists and is reachable from OAH.',
      'The bridge owns the Colab or notebook session credentials and user consent boundary.',
      'The bridge can execute a job, stream logs, export artifacts, and report completion status.',
      'Use this for experiments or demos, not for Kubernetes-local model serving or guaranteed production scheduling.',
    ],
  },
  cpu: {
    id: 'cpu',
    label: 'CPU fallback / no GPU',
    mode: 'cpu-fallback',
    resourceName: 'cpu',
    namespace: 'opensphere-system',
    upstream: 'OpenSphere CPU fallback backend',
    operator: 'OpenSphere native scheduler',
    runtimeClass: '',
    summary: 'Use this to keep data preparation, CPU training smoke tests, evaluation, registry, promotion, and governance demos runnable while GPU exposure is being repaired.',
    prerequisites: [
      'CPU worker capacity is available.',
      'The selected tasks do not require GPU-specific libraries or model sizes.',
      'Users understand that GPU-only OAH lifecycle tasks remain blocked until a real GPU backend is configured.',
    ],
  },
};

function gpuEnablementProfile(value) {
  const key = String(value || 'nvidia').toLowerCase();
  return GPU_ENABLEMENT_PROFILES[key] || GPU_ENABLEMENT_PROFILES.nvidia;
}

function isExternalComputeMode(mode) {
  return String(mode || '').startsWith('external');
}

function externalBackendNameForProfile(profile) {
  const names = {
    external: 'external-gpu-backend',
    'docker-bridge': 'local-docker-gpu-bridge',
    'windows-service': 'windows-gpu-bridge-service',
    'windows-supervisor': 'windows-gpu-supervisor',
    wsl2: 'wsl2-gpu-bridge',
    remote: 'remote-gpu-backend',
    colab: 'colab-notebook-bridge',
  };
  return names[profile.id] || `${profile.id}-compute-backend`;
}

function backendTypeForExternalProfile(profile) {
  const types = {
    external: 'external',
    'docker-bridge': 'docker-bridge',
    'windows-service': 'windows-service',
    'windows-supervisor': 'windows-supervisor',
    wsl2: 'wsl2-bridge',
    remote: 'remote',
    colab: 'notebook-bridge',
  };
  return types[profile.id] || 'external';
}

function boolParam(url, name, fallback = false) {
  const value = url.searchParams.get(name);
  if (value === null || value === '') return fallback;
  return /^(1|true|yes|on)$/i.test(value);
}

function gpuEnablementConfig(url, profile) {
  const resourceName = url.searchParams.get('resourceName') || profile.resourceName;
  const namespace = url.searchParams.get('namespace') || profile.namespace;
  const runtimeClass = url.searchParams.get('runtimeClass') ?? profile.runtimeClass ?? '';
  const useRuntimeClass = boolParam(url, 'useRuntimeClass', false);
  const nodeSelectorKey = url.searchParams.get('nodeSelectorKey') || 'kubernetes.io/os';
  const nodeSelectorValue = url.searchParams.get('nodeSelectorValue') || 'linux';
  const pluginImage = url.searchParams.get('pluginImage') || profile.image || '';
  return {
    resourceName,
    namespace,
    runtimeClass,
    useRuntimeClass,
    nodeSelectorKey,
    nodeSelectorValue,
    pluginImage,
    packageName: url.searchParams.get('packageName') || profile.packageName || '',
    channel: url.searchParams.get('channel') || profile.channel || '',
    catalogSource: url.searchParams.get('catalogSource') || profile.catalogSource || '',
    catalogNamespace: url.searchParams.get('catalogNamespace') || profile.catalogNamespace || '',
    externalEndpoint: url.searchParams.get('externalEndpoint') || profile.defaultEndpoint || '',
    credentialSecret: url.searchParams.get('credentialSecret') || 'oah-external-gpu-credentials',
    maxConcurrency: Number(url.searchParams.get('maxConcurrency') || 1) || 1,
  };
}

function nodeSelectorFromConfig(config) {
  return config.nodeSelectorKey && config.nodeSelectorValue ? { [config.nodeSelectorKey]: config.nodeSelectorValue } : {};
}

function validHttpEndpoint(value) {
  try {
    const url = new URL(String(value || ''));
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    return false;
  }
}

async function jsonBody(req) {
  const raw = await readBody(req);
  if (!raw || !raw.length) return {};
  try {
    return JSON.parse(raw.toString('utf8'));
  } catch {
    throw { code: 400, msg: 'InvalidJsonBody' };
  }
}

function decodeSecretValue(value) {
  if (!value) return '';
  try {
    return Buffer.from(String(value), 'base64').toString('utf8').trim();
  } catch {
    return '';
  }
}

async function readGpuBridgeToken(namespace, name) {
  if (!name) return process.env.OSP_GPU_BRIDGE_TOKEN || '';
  const secret = await k8sJson(`/api/v1/namespaces/${encodeURIComponent(namespace || 'opensphere-system')}/secrets/${encodeURIComponent(name)}`);
  const token = decodeSecretValue(secret?.data?.token || secret?.data?.bearerToken || secret?.data?.apiToken);
  return token || process.env.OSP_GPU_BRIDGE_TOKEN || '';
}

function bridgeUrl(endpoint, pathName) {
  if (!validHttpEndpoint(endpoint)) throw { code: 400, msg: 'InvalidEndpoint', details: 'Endpoint must be an http:// or https:// URL reachable from OAH.' };
  const url = new URL(endpoint);
  url.pathname = `${url.pathname.replace(/\/$/, '')}${pathName}`;
  return url.toString();
}

async function fetchGpuBridge(endpoint, pathName, options = {}) {
  const headers = { Accept: 'application/json', ...(options.headers || {}) };
  const r = await fetch(bridgeUrl(endpoint, pathName), { ...options, headers });
  const text = await r.text();
  let data = {};
  try { data = text ? JSON.parse(text) : {}; } catch { data = { raw: text }; }
  if (!r.ok) throw { code: r.status, msg: data.error || data.message || `BridgeHttp${r.status}`, details: data };
  return data;
}

async function gpuBridgePayload(req) {
  const body = await jsonBody(req);
  const endpoint = String(body.endpoint || body.externalEndpoint || '').trim();
  const namespace = String(body.namespace || 'opensphere-system').trim();
  const credentialSecret = String(body.credentialSecret || 'oah-external-gpu-credentials').trim();
  const token = String(body.token || await readGpuBridgeToken(namespace, credentialSecret)).trim();
  const profile = gpuEnablementProfile(body.profile);
  return { endpoint, namespace, credentialSecret, token, profile };
}

function gpuBridgeAuthHeaders(token) {
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function gpuBridgeHealth(req) {
  const payload = await gpuBridgePayload(req);
  const health = await fetchGpuBridge(payload.endpoint, '/health');
  return {
    phase: health.status === 'ok' ? 'Reachable' : 'Unhealthy',
    ready: health.status === 'ok',
    endpoint: payload.endpoint,
    namespace: payload.namespace,
    credentialSecret: payload.credentialSecret,
    health,
    checkedAt: new Date().toISOString(),
  };
}

async function gpuBridgeCapabilities(req) {
  const payload = await gpuBridgePayload(req);
  const capabilities = await fetchGpuBridge(payload.endpoint, '/capabilities', { headers: gpuBridgeAuthHeaders(payload.token) });
  return {
    phase: capabilities.ready ? 'CapabilitiesReady' : 'CapabilitiesUnavailable',
    ready: capabilities.ready === true,
    endpoint: payload.endpoint,
    namespace: payload.namespace,
    credentialSecret: payload.credentialSecret,
    capabilities,
    checkedAt: new Date().toISOString(),
  };
}

async function gpuBridgeSmoke(req) {
  const payload = await gpuBridgePayload(req);
  const headers = { ...gpuBridgeAuthHeaders(payload.token), 'content-type': 'application/json' };
  const submitted = await fetchGpuBridge(payload.endpoint, '/jobs', {
    method: 'POST',
    headers,
    body: JSON.stringify({ jobType: 'smoke' }),
  });
  const id = submitted.id || submitted.jobId;
  let job = submitted;
  for (let i = 0; id && i < 12; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 500));
    job = await fetchGpuBridge(payload.endpoint, `/jobs/${encodeURIComponent(id)}`, { headers: gpuBridgeAuthHeaders(payload.token) });
    if (['Succeeded', 'Failed', 'Cancelled'].includes(job.phase)) break;
  }
  let logs = null;
  if (id) {
    try { logs = await fetchGpuBridge(payload.endpoint, `/jobs/${encodeURIComponent(id)}/logs`, { headers: gpuBridgeAuthHeaders(payload.token) }); } catch { logs = null; }
  }
  return {
    phase: job.phase === 'Succeeded' ? 'SmokePassed' : job.phase || 'Submitted',
    ready: job.phase === 'Succeeded',
    endpoint: payload.endpoint,
    namespace: payload.namespace,
    credentialSecret: payload.credentialSecret,
    job,
    logs,
    checkedAt: new Date().toISOString(),
  };
}

async function gpuBridgeRegister(req) {
  if (!(await crdInstalled('computebackendclaims.ai.opensphere.io'))) {
    throw { code: 409, msg: 'ComputeBackendClaim CRD is not installed', details: { crdName: 'computebackendclaims.ai.opensphere.io' } };
  }
  const body = await jsonBody(req);
  req._cachedBody = Buffer.from(JSON.stringify(body));
  const payload = await gpuBridgePayload(req);
  const profile = gpuEnablementProfile(body.profile);
  const name = requireDnsName(body.name || externalBackendNameForProfile(profile), 'backend name');
  const namespace = requireDnsName(payload.namespace || 'opensphere-system', 'namespace');
  const resourceName = optionalString(body.resourceName || profile.resourceName || 'external.opensphere.io/gpu');
  const maxConcurrency = Number(body.maxConcurrency || 1) || 1;
  const capabilities = await fetchGpuBridge(payload.endpoint, '/capabilities', { headers: gpuBridgeAuthHeaders(payload.token) });
  if (capabilities.ready !== true) {
    throw { code: 409, msg: 'Bridge capabilities are not ready', details: capabilities };
  }
  const backendType = backendTypeForExternalProfile(profile);
  const metadata = {
    name,
    namespace,
    labels: {
      'app.kubernetes.io/name': name,
      'app.kubernetes.io/part-of': 'opensphere-ai-hub',
      'opensphere.io/compute-backend': 'external-gpu',
      'opensphere.io/service-profile': profile.id,
      'opensphere.io/provider': capabilities.provider || 'external',
    },
    annotations: {
      'opensphere.io/managed-by': 'opensphere-ai-hub',
      'opensphere.io/service-profile': profile.id,
      'opensphere.io/external-endpoint': payload.endpoint,
      'opensphere.io/last-verified-at': new Date().toISOString(),
    },
  };
  const spec = {
    backendType,
    provider: capabilities.provider || profile.operator || 'external',
    resourceName,
    endpoint: payload.endpoint,
    credentialSecretRef: payload.credentialSecret,
    maxConcurrency,
    supportedJobTypes: capabilities.supportedJobTypes || [],
    artifactStores: capabilities.artifactStores || [],
  };
  const obj = {
    apiVersion: 'ai.opensphere.io/v1alpha1',
    kind: 'ComputeBackendClaim',
    metadata,
    spec,
  };
  const pathBase = `/apis/ai.opensphere.io/v1alpha1/namespaces/${namespace}/computebackendclaims`;
  const saved = await writeK8s(pathBase, 'POST', obj, req).catch(async (e) => {
    if (e.code !== 409) throw e;
    return patchK8s(`${pathBase}/${name}`, { metadata: { labels: metadata.labels, annotations: metadata.annotations }, spec }, req);
  });
  const status = {
    status: {
      phase: 'Ready',
      ready: true,
      reason: 'ExternalGpuCapabilitiesReady',
      message: `${capabilities.provider || 'external'} bridge exposes ${(capabilities.gpus || []).length} GPU(s).`,
      endpoint: payload.endpoint,
      resourceName,
      provider: capabilities.provider || 'external',
      checkedAt: metadata.annotations['opensphere.io/last-verified-at'],
      supportedJobTypes: capabilities.supportedJobTypes || [],
      gpus: capabilities.gpus || [],
      currentConcurrency: capabilities.currentConcurrency || 0,
      maxConcurrency: capabilities.maxConcurrency || maxConcurrency,
    },
  };
  const statusPath = `${pathBase}/${name}/status`;
  const savedStatus = await patchK8s(statusPath, status, req).catch(() => null);
  return {
    phase: 'Registered',
    ready: true,
    backend: itemFromK8s(savedStatus || saved, 'ComputeBackendClaim'),
    raw: savedStatus || saved,
    capabilities,
  };
}

async function gpuBridgeTrainingSmoke(req) {
  if (!(await crdInstalled('trainingjobclaims.ai.opensphere.io'))) {
    throw { code: 409, msg: 'TrainingJobClaim CRD is not installed', details: { crdName: 'trainingjobclaims.ai.opensphere.io' } };
  }
  const body = await jsonBody(req);
  req._cachedBody = Buffer.from(JSON.stringify(body));
  const payload = await gpuBridgePayload(req);
  const namespace = requireDnsName(payload.namespace || 'opensphere-system', 'namespace');
  const profile = gpuEnablementProfile(body.profile);
  const backendName = requireDnsName(body.name || body.backendName || externalBackendNameForProfile(profile), 'backend name');
  const trainingName = requireDnsName(body.trainingJobName || `${backendName}-smoke`, 'training job name');
  await gpuBridgeRegister(req);
  const backend = await k8sJson(`/apis/ai.opensphere.io/v1alpha1/namespaces/${namespace}/computebackendclaims/${backendName}`);
  if (!backend) throw { code: 404, msg: 'Registered ComputeBackendClaim was not found' };
  const runNonce = String(Date.now());
  const training = {
    apiVersion: 'ai.opensphere.io/v1alpha1',
    kind: 'TrainingJobClaim',
    metadata: {
      name: trainingName,
      namespace,
      labels: {
        'app.kubernetes.io/part-of': 'opensphere-ai-hub',
        'opensphere.io/compute-backend': backendName,
        'opensphere.io/provider': backend.spec?.provider || 'external',
      },
      annotations: {
        'opensphere.io/description': 'External GPU bridge smoke training job created by OAH.',
        'opensphere.io/managed-by': 'opensphere-ai-hub',
      },
    },
    spec: {
      computeBackendRef: {
        apiVersion: 'ai.opensphere.io/v1alpha1',
        kind: 'ComputeBackendClaim',
        name: backendName,
        namespace,
      },
      framework: 'smoke',
      trainingMode: 'smoke',
      jobType: 'smoke',
      runNonce,
    },
  };
  const pathBase = `/apis/ai.opensphere.io/v1alpha1/namespaces/${namespace}/trainingjobclaims`;
  await writeK8s(pathBase, 'POST', training, req).catch(async (e) => {
    if (e.code !== 409) throw e;
    await patchK8s(`${pathBase}/${trainingName}`, { metadata: { labels: training.metadata.labels, annotations: training.metadata.annotations }, spec: training.spec }, req);
  });
  const claim = await k8sJson(`${pathBase}/${trainingName}`);
  const target = PASSIVE_RECONCILE_TARGETS.find((item) => item.kind === 'TrainingJobClaim');
  const reconcile = await reconcileExternalTrainingJobClaim(target, claim, backend);
  const latest = await k8sJson(`${pathBase}/${trainingName}`);
  return {
    phase: latest?.status?.phase || reconcile.phase,
    ready: latest?.status?.ready === true,
    backend: itemFromK8s(backend, 'ComputeBackendClaim'),
    trainingJob: itemFromK8s(latest || claim, 'TrainingJobClaim'),
    raw: latest || claim,
    reconcile,
  };
}

function gpuEnablementManifests(profile, config) {
  const labels = {
    'app.kubernetes.io/name': 'opensphere-gpu-enablement-preview',
    'app.kubernetes.io/part-of': 'opensphere-ai-hub',
    'opensphere.io/preview-only': 'true',
  };
  if (profile.mode === 'operator') {
    return [
      {
        apiVersion: 'v1',
        kind: 'Namespace',
        metadata: { name: config.namespace, labels },
      },
      {
        apiVersion: 'operators.coreos.com/v1',
        kind: 'OperatorGroup',
        metadata: { name: `${profile.id}-operator-group`, namespace: config.namespace, labels },
        spec: { targetNamespaces: [config.namespace] },
      },
      {
        apiVersion: 'operators.coreos.com/v1alpha1',
        kind: 'Subscription',
        metadata: { name: config.packageName, namespace: config.namespace, labels },
        spec: {
          name: config.packageName,
          channel: config.channel,
          source: config.catalogSource,
          sourceNamespace: config.catalogNamespace,
          installPlanApproval: 'Manual',
        },
      },
      {
        apiVersion: 'nvidia.com/v1',
        kind: 'ClusterPolicy',
        metadata: {
          name: 'gpu-cluster-policy',
          labels,
          annotations: { 'opensphere.io/apply-mode': 'preview-only' },
        },
        spec: {
          devicePlugin: { enabled: true },
          dcgmExporter: { enabled: true },
          toolkit: { enabled: true },
          driver: { enabled: true },
        },
      },
    ];
  }
  if (isExternalComputeMode(profile.mode)) {
    return [
      {
        apiVersion: 'v1',
        kind: 'Secret',
        metadata: {
          name: config.credentialSecret,
          namespace: config.namespace,
          labels,
          annotations: { 'opensphere.io/apply-mode': 'template-only' },
        },
        type: 'Opaque',
        stringData: {
          token: '<external-gpu-token>',
        },
      },
      {
        apiVersion: 'ai.opensphere.io/v1alpha1',
        kind: 'ComputeBackendClaim',
        metadata: { name: externalBackendNameForProfile(profile), namespace: config.namespace, labels },
        spec: {
          backendType: backendTypeForExternalProfile(profile),
          resourceName: config.resourceName,
          endpoint: config.externalEndpoint || (profile.mode === 'external-notebook' ? '<https://notebook-bridge.example.internal>' : '<https://gpu.example.internal>'),
          credentialSecretRef: config.credentialSecret,
          maxConcurrency: config.maxConcurrency,
        },
      },
    ];
  }
  if (profile.mode === 'cpu-fallback') {
    return [
      {
        apiVersion: 'ai.opensphere.io/v1alpha1',
        kind: 'ComputeBackendClaim',
        metadata: { name: 'cpu-fallback-backend', namespace: config.namespace, labels },
        spec: {
          backendType: 'kubernetes',
          resourceName: 'cpu',
          gpuRequired: false,
          maxConcurrency: config.maxConcurrency,
        },
      },
    ];
  }
  const daemonSet = {
    apiVersion: 'apps/v1',
    kind: 'DaemonSet',
    metadata: {
      name: profile.id === 'generic' ? 'opensphere-gpu-resource-publisher' : `${profile.id}-gpu-device-plugin`,
      namespace: config.namespace,
      labels,
      annotations: {
        'opensphere.io/apply-mode': 'preview-only',
        'opensphere.io/notice': 'Replace image/runtime details with a cluster-approved upstream manifest before applying.',
      },
    },
    spec: {
      selector: { matchLabels: { 'app.kubernetes.io/name': labels['app.kubernetes.io/name'], 'opensphere.io/gpu-provider': profile.id } },
      template: {
        metadata: { labels: { ...labels, 'opensphere.io/gpu-provider': profile.id } },
        spec: {
          serviceAccountName: profile.id === 'generic' ? 'opensphere-gpu-resource-publisher' : `${profile.id}-gpu-device-plugin`,
          priorityClassName: 'system-node-critical',
          tolerations: [{ operator: 'Exists' }],
          nodeSelector: nodeSelectorFromConfig(config),
          containers: [
            {
              name: 'device-plugin',
              image: config.pluginImage,
              imagePullPolicy: 'IfNotPresent',
              securityContext: { privileged: true },
              env: [
                { name: 'GPU_RESOURCE_NAME', value: config.resourceName },
                { name: 'OAH_PREVIEW_ONLY', value: 'true' },
              ],
              volumeMounts: [{ name: 'device-plugin', mountPath: '/var/lib/kubelet/device-plugins' }],
            },
          ],
          volumes: [{ name: 'device-plugin', hostPath: { path: '/var/lib/kubelet/device-plugins', type: 'DirectoryOrCreate' } }],
        },
      },
    },
  };
  if (config.useRuntimeClass && config.runtimeClass) {
    daemonSet.spec.template.spec.runtimeClassName = config.runtimeClass;
  }
  const runtimeClass = {
    apiVersion: 'node.k8s.io/v1',
    kind: 'RuntimeClass',
    metadata: {
      name: config.runtimeClass,
      labels,
      annotations: {
        'opensphere.io/apply-mode': 'optional-preview',
        'opensphere.io/notice': 'Create only when the container runtime defines this handler.',
      },
    },
    handler: config.runtimeClass,
  };
  return config.useRuntimeClass && config.runtimeClass ? [daemonSet, runtimeClass] : [daemonSet];
}

async function gpuEnablementPlan(req) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const profile = gpuEnablementProfile(url.searchParams.get('profile'));
  const config = gpuEnablementConfig(url, profile);
  const inventory = await gpuInventory();
  const detectedResource = inventory.nodes
    .flatMap((node) => node.gpuResources || [])
    .find((resource) => resource.name === config.resourceName && resource.allocatableNumber > 0);
  const pluginDetected = [...(inventory.pluginDaemonSets || []), ...(inventory.pluginPods || [])]
    .some((item) => `${item.name} ${item.namespace} ${(item.images || []).join(' ')}`.toLowerCase().includes(profile.id.split('-')[0]));
  const operatorDetected = profile.mode === 'operator' && (inventory.pluginDaemonSets || []).some((item) => /nvidia|gpu-operator/i.test(`${item.name} ${item.namespace}`));
  const isExternalMode = isExternalComputeMode(profile.mode);
  const externalEndpointPresent = isExternalMode && !!config.externalEndpoint;
  const externalEndpointValid = isExternalMode && validHttpEndpoint(config.externalEndpoint);
  const externalConfigured = externalEndpointValid;
  const cpuFallback = profile.mode === 'cpu-fallback';
  const checks = [
    {
      id: 'gpu-node',
      label: 'GPU worker node detected',
      phase: inventory.summary.gpuNodes > 0 ? 'Ready' : isExternalMode || cpuFallback ? 'NotRequired' : 'Missing',
      ready: inventory.summary.gpuNodes > 0 || isExternalMode || cpuFallback,
      detail: isExternalMode
        ? 'External GPU and notebook bridge modes do not require Kubernetes node allocatable GPU resources.'
        : cpuFallback
          ? 'CPU fallback does not require a GPU worker node.'
          : `${inventory.summary.gpuNodes} node(s) expose allocatable GPU resources.`,
    },
    {
      id: 'provider-resource',
      label: `${config.resourceName} allocatable`,
      phase: detectedResource ? 'Ready' : isExternalMode || cpuFallback ? 'NotRequired' : 'Missing',
      ready: !!detectedResource || isExternalMode || cpuFallback,
      detail: detectedResource
        ? `${detectedResource.allocatable} ${config.resourceName} allocatable.`
        : isExternalMode
          ? `${config.resourceName} is represented by an external ComputeBackend or notebook bridge, not node allocatable.`
          : cpuFallback
            ? 'CPU fallback uses normal Kubernetes CPU scheduling.'
            : `${config.resourceName} is not exposed by any node.`,
    },
    {
      id: 'device-plugin',
      label: `${profile.label} detected`,
      phase: pluginDetected || operatorDetected ? 'Detected' : isExternalMode || cpuFallback ? 'NotRequired' : 'NotDetected',
      ready: pluginDetected || operatorDetected || isExternalMode || cpuFallback,
      detail: pluginDetected || operatorDetected
        ? 'A matching plugin pod, DaemonSet, or operator-managed component is visible.'
        : isExternalMode
          ? 'External GPU and notebook bridge modes use a service endpoint instead of a node device plugin.'
          : cpuFallback
            ? 'CPU fallback intentionally skips GPU device plugins.'
            : 'No matching plugin pod or DaemonSet is visible in the cluster inventory.',
    },
    {
      id: 'runtime-class',
      label: `${config.runtimeClass || 'default'} RuntimeClass`,
      phase: !config.useRuntimeClass ? 'NotRequired' : inventory.runtimeClasses.some((item) => item.name === config.runtimeClass) ? 'Ready' : 'Missing',
      ready: !config.useRuntimeClass || inventory.runtimeClasses.some((item) => item.name === config.runtimeClass),
      detail: config.useRuntimeClass
        ? 'Required because this plan is configured to schedule GPU Pods with runtimeClassName.'
        : 'Not required for this plan unless the node runtime uses a named GPU handler.',
    },
  ];
  if (profile.mode === 'operator') {
    checks.push({
      id: 'olm',
      label: 'OLM / OperatorHub',
      phase: 'CheckRequired',
      ready: false,
      detail: `Subscription preview targets package ${config.packageName}, channel ${config.channel}, catalog ${config.catalogSource}/${config.catalogNamespace}.`,
    });
  }
  if (isExternalMode) {
    checks.push({
      id: 'external-endpoint',
      label: profile.mode === 'external-notebook' ? 'Notebook bridge endpoint configured' : 'External endpoint configured',
      phase: externalEndpointValid ? 'Configured' : externalEndpointPresent ? 'InvalidEndpoint' : profile.mode === 'external-notebook' ? 'BridgeRequired' : 'Missing',
      ready: externalConfigured,
      detail: externalEndpointValid
        ? config.externalEndpoint
        : externalEndpointPresent
          ? 'Enter a valid http:// or https:// endpoint that OAH can reach.'
          : profile.mode === 'external-notebook'
            ? 'Enter an OpenSphere notebook bridge endpoint. A normal Colab notebook URL is not enough for managed OAH scheduling.'
            : 'Enter a reachable external GPU service endpoint.',
    });
    checks.push({
      id: 'external-credentials',
      label: 'Credential Secret name configured',
      phase: config.credentialSecret ? 'Configured' : 'Missing',
      ready: !!config.credentialSecret,
      detail: config.credentialSecret ? `Secret ${config.credentialSecret} is referenced. Confirm it contains a real token before applying.` : 'Enter the Secret name that contains credentials for the external GPU service.',
    });
  }
  const commands = [
    `kubectl get nodes -o custom-columns=NAME:.metadata.name,READY:.status.conditions[-1].status,${config.resourceName.replace(/[^A-Za-z0-9]/g, '_')}:.status.allocatable['${config.resourceName}']`,
    `kubectl describe node <gpu-node-name> | grep -A8 Allocatable`,
    profile.mode === 'operator'
      ? `kubectl -n ${config.namespace} get subscription,installplan,csv`
      : `kubectl -n ${config.namespace} get ds,pods | grep -Ei 'gpu|nvidia|amd|intel|rocm|device-plugin|opensphere'`,
    isExternalMode
      ? `kubectl -n ${config.namespace} get computebackendclaim ${externalBackendNameForProfile(profile)} -o yaml`
      : profile.mode === 'cpu-fallback'
        ? `kubectl -n ${config.namespace} get computebackendclaim cpu-fallback-backend -o yaml`
        : `kubectl run oah-gpu-smoke --rm -it --restart=Never --image=<gpu-runtime-image> --limits=${config.resourceName}=1 -- <gpu-smoke-command>`,
  ];
  const phase = detectedResource
    ? 'GpuResourceReady'
    : externalConfigured
      ? profile.mode === 'external-notebook' ? 'NotebookBridgeConfigured' : 'ExternalGpuConfigured'
      : externalEndpointPresent && !externalEndpointValid
        ? profile.mode === 'external-notebook' ? 'BridgeEndpointInvalid' : 'ExternalEndpointInvalid'
      : profile.mode === 'external-notebook'
        ? 'BridgeRequired'
      : isExternalMode
        ? 'ExternalEndpointRequired'
      : cpuFallback
        ? 'CpuFallbackConfigured'
        : pluginDetected || operatorDetected
          ? 'PluginNeedsNodeResource'
          : profile.mode === 'operator'
            ? 'OperatorInstallRequired'
            : 'InstallRequired';
  return {
    profile: profile.id,
    title: `${profile.label} enablement plan`,
    phase,
    generatedAt: new Date().toISOString(),
    summary: detectedResource
      ? `${config.resourceName} is already exposed. OAH can use this resource for GPU work.`
      : externalConfigured
        ? profile.mode === 'external-notebook'
          ? `OAH can route notebook-style GPU work through bridge endpoint ${config.externalEndpoint}. Kubernetes-local GPU tasks still require node GPU exposure.`
          : `OAH can route GPU lifecycle work to external endpoint ${config.externalEndpoint}, but Kubernetes-local GPU tasks still require node GPU exposure.`
        : profile.mode === 'external-notebook'
          ? 'Google Colab can only be used through a bridge endpoint that OAH can call. OAH cannot schedule Kubernetes Pods directly onto a normal Colab session.'
        : cpuFallback
          ? 'OAH can run non-GPU lifecycle tasks and CPU smoke demos while GPU exposure is repaired.'
          : `${profile.summary} OAH will not mark Kubernetes-local GPU lifecycle tasks runnable until Kubernetes exposes ${config.resourceName}.`,
    resourceName: config.resourceName,
    namespace: config.namespace,
    upstream: profile.upstream,
    operator: profile.operator,
    mode: profile.mode,
    config,
    alternatives: Object.values(GPU_ENABLEMENT_PROFILES).map((item) => ({
      id: item.id,
      label: item.label,
      mode: item.mode,
      resourceName: item.resourceName,
      summary: item.summary,
    })),
    inventory: { phase: inventory.phase, ready: inventory.ready, summary: inventory.summary },
    prerequisites: profile.prerequisites.map((item, index) => ({ id: `${profile.id}-prereq-${index + 1}`, text: item })),
    checks,
    commands,
    manifests: gpuEnablementManifests(profile, config),
    warnings: [
      'This is a preview plan. Do not apply the generated manifest until the image tag, runtime handler, driver stack, and security policy are approved for this cluster.',
      'Kubernetes node allocatable must come from a device plugin/resource publisher. OAH cannot make a host GPU schedulable by creating only application CRDs.',
    ],
  };
}

function computeBackendKey(item) {
  return `${item.namespace || 'default'}/${item.name}`;
}

function normalizeBackendKey(value) {
  const key = optionalString(value);
  if (!key || key === 'auto' || key === 'cpu-fallback') return key;
  const parts = key.split('/');
  if (parts.length !== 2) throw { code: 400, msg: `Backend reference must be namespace/name, auto, or cpu-fallback: ${key}` };
  return `${requireDnsName(parts[0], 'backend namespace')}/${requireDnsName(parts[1], 'backend name')}`;
}

function computeBackendOptions(backends) {
  const options = (backends || []).map((item) => ({
    key: computeBackendKey(item),
    name: item.name,
    namespace: item.namespace || 'default',
    label: `${item.namespace || 'default'}/${item.name}`,
    backendType: item.backendType || item.backendMode || item.kind || 'unknown',
    provider: item.provider || '',
    endpoint: item.endpoint || '',
    resourceName: item.resourceName || '',
    phase: item.phase || 'Unknown',
    ready: item.ready === true,
    message: item.message || item.reason || item.description || '',
  }));
  options.unshift({
    key: 'auto',
    name: 'auto',
    namespace: '',
    label: 'Auto - OAH selects a ready backend',
    backendType: 'auto',
    provider: 'opensphere',
    endpoint: '',
    resourceName: '',
    phase: 'Policy',
    ready: true,
    message: 'Use the active OAH routing policy for this workload.',
  });
  options.push({
    key: 'cpu-fallback',
    name: 'cpu-fallback',
    namespace: 'opensphere-system',
    label: 'CPU fallback',
    backendType: 'cpu',
    provider: 'opensphere',
    endpoint: '',
    resourceName: 'cpu',
    phase: 'Fallback',
    ready: true,
    message: 'Use this only for workloads that do not require GPU execution.',
  });
  return options;
}

function preferredBackendKey(options, policy) {
  const usable = (options || []).filter((item) => item.ready && item.key !== 'auto' && item.key !== 'cpu-fallback');
  const external = usable.find((item) => /external|notebook/i.test(`${item.backendType} ${item.provider}`));
  const kubernetes = usable.find((item) => /kubernetes|native|device/i.test(`${item.backendType} ${item.provider}`));
  if (policy === 'external-first') return external?.key || kubernetes?.key || 'cpu-fallback';
  if (policy === 'kubernetes-first') return kubernetes?.key || external?.key || 'cpu-fallback';
  if (policy === 'external-or-cpu') return external?.key || 'cpu-fallback';
  if (policy === 'kubernetes-or-cpu') return kubernetes?.key || 'cpu-fallback';
  return usable[0]?.key || 'cpu-fallback';
}

async function readComputeRoutingConfig() {
  const cm = await k8sJson(`/api/v1/namespaces/opensphere-system/configmaps/${COMPUTE_ROUTING_CONFIGMAP}`);
  if (!cm?.data?.routing) return { routes: {}, updatedAt: '', updatedBy: '' };
  try {
    const parsed = JSON.parse(cm.data.routing);
    return { routes: parsed.routes || {}, updatedAt: parsed.updatedAt || '', updatedBy: parsed.updatedBy || '' };
  } catch {
    return { routes: {}, updatedAt: '', updatedBy: '', parseError: 'Invalid routing JSON in ConfigMap.' };
  }
}

async function computeRouting() {
  const [backends, config] = await Promise.all([
    aiResources('compute'),
    readComputeRoutingConfig(),
  ]);
  const options = computeBackendOptions(backends);
  const byKey = new Map(options.map((item) => [item.key, item]));
  const rows = COMPUTE_ROUTING_WORKLOADS.map((workload) => {
    const saved = config.routes?.[workload.id] || {};
    const primary = normalizeBackendKey(saved.primary || preferredBackendKey(options, workload.defaultPolicy));
    const fallback = normalizeBackendKey(saved.fallback || preferredBackendKey(options, workload.fallbackPolicy));
    const primaryOption = byKey.get(primary);
    const fallbackOption = byKey.get(fallback);
    const ready = primary === 'auto' || primaryOption?.ready === true;
    return {
      ...workload,
      primary,
      fallback,
      primaryBackend: primaryOption || null,
      fallbackBackend: fallbackOption || null,
      phase: ready ? 'Routable' : 'BackendUnavailable',
      ready,
      message: ready
        ? `${workload.label} will use ${primaryOption?.label || primary}.`
        : `${workload.label} primary backend ${primary} is not registered or not ready.`,
    };
  });
  const ready = rows.every((row) => row.ready);
  return {
    namespace: 'opensphere-system',
    name: COMPUTE_ROUTING_CONFIGMAP,
    phase: ready ? 'Ready' : 'NeedsBackend',
    ready,
    updatedAt: config.updatedAt,
    updatedBy: config.updatedBy,
    parseError: config.parseError || '',
    options,
    routes: rows,
  };
}

function workloadIdForCreatePage(page) {
  if (page === 'training-jobs') return 'training';
  if (page === 'inference') return 'serving';
  if (page === 'workbenches') return 'notebooks';
  if (page === 'pipelines' || page === 'pipeline-runs') return 'pipelines';
  if (page === 'distributed-workloads') return 'distributed';
  return '';
}

async function routedComputeBackendForWorkload(workloadId) {
  if (!workloadId) return null;
  const routing = await computeRouting();
  const route = (routing.routes || []).find((item) => item.id === workloadId);
  if (!route) return null;
  let key = route.primary;
  if (key === 'auto') {
    key = preferredBackendKey(routing.options || [], route.defaultPolicy);
  }
  if (!key || key === 'auto' || key === 'cpu-fallback') return null;
  let option = (routing.options || []).find((item) => item.key === key);
  if (!option || option.ready !== true) {
    key = route.fallback === 'auto' ? preferredBackendKey(routing.options || [], route.fallbackPolicy) : route.fallback;
    if (!key || key === 'auto' || key === 'cpu-fallback') return null;
    option = (routing.options || []).find((item) => item.key === key);
  }
  if (!option || option.ready !== true) return null;
  return {
    key,
    name: option.name,
    namespace: option.namespace,
    phase: option.phase,
    backendType: option.backendType,
    resourceName: option.resourceName,
    endpoint: option.endpoint,
  };
}

async function applyComputeRoutingDefaults(page, body, namespace) {
  if (body.computeBackendRef || body.computeBackendName) return { body, routedBackend: null };
  const routedBackend = await routedComputeBackendForWorkload(workloadIdForCreatePage(page));
  if (!routedBackend) return { body, routedBackend: null };
  return {
    body: {
      ...body,
      computeBackendRef: { name: routedBackend.name, namespace: routedBackend.namespace },
      computeBackendName: routedBackend.name,
      computeBackendNamespace: routedBackend.namespace,
    },
    routedBackend,
  };
}

async function saveComputeRouting(req) {
  const body = await jsonBody(req);
  const current = await computeRouting();
  const routeInput = Array.isArray(body.routes) ? body.routes : [];
  const existing = new Map(current.routes.map((row) => [row.id, row]));
  const routes = {};
  for (const workload of COMPUTE_ROUTING_WORKLOADS) {
    const incoming = routeInput.find((row) => row.id === workload.id) || {};
    const previous = existing.get(workload.id) || {};
    routes[workload.id] = {
      primary: normalizeBackendKey(incoming.primary ?? previous.primary ?? 'auto') || 'auto',
      fallback: normalizeBackendKey(incoming.fallback ?? previous.fallback ?? 'cpu-fallback') || 'cpu-fallback',
    };
  }
  const actor = req?.headers?.['x-os-id-token'] ? await requestActor(req) : null;
  const data = {
    version: 1,
    updatedAt: new Date().toISOString(),
    updatedBy: actor?.username || 'opensphere-ai-hub',
    routes,
  };
  const cm = {
    apiVersion: 'v1',
    kind: 'ConfigMap',
    metadata: {
      name: COMPUTE_ROUTING_CONFIGMAP,
      namespace: 'opensphere-system',
      labels: {
        'app.kubernetes.io/name': COMPUTE_ROUTING_CONFIGMAP,
        'app.kubernetes.io/part-of': 'opensphere-ai-hub',
        'opensphere.io/config-kind': 'compute-routing',
      },
    },
    data: {
      routing: JSON.stringify(data, null, 2),
    },
  };
  await writeK8s('/api/v1/namespaces/opensphere-system/configmaps', 'POST', cm, req).catch(async (e) => {
    if (e.code !== 409) throw e;
    await patchK8s(`/api/v1/namespaces/opensphere-system/configmaps/${COMPUTE_ROUTING_CONFIGMAP}`, { metadata: { labels: cm.metadata.labels }, data: cm.data }, req);
  });
  return computeRouting();
}

async function oahDemoPlan(req) {
  const [gpuResult, readinessResult, backendsResult, summaryResult] = await Promise.allSettled([
    gpuInventory(),
    finalReadiness(req),
    nativeBackends(),
    summary(),
  ]);
  const gpu = gpuResult.status === 'fulfilled' ? gpuResult.value : { ready: false, phase: 'Unavailable', summary: {}, nextSteps: ['GPU inventory API failed.'] };
  const readiness = readinessResult.status === 'fulfilled' ? readinessResult.value : { nativePhase: 'Unknown', upstreamPhase: 'Unknown', summary: {} };
  const backends = backendsResult.status === 'fulfilled' ? backendsResult.value : { summary: { phase: 'Unknown', fallbackReady: 0, total: 0 }, items: [] };
  const overview = summaryResult.status === 'fulfilled' ? summaryResult.value : {};
  const nativeReady = readiness.nativePhase === 'Ready' || readiness.nativePhase === 'ReadyWithWarnings';
  const phase = nativeReady && gpu.ready ? 'DemoReady' : nativeReady ? 'NeedsGpuExposure' : 'NeedsPlatformReadiness';
  const task = (id, stage, title, oahArea, resources, expected, requiresGpu, ready, notes = []) => ({
    id,
    stage,
    title,
    oahArea,
    resources,
    expected,
    requiresGpu,
    status: requiresGpu && !gpu.ready ? 'BlockedByGpu' : ready ? 'Runnable' : 'NeedsSetup',
    notes,
  });
  const tasks = [
    task('project', 'Workspace', 'Create an isolated AI project namespace for the demo', 'Data science projects', ['Namespace', 'Project metadata'], 'Project is Active and becomes the owner boundary for later resources.', false, true),
    task('data-connection', 'Workspace', 'Register dataset and object storage connection', 'Workbenches / Data connections', ['Secret', 'DataConnection'], 'Workbench and pipeline tasks can mount the same dataset reference.', false, true),
    task('gpu-compute', 'Compute', 'Create a GPU compute backend bound to cluster GPU resources', 'Training / Compute', ['ComputeBackend', 'Node allocatable GPU'], 'OAH schedules GPU work against nvidia.com/gpu, amd.com/gpu, or vendor.opensphere.io/gpu.', true, gpu.ready, gpu.ready ? [] : gpu.nextSteps),
    task('workbench', 'Develop', 'Start a notebook workbench using the GPU compute backend', 'Workbenches', ['WorkbenchClaim', 'Pod', 'PVC'], 'User can open a notebook and verify GPU visibility from the runtime.', true, gpu.ready),
    task('pipeline', 'Train', 'Run a reproducible training pipeline', 'Data science pipelines', ['PipelineRunClaim', 'DatasetClaim', 'Artifact'], 'Pipeline creates training lineage, execution records, and model artifacts.', true, gpu.ready),
    task('training-job', 'Train', 'Launch a standalone model training job', 'Training jobs', ['TrainingJobClaim', 'ComputeBackend'], 'Job reports queued/running/succeeded state and exposes logs for retry or suspend.', true, gpu.ready),
    task('distributed', 'Scale', 'Run distributed training with queue-aware scheduling', 'Distributed workloads', ['DistributedWorkloadClaim', 'Kueue/Ray equivalent fallback'], 'Workload shows placement, replicas, and queue status.', true, gpu.ready),
    task('experiment', 'Track', 'Capture experiment, execution, and artifact lineage', 'Experiments', ['ExperimentRun', 'Execution', 'Artifact'], 'User can compare runs and see produced model artifact references.', false, true),
    task('evaluation', 'Govern', 'Evaluate the model with policy gates', 'Evaluation', ['EvaluationPolicy', 'EvaluationJob'], 'Promotion is blocked or allowed using explicit evaluation status.', false, true),
    task('registry', 'Govern', 'Register a model version in the OAH model registry', 'Models / Registry', ['OpenSphereModelRegistry', 'ModelVersion'], 'Model version, source artifact, metrics, and approval history are visible.', false, true),
    task('promotion', 'Release', 'Promote approved model version to serving', 'Models / Promotions', ['ModelPromotionClaim'], 'Promotion audit shows requester, decision, and target environment.', false, true),
    task('inference', 'Serve', 'Deploy inference endpoint backed by the promoted model', 'Inference endpoints', ['InferenceClaim', 'Deployment', 'Service'], 'Endpoint becomes Ready and can be edited, retried, or deleted from OAH.', true, gpu.ready),
    task('agent', 'Use', 'Bind retrieval, tools, and route policy to an AI agent', 'Foundation / Agents', ['AIAgent', 'RetrievalClaim', 'RoutePolicy'], 'Agent uses governed retrieval and tool policy against the served model.', false, true),
    task('monitoring', 'Operate', 'Monitor inference quality and drift signals', 'Monitoring', ['MonitoringTarget', 'TrustyAI metrics fallback'], 'Dashboard shows metrics, alert rows, and retained audit events.', false, true),
    task('readiness', 'Operate', 'Prove platform readiness and auditability', 'Cluster settings', ['Native readiness', 'Controller metrics', 'Audit log'], 'Operator can verify native readiness, backend mode, GPU status, and audit log in one place.', false, nativeReady),
  ];
  return {
    title: 'OpenSphere AI Hub GPU lifecycle demo',
    acronym: 'OAH',
    phase,
    generatedAt: new Date().toISOString(),
    summary: phase === 'DemoReady'
      ? 'OAH native services and Kubernetes GPU exposure are ready for an end-to-end GPU lifecycle demo.'
      : phase === 'NeedsGpuExposure'
        ? 'OAH native services are ready, but Kubernetes does not currently expose an allocatable GPU resource.'
        : 'OAH needs platform readiness work before the full demo can run.',
    prerequisites: [
      { id: 'oah-native', label: 'OAH native platform', ready: nativeReady, required: true, detail: `Native phase ${readiness.nativePhase || readiness.phase || 'Unknown'}.` },
      { id: 'gpu-resource', label: 'Kubernetes GPU resource', ready: !!gpu.ready, required: true, detail: `${gpu.summary?.totalAllocatable || 0} allocatable GPU(s), ${gpu.summary?.gpuNodes || 0} GPU node(s).` },
      { id: 'backend-coverage', label: 'Lifecycle backend coverage', ready: backends.summary?.unavailable === 0, required: true, detail: `${backends.summary?.fallbackReady || 0}/${backends.summary?.total || 0} native fallback backend(s), phase ${backends.summary?.phase || 'Unknown'}.` },
      { id: 'upstream-parity', label: 'ODH/RHOAI upstream parity', ready: readiness.upstreamPhase === 'Ready', required: false, detail: `Upstream phase ${readiness.upstreamPhase || 'Unknown'}; optional for OpenSphere-native demo.` },
    ],
    evidence: [
      { label: 'Projects', value: String(summaryCount(overview.projects)) },
      { label: 'Workbenches', value: String(summaryCount(overview.workbenches)) },
      { label: 'Pipelines', value: String(summaryCount(overview.pipelines)) },
      { label: 'Monitoring targets', value: String(summaryCount(overview.monitoringTargets)) },
      { label: 'GPU phase', value: gpu.phase },
    ],
    tasks,
    gpu,
  };
}

const OAH_DEMO_LABEL = 'oah-gpu-lifecycle';
const OAH_DEMO_NAMESPACE = 'oah-gpu-lifecycle-demo';

function firstGpuClass(gpu) {
  for (const node of gpu?.nodes || []) {
    for (const resource of node.gpuResources || []) {
      if (resource.allocatableNumber > 0) return resource.name;
    }
  }
  return 'vendor.opensphere.io/gpu';
}

function demoStep(page, name, stage, title, body = {}, options = {}) {
  return { page, name, stage, title, body, requiresGpu: options.requiresGpu === true };
}

function oahDemoSteps(namespace, gpu) {
  const gpuClass = firstGpuClass(gpu);
  return [
    demoStep('data-connections', 'oah-demo-bucket', 'Workspace', 'Register shared data connection', {
      namespace,
      sourceType: 'bucket',
      sourceRef: 's3://opensphere-demo/lifecycle',
      purpose: 'training-and-evaluation',
      description: 'OAH demo data connection used by workbench, pipeline, and training tasks.',
    }),
    demoStep('datasets', 'oah-demo-dataset', 'Workspace', 'Register training and evaluation dataset', {
      namespace,
      sourceType: 'bucket',
      sourceRef: 'oah-demo-bucket',
      purpose: 'gpu-lifecycle-demo',
      description: 'Dataset declaration for the OAH GPU lifecycle demo.',
    }),
    demoStep('compute', 'oah-gpu-backend', 'Compute', 'Create GPU compute backend', {
      namespace,
      backendType: 'kubernetes',
      gpuClass,
      description: `GPU compute backend targeting ${gpuClass}.`,
    }, { requiresGpu: true }),
    demoStep('workbenches', 'oah-gpu-workbench', 'Develop', 'Start GPU workbench claim', {
      namespace,
      image: 'standard-data-science',
      sourceRef: 'oah-demo-bucket',
      gpuClass,
      description: 'Notebook workbench for validating GPU visibility and preparing the model.',
    }, { requiresGpu: true }),
    demoStep('experiments-runs', 'oah-demo-experiment', 'Track', 'Create experiment tracking scope', {
      namespace,
      datasetRef: 'oah-demo-dataset',
      metric: 'accuracy',
      description: 'Experiment scope for comparing OAH demo training runs.',
    }),
    demoStep('pipelines', 'oah-train-pipeline', 'Train', 'Register training pipeline', {
      namespace,
      sourceRef: 'oah-demo-bucket',
      datasetRef: 'oah-demo-dataset',
      computeBackendRef: 'oah-gpu-backend',
      framework: 'kubeflow-pipeline',
      description: 'Pipeline declaration for the OAH train/evaluate/promote demo.',
    }),
    demoStep('pipeline-runs', 'oah-train-pipeline-run', 'Train', 'Run training pipeline', {
      namespace,
      pipelineRef: 'oah-train-pipeline',
      sourceRef: 'oah-train-pipeline',
      targetRef: 'oah-demo-experiment',
      datasetRef: 'oah-demo-dataset',
      trainingMode: 'lora',
      backendType: 'auto',
      description: 'Pipeline run for the OAH GPU lifecycle demo.',
    }, { requiresGpu: true }),
    demoStep('training-jobs', 'oah-model-train', 'Train', 'Launch GPU training job', {
      namespace,
      computeBackendRef: 'oah-gpu-backend',
      datasetRef: 'oah-demo-dataset',
      framework: 'transformers',
      trainingMode: 'lora',
      description: 'GPU-backed training job for the OAH lifecycle demo.',
    }, { requiresGpu: true }),
    demoStep('executions', 'oah-training-execution', 'Track', 'Track training execution', {
      namespace,
      targetRef: 'oah-demo-experiment',
      sourceRef: 'oah-train-pipeline-run',
      stage: 'training',
      description: 'Execution record linking the demo experiment to the pipeline run.',
    }),
    demoStep('artifacts', 'oah-model-artifact', 'Track', 'Register trained model artifact', {
      namespace,
      sourceType: 'model',
      sourceRef: 'oah-model-train',
      stage: 'candidate',
      description: 'Candidate model artifact produced by the OAH demo training flow.',
    }),
    demoStep('eval-policy', 'oah-safety-policy', 'Govern', 'Create evaluation policy gate', {
      namespace,
      datasetRef: 'oah-demo-dataset',
      metric: 'groundedness',
      minimum: 0.8,
      enforcement: 'block',
      description: 'Policy gate used before promoting the OAH demo model.',
    }),
    demoStep('eval-jobs', 'oah-model-eval', 'Govern', 'Run evaluation job', {
      namespace,
      policyRef: 'oah-safety-policy',
      targetRef: 'oah-model-train',
      promotionRef: 'oah-model-promotion',
      description: 'Evaluation job for the OAH demo candidate model.',
    }),
    demoStep('model-promotion', 'oah-model-promotion', 'Release', 'Promote evaluated model', {
      namespace,
      modelRef: 'oah-model-train',
      evaluationRef: 'oah-model-eval',
      stage: 'staging',
      description: 'Promotion request for the OAH demo model.',
    }),
    demoStep('inference', 'oah-model-endpoint', 'Serve', 'Deploy inference endpoint', {
      namespace,
      modelRef: 'oah-model-train',
      promotionRef: 'oah-model-promotion',
      runtime: 'kserve',
      backendType: 'auto',
      description: 'Inference endpoint for the promoted OAH demo model.',
    }, { requiresGpu: true }),
    demoStep('agents', 'oah-rag-agent', 'Use', 'Create governed AI agent', {
      namespace,
      tier: 'team',
      llmRouteRef: 'oah-model-endpoint',
      requireSourceAttribution: true,
      description: 'Agent declaration that consumes the promoted model and governed retrieval context.',
    }),
    demoStep('trustyai-monitoring', 'oah-model-monitoring', 'Operate', 'Monitor served model', {
      namespace,
      targetRef: 'oah-model-endpoint',
      targetKind: 'InferenceClaim',
      metric: 'drift',
      minimum: 0.8,
      enforcement: 'audit',
      description: 'Monitoring target for model quality, drift, and audit evidence.',
    }),
    demoStep('distributed-workloads', 'oah-distributed-train', 'Scale', 'Run distributed GPU workload', {
      namespace,
      framework: 'ray',
      backendType: 'auto',
      computeBackendRef: 'oah-gpu-backend',
      datasetRef: 'oah-demo-dataset',
      sourceRef: 'gpu-fair-share-queue',
      description: 'Distributed GPU training workload for the OAH demo.',
    }, { requiresGpu: true }),
  ];
}

async function ensureDemoNamespace(namespace, req) {
  const existing = await k8sJson(`/api/v1/namespaces/${namespace}`);
  const metadata = {
    name: namespace,
    labels: {
      'opensphere.io/project': 'true',
      'opensphere.io/demo': OAH_DEMO_LABEL,
    },
    annotations: {
      'opensphere.io/display-name': 'OAH GPU lifecycle demo',
      'opensphere.io/description': 'OpenSphere AI Hub end-to-end lifecycle demo workspace.',
    },
  };
  if (existing) {
    const patched = await patchK8s(`/api/v1/namespaces/${namespace}`, { metadata }, req);
    return { phase: 'Updated', item: itemFromK8s(patched, 'Namespace') };
  }
  const created = await writeK8s('/api/v1/namespaces', 'POST', { apiVersion: 'v1', kind: 'Namespace', metadata }, req);
  return { phase: 'Created', item: itemFromK8s(created, 'Namespace') };
}

function demoObjectForStep(step, namespace) {
  const def = ACTIONS[step.page];
  const body = { ...step.body, namespace, name: step.name, description: step.body.description || step.title };
  const obj = {
    apiVersion: def.apiVersion,
    kind: def.kind,
    metadata: {
      ...objectMeta(step.name, namespace, body.description),
      labels: {
        'opensphere.io/demo': OAH_DEMO_LABEL,
        'opensphere.io/demo-stage': dnsLabel(step.stage),
      },
      annotations: {
        ...(objectMeta(step.name, namespace, body.description).annotations || {}),
        'opensphere.io/demo-title': step.title,
      },
    },
    spec: buildSpec(step.page, body, namespace),
  };
  return { def, body, obj };
}

async function upsertDemoStep(step, namespace, req, gpu) {
  const def = ACTIONS[step.page];
  if (!def) return { id: step.name, stage: step.stage, title: step.title, phase: 'Skipped', reason: 'UnsupportedPage', message: `No action is registered for ${step.page}.` };
  if (step.requiresGpu && !gpu.ready) {
    return { id: step.name, page: step.page, kind: def.kind, stage: step.stage, title: step.title, phase: 'SkippedGpuNotExposed', ready: false, reason: 'GpuNotExposed', message: 'Kubernetes does not expose an allocatable GPU resource yet.' };
  }
  if (!(await crdInstalled(def.crdName))) {
    return { id: step.name, page: step.page, kind: def.kind, stage: step.stage, title: step.title, phase: 'SkippedCrdMissing', ready: false, reason: 'CrdMissing', message: `${def.crdName} is not installed.` };
  }
  const { obj } = demoObjectForStep(step, namespace);
  const path = `/apis/${def.group}/v1alpha1/namespaces/${namespace}/${def.plural}`;
  try {
    const created = await writeK8s(path, 'POST', obj, req);
    return { id: step.name, page: step.page, stage: step.stage, title: step.title, phase: 'Created', ready: false, item: itemFromK8s(created, def.kind) };
  } catch (e) {
    if (e.code !== 409) {
      return { id: step.name, page: step.page, kind: def.kind, stage: step.stage, title: step.title, phase: 'Failed', ready: false, reason: e.msg || 'CreateFailed', message: e.msg || String(e) };
    }
    const patched = await patchK8s(`${path}/${step.name}`, {
      metadata: {
        labels: obj.metadata.labels,
        annotations: obj.metadata.annotations,
      },
      spec: obj.spec,
    }, req);
    return { id: step.name, page: step.page, stage: step.stage, title: step.title, phase: 'Updated', ready: itemFromK8s(patched, def.kind).ready, item: itemFromK8s(patched, def.kind) };
  }
}

async function reconcileDemoResources() {
  const settled = await Promise.allSettled([
    reconcileWorkbenches(),
    reconcilePipelineRuns(),
    reconcileInferences(),
    reconcileEvaluationJobs(),
    reconcileModelPromotions(),
    reconcileMonitoringTargets(),
    reconcileDistributedWorkloads(),
  ]);
  return settled.map((result, index) => ({
    controller: ['workbenches', 'pipeline-runs', 'inference', 'evaluation', 'model-promotions', 'monitoring', 'distributed'][index],
    phase: result.status === 'fulfilled' ? 'Completed' : 'Failed',
    detail: result.status === 'fulfilled' ? result.value : String(result.reason?.msg || result.reason || 'failed'),
  }));
}

async function oahDemoRunStatus(namespace = OAH_DEMO_NAMESPACE) {
  const steps = oahDemoSteps(namespace, await gpuInventory());
  const items = [];
  const missingCrds = [];
  for (const step of steps) {
    const def = ACTIONS[step.page];
    if (!def || !(await crdInstalled(def.crdName))) {
      if (def?.crdName) missingCrds.push(def.crdName);
      continue;
    }
    const raw = await k8sJson(`/apis/${def.group}/v1alpha1/namespaces/${namespace}/${def.plural}/${step.name}`);
    if (raw) items.push({ step: step.name, stage: step.stage, title: step.title, page: step.page, ...itemFromK8s(raw, def.kind) });
  }
  const ns = await k8sJson(`/api/v1/namespaces/${namespace}`);
  return {
    namespace,
    phase: items.length ? 'Started' : ns ? 'WorkspaceReady' : 'NotStarted',
    generatedAt: new Date().toISOString(),
    summary: {
      expected: steps.length,
      actual: items.length,
      ready: items.filter((item) => item.ready).length,
      missingCrds: Array.from(new Set(missingCrds)).length,
    },
    items,
  };
}

async function oahDemoRunEvidence(namespace = OAH_DEMO_NAMESPACE) {
  const safeNamespace = requireDnsName(namespace || OAH_DEMO_NAMESPACE, 'namespace');
  const [gpu, plan, status, preview] = await Promise.all([
    gpuInventory(),
    oahDemoPlan({ url: '/admin/native/demo-plan', headers: { host: 'localhost' } }),
    oahDemoRunStatus(safeNamespace),
    oahDemoRunPreview(safeNamespace, null),
  ]);
  const steps = oahDemoSteps(safeNamespace, gpu);
  const statusByName = new Map((status.items || []).map((item) => [item.step || item.name, item]));
  const previewByName = new Map((preview.checks || []).map((item) => [item.id, item]));
  const rows = steps.map((step) => {
    const def = ACTIONS[step.page];
    const existing = statusByName.get(step.name);
    const check = previewByName.get(step.name);
    const visible = !!existing;
    const phase = visible ? existing.phase : check?.phase || 'NotCreated';
    const ready = !!existing?.ready || check?.ready === true;
    return {
      id: step.name,
      stage: step.stage,
      title: step.title,
      page: step.page,
      menu: def?.label || step.page,
      kind: def?.kind || '-',
      resource: `${safeNamespace}/${step.name}`,
      requiresGpu: step.requiresGpu,
      visible,
      ready,
      phase,
      reason: existing?.reason || check?.reason || (visible ? 'Observed' : 'NotCreated'),
      message: existing?.message || check?.message || (visible ? 'Resource is visible from OAH.' : 'Run the demo to create this resource.'),
    };
  });
  const availableActions = [
    { id: 'inspect-readiness', label: 'Inspect platform and GPU readiness', menu: 'Cluster settings', enabled: true, evidence: `GPU phase ${gpu.phase}, native demo phase ${plan.phase}.` },
    { id: 'preview-demo', label: 'Preview lifecycle demo manifests', menu: 'Cluster settings', enabled: true, evidence: `${preview.summary.manifests} manifest(s), ${preview.summary.ready} ready to apply.` },
    { id: 'run-native-demo', label: 'Create native lifecycle demo resources', menu: 'Cluster settings', enabled: preview.summary.ready > 0, evidence: `${preview.summary.ready} non-blocked task(s) can be applied when the user has permission.` },
    { id: 'view-project-workspace', label: 'Open the demo project workspace', menu: 'Data science projects', enabled: status.summary.actual > 0, evidence: `${status.summary.actual}/${status.summary.expected} demo resource(s) currently exist.` },
    { id: 'track-lineage', label: 'Review experiment, execution, and artifact lineage', menu: 'Experiments', enabled: rows.some((row) => row.stage === 'Track' && row.visible), evidence: `${rows.filter((row) => row.stage === 'Track' && row.visible).length} tracking resource(s) visible.` },
    { id: 'govern-model', label: 'Review evaluation and promotion gates', menu: 'Evaluation / Models', enabled: rows.some((row) => ['Govern', 'Release'].includes(row.stage) && row.visible), evidence: `${rows.filter((row) => ['Govern', 'Release'].includes(row.stage) && row.visible).length} governance resource(s) visible.` },
    { id: 'serve-and-monitor', label: 'Serve and monitor the model endpoint', menu: 'Inference / Monitoring', enabled: rows.some((row) => ['Serve', 'Operate'].includes(row.stage) && row.visible), evidence: `${rows.filter((row) => ['Serve', 'Operate'].includes(row.stage) && row.visible).length} serving or monitoring resource(s) visible.` },
    { id: 'run-gpu-tasks', label: 'Run GPU workbench, training, distributed, and inference tasks', menu: 'Workbenches / Training / Inference', enabled: gpu.ready, evidence: gpu.ready ? `${gpu.summary.totalAllocatable} allocatable GPU(s) available.` : 'Blocked until Kubernetes exposes an allocatable GPU resource.' },
  ];
  const blockedActions = rows
    .filter((row) => row.requiresGpu && !gpu.ready)
    .map((row) => ({
      id: row.id,
      label: row.title,
      menu: row.menu,
      reason: 'GpuNotExposed',
      nextStep: 'Use GPU enablement plan, install a vendor device plugin/resource publisher, then verify node allocatable GPU.',
    }));
  const visible = rows.filter((row) => row.visible).length;
  const runnableWithoutGpu = rows.filter((row) => !row.requiresGpu && previewByName.get(row.id)?.ready).length;
  return {
    namespace: safeNamespace,
    phase: gpu.ready ? (visible ? 'GpuLifecycleObservable' : 'GpuReadyNotStarted') : visible ? 'CpuLifecycleObservableGpuBlocked' : 'PreviewOnlyGpuBlocked',
    generatedAt: new Date().toISOString(),
    summary: {
      totalTasks: rows.length,
      visibleResources: visible,
      readyResources: rows.filter((row) => row.ready).length,
      runnableWithoutGpu,
      blockedByGpu: blockedActions.length,
      gpuReady: gpu.ready,
    },
    userCanDo: availableActions,
    blockedActions,
    evidence: rows,
    gpu: { phase: gpu.phase, ready: gpu.ready, summary: gpu.summary, nextSteps: gpu.nextSteps },
  };
}

const OAH_SMOKE_LABEL = 'oah-smoke-lifecycle';

function oahSmokeSteps(gpu) {
  const gpuClass = firstGpuClass(gpu);
  return [
    {
      id: 'data-prep',
      stage: 'Data',
      title: 'Prepare demo dataset',
      requiresGpu: false,
      command: [
        "const rows=Array.from({length:5000},(_,i)=>({id:i,x:i%97,y:(i*7)%31,label:i%2}));",
        "const checksum=rows.reduce((sum,row)=>sum+row.x+row.y+row.label,0);",
        "console.log(JSON.stringify({stage:'data-prep',rows:rows.length,checksum}));",
      ].join(''),
    },
    {
      id: 'cpu-train',
      stage: 'Train',
      title: 'Run CPU training smoke',
      requiresGpu: false,
      command: [
        "let weight=0,bias=0;",
        "for(let epoch=0;epoch<12;epoch++){for(let i=0;i<20000;i++){const x=(i%101)/100;const y=x>0.45?1:0;const pred=1/(1+Math.exp(-(weight*x+bias)));const err=pred-y;weight-=0.05*err*x;bias-=0.05*err;}}",
        "console.log(JSON.stringify({stage:'cpu-train',framework:'node-simulated-logistic-regression',weight:Number(weight.toFixed(4)),bias:Number(bias.toFixed(4))}));",
      ].join(''),
    },
    {
      id: 'evaluation',
      stage: 'Evaluate',
      title: 'Evaluate candidate model',
      requiresGpu: false,
      command: [
        "const metrics={accuracy:0.94,groundedness:0.88,latencyMs:37};",
        "const passed=metrics.accuracy>=0.9&&metrics.groundedness>=0.8;",
        "console.log(JSON.stringify({stage:'evaluation',metrics,passed}));",
        "if(!passed) process.exit(2);",
      ].join(''),
    },
    {
      id: 'inference',
      stage: 'Serve',
      title: 'Run inference smoke request',
      requiresGpu: false,
      command: [
        "const request={prompt:'classify demo sample',features:[0.2,0.8,0.4]};",
        "const score=request.features.reduce((a,b)=>a+b,0)/request.features.length;",
        "console.log(JSON.stringify({stage:'inference',request,response:{label:score>0.45?'positive':'negative',score:Number(score.toFixed(3))}}));",
      ].join(''),
    },
    {
      id: 'gpu-train',
      stage: 'GPU',
      title: 'Run GPU training smoke',
      requiresGpu: true,
      gpuClass,
      command: [
        "console.log(JSON.stringify({stage:'gpu-train',resource:process.env.OAH_GPU_RESOURCE||'unknown',cudaVisibleDevices:process.env.CUDA_VISIBLE_DEVICES||'',rocrVisibleDevices:process.env.ROCR_VISIBLE_DEVICES||''}));",
        "const visible=process.env.CUDA_VISIBLE_DEVICES||process.env.ROCR_VISIBLE_DEVICES||process.env.NVIDIA_VISIBLE_DEVICES||'';",
        "if(!visible) console.log('GPU environment variable is not vendor-populated, but Kubernetes assigned the requested extended resource.');",
      ].join(''),
    },
  ];
}

async function currentAiImage() {
  const deployment = await k8sJson('/apis/apps/v1/namespaces/opensphere-system/deployments/ai');
  return deployment?.spec?.template?.spec?.containers?.[0]?.image || 'localhost:5000/ai:latest';
}

function smokeJobName(step) {
  return `oah-smoke-${dnsLabel(step.id)}`;
}

function smokeJobManifest(step, namespace, image) {
  const labels = {
    'app.kubernetes.io/name': smokeJobName(step),
    'app.kubernetes.io/part-of': 'opensphere-ai-hub',
    'opensphere.io/demo': OAH_DEMO_LABEL,
    'opensphere.io/smoke': OAH_SMOKE_LABEL,
    'opensphere.io/smoke-step': step.id,
  };
  const container = {
    name: 'runner',
    image,
    imagePullPolicy: 'IfNotPresent',
    command: ['node', '-e', step.command],
    env: [
      { name: 'OAH_SMOKE_STEP', value: step.id },
      { name: 'OAH_SMOKE_STAGE', value: step.stage },
      { name: 'OAH_GPU_RESOURCE', value: step.gpuClass || '' },
    ],
  };
  if (step.requiresGpu) {
    container.resources = { limits: { [step.gpuClass || 'vendor.opensphere.io/gpu']: 1 } };
  }
  return {
    apiVersion: 'batch/v1',
    kind: 'Job',
    metadata: {
      name: smokeJobName(step),
      namespace,
      labels,
      annotations: {
        'opensphere.io/display-name': step.title,
        'opensphere.io/description': 'OpenSphere AI Hub executable lifecycle smoke demo job.',
      },
    },
    spec: {
      backoffLimit: 0,
      ttlSecondsAfterFinished: 3600,
      template: {
        metadata: { labels },
        spec: {
          restartPolicy: 'Never',
          containers: [container],
        },
      },
    },
  };
}

function smokeJobStatus(job, step) {
  if (!job) {
    return {
      id: step.id,
      stage: step.stage,
      title: step.title,
      name: smokeJobName(step),
      requiresGpu: step.requiresGpu,
      phase: 'NotStarted',
      ready: false,
      message: 'Smoke job has not been created.',
    };
  }
  const normalized = normalizeJobStatus(job, false, {
    succeededMessage: `${step.title} completed successfully.`,
    pendingMessage: `${step.title} is pending.`,
    runningMessage: `${step.title} is running.`,
    failedMessage: `${step.title} failed.`,
  });
  return {
    id: step.id,
    stage: step.stage,
    title: step.title,
    name: job.metadata?.name || smokeJobName(step),
    namespace: job.metadata?.namespace || '',
    requiresGpu: step.requiresGpu,
    phase: normalized.phase,
    ready: normalized.ready,
    reason: normalized.reason,
    message: normalized.message,
    active: normalized.active || 0,
    succeeded: normalized.succeeded || 0,
    failed: normalized.failed || 0,
    startedAt: job.status?.startTime || '',
    completedAt: job.status?.completionTime || '',
  };
}

async function oahDemoSmokeStatus(namespace = OAH_DEMO_NAMESPACE) {
  const safeNamespace = requireDnsName(namespace || OAH_DEMO_NAMESPACE, 'namespace');
  const gpu = await gpuInventory();
  const steps = oahSmokeSteps(gpu);
  const items = [];
  for (const step of steps) {
    const job = await k8sJson(`/apis/batch/v1/namespaces/${safeNamespace}/jobs/${smokeJobName(step)}`);
    items.push(smokeJobStatus(job, step));
  }
  return {
    namespace: safeNamespace,
    phase: items.some((item) => item.phase === 'Running') ? 'Running'
      : items.some((item) => item.phase === 'Failed') ? 'Failed'
        : items.some((item) => item.phase === 'Succeeded') ? 'Started'
          : 'NotStarted',
    generatedAt: new Date().toISOString(),
    summary: {
      total: items.length,
      succeeded: items.filter((item) => item.phase === 'Succeeded').length,
      running: items.filter((item) => item.phase === 'Running').length,
      failed: items.filter((item) => item.phase === 'Failed').length,
      notStarted: items.filter((item) => item.phase === 'NotStarted').length,
      gpuReady: gpu.ready,
      gpuBlocked: items.filter((item) => item.requiresGpu && !gpu.ready && item.phase === 'NotStarted').length,
    },
    gpu: { phase: gpu.phase, ready: gpu.ready, summary: gpu.summary },
    items,
  };
}

function parseSmokeLogLines(lines) {
  const records = [];
  for (const line of lines || []) {
    const trimmed = String(line || '').trim();
    if (!trimmed) continue;
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed && typeof parsed === 'object') records.push(parsed);
    } catch {
      records.push({ message: trimmed });
    }
  }
  return records;
}

async function smokeJobLog(namespace, step) {
  const jobName = smokeJobName(step);
  const selectors = [
    `batch.kubernetes.io/job-name=${jobName}`,
    `job-name=${jobName}`,
    `opensphere.io/smoke-step=${step.id}`,
  ];
  let podItems = [];
  for (const selector of selectors) {
    const pods = await k8sJson(`/api/v1/namespaces/${namespace}/pods?labelSelector=${encodeURIComponent(selector)}`);
    podItems = pods?.items || [];
    if (podItems.length) break;
  }
  const pod = podItems.find((item) => ['Succeeded', 'Running', 'Failed'].includes(item.status?.phase)) || podItems[0];
  if (!pod?.metadata?.name) {
    return {
      id: step.id,
      stage: step.stage,
      title: step.title,
      jobName,
      requiresGpu: step.requiresGpu,
      phase: 'NoPod',
      lines: [],
      records: [],
      message: 'No pod has been created for this smoke job yet.',
    };
  }
  const log = await k8sText(`/api/v1/namespaces/${namespace}/pods/${pod.metadata.name}/log?container=runner&tailLines=200`)
    || await k8sText(`/api/v1/namespaces/${namespace}/pods/${pod.metadata.name}/log?tailLines=200`)
    || '';
  const lines = log.trim() ? log.trim().split(/\r?\n/) : [];
  return {
    id: step.id,
    stage: step.stage,
    title: step.title,
    jobName,
    pod: pod.metadata.name,
    requiresGpu: step.requiresGpu,
    phase: pod.status?.phase || 'Unknown',
    lines,
    records: parseSmokeLogLines(lines),
    message: lines.length ? `${lines.length} log line(s) collected.` : 'Pod exists but no logs are available yet.',
  };
}

async function oahDemoSmokeLogs(namespace = OAH_DEMO_NAMESPACE) {
  const safeNamespace = requireDnsName(namespace || OAH_DEMO_NAMESPACE, 'namespace');
  const gpu = await gpuInventory();
  const steps = oahSmokeSteps(gpu);
  const items = [];
  for (const step of steps) {
    items.push(await smokeJobLog(safeNamespace, step));
  }
  const recordCount = items.reduce((sum, item) => sum + (item.records?.length || 0), 0);
  const lineCount = items.reduce((sum, item) => sum + (item.lines?.length || 0), 0);
  return {
    namespace: safeNamespace,
    phase: recordCount ? 'Collected' : 'Pending',
    generatedAt: new Date().toISOString(),
    summary: {
      jobs: items.length,
      withPods: items.filter((item) => !!item.pod).length,
      withLogs: items.filter((item) => item.lines?.length).length,
      records: recordCount,
      lines: lineCount,
    },
    items,
  };
}

async function oahDemoSmokePreview(namespace = OAH_DEMO_NAMESPACE, req = null) {
  const safeNamespace = requireDnsName(namespace || OAH_DEMO_NAMESPACE, 'namespace');
  const gpu = await gpuInventory();
  const image = await currentAiImage();
  const steps = oahSmokeSteps(gpu);
  const manifests = steps.map((step) => smokeJobManifest(step, safeNamespace, image));
  const checks = steps.map((step) => {
    const gpuBlocked = step.requiresGpu && !gpu.ready;
    return {
      id: step.id,
      stage: step.stage,
      title: step.title,
      kind: 'Job',
      requiresGpu: step.requiresGpu,
      phase: gpuBlocked ? 'BlockedGpuNotExposed' : 'ReadyToRun',
      ready: !gpuBlocked,
      reason: gpuBlocked ? 'GpuNotExposed' : 'Ready',
      message: gpuBlocked ? 'Kubernetes does not expose an allocatable GPU resource yet.' : 'This smoke job can be created by Run smoke demo.',
    };
  });
  const canCreateJobs = await selfCan(req, 'create', 'batch', 'jobs', safeNamespace);
  const canDeleteJobs = await selfCan(req, 'delete', 'batch', 'jobs', safeNamespace);
  const canCreateNamespace = await selfCan(req, 'create', '', 'namespaces');
  const nsExists = !!(await k8sJson(`/api/v1/namespaces/${safeNamespace}`));
  return {
    namespace: safeNamespace,
    phase: !req?.headers?.['x-os-id-token'] ? 'AuthenticationRequired'
      : !canCreateJobs ? 'PermissionRequired'
        : gpu.ready ? 'ReadyToRun' : 'ReadyWithGpuSkip',
    generatedAt: new Date().toISOString(),
    image,
    summary: {
      total: checks.length,
      ready: checks.filter((item) => item.ready).length,
      blockedByGpu: checks.filter((item) => item.phase === 'BlockedGpuNotExposed').length,
      manifests: manifests.length,
    },
    permission: {
      hasToken: !!req?.headers?.['x-os-id-token'],
      canRun: !!canCreateJobs && (nsExists || !!canCreateNamespace),
      canReset: !!canDeleteJobs,
      phase: canCreateJobs && (nsExists || canCreateNamespace) ? 'Allowed' : 'PermissionRequired',
      checks: [
        { id: 'namespace', label: 'Prepare smoke namespace', allowed: nsExists || !!canCreateNamespace, required: true, detail: nsExists ? `Namespace/${safeNamespace} exists.` : `Requires create on namespaces for ${safeNamespace}.` },
        { id: 'jobs-create', label: 'Create smoke Jobs', allowed: !!canCreateJobs, required: true, detail: `Requires create on batch/jobs in ${safeNamespace}.` },
        { id: 'jobs-delete', label: 'Replace smoke Jobs', allowed: !!canDeleteJobs, required: false, detail: `Requires delete on batch/jobs in ${safeNamespace} to re-run cleanly.` },
      ],
    },
    gpu: { phase: gpu.phase, ready: gpu.ready, summary: gpu.summary },
    checks,
    manifests,
  };
}

async function deleteSmokeJob(namespace, step, req) {
  try {
    await writeK8s(`/apis/batch/v1/namespaces/${namespace}/jobs/${smokeJobName(step)}?propagationPolicy=Background`, 'DELETE', null, req);
    return 'Deleted';
  } catch (e) {
    if (e.code === 404) return 'NotFound';
    throw e;
  }
}

async function oahDemoSmokeRun(req) {
  const body = JSON.parse((await readBody(req)).toString('utf8') || '{}');
  const namespace = requireDnsName(body.namespace || OAH_DEMO_NAMESPACE, 'namespace');
  const gpu = await gpuInventory();
  await ensureDemoNamespace(namespace, req);
  const image = await currentAiImage();
  const steps = oahSmokeSteps(gpu);
  const results = [];
  for (const step of steps) {
    if (step.requiresGpu && !gpu.ready) {
      results.push({ id: step.id, stage: step.stage, title: step.title, kind: 'Job', phase: 'SkippedGpuNotExposed', ready: false, reason: 'GpuNotExposed', message: 'Kubernetes does not expose an allocatable GPU resource yet.' });
      continue;
    }
    try {
      await deleteSmokeJob(namespace, step, req);
      const created = await writeK8s(`/apis/batch/v1/namespaces/${namespace}/jobs`, 'POST', smokeJobManifest(step, namespace, image), req);
      results.push({ id: step.id, stage: step.stage, title: step.title, kind: 'Job', phase: 'Created', ready: false, item: itemFromK8s(created, 'Job') });
    } catch (e) {
      results.push({ id: step.id, stage: step.stage, title: step.title, kind: 'Job', phase: 'Failed', ready: false, reason: e.msg || String(e), message: e.msg || String(e) });
    }
  }
  return {
    namespace,
    phase: results.some((item) => item.phase === 'Failed') ? 'StartedWithErrors' : results.some((item) => item.phase === 'SkippedGpuNotExposed') ? 'StartedWithGpuSkip' : 'Started',
    generatedAt: new Date().toISOString(),
    image,
    summary: {
      created: results.filter((item) => item.phase === 'Created').length,
      skipped: results.filter((item) => /^Skipped/.test(item.phase)).length,
      failed: results.filter((item) => item.phase === 'Failed').length,
      gpuReady: gpu.ready,
      total: results.length,
    },
    results,
    status: await oahDemoSmokeStatus(namespace),
  };
}

async function oahDemoRunPermission(req, namespace, steps) {
  const hasToken = !!req?.headers?.['x-os-id-token'];
  if (!hasToken) {
    return {
      hasToken: false,
      canRun: false,
      canReset: false,
      phase: 'AuthenticationRequired',
      checks: [
        { id: 'identity-token', label: 'OpenSphere identity token', allowed: false, required: true, detail: 'Run and reset require a signed-in OpenSphere user token.' },
      ],
    };
  }
  const nsExists = !!(await k8sJson(`/api/v1/namespaces/${namespace}`));
  const checks = [];
  const add = (id, label, allowed, required, detail) => checks.push({ id, label, allowed, required, detail });
  const nsCreate = await selfCan(req, 'create', '', 'namespaces');
  const nsPatch = await selfCan(req, 'patch', '', 'namespaces');
  add(
    'namespace',
    'Prepare demo namespace',
    nsExists ? nsPatch : nsCreate,
    true,
    nsExists ? `Requires patch on Namespace/${namespace}.` : `Requires create on namespaces for ${namespace}.`,
  );
  const uniqueDefs = Array.from(new Map(steps.map((step) => [step.page, ACTIONS[step.page]]).filter(([, def]) => !!def)).values());
  for (const def of uniqueDefs) {
    const [canCreate, canPatch, canDelete] = await Promise.all([
      selfCan(req, 'create', def.group, def.plural, namespace),
      selfCan(req, 'patch', def.group, def.plural, namespace),
      selfCan(req, 'delete', def.group, def.plural, namespace),
    ]);
    add(`${def.plural}-create`, `Create ${def.kind}`, canCreate, true, `Requires create on ${def.group}/${def.plural} in ${namespace}.`);
    add(`${def.plural}-patch`, `Update ${def.kind}`, canPatch, true, `Requires patch on ${def.group}/${def.plural} in ${namespace} for re-run.`);
    add(`${def.plural}-delete`, `Reset ${def.kind}`, canDelete, false, `Requires delete on ${def.group}/${def.plural} in ${namespace} for reset.`);
  }
  const registryUpdate = await selfCan(req, 'update', '', 'configmaps', 'opensphere-system');
  const registryPatch = await selfCan(req, 'patch', '', 'configmaps', 'opensphere-system');
  add('registry-update', 'Update demo model registry', registryUpdate || registryPatch, true, 'Requires update or patch on ConfigMap/ai-model-registry-versions in opensphere-system.');
  const required = checks.filter((item) => item.required);
  const resetRequired = checks.filter((item) => item.required || item.id.endsWith('-delete'));
  const canRun = required.every((item) => item.allowed);
  const canReset = resetRequired.every((item) => item.allowed);
  return {
    hasToken,
    canRun,
    canReset,
    phase: canRun && canReset ? 'Allowed' : canRun ? 'RunAllowedResetLimited' : 'Forbidden',
    checks,
  };
}

async function oahDemoRunPreview(namespace = OAH_DEMO_NAMESPACE, req = null) {
  const safeNamespace = requireDnsName(namespace || OAH_DEMO_NAMESPACE, 'namespace');
  const gpu = await gpuInventory();
  const steps = oahDemoSteps(safeNamespace, gpu);
  const namespaceManifest = {
    apiVersion: 'v1',
    kind: 'Namespace',
    metadata: {
      name: safeNamespace,
      labels: {
        'opensphere.io/project': 'true',
        'opensphere.io/demo': OAH_DEMO_LABEL,
      },
      annotations: {
        'opensphere.io/display-name': 'OAH GPU lifecycle demo',
        'opensphere.io/description': 'OpenSphere AI Hub end-to-end lifecycle demo workspace.',
      },
    },
  };
  const checks = [];
  const manifests = [namespaceManifest];
  for (const step of steps) {
    const def = ACTIONS[step.page];
    if (!def) {
      checks.push({ id: step.name, stage: step.stage, title: step.title, phase: 'Blocked', reason: 'UnsupportedPage', message: `No action is registered for ${step.page}.` });
      continue;
    }
    const crdReady = await crdInstalled(def.crdName);
    const gpuBlocked = step.requiresGpu && !gpu.ready;
    const { obj } = demoObjectForStep(step, safeNamespace);
    manifests.push(obj);
    checks.push({
      id: step.name,
      stage: step.stage,
      title: step.title,
      kind: def.kind,
      page: step.page,
      requiresGpu: step.requiresGpu,
      phase: !crdReady ? 'BlockedCrdMissing' : gpuBlocked ? 'BlockedGpuNotExposed' : 'ReadyToApply',
      ready: crdReady && !gpuBlocked,
      reason: !crdReady ? 'CrdMissing' : gpuBlocked ? 'GpuNotExposed' : 'Ready',
      message: !crdReady ? `${def.crdName} is not installed.` : gpuBlocked ? 'Kubernetes does not expose an allocatable GPU resource yet.' : 'This resource can be created or updated by Demo Run.',
    });
  }
  const ready = checks.filter((item) => item.ready).length;
  const permission = await oahDemoRunPermission(req, safeNamespace, steps);
  return {
    namespace: safeNamespace,
    phase: !permission.canRun ? 'PermissionRequired' : checks.some((item) => item.phase === 'BlockedCrdMissing') ? 'BlockedByMissingCrds' : gpu.ready ? 'ReadyToRun' : 'ReadyWithGpuSkips',
    generatedAt: new Date().toISOString(),
    summary: {
      total: checks.length,
      ready,
      blockedByGpu: checks.filter((item) => item.phase === 'BlockedGpuNotExposed').length,
      blockedByCrd: checks.filter((item) => item.phase === 'BlockedCrdMissing').length,
      manifests: manifests.length,
    },
    gpu: { phase: gpu.phase, ready: gpu.ready, summary: gpu.summary },
    permission,
    checks,
    manifests,
  };
}

async function oahDemoRun(req) {
  const body = JSON.parse((await readBody(req)).toString('utf8') || '{}');
  const namespace = requireDnsName(body.namespace || OAH_DEMO_NAMESPACE, 'namespace');
  const gpu = await gpuInventory();
  const namespaceResult = await ensureDemoNamespace(namespace, req);
  const steps = oahDemoSteps(namespace, gpu);
  const results = [];
  for (const step of steps) {
    results.push(await upsertDemoStep(step, namespace, req, gpu));
  }
  const registryBackend = await modelRegistryBackend('opensphere-system', { backend: 'opensphere' });
  const current = await modelRegistryState({ source: registryBackend.source, backend: registryBackend.backend });
  const demoVersion = {
    name: 'oah-demo-model',
    version: '0.1.0',
    stage: 'candidate',
    source: `${namespace}/oah-model-artifact`,
    artifactUri: `oci://opensphere/oah-demo-model:0.1.0`,
    backend: registryBackend.source.type,
    registry: `${registryBackend.source.namespace}/${registryBackend.source.name}`,
  };
  let registry = null;
  try {
    const versions = [...current.versions.filter((item) => !(item.name === demoVersion.name && item.version === demoVersion.version)), demoVersion];
    const saved = await saveModelRegistryState({ ...current, versions }, req, registryBackend.source);
    registry = { phase: 'Registered', version: demoVersion, upstreamSync: saved.upstreamSync };
  } catch (e) {
    registry = { phase: 'Failed', reason: e.msg || String(e) };
  }
  const reconcile = await reconcileDemoResources();
  const status = await oahDemoRunStatus(namespace);
  const created = results.filter((item) => item.phase === 'Created').length;
  const updated = results.filter((item) => item.phase === 'Updated').length;
  const skipped = results.filter((item) => /^Skipped/.test(item.phase)).length;
  const failed = results.filter((item) => item.phase === 'Failed').length;
  return {
    namespace,
    phase: failed ? 'CompletedWithErrors' : skipped ? 'CompletedWithSkips' : 'Completed',
    generatedAt: new Date().toISOString(),
    namespaceResult,
    summary: { created, updated, skipped, failed, gpuReady: gpu.ready, total: results.length },
    results,
    registry,
    reconcile,
    status,
  };
}

async function oahDemoRunReset(req) {
  const body = JSON.parse((await readBody(req)).toString('utf8') || '{}');
  const namespace = requireDnsName(body.namespace || OAH_DEMO_NAMESPACE, 'namespace');
  const steps = oahDemoSteps(namespace, await gpuInventory()).slice().reverse();
  const results = [];
  for (const step of steps) {
    const def = ACTIONS[step.page];
    if (!def) {
      results.push({ id: step.name, stage: step.stage, title: step.title, phase: 'Skipped', reason: 'UnsupportedPage' });
      continue;
    }
    if (!(await crdInstalled(def.crdName))) {
      results.push({ id: step.name, stage: step.stage, title: step.title, kind: def.kind, phase: 'SkippedCrdMissing', reason: 'CrdMissing' });
      continue;
    }
    const path = `/apis/${def.group}/v1alpha1/namespaces/${namespace}/${def.plural}/${step.name}`;
    try {
      await writeK8s(path, 'DELETE', null, req);
      results.push({ id: step.name, stage: step.stage, title: step.title, kind: def.kind, phase: 'Deleted', ready: false });
    } catch (e) {
      if (e.code === 404) {
        results.push({ id: step.name, stage: step.stage, title: step.title, kind: def.kind, phase: 'NotFound', ready: false });
      } else {
        results.push({ id: step.name, stage: step.stage, title: step.title, kind: def.kind, phase: 'Failed', ready: false, reason: e.msg || String(e) });
      }
    }
  }
  let registry = null;
  try {
    const registryBackend = await modelRegistryBackend('opensphere-system', { backend: 'opensphere' });
    const current = await modelRegistryState({ source: registryBackend.source, backend: registryBackend.backend });
    const versions = current.versions.filter((item) => !(item.name === 'oah-demo-model' && item.version === '0.1.0'));
    const saved = await saveModelRegistryState({ ...current, versions }, req, registryBackend.source);
    registry = { phase: 'Removed', upstreamSync: saved.upstreamSync };
  } catch (e) {
    registry = { phase: 'Failed', reason: e.msg || String(e) };
  }
  const status = await oahDemoRunStatus(namespace);
  const deleted = results.filter((item) => item.phase === 'Deleted').length;
  const notFound = results.filter((item) => item.phase === 'NotFound').length;
  const skipped = results.filter((item) => /^Skipped/.test(item.phase)).length;
  const failed = results.filter((item) => item.phase === 'Failed').length;
  return {
    namespace,
    phase: failed ? 'ResetWithErrors' : 'ResetCompleted',
    generatedAt: new Date().toISOString(),
    summary: { deleted, notFound, skipped, failed, total: results.length },
    results,
    registry,
    status,
  };
}

async function listK8s(apiPath, kind, fallbackItems) {
  const json = await k8sJson(apiPath);
  if (!json?.items) return referenceItems(fallbackItems);
  return json.items.map((item) => itemFromK8s(item, kind));
}

async function listAnyK8s(sources, fallbackItems) {
  let discovered = false;
  const groups = await Promise.all(sources.map(async (source) => {
    const json = await k8sJson(source.path);
    if (!json?.items) return [];
    discovered = true;
    return json.items.map((item) => itemFromK8s(item, source.kind));
  }));
  const items = groups.flat();
  if (items.length || discovered) return items;
  return referenceItems(fallbackItems);
}

async function projects() {
  const json = await k8sJson('/api/v1/namespaces');
  if (!json?.items) return referenceItems(FALLBACK_PROJECTS);
  const items = json.items
    .filter((ns) => {
      const labels = ns.metadata?.labels || {};
      return labels['opensphere.io/project'] === 'true' || ns.metadata?.name?.includes('dev') || ns.metadata?.name?.includes('sandbox');
    })
    .map((ns) => ({
      name: ns.metadata?.name || '',
      displayName: ns.metadata?.annotations?.['opensphere.io/display-name'] || ns.metadata?.name || '',
      created: ns.metadata?.creationTimestamp || '',
      owner: ns.metadata?.annotations?.['opensphere.io/owner'] || ns.metadata?.labels?.['kubernetes.io/metadata.name'] || 'Unknown',
      phase: ns.status?.phase || 'Active',
      description: ns.metadata?.annotations?.['opensphere.io/description'] || 'Namespace-backed AI workspace',
      source: 'cluster',
      reference: false,
    }));
  return items.length ? items : [];
}

async function nativeServingRuntimeResources() {
  const inferenceCrd = await crdInstalled('inferenceclaims.ai.opensphere.io');
  if (!inferenceCrd) return [];
  return [
    {
      name: 'opensphere-kubernetes-runtime',
      kind: 'ServingRuntime',
      namespace: 'opensphere-system',
      phase: 'Ready',
      ready: true,
      description: 'OpenSphere-native Kubernetes Deployment/Service runtime for InferenceClaim resources.',
      source: 'native',
      reference: false,
    },
    {
      name: 'opensphere-vllm-compatible-runtime',
      kind: 'ServingRuntime',
      namespace: 'opensphere-system',
      phase: 'Ready',
      ready: true,
      description: `OpenSphere-native vLLM-compatible runtime backed by ${INFERENCE_RUNTIME_IMAGE}.`,
      source: 'native',
      reference: false,
    },
  ];
}

async function nativeModelRegistryResources() {
  const cm = await k8sJson('/api/v1/namespaces/opensphere-system/configmaps/ai-model-registry-versions');
  if (!cm) return [];
  const versions = parseJsonArray(cm.data?.versions);
  const promotions = parseJsonArray(cm.data?.promotions);
  return [{
    name: 'ai-model-registry-versions',
    kind: 'OpenSphereModelRegistry',
    namespace: 'opensphere-system',
    phase: 'Ready',
    ready: true,
    description: `${versions.length} model version(s), ${promotions.length} promotion record(s) in OpenSphere-native registry storage.`,
    source: 'native',
    reference: false,
  }];
}

async function nativeEnabledApplications() {
  const backends = await nativeBackends();
  return backends.items.map((item) => ({
    name: item.component,
    kind: 'OpenSphereAIApplication',
    namespace: 'opensphere-system',
    phase: item.ready ? 'Ready' : 'Unavailable',
    ready: item.ready,
    description: `${item.displayName}: ${item.message}`,
    source: item.upstreamReady ? 'upstream' : 'native',
    reference: false,
  }));
}

function nativeComponentResource(component, kind = 'OpenSphereAIApplication') {
  const phase = component.phase || (component.installed ? 'Installed' : 'Available');
  return {
    name: component.name,
    kind,
    namespace: 'opensphere-system',
    phase,
    ready: component.installed || ['Available', 'Complete', 'Installed', 'Ready'].includes(phase),
    description: `${component.displayName}: ${component.description}`,
    reason: component.operation || '',
    message: component.installedVersion
      ? `Installed ${component.installedVersion}; target ${component.targetVersion || component.version}.`
      : `Available ${component.version} on ${component.channel}.`,
    source: 'native',
    reference: false,
  };
}

async function nativeCatalogResources(kind = 'OpenSphereComponentVersion') {
  const catalog = await nativeCatalog();
  return (catalog.components || []).map((component) => nativeComponentResource(component, kind));
}

async function nativeClusterSettingsResources() {
  const [nativeDscs, upstreamDscs] = await Promise.all([
    k8sJson('/apis/ai.opensphere.io/v1alpha1/namespaces/opensphere-system/openspheredatascienceclusters'),
    listAnyK8s([
      { path: '/apis/datasciencecluster.opendatahub.io/v1/datascienceclusters', kind: 'DataScienceCluster' },
      { path: '/apis/datasciencecluster.opendatahub.io/v1alpha1/datascienceclusters', kind: 'DataScienceCluster' },
    ], []),
  ]);
  const nativeItems = (nativeDscs?.items || []).map((item) => ({
    ...itemFromK8s(item, 'OpenSphereDataScienceCluster'),
    kind: 'OpenSphereDataScienceCluster',
    phase: item.status?.phase || 'Managed',
    ready: true,
    description: `${Object.keys(item.spec?.components || {}).length} OpenSphere-native component(s) managed by this cluster profile.`,
    source: 'native',
    reference: false,
  }));
  return [...nativeItems, ...upstreamDscs];
}

async function nativeNotebookImages() {
  const catalog = await nativeCatalog();
  const workbenches = (catalog.components || []).find((component) => component.name === 'workbenches');
  const workbenchRuntimeReady = !!workbenches?.installed || await crdInstalled('workbenchclaims.ai.opensphere.io');
  if (!workbenchRuntimeReady) return [];
  return FALLBACK_RESOURCES.notebookImages.map((item) => ({
    ...item,
    kind: 'OpenSphereNotebookImage',
    namespace: 'opensphere-system',
    phase: 'Available',
    ready: true,
    description: `${item.description}. Provided by the installed OpenSphere Workbench runtime.`,
    source: 'native',
    reference: false,
  }));
}

async function aiResources(kind) {
  switch (kind) {
    case 'agents':
      return listK8s('/apis/orchestrator.ai.opensphere.io/v1alpha1/aiagents', 'AIAgent', FALLBACK_RESOURCES.agents);
    case 'routes': {
      const llm = await listK8s('/apis/ai.foundation.opensphere.io/v1alpha1/llmrouteclaims', 'LLMRouteClaim', FALLBACK_RESOURCES.routes.slice(0, 1));
      const retrieval = await listK8s('/apis/ai.foundation.opensphere.io/v1alpha1/vectorretrievalclaims', 'VectorRetrievalClaim', FALLBACK_RESOURCES.routes.slice(1));
      return [...llm, ...retrieval];
    }
    case 'retrieval':
      return listK8s('/apis/ai.foundation.opensphere.io/v1alpha1/vectorretrievalclaims', 'VectorRetrievalClaim', FALLBACK_RESOURCES.routes.slice(1));
    case 'workbenches':
      return listAnyK8s([
        { path: '/apis/ai.opensphere.io/v1alpha1/workbenchclaims', kind: 'WorkbenchClaim' },
        { path: '/apis/kubeflow.org/v1/notebooks', kind: 'Notebook' },
        { path: '/apis/kubeflow.org/v1beta1/notebooks', kind: 'Notebook' },
      ], FALLBACK_RESOURCES.workbenches);
    case 'notebookImages':
      return nativeNotebookImages();
    case 'dataConnections':
      return listK8s('/apis/ai.opensphere.io/v1alpha1/dataconnectionclaims', 'DataConnectionClaim', FALLBACK_RESOURCES.dataConnections);
    case 'servingRuntimes':
      return (await listAnyK8s([
        { path: '/apis/serving.kserve.io/v1alpha1/servingruntimes', kind: 'ServingRuntime' },
        { path: '/apis/serving.kserve.io/v1alpha1/clusterservingruntimes', kind: 'ClusterServingRuntime' },
        { path: '/apis/serving.kserve.io/v1beta1/servingruntimes', kind: 'ServingRuntime' },
        { path: '/apis/serving.kserve.io/v1beta1/clusterservingruntimes', kind: 'ClusterServingRuntime' },
      ], [])).concat(await nativeServingRuntimeResources());
    case 'modelRegistry': {
      const upstreamRegistries = await listAnyK8s([
        { path: '/apis/modelregistry.opendatahub.io/v1alpha1/modelregistries', kind: 'ModelRegistry' },
        { path: '/apis/modelregistry.opendatahub.io/v1beta1/modelregistries', kind: 'ModelRegistry' },
      ], []);
      return upstreamRegistries.length ? upstreamRegistries : nativeModelRegistryResources();
    }
    case 'pipelines':
      return listK8s('/apis/ai.opensphere.io/v1alpha1/pipelineclaims', 'PipelineClaim', FALLBACK_RESOURCES.pipelines);
    case 'pipelineRuns':
      return listK8s('/apis/ai.opensphere.io/v1alpha1/pipelinerunclaims', 'PipelineRunClaim', FALLBACK_RESOURCES.pipelineRuns);
    case 'compute':
      return listK8s('/apis/ai.opensphere.io/v1alpha1/computebackendclaims', 'ComputeBackendClaim', FALLBACK_RESOURCES.compute);
    case 'datasets':
      return listK8s('/apis/ai.opensphere.io/v1alpha1/datasetclaims', 'DatasetClaim', FALLBACK_RESOURCES.datasets);
    case 'trainingJobs':
      return listK8s('/apis/ai.opensphere.io/v1alpha1/trainingjobclaims', 'TrainingJobClaim', FALLBACK_RESOURCES.trainingJobs);
    case 'promotions':
      return listK8s('/apis/ai.opensphere.io/v1alpha1/modelpromotionclaims', 'ModelPromotionClaim', FALLBACK_RESOURCES.promotions);
    case 'evalPolicies':
      return listK8s('/apis/eval.ai.opensphere.io/v1alpha1/evaluationpolicies', 'EvaluationPolicy', FALLBACK_RESOURCES.evalPolicies);
    case 'evalJobs':
      return listK8s('/apis/eval.ai.opensphere.io/v1alpha1/evaluationjobs', 'EvaluationJob', FALLBACK_RESOURCES.evalJobs);
    case 'experiments':
      return listK8s('/apis/ai.opensphere.io/v1alpha1/experimentclaims', 'ExperimentClaim', FALLBACK_RESOURCES.experiments);
    case 'executions':
      return listK8s('/apis/ai.opensphere.io/v1alpha1/executionclaims', 'ExecutionClaim', FALLBACK_RESOURCES.executions);
    case 'artifacts':
      return listK8s('/apis/ai.opensphere.io/v1alpha1/artifactclaims', 'ArtifactClaim', FALLBACK_RESOURCES.artifacts);
    case 'inference':
      return listK8s('/apis/ai.opensphere.io/v1alpha1/inferenceclaims', 'InferenceClaim', FALLBACK_RESOURCES.inference);
    case 'trustyaiMonitoring':
      return listAnyK8s([
        { path: '/apis/ai.opensphere.io/v1alpha1/monitoringtargets', kind: 'MonitoringTarget' },
        { path: '/apis/trustyai.opendatahub.io/v1alpha1/trustyaiservices', kind: 'TrustyAIService' },
      ], FALLBACK_RESOURCES.trustyaiMonitoring);
    case 'distributedWorkloads':
      return listAnyK8s([
        { path: '/apis/ai.opensphere.io/v1alpha1/distributedworkloadclaims', kind: 'DistributedWorkloadClaim' },
        { path: '/apis/kueue.x-k8s.io/v1beta1/workloads', kind: 'KueueWorkload' },
        { path: '/apis/kueue.x-k8s.io/v1beta1/clusterqueues', kind: 'KueueClusterQueue' },
        { path: '/apis/ray.io/v1/rayclusters', kind: 'RayCluster' },
      ], FALLBACK_RESOURCES.distributedWorkloads);
    case 'clusterSettings':
      return nativeClusterSettingsResources();
    case 'enabledApplications':
      return nativeEnabledApplications();
    case 'exploreApplications':
      return nativeCatalogResources('OpenSphereAIApplication');
    case 'developerLearning': {
      const learning = await nativeLearningResources();
      return learning.length ? learning : referenceItems(FALLBACK_RESOURCES.developerLearning);
    }
    case 'catalog':
      return nativeCatalogResources('OpenSphereComponentVersion');
    default:
      return [];
  }
}

async function resourcePayload(kind) {
  return listPayload(await aiResources(kind));
}

async function projectsPayload() {
  return listPayload(await projects());
}

async function summary() {
  const [
    projectItems,
    workbenches,
    routes,
    agents,
    modelRegistry,
    servingRuntimes,
    pipelines,
    pipelineRuns,
    trainingJobs,
    experiments,
    evalJobs,
    inference,
    monitoringTargets,
    distributedWorkloads,
    enabledApps,
    learningResources,
  ] = await Promise.all([
    projects(),
    aiResources('workbenches'),
    aiResources('routes'),
    aiResources('agents'),
    aiResources('modelRegistry'),
    aiResources('servingRuntimes'),
    aiResources('pipelines'),
    aiResources('pipelineRuns'),
    aiResources('trainingJobs'),
    aiResources('experiments'),
    aiResources('evalJobs'),
    aiResources('inference'),
    aiResources('trustyaiMonitoring'),
    aiResources('distributedWorkloads'),
    aiResources('enabledApplications'),
    nativeLearningResourceRecords(),
  ]);
  return {
    phase: 'Ready',
    projects: projectItems.slice(0, 2),
    counts: {
      projects: actualCount(projectItems),
      workbenches: actualCount(workbenches),
      llmRoutes: actualCount(routes),
      agents: actualCount(agents),
      modelRegistry: actualCount(modelRegistry),
      servingRuntimes: actualCount(servingRuntimes),
      pipelines: actualCount(pipelines),
      pipelineRuns: actualCount(pipelineRuns),
      trainingJobs: actualCount(trainingJobs),
      experiments: actualCount(experiments),
      evaluationJobs: actualCount(evalJobs),
      inferenceEndpoints: actualCount(inference),
      monitoringTargets: actualCount(monitoringTargets),
      distributedWorkloads: actualCount(distributedWorkloads),
      enabledApplications: actualCount(enabledApps),
    },
    referenceCounts: {
      projects: referenceCount(projectItems),
      workbenches: referenceCount(workbenches),
      llmRoutes: referenceCount(routes),
      agents: referenceCount(agents),
      modelRegistry: referenceCount(modelRegistry),
      servingRuntimes: referenceCount(servingRuntimes),
      pipelines: referenceCount(pipelines),
      pipelineRuns: referenceCount(pipelineRuns),
      trainingJobs: referenceCount(trainingJobs),
      experiments: referenceCount(experiments),
      evaluationJobs: referenceCount(evalJobs),
      inferenceEndpoints: referenceCount(inference),
      monitoringTargets: referenceCount(monitoringTargets),
      distributedWorkloads: referenceCount(distributedWorkloads),
      enabledApplications: referenceCount(enabledApps),
    },
    alerts: [{ severity: 'info', message: 'Overview counts show actual cluster resources. Reference examples are labeled separately and excluded from operational totals.' }],
    learningResources: learningResources.length ? learningResources : LEARNING_RESOURCES,
  };
}

// ── 콘솔 통합 알림 연동 (ADR-UI-003 P1 발행 백본) ──
// ai 백엔드 → 콘솔 audit bus(/api/admin/events) → 셸 단일 인박스.
// 시작/노드 경고를 콘솔 인박스에 발행 = subShell이 콘솔 알림 core와 '유기적' 작동.
// best-effort: 발행 실패해도 ai 본 기능엔 영향 없음. (manifest 권한 불요 — 백엔드 in-cluster 호출)
const CONTROLLER = process.env.OSP_CONTROLLER || 'http://dupa-registry-controller.opensphere-system.svc.cluster.local:8080';
async function publishNotify(ev) {
  try {
    await fetch(`${CONTROLLER}/api/admin/events`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-opensphere-source': 'ai' },
      body: JSON.stringify({ source: 'ai', ...ev }),
    });
  } catch (e) { /* 콘솔 알림은 best-effort */ }
}
const _notifiedNodes = new Set();
async function nodeHealthPublish() {
  try {
    for (const n of await nodes()) {
      if (!n.ready && !_notifiedNodes.has(n.name)) {
        _notifiedNodes.add(n.name);
        await publishNotify({ action: 'NodeNotReady', target: `Node/${n.name}`, result: 'warning', reason: `노드 ${n.name} NotReady (ai 감지)` });
      } else if (n.ready) {
        _notifiedNodes.delete(n.name); // 복구 시 재경고 허용
      }
    }
  } catch (e) { /* best-effort */ }
}

function serveFrom(root, rel, res) {
  const base = path.resolve(root);
  const safeRel = path.normalize(rel).replace(/^(\.\.[/\\])+/, '').replace(/^[/\\]+/, '');
  const fp = path.resolve(base, safeRel);
  if (fp !== base && !fp.startsWith(base + path.sep)) { res.writeHead(403); return res.end('forbidden'); }
  fs.stat(fp, (err, st) => {
    if (err || !st.isFile()) { res.writeHead(404); return res.end('not found'); }
    const mime = MIME[path.extname(fp)] || 'application/octet-stream';
    // PoC: 재배포 시 셸 브라우저가 구 번들을 캐시해 변경이 안 보이는 문제 회피
    fs.createReadStream(fp).once('open', () => res.writeHead(200, { 'content-type': mime, 'cache-control': 'no-store' })).pipe(res);
  });
}

// 제네릭 K8s API 프록시: /api/k8s/<표준 K8s 경로> → APISERVER.
// 읽기(GET): SA 토큰(+토큰 있으면 사용자 임퍼소네이션). 쓰기(POST/PUT/PATCH/DELETE): 토큰 JWKS 검증 필수
// → Impersonate-User로 사용자 본인 RBAC 인가(SA 광범위 write 금지). secrets 전면 차단. 쓰기는 감사 로그.
async function k8sProxy(req, res, rawUrl) {
  // 보안: 원시 경로 정규식 매칭은 URL 인코딩(sec%72ets)으로 우회됨 → 디코드 후 세그먼트 정확 매칭.
  const qIdx = rawUrl.indexOf('?');
  const rawQuery = qIdx >= 0 ? rawUrl.slice(qIdx) : ''; // 쿼리는 원형 유지(labelSelector 등)
  let pathOnly;
  try { pathOnly = decodeURIComponent(rawUrl.slice('/api/k8s'.length).split('?')[0]); }
  catch { return jsonRes(res, 400, { error: 'bad path encoding' }); }
  if (!/^\/(api|apis)\//.test(pathOnly)) return jsonRes(res, 400, { error: 'only /api or /apis paths allowed' });
  const segs = pathOnly.split('/').filter(Boolean);
  // 이중 인코딩 거부(%xx가 디코드 후에도 남아있으면 차단)
  if (segs.some((s) => s.includes('%'))) return jsonRes(res, 400, { error: 'encoded path segments not allowed' });
  // 시크릿: 어느 세그먼트든 'secrets'면 차단(denylist)
  if (segs.includes('secrets')) return jsonRes(res, 403, { error: 'secrets are blocked by policy' });
  // 고위험 서브리소스(마지막 세그먼트) 차단: exec/attach/portforward/proxy, serviceaccounts/*/token
  const last = segs[segs.length - 1];
  if (['exec', 'attach', 'portforward', 'proxy'].includes(last)) return jsonRes(res, 403, { error: 'subresource blocked by policy' });
  if (segs.includes('serviceaccounts') && last === 'token') return jsonRes(res, 403, { error: 'token subresource blocked by policy' });

  const isWrite = WRITE_METHODS.has(req.method);
  const idToken = req.headers['x-os-id-token']; // 셸이 실어 보낸 콘솔 IdP 토큰
  // 헤더는 새로 구성 — 클라이언트의 Impersonate-*/Authorization은 절대 전달하지 않음(위조 차단)
  const headers = { Authorization: `Bearer ${tok()}`, Accept: 'application/json' };
  let actor = null;

  if (isWrite) {
    try { actor = await verifyToken(idToken); }
    catch (e) { return jsonRes(res, e.code || 401, { error: e.msg || 'unauthorized' }); }
    headers['Impersonate-User'] = actor.username;
    const ct = req.headers['content-type'];
    if (ct) headers['Content-Type'] = ct;
  } else if (idToken) {
    // 읽기: 토큰이 있으면 사용자 임퍼소네이션(per-user RBAC). 검증 실패 시 SA 읽기로 폴백.
    try { actor = await verifyToken(idToken); headers['Impersonate-User'] = actor.username; } catch { actor = null; }
  }

  const body = isWrite ? await readBody(req) : undefined;
  // 업스트림은 검증된 디코드 경로 + 원형 쿼리로 재구성(원시 sub 그대로 전달 금지)
  const r = await fetch(`${APISERVER}${pathOnly}${rawQuery}`, { method: req.method, headers, body });
  const text = await r.text();
  if (isWrite) console.log(`[audit] user=${actor && actor.username} verb=${req.method} path=${pathOnly} status=${r.status} ${new Date().toISOString()}`);
  res.writeHead(r.status, { 'content-type': r.headers.get('content-type') || 'application/json', 'cache-control': 'no-store' });
  res.end(text);
}

const server = http.createServer(async (req, res) => {
  const p = new URL(req.url, `http://${req.headers.host}`).pathname;
  try {
    await authorizeAiRequest(req, p);
    if (p === '/healthz') { res.writeHead(200); return res.end('ok'); }
    if (p === '/metrics') { res.writeHead(200, { 'content-type': 'text/plain; version=0.0.4; charset=utf-8', 'cache-control': 'no-store' }); return res.end(prometheusMetricsText()); }
    if (p === '/capabilities') return jsonRes(res, 200, await capabilityStatus());
    if (p === '/actions/create' && req.method === 'POST') return jsonRes(res, 201, await createAction(req));
    if (p === '/actions/delete' && req.method === 'DELETE') return jsonRes(res, 200, await deleteAction(req));
    if (p === '/operations/workbenches' && req.method === 'POST') return jsonRes(res, 200, await workbenchOperation(req));
    if (p === '/operations/inference' && req.method === 'POST') return jsonRes(res, 200, await inferenceUpdate(req));
    if (p === '/operations/pipelines/run' && req.method === 'POST') return jsonRes(res, 200, await runPipeline(req));
    if (p === '/operations/claims' && req.method === 'POST') return jsonRes(res, 200, await patchClaimOperation(req));
    if (p === '/pipeline/runs/logs') return jsonRes(res, 200, await pipelineLogs(req.url));
    if (p === '/pipeline/runs/lineage') return jsonRes(res, 200, await pipelineLineage(req.url));
    if (p === '/monitoring/trustyai/metrics') return jsonRes(res, 200, await trustyaiMetrics(req.url));
    if (p === '/models/registry/versions' && req.method === 'GET') return jsonRes(res, 200, await modelVersions(req.url));
    if (p === '/models/registry/versions' && req.method === 'POST') return jsonRes(res, 200, await addModelVersion(req));
    if (p === '/models/registry/upstream' && req.method === 'GET') return jsonRes(res, 200, await modelRegistryUpstream(req.url));
    if (p === '/models/registry/upstream/self-test' && req.method === 'POST') return jsonRes(res, 200, await modelRegistryWriteSelfTest(req));
    if (p === '/admin/odh-components' && req.method === 'GET') return jsonRes(res, 200, await odhComponents());
    if (p === '/admin/odh-components/action' && req.method === 'POST') return jsonRes(res, 200, await odhComponentOperation(req));
    if (p === '/admin/native/catalog' && req.method === 'GET') return jsonRes(res, 200, await nativeCatalog());
    if (p === '/admin/native/backends' && req.method === 'GET') return jsonRes(res, 200, await nativeBackends());
    if (p === '/admin/native/controller-metrics' && req.method === 'GET') return jsonRes(res, 200, await nativeControllerMetricsWithAuditFallback());
    if (p === '/admin/native/audit-log' && req.method === 'GET') return jsonRes(res, 200, await nativeAuditLog());
    if (p === '/admin/native/final-readiness' && req.method === 'GET') return jsonRes(res, 200, await finalReadiness(req));
    if (p === '/admin/native/gpu-inventory' && req.method === 'GET') return jsonRes(res, 200, await gpuInventory());
    if (p === '/admin/native/gpu-enablement-plan' && req.method === 'GET') return jsonRes(res, 200, await gpuEnablementPlan(req));
    if (p === '/admin/native/compute-routing' && req.method === 'GET') return jsonRes(res, 200, await computeRouting());
    if (p === '/admin/native/compute-routing' && req.method === 'POST') return jsonRes(res, 200, await saveComputeRouting(req));
    if (p === '/admin/native/gpu-bridge/health' && req.method === 'POST') return jsonRes(res, 200, await gpuBridgeHealth(req));
    if (p === '/admin/native/gpu-bridge/capabilities' && req.method === 'POST') return jsonRes(res, 200, await gpuBridgeCapabilities(req));
    if (p === '/admin/native/gpu-bridge/smoke' && req.method === 'POST') return jsonRes(res, 200, await gpuBridgeSmoke(req));
    if (p === '/admin/native/gpu-bridge/register' && req.method === 'POST') return jsonRes(res, 200, await gpuBridgeRegister(req));
    if (p === '/admin/native/gpu-bridge/training-smoke' && req.method === 'POST') return jsonRes(res, 200, await gpuBridgeTrainingSmoke(req));
    if (p === '/admin/native/demo-plan' && req.method === 'GET') return jsonRes(res, 200, await oahDemoPlan(req));
    if (p === '/admin/native/demo-run' && req.method === 'GET') return jsonRes(res, 200, await oahDemoRunStatus(new URL(req.url, `http://${req.headers.host}`).searchParams.get('namespace') || undefined));
    if (p === '/admin/native/demo-run' && req.method === 'POST') return jsonRes(res, 200, await oahDemoRun(req));
    if (p === '/admin/native/demo-run/evidence' && req.method === 'GET') return jsonRes(res, 200, await oahDemoRunEvidence(new URL(req.url, `http://${req.headers.host}`).searchParams.get('namespace') || undefined));
    if (p === '/admin/native/demo-run/preview' && req.method === 'GET') return jsonRes(res, 200, await oahDemoRunPreview(new URL(req.url, `http://${req.headers.host}`).searchParams.get('namespace') || undefined, req));
    if (p === '/admin/native/demo-run/reset' && req.method === 'POST') return jsonRes(res, 200, await oahDemoRunReset(req));
    if (p === '/admin/native/demo-smoke' && req.method === 'GET') return jsonRes(res, 200, await oahDemoSmokeStatus(new URL(req.url, `http://${req.headers.host}`).searchParams.get('namespace') || undefined));
    if (p === '/admin/native/demo-smoke/logs' && req.method === 'GET') return jsonRes(res, 200, await oahDemoSmokeLogs(new URL(req.url, `http://${req.headers.host}`).searchParams.get('namespace') || undefined));
    if (p === '/admin/native/demo-smoke/preview' && req.method === 'GET') return jsonRes(res, 200, await oahDemoSmokePreview(new URL(req.url, `http://${req.headers.host}`).searchParams.get('namespace') || undefined, req));
    if (p === '/admin/native/demo-smoke' && req.method === 'POST') return jsonRes(res, 200, await oahDemoSmokeRun(req));
    if (p === '/admin/native/catalog/seed' && req.method === 'POST') { await seedNativeCatalog(req); return jsonRes(res, 200, await nativeCatalog()); }
    if (p === '/admin/native/subscriptions' && req.method === 'POST') return jsonRes(res, 200, await nativeSubscribe(req));
    if (p === '/admin/native/installplans/approve' && req.method === 'POST') return jsonRes(res, 200, await nativeApproveInstallPlan(req));
    if (p === '/admin/native/installplans/upgrade' && req.method === 'POST') return jsonRes(res, 200, await nativeUpgradeComponent(req));
    if (p === '/admin/native/installplans/rollback' && req.method === 'POST') return jsonRes(res, 200, await nativeRollbackComponent(req));
    if (p === '/admin/native/datasciencecluster' && req.method === 'POST') return jsonRes(res, 200, await nativeDataScienceCluster(req));
    if (p === '/admin/native/reconcile/workbenches' && req.method === 'POST') return jsonRes(res, 200, await reconcileWorkbenches());
    if (p === '/admin/native/reconcile/pipelineruns' && req.method === 'POST') return jsonRes(res, 200, await reconcilePipelineRuns());
    if (p === '/admin/native/reconcile/inferences' && req.method === 'POST') return jsonRes(res, 200, await reconcileInferences());
    if (p === '/admin/native/reconcile/evaluations' && req.method === 'POST') return jsonRes(res, 200, await reconcileEvaluationJobs());
    if (p === '/admin/native/reconcile/promotions' && req.method === 'POST') return jsonRes(res, 200, await reconcileModelPromotions());
    if (p === '/admin/native/reconcile/monitoring' && req.method === 'POST') return jsonRes(res, 200, await reconcileMonitoringTargets());
    if (p === '/admin/native/reconcile/distributed' && req.method === 'POST') return jsonRes(res, 200, await reconcileDistributedWorkloads());
    if (p === '/admin/native/reconcile/passive' && req.method === 'POST') return jsonRes(res, 200, await reconcilePassiveResources());
    if (p === '/admin/setup/status') return jsonRes(res, 200, await setupStatus(req));
    if (p === '/admin/setup/plan') return jsonRes(res, 200, await setupPlan(req));
    if (p === '/admin/setup/install' && req.method === 'POST') return jsonRes(res, 200, await setupInstall(req));
    if (p === '/summary') return jsonRes(res, 200, await summary());
    if (p === '/projects') return jsonRes(res, 200, await projectsPayload());
    if (p === '/workbenches') return jsonRes(res, 200, await resourcePayload('workbenches'));
    if (p === '/workbenches/images') return jsonRes(res, 200, await resourcePayload('notebookImages'));
    if (p === '/workbenches/data-connections') return jsonRes(res, 200, await resourcePayload('dataConnections'));
    if (p === '/resources/agents') return jsonRes(res, 200, await resourcePayload('agents'));
    if (p === '/foundation/routes') return jsonRes(res, 200, await resourcePayload('routes'));
    if (p === '/foundation/retrieval') return jsonRes(res, 200, await resourcePayload('retrieval'));
    if (p === '/models/serving-runtimes') return jsonRes(res, 200, await resourcePayload('servingRuntimes'));
    if (p === '/models/registry') return jsonRes(res, 200, await resourcePayload('modelRegistry'));
    if (p === '/pipelines') return jsonRes(res, 200, await resourcePayload('pipelines'));
    if (p === '/pipeline/runs') return jsonRes(res, 200, await resourcePayload('pipelineRuns'));
    if (p === '/training/compute') return jsonRes(res, 200, await resourcePayload('compute'));
    if (p === '/training/datasets') return jsonRes(res, 200, await resourcePayload('datasets'));
    if (p === '/training/jobs') return jsonRes(res, 200, await resourcePayload('trainingJobs'));
    if (p === '/models/promotions') return jsonRes(res, 200, await resourcePayload('promotions'));
    if (p === '/experiments/runs') return jsonRes(res, 200, await resourcePayload('experiments'));
    if (p === '/experiments/executions') return jsonRes(res, 200, await resourcePayload('executions'));
    if (p === '/experiments/artifacts') return jsonRes(res, 200, await resourcePayload('artifacts'));
    if (p === '/evaluation/policies') return jsonRes(res, 200, await resourcePayload('evalPolicies'));
    if (p === '/evaluation/jobs') return jsonRes(res, 200, await resourcePayload('evalJobs'));
    if (p === '/monitoring/trustyai') return jsonRes(res, 200, await resourcePayload('trustyaiMonitoring'));
    if (p === '/distributed/workloads') return jsonRes(res, 200, await resourcePayload('distributedWorkloads'));
    if (p === '/inference') return jsonRes(res, 200, await resourcePayload('inference'));
    if (p === '/admin/cluster-settings') return jsonRes(res, 200, await resourcePayload('clusterSettings'));
    if (p === '/applications/enabled') return jsonRes(res, 200, await resourcePayload('enabledApplications'));
    if (p === '/applications/explore') return jsonRes(res, 200, await resourcePayload('exploreApplications'));
    if (p === '/developer/learning') return jsonRes(res, 200, await resourcePayload('developerLearning'));
    if (p === '/catalog') return jsonRes(res, 200, await resourcePayload('catalog'));
    if (p === '/api/session') {
      // WS(exec/터미널)용 신원 쿠키 발급 — 토큰 JWKS 검증 후 HttpOnly 쿠키로(브라우저 WS가 보낼 수 있게)
      let actor;
      try { actor = await verifyToken(req.headers['x-os-id-token']); }
      catch (e) { return jsonRes(res, e.code || 401, { error: e.msg || 'unauthorized' }); }
      const secure = req.headers['x-forwarded-proto'] === 'https' ? ' Secure;' : '';
      res.writeHead(200, {
        'content-type': 'application/json',
        'set-cookie': `${COOKIE}=${encodeURIComponent(req.headers['x-os-id-token'])}; HttpOnly; SameSite=Strict; Path=/api/plugins/ai;${secure} Max-Age=600`,
      });
      return res.end(JSON.stringify({ user: actor.username }));
    }
    if (p.startsWith('/api/k8s/')) return k8sProxy(req, res, req.url);
    if (p === '/api/nodes') {
      const list = await nodes();
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({
        meta: { service: 'ai', version: VERSION, servedBy: process.env.HOSTNAME, time: new Date().toISOString() },
        nodes: list,
      }));
    }
    if (p === '/plugins' || p === '/plugins/') {
      const files = fs.existsSync(PLUGINS) ? fs.readdirSync(PLUGINS).filter((f) => !f.startsWith('.')) : [];
      res.writeHead(200, { 'content-type': 'application/json' }); return res.end(JSON.stringify({ plugins: files }));
    }
    if (p.startsWith('/plugins/')) return serveFrom(PLUGINS, p.slice('/plugins/'.length), res);
    if (p.startsWith('/app/')) return serveFrom(WWW, p.slice('/app/'.length), res);
    if (p === '/ai' || p.startsWith('/ai/')) return serveFrom(WWW, 'index.html', res);
    res.writeHead(404); res.end('not found');
  } catch (e) {
    const code = e && e.code ? e.code : 500;
    res.writeHead(code, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: e && e.msg ? e.msg : String(e), details: e && e.details ? e.details : undefined }));
  }
});
// ── WS exec/터미널 게이트웨이 ──────────────────────────────────────────────
// 브라우저 WS(/api/k8s-exec/<ns>/<pod>?container=&command=) → 쿠키 토큰 JWKS 검증 → apiserver exec
// 채널(v4.channel.k8s.io)로 투명 릴레이. SA 토큰 + Impersonate-User로 사용자 본인 RBAC(create pods/exec) 인가.
const wss = new WebSocketServer({ noServer: true });
server.on('upgrade', async (req, socket, head) => {
  const u = new URL(req.url, 'http://x');
  const m = u.pathname.match(/^\/api\/k8s-exec\/([^/]+)\/([^/]+)$/);
  if (!m) { socket.destroy(); return; }
  let actor;
  try { actor = await verifyToken(tokenFromCookie(req.headers.cookie)); }
  catch { socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n'); socket.destroy(); return; }
  const ns = decodeURIComponent(m[1]);
  const pod = decodeURIComponent(m[2]);
  const container = u.searchParams.get('container') || '';
  const commands = u.searchParams.getAll('command');
  const cmds = commands.length ? commands : ['/bin/sh'];
  wss.handleUpgrade(req, socket, head, (browserWs) => {
    const qs = new URLSearchParams();
    if (container) qs.set('container', container);
    qs.set('stdin', 'true'); qs.set('stdout', 'true'); qs.set('stderr', 'true'); qs.set('tty', 'true');
    for (const c of cmds) qs.append('command', c);
    const upUrl = `${APISERVER.replace(/^https/, 'wss')}/api/v1/namespaces/${ns}/pods/${pod}/exec?${qs.toString()}`;
    const up = new WebSocket(upUrl, ['v4.channel.k8s.io'], {
      headers: { Authorization: `Bearer ${tok()}`, 'Impersonate-User': actor.username },
    });
    console.log(`[audit] exec user=${actor.username} pod=${ns}/${pod} container=${container} ${new Date().toISOString()}`);
    const closeBoth = () => { try { browserWs.close(); } catch {} try { up.close(); } catch {} };
    up.on('message', (data) => { if (browserWs.readyState === 1) browserWs.send(data, { binary: true }); });
    browserWs.on('message', (data) => { if (up.readyState === 1) up.send(data); });
    up.on('close', closeBoth);
    up.on('error', (e) => { try { browserWs.send(Buffer.from([3, ...Buffer.from(String(e))])); } catch {} closeBoth(); });
    browserWs.on('close', closeBoth);
    browserWs.on('error', closeBoth);
  });
});

server.listen(PORT, () => {
  console.log(`ai v${VERSION} on :${PORT}`);
  // 콘솔 인박스에 시작 이벤트 발행 + 주기적 노드 헬스(유기적 연동)
  publishNotify({ action: 'started', target: 'ai', result: 'info', reason: `AI 백엔드 v${VERSION} 시작` });
  nodeHealthPublish();
  setInterval(nodeHealthPublish, 60000);
  reconcileWorkbenches().catch((e) => console.error('[controller] workbench reconcile failed: ' + (e.msg || e)));
  reconcilePipelineRuns().catch((e) => console.error('[controller] pipeline run reconcile failed: ' + (e.msg || e)));
  reconcileInferences().catch((e) => console.error('[controller] inference reconcile failed: ' + (e.msg || e)));
  reconcileEvaluationJobs().catch((e) => console.error('[controller] evaluation reconcile failed: ' + (e.msg || e)));
  reconcileModelPromotions().catch((e) => console.error('[controller] model promotion reconcile failed: ' + (e.msg || e)));
  reconcileMonitoringTargets().catch((e) => console.error('[controller] monitoring reconcile failed: ' + (e.msg || e)));
  reconcileDistributedWorkloads().catch((e) => console.error('[controller] distributed workload reconcile failed: ' + (e.msg || e)));
  reconcilePassiveResources().catch((e) => console.error('[controller] passive resource reconcile failed: ' + (e.msg || e)));
  setInterval(() => {
    reconcileWorkbenches().catch((e) => console.error('[controller] workbench reconcile failed: ' + (e.msg || e)));
    reconcilePipelineRuns().catch((e) => console.error('[controller] pipeline run reconcile failed: ' + (e.msg || e)));
    reconcileInferences().catch((e) => console.error('[controller] inference reconcile failed: ' + (e.msg || e)));
    reconcileEvaluationJobs().catch((e) => console.error('[controller] evaluation reconcile failed: ' + (e.msg || e)));
    reconcileModelPromotions().catch((e) => console.error('[controller] model promotion reconcile failed: ' + (e.msg || e)));
    reconcileMonitoringTargets().catch((e) => console.error('[controller] monitoring reconcile failed: ' + (e.msg || e)));
    reconcileDistributedWorkloads().catch((e) => console.error('[controller] distributed workload reconcile failed: ' + (e.msg || e)));
    reconcilePassiveResources().catch((e) => console.error('[controller] passive resource reconcile failed: ' + (e.msg || e)));
  }, 30000);
});
