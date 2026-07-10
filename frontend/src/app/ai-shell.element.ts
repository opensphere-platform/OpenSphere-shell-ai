import { Component, OnDestroy, OnInit, computed, signal } from '@angular/core';
import { ClarityModule } from '@clr/angular';
import Application16 from '@carbon/icons/es/application/16';
import ChartLine16 from '@carbon/icons/es/chart--line/16';
import Document16 from '@carbon/icons/es/document/16';
import Education16 from '@carbon/icons/es/education/16';
import Flow16 from '@carbon/icons/es/flow/16';
import Folder16 from '@carbon/icons/es/folder/16';
import Home16 from '@carbon/icons/es/home/16';
import MachineLearningModel16 from '@carbon/icons/es/machine-learning-model/16';
import Settings16 from '@carbon/icons/es/settings/16';
import Workspace16 from '@carbon/icons/es/workspace/16';
import { AiCarbonIcon, type AiIconNode } from './ai-carbon-icon';

type PageId =
  | 'home'
  | 'projects'
  | 'workbenches'
  | 'notebook-images'
  | 'data-connections'
  | 'agents'
  | 'llm-routes'
  | 'retrieval'
  | 'serving-runtimes'
  | 'model-registry'
  | 'pipelines'
  | 'pipeline-runs'
  | 'compute'
  | 'datasets'
  | 'training-jobs'
  | 'model-promotion'
  | 'experiments-runs'
  | 'executions'
  | 'artifacts'
  | 'eval-policy'
  | 'eval-jobs'
  | 'trustyai-monitoring'
  | 'distributed-workloads'
  | 'inference'
  | 'cluster-settings'
  | 'apps-enabled'
  | 'apps-explore'
  | 'developer-learning'
  | 'resources';

type ClusterSettingsTab = 'setup' | 'readiness' | 'gpu' | 'demo' | 'operations';

interface NavLeaf {
  kind: 'leaf';
  id: PageId;
  label: string;
  icon?: AiIconNode;
}

interface NavGroup {
  kind: 'group';
  id: string;
  label: string;
  icon?: AiIconNode;
  children: NavLeaf[];
}

type NavNode = NavLeaf | NavGroup;

interface ProjectItem {
  name: string;
  displayName: string;
  created: string;
  owner: string;
  phase: string;
  description?: string;
  source?: string;
  reference?: boolean;
}

interface ResourceItem {
  name: string;
  kind: string;
  phase: string;
  ready: boolean;
  namespace?: string;
  description?: string;
  reason?: string;
  message?: string;
  retryCount?: number;
  nextRetryAt?: string;
  finalizing?: boolean;
  computeBackendRef?: string;
  computeRoutingWorkload?: string;
  computeRoutingBackend?: string;
  computeRoutingAppliedAt?: string;
  backendType?: string;
  provider?: string;
  endpoint?: string;
  resourceName?: string;
  supportedJobTypes?: string[];
  gpus?: Array<Record<string, unknown>>;
  externalJob?: Record<string, unknown> | null;
  externalJobLogs?: { lines?: Array<string | Record<string, unknown>>; text?: string } | null;
  externalJobLogSummary?: { latest?: string; nvidiaSmi?: string; gpu?: string; usage?: string; lineCount?: number } | null;
  maxConcurrency?: string | number;
  currentConcurrency?: string | number;
  source?: string;
  backendMode?: string;
  parityReady?: boolean;
  reference?: boolean;
}

interface K8sObjectSummary {
  name: string;
  namespace: string;
  kind: string;
  phase: string;
  ready: boolean;
  message?: string;
}

interface WorkbenchDetailResponse {
  item: ResourceItem;
  runtime: {
    name: string;
    namespace: string;
    image: string;
    openUrl: string;
    proxyUrl: string;
    backendMode: string;
    reachability?: {
      checked: boolean;
      ready: boolean;
      status: number;
      phase: string;
      message: string;
    };
  };
  storage?: K8sObjectSummary | null;
  deployment?: K8sObjectSummary | null;
  service?: K8sObjectSummary | null;
  pods: K8sObjectSummary[];
  events: Array<{ time: string; type: string; reason: string; message: string }>;
  logs: { pod: string; tailLines: string[] };
}

interface PipelineDetailResponse {
  item: ResourceItem;
  pipelineName: string;
  backendMode: string;
  definition: {
    version: string;
    source: string;
    parameters: Record<string, unknown>;
  };
  runs: ResourceItem[];
  experiments: ResourceItem[];
  artifacts: ResourceItem[];
  lineage: PipelineLineageItem[];
  logs: string[];
}

interface InferenceDetailResponse {
  item: ResourceItem;
  runtime: {
    name: string;
    namespace: string;
    image: string;
    modelName: string;
    runtime: string;
    modelUri: string;
    url: string;
    predictUrl: string;
    backendMode: string;
    backendResource: string;
    reachability?: {
      checked: boolean;
      ready: boolean;
      status: number;
      phase: string;
      message: string;
    };
  };
  deployment?: K8sObjectSummary | null;
  service?: K8sObjectSummary | null;
  inferenceService?: K8sObjectSummary | null;
  pods: K8sObjectSummary[];
  conditions: Array<{ type: string; status: string; reason: string; message: string; lastTransitionTime: string }>;
  upstreamConditions: Array<{ type: string; status: string; reason: string; message: string; lastTransitionTime: string }>;
  events: Array<{ time: string; type: string; reason: string; message: string }>;
  logs: { pod: string; tailLines: string[] };
}

interface DataConnectionDetailResponse {
  item: ResourceItem;
  provider: string;
  endpoint: string;
  database: string;
  owner: string;
  secret: {
    name: string;
    namespace: string;
    readable: boolean;
    type: string;
    keys: string[];
    masked: boolean;
    message: string;
  };
  usage: ResourceItem[];
  conditions: Array<{ type: string; status: string; reason: string; message: string; lastTransitionTime: string }>;
}

interface LearningResource {
  title: string;
  provider: string;
  type: string;
  duration: string;
  description: string;
  href: string;
}

interface SummaryResponse {
  phase: string;
  projects: ProjectItem[];
  counts: {
    projects: number;
    workbenches: number;
    llmRoutes: number;
    agents: number;
    modelRegistry: number;
    servingRuntimes: number;
    pipelines: number;
    pipelineRuns: number;
    trainingJobs: number;
    experiments: number;
    evaluationJobs: number;
    inferenceEndpoints: number;
    monitoringTargets: number;
    distributedWorkloads: number;
    enabledApplications: number;
  };
  referenceCounts?: Partial<SummaryResponse['counts']>;
  alerts: Array<{ severity: string; message: string }>;
  learningResources: LearningResource[];
}

interface ResourceListResponse {
  items: ResourceItem[];
  actualCount?: number;
  referenceCount?: number;
  source?: string;
  sourceBreakdown?: Record<string, number>;
  backendModes?: Record<string, number>;
  readinessModel?: ResourceReadinessModel;
}

interface ProjectListResponse {
  items: ProjectItem[];
  actualCount?: number;
  referenceCount?: number;
  source?: string;
}

interface ResourceMeta {
  actualCount: number;
  referenceCount: number;
  source: string;
  sourceBreakdown?: Record<string, number>;
  backendModes?: Record<string, number>;
  readinessModel?: ResourceReadinessModel;
}

interface ResourceReadinessModel {
  nativeReady: number;
  upstreamAdapterReady: number;
  upstreamParityReady: number;
  reference: number;
}

interface CapabilityItem {
  page: PageId | 'projects';
  label: string;
  kind: string;
  crdName: string;
  installed: boolean;
  namespaced: boolean;
}

interface CapabilityResponse {
  items: CapabilityItem[];
}

interface CreateForm {
  page: PageId;
  name: string;
  namespace: string;
  displayName: string;
  description: string;
  tier: string;
  llmRouteRef: string;
  promptLibraryRef: string;
  provider: string;
  model: string;
  endpoint: string;
  backendType: string;
  gpuClass: string;
  sourceType: string;
  sourceRef: string;
  purpose: string;
  computeBackendRef: string;
  datasetRef: string;
  framework: string;
  trainingMode: string;
  modelRef: string;
  evaluationRef: string;
  stage: string;
  metric: string;
  minimum: string;
  enforcement: string;
  policyRef: string;
  targetRef: string;
  targetKind: string;
  promotionRef: string;
  runtime: string;
  version: string;
  source: string;
  requireSourceAttribution: boolean;
}

interface PipelineLineageItem {
  from: string;
  to: string;
  type: string;
}

interface TrustyMetricItem {
  metric: string;
  value: number;
  threshold: number;
  status: string;
  source?: string;
}

interface TrustyAlertItem {
  id: string;
  rule: string;
  severity: string;
  metric: string;
  status: string;
  value: number;
  threshold: number;
  activeSamples: number;
  message: string;
}

interface TrustyHistoryItem {
  id: string;
  time: string;
  metric: string;
  value: number;
  threshold: number;
  status: string;
}

interface ModelVersionItem {
  name: string;
  version: string;
  stage: string;
  source: string;
  backend?: string;
  registry?: string;
}

interface RegistryResourceItem {
  id: string;
  label: string;
  path: string;
  ready: boolean;
  count: number;
  error?: string;
}

interface RegistryStatusResponse {
  backend?: {
    mode?: string;
    phase?: string;
    message?: string;
    ready?: boolean;
  };
  source?: {
    type?: string;
    name?: string;
    namespace?: string;
    endpoint?: string;
  };
  upstream?: {
    attempted?: boolean;
    ready?: boolean;
    message?: string;
    resources?: RegistryResourceItem[];
    artifacts?: unknown[];
  };
  summary?: {
    phase?: string;
    mode?: string;
    ready?: boolean;
    resourcesReady?: number;
    resourcesTotal?: number;
    versions?: number;
    upstreamVersions?: number;
    artifacts?: number;
  };
}

interface RegistryPromotionItem {
  name: string;
  namespace: string;
  modelName: string;
  version: string;
  stage: string;
  approvalDecision?: string;
  evaluationPhase?: string;
  metricCount?: number;
  promotedAt?: string;
}

interface RegistryApprovalAuditItem {
  id: string;
  recordedAt: string;
  namespace: string;
  promotionRef: string;
  modelName: string;
  version: string;
  stage: string;
  decision: string;
  evaluationPhase?: string;
  actor?: string;
}

interface RegistryEvaluationMetricItem {
  id: string;
  recordedAt: string;
  namespace: string;
  promotionRef: string;
  modelName: string;
  version: string;
  metric: string;
  value: number;
  threshold?: number;
  passed: boolean;
  evaluationPhase?: string;
}

interface RegistrySelfTestResponse {
  attempted?: boolean;
  synced?: boolean;
  message?: string;
  source?: {
    type?: string;
    name?: string;
    namespace?: string;
    endpoint?: string;
  };
  version?: {
    name?: string;
    version?: string;
    stage?: string;
  };
  upstreamSync?: {
    synced?: boolean;
    steps?: Array<{
      resource: string;
      path: string;
      ready: boolean;
      error?: string;
    }>;
  };
}

interface SetupCheckItem {
  id: string;
  label: string;
  ready: boolean;
  detail: string;
}

interface SetupCrdItem {
  name: string;
  label: string;
  installed: boolean;
  family: string;
}

interface SetupStepItem {
  id: string;
  label: string;
  phase?: string;
  detail?: string;
  action?: string;
}

interface SetupStatusResponse {
  prerequisites: SetupCheckItem[];
  crds: SetupCrdItem[];
  operators: {
    olmAvailable: boolean;
    subscriptions: Array<{ name: string; namespace: string; package: string; channel: string; source: string }>;
    csvs: Array<{ name: string; namespace: string; phase: string }>;
  };
  namespaces: string[];
  dataScienceClusters: ResourceItem[];
  nativePlatform?: NativePlatformResponse;
}

interface NativeComponentItem {
  name: string;
  displayName: string;
  channel: string;
  version: string;
  operation?: string;
  installedVersion?: string;
  targetVersion?: string;
  previousVersion?: string;
  rollbackVersion?: string;
  lastTransitionTime?: string;
  description: string;
  upstream: string[];
  subscribed: boolean;
  installed: boolean;
  phase: string;
  managementState: string;
}

interface NativePlatformResponse {
  components: NativeComponentItem[];
  subscriptions: ResourceItem[];
  installPlans: ResourceItem[];
  dataScienceClusters: ResourceItem[];
}

interface NativeBackendCrdItem {
  name: string;
  label: string;
  installed: boolean;
  optional?: boolean;
}

interface NativeBackendItem {
  id: string;
  displayName: string;
  component: string;
  upstream: string[];
  fallback: string;
  mode: string;
  phase: string;
  ready: boolean;
  upstreamReady: boolean;
  fallbackReady: boolean;
  crds: NativeBackendCrdItem[];
  missing: string[];
  message: string;
}

interface NativeBackendsResponse {
  summary: {
    upstreamReady: number;
    fallbackReady: number;
    unavailable: number;
    total: number;
    phase: string;
  };
  items: NativeBackendItem[];
}

interface GpuResourceItem {
  name: string;
  capacity: string;
  allocatable: string;
  capacityNumber: number;
  allocatableNumber: number;
}

interface GpuInventoryNode {
  name: string;
  ready: boolean;
  schedulable: boolean;
  gpuResources: GpuResourceItem[];
  gpuCapacity: number;
  gpuAllocatable: number;
  gpuLabels: Record<string, string>;
}

interface GpuInventoryPlugin {
  name: string;
  namespace: string;
  phase: string;
  nodeName?: string;
  desired?: number;
  ready?: number | boolean;
  images?: string[];
}

interface GpuInventoryResponse {
  phase: string;
  ready: boolean;
  generatedAt: string;
  summary: {
    nodes: number;
    readyNodes: number;
    gpuNodes: number;
    totalCapacity: number;
    totalAllocatable: number;
    pluginPods: number;
    pluginDaemonSets: number;
    runtimeClasses: number;
    diagnostics?: number;
  };
  nodes: GpuInventoryNode[];
  pluginPods: GpuInventoryPlugin[];
  pluginDaemonSets: GpuInventoryPlugin[];
  runtimeClasses: Array<{ name: string; handler: string }>;
  diagnostics: Array<{
    source: string;
    namespace: string;
    kind: string;
    nodeName?: string;
    phase: string;
    severity: string;
    message: string;
    nextStep: string;
    evidence: string[];
  }>;
  nextSteps: string[];
}

interface GpuEnablementPlanResponse {
  profile: string;
  title: string;
  phase: string;
  generatedAt: string;
  summary: string;
  resourceName: string;
  namespace: string;
  upstream: string;
  operator: string;
  mode: string;
  config: GpuEnablementConfig;
  alternatives: Array<{ id: string; label: string; mode: string; resourceName: string; summary: string }>;
  inventory: {
    phase: string;
    ready: boolean;
    summary: Record<string, number>;
  };
  prerequisites: Array<{ id: string; text: string }>;
  checks: Array<{ id: string; label: string; phase: string; ready: boolean; detail: string }>;
  commands: string[];
  manifests: unknown[];
  warnings: string[];
}

interface GpuCatalogServiceItem {
  id: string;
  label: string;
  mode: string;
  resourceName: string;
  summary: string;
  category: string;
  serviceRole: string;
  workloads: string;
  verification: string;
  phase: string;
  ready: boolean;
  selected: boolean;
  selectable: boolean;
  registered: boolean;
  endpoint?: string;
  backendName?: string;
  backendNamespace?: string;
}

interface GpuEnablementConfig {
  namespace: string;
  resourceName: string;
  pluginImage: string;
  runtimeClass: string;
  useRuntimeClass: boolean;
  nodeSelectorKey: string;
  nodeSelectorValue: string;
  packageName: string;
  channel: string;
  catalogSource: string;
  catalogNamespace: string;
  externalEndpoint: string;
  credentialSecret: string;
  maxConcurrency: number;
}

interface GpuBridgeProbeResponse {
  phase: string;
  ready: boolean;
  endpoint: string;
  namespace: string;
  credentialSecret: string;
  checkedAt: string;
  health?: Record<string, unknown>;
  backend?: ResourceItem;
  trainingJob?: ResourceItem;
  capabilities?: {
    backendType?: string;
    provider?: string;
    ready?: boolean;
    gpus?: Array<Record<string, unknown>>;
    supportedJobTypes?: string[];
    maxConcurrency?: number;
    currentConcurrency?: number;
  };
  job?: Record<string, unknown>;
  logs?: { lines?: string[]; text?: string };
}

interface ComputeRoutingOption {
  key: string;
  label: string;
  name: string;
  namespace: string;
  backendType: string;
  provider?: string;
  endpoint?: string;
  resourceName?: string;
  phase: string;
  ready: boolean;
  message?: string;
}

interface ComputeRoutingRoute {
  id: string;
  label: string;
  primary: string;
  fallback: string;
  phase: string;
  ready: boolean;
  message: string;
  primaryBackend?: ComputeRoutingOption | null;
  fallbackBackend?: ComputeRoutingOption | null;
}

interface ComputeRoutingResponse {
  namespace: string;
  name: string;
  phase: string;
  ready: boolean;
  updatedAt?: string;
  updatedBy?: string;
  parseError?: string;
  options: ComputeRoutingOption[];
  routes: ComputeRoutingRoute[];
}

interface DemoPrerequisiteItem {
  id: string;
  label: string;
  ready: boolean;
  required: boolean;
  detail: string;
}

interface DemoTaskItem {
  id: string;
  stage: string;
  title: string;
  oahArea: string;
  resources: string[];
  expected: string;
  requiresGpu: boolean;
  status: string;
  notes: string[];
}

interface OahDemoPlanResponse {
  title: string;
  acronym: string;
  phase: string;
  generatedAt: string;
  summary: string;
  prerequisites: DemoPrerequisiteItem[];
  evidence: Array<{ label: string; value: string }>;
  tasks: DemoTaskItem[];
  gpu?: GpuInventoryResponse;
}

interface DemoRunItem {
  id?: string;
  step?: string;
  page?: string;
  kind?: string;
  stage: string;
  title: string;
  name?: string;
  namespace?: string;
  phase: string;
  ready?: boolean;
  reason?: string;
  message?: string;
  item?: ResourceItem;
}

interface DemoRunStatusResponse {
  namespace: string;
  phase: string;
  generatedAt: string;
  summary: {
    expected: number;
    actual: number;
    ready: number;
    missingCrds: number;
    created?: number;
    updated?: number;
    skipped?: number;
    failed?: number;
    gpuReady?: boolean;
    total?: number;
  };
  items: DemoRunItem[];
  results?: DemoRunItem[];
  registry?: {
    phase: string;
    reason?: string;
    version?: { name: string; version: string; stage: string; source: string };
  };
}

interface DemoRunPreviewResponse {
  namespace: string;
  phase: string;
  generatedAt: string;
  summary: {
    total: number;
    ready: number;
    blockedByGpu: number;
    blockedByCrd: number;
    manifests: number;
  };
  gpu: {
    phase: string;
    ready: boolean;
    summary: Record<string, number>;
  };
  permission?: {
    hasToken: boolean;
    canRun: boolean;
    canReset: boolean;
    phase: string;
    checks: Array<{ id: string; label: string; allowed: boolean; required: boolean; detail: string }>;
  };
  checks: DemoRunItem[];
  manifests: unknown[];
}

interface DemoEvidenceAction {
  id: string;
  label: string;
  menu: string;
  enabled: boolean;
  evidence: string;
}

interface DemoEvidenceRow {
  id: string;
  stage: string;
  title: string;
  page: string;
  menu: string;
  kind: string;
  resource: string;
  requiresGpu: boolean;
  visible: boolean;
  ready: boolean;
  phase: string;
  reason: string;
  message: string;
}

interface DemoRunEvidenceResponse {
  namespace: string;
  phase: string;
  generatedAt: string;
  summary: {
    totalTasks: number;
    visibleResources: number;
    readyResources: number;
    runnableWithoutGpu: number;
    blockedByGpu: number;
    gpuReady: boolean;
  };
  userCanDo: DemoEvidenceAction[];
  blockedActions: Array<{ id: string; label: string; menu: string; reason: string; nextStep: string }>;
  evidence: DemoEvidenceRow[];
  gpu: {
    phase: string;
    ready: boolean;
    summary: Record<string, number>;
    nextSteps: string[];
  };
}

interface DemoSmokeItem {
  id: string;
  stage: string;
  title: string;
  name?: string;
  namespace?: string;
  kind?: string;
  requiresGpu: boolean;
  phase: string;
  ready: boolean;
  reason?: string;
  message?: string;
  active?: number;
  succeeded?: number;
  failed?: number;
  startedAt?: string;
  completedAt?: string;
  item?: ResourceItem;
}

interface DemoSmokeStatusResponse {
  namespace: string;
  phase: string;
  generatedAt: string;
  summary: {
    total: number;
    succeeded: number;
    running: number;
    failed: number;
    notStarted: number;
    gpuReady: boolean;
    gpuBlocked: number;
    created?: number;
    skipped?: number;
  };
  image?: string;
  gpu: { phase: string; ready: boolean; summary: Record<string, number> };
  items: DemoSmokeItem[];
  results?: DemoSmokeItem[];
  status?: DemoSmokeStatusResponse;
}

interface DemoSmokePreviewResponse {
  namespace: string;
  phase: string;
  generatedAt: string;
  image: string;
  summary: {
    total: number;
    ready: number;
    blockedByGpu: number;
    manifests: number;
  };
  permission: {
    hasToken: boolean;
    canRun: boolean;
    canReset: boolean;
    phase: string;
    checks: Array<{ id: string; label: string; allowed: boolean; required: boolean; detail: string }>;
  };
  gpu: { phase: string; ready: boolean; summary: Record<string, number> };
  checks: DemoSmokeItem[];
  manifests: unknown[];
}

interface DemoSmokeLogItem {
  id: string;
  stage: string;
  title: string;
  jobName: string;
  pod?: string;
  requiresGpu: boolean;
  phase: string;
  lines: string[];
  records: unknown[];
  message: string;
}

interface DemoSmokeLogsResponse {
  namespace: string;
  phase: string;
  generatedAt: string;
  summary: {
    jobs: number;
    withPods: number;
    withLogs: number;
    records: number;
    lines: number;
  };
  items: DemoSmokeLogItem[];
}

interface ControllerMetricItem {
  controller: string;
  phase: string;
  backend: string;
  total: number;
  failures: number;
  historicalFailures?: number;
  avgDurationMs: number;
  lastDurationMs: number;
  lastAt: string;
  lastName: string;
}

interface ControllerEventMetricItem {
  reason: string;
  type: string;
  total: number;
  lastAt: string;
}

interface ControllerMetricsResponse {
  startedAt: string;
  source?: string;
  summary: {
    controllers: number;
    reconciles: number;
    failures: number;
    historicalFailures?: number;
    events: number;
  };
  items: ControllerMetricItem[];
  events: ControllerEventMetricItem[];
}

interface AuditLogItem {
  id: string;
  time: string;
  type: string;
  reason: string;
  message: string;
  namespace: string;
  kind: string;
  name: string;
  phase: string;
  ready: boolean;
  backendMode: string;
  backendPhase: string;
  controller: string;
  activeResource?: boolean;
  resourceState?: string;
}

interface AuditLogResponse {
  summary: {
    total: number;
    warnings: number;
    namespaces: number;
    kinds: number;
    activeEntries?: number;
    historicalEntries?: number;
    systemEntries?: number;
    activeWarnings?: number;
    historicalWarnings?: number;
    systemWarnings?: number;
  };
  items: AuditLogItem[];
}

interface FinalReadinessCheck {
  id: string;
  label: string;
  status: string;
  scope: string;
  evidence: string;
  nextStep: string;
}

interface FinalReadinessResponse {
  phase: string;
  nativePhase?: string;
  upstreamPhase?: string;
  generatedAt: string;
  version?: string;
  summary: {
    pass: number;
    warning: number;
    fail: number;
    externalRequired: number;
    nativeReady?: number;
    nativeWarning?: number;
    nativeFail?: number;
    nativeTotal?: number;
    upstreamReady?: number;
    upstreamWarning?: number;
    upstreamNotInstalled?: number;
    upstreamTotal?: number;
    total: number;
  };
  checks: FinalReadinessCheck[];
  readinessModel?: {
    nativeReadiness: FinalReadinessStage;
    upstreamAdapterReadiness: FinalReadinessStage;
    parityReadiness: FinalReadinessStage;
  };
}

interface FinalReadinessStage {
  phase: string;
  ready: boolean;
  checks: number;
  readyChecks: number;
  warningChecks?: number;
  failedChecks?: number;
  notInstalledChecks?: number;
  requiredReadyChecks?: number;
  mode: string;
  evidence?: string;
}

interface SetupForm {
  provider: string;
  namespaceMode: string;
  namespace: string;
  operatorPackage: string;
  channel: string;
  source: string;
  sourceNamespace: string;
  dataScienceClusterName: string;
  components: string[];
  installInternalCrds: boolean;
  installOperator: boolean;
  createDataScienceCluster: boolean;
}

const NAV_NODES: NavNode[] = [
  { kind: 'leaf', id: 'home', label: 'Overview', icon: Home16 },
  { kind: 'leaf', id: 'projects', label: 'Data science projects', icon: Folder16 },
  {
    kind: 'group',
    id: 'g-workbenches',
    label: 'Workbenches',
    icon: Workspace16,
    children: [
      { kind: 'leaf', id: 'workbenches', label: 'Workbenches' },
      { kind: 'leaf', id: 'notebook-images', label: 'Notebook images' },
      { kind: 'leaf', id: 'data-connections', label: 'Data connections' },
    ],
  },
  {
    kind: 'group',
    id: 'g-models',
    label: 'Models',
    icon: MachineLearningModel16,
    children: [
      { kind: 'leaf', id: 'model-registry', label: 'Model registry' },
      { kind: 'leaf', id: 'serving-runtimes', label: 'Serving runtimes' },
      { kind: 'leaf', id: 'llm-routes', label: 'LLM routes' },
      { kind: 'leaf', id: 'retrieval', label: 'Retrieval' },
      { kind: 'leaf', id: 'inference', label: 'Model deployments' },
    ],
  },
  {
    kind: 'group',
    id: 'g-pipelines',
    label: 'Data science pipelines',
    icon: Flow16,
    children: [
      { kind: 'leaf', id: 'pipelines', label: 'Pipelines' },
      { kind: 'leaf', id: 'pipeline-runs', label: 'Runs' },
      { kind: 'leaf', id: 'compute', label: 'Compute backends' },
      { kind: 'leaf', id: 'datasets', label: 'Datasets' },
      { kind: 'leaf', id: 'training-jobs', label: 'Training jobs' },
      { kind: 'leaf', id: 'model-promotion', label: 'Model promotion' },
    ],
  },
  {
    kind: 'group',
    id: 'g-experiments',
    label: 'Experiments',
    icon: ChartLine16,
    children: [
      { kind: 'leaf', id: 'experiments-runs', label: 'Experiments and runs' },
      { kind: 'leaf', id: 'executions', label: 'Executions' },
      { kind: 'leaf', id: 'artifacts', label: 'Artifacts' },
      { kind: 'leaf', id: 'eval-policy', label: 'Evaluation policies' },
      { kind: 'leaf', id: 'eval-jobs', label: 'Evaluation jobs' },
    ],
  },
  {
    kind: 'group',
    id: 'g-monitoring',
    label: 'Monitoring',
    icon: ChartLine16,
    children: [
      { kind: 'leaf', id: 'trustyai-monitoring', label: 'TrustyAI monitoring' },
      { kind: 'leaf', id: 'distributed-workloads', label: 'Distributed workloads' },
    ],
  },
  {
    kind: 'group',
    id: 'g-applications',
    label: 'Applications',
    icon: Application16,
    children: [
      { kind: 'leaf', id: 'apps-enabled', label: 'Enabled' },
      { kind: 'leaf', id: 'apps-explore', label: 'Explore' },
      { kind: 'leaf', id: 'agents', label: 'AI agents' },
    ],
  },
  {
    kind: 'group',
    id: 'g-administration',
    label: 'Administration',
    icon: Settings16,
    children: [
      { kind: 'leaf', id: 'cluster-settings', label: 'Cluster settings' },
    ],
  },
  { kind: 'leaf', id: 'developer-learning', label: 'Learning hub', icon: Education16 },
  { kind: 'leaf', id: 'resources', label: 'Resources', icon: Document16 },
];

const PAGE_ROUTE: Record<PageId, string> = {
  home: 'overview',
  projects: 'projects',
  workbenches: 'workbenches',
  'notebook-images': 'workbenches/notebook-images',
  'data-connections': 'workbenches/data-connections',
  agents: 'applications/agents',
  'llm-routes': 'models/llm-routes',
  retrieval: 'models/retrieval',
  'serving-runtimes': 'models/serving-runtimes',
  'model-registry': 'models/registry',
  pipelines: 'pipelines',
  'pipeline-runs': 'pipelines/runs',
  compute: 'pipelines/compute',
  datasets: 'pipelines/datasets',
  'training-jobs': 'pipelines/training-jobs',
  'model-promotion': 'pipelines/model-promotion',
  'experiments-runs': 'experiments/runs',
  executions: 'experiments/executions',
  artifacts: 'experiments/artifacts',
  'eval-policy': 'experiments/evaluation-policies',
  'eval-jobs': 'experiments/evaluation-jobs',
  'trustyai-monitoring': 'monitoring/trustyai',
  'distributed-workloads': 'monitoring/distributed-workloads',
  inference: 'models/deployments',
  'cluster-settings': 'cluster-settings',
  'apps-enabled': 'applications/enabled',
  'apps-explore': 'applications/explore',
  'developer-learning': 'learning-hub',
  resources: 'resources',
};

const CLUSTER_SETTINGS_TAB_ROUTE: Record<ClusterSettingsTab, string> = {
  setup: 'setup',
  readiness: 'readiness',
  gpu: 'gpu',
  demo: 'demo',
  operations: 'operations',
};

const RESOURCE_PATH: Partial<Record<PageId, string>> = {
  workbenches: 'workbenches',
  'notebook-images': 'workbenches/images',
  'data-connections': 'workbenches/data-connections',
  agents: 'resources/agents',
  'llm-routes': 'foundation/routes',
  retrieval: 'foundation/retrieval',
  'serving-runtimes': 'models/serving-runtimes',
  'model-registry': 'models/registry',
  pipelines: 'pipelines',
  'pipeline-runs': 'pipeline/runs',
  compute: 'training/compute',
  datasets: 'training/datasets',
  'training-jobs': 'training/jobs',
  'model-promotion': 'models/promotions',
  'experiments-runs': 'experiments/runs',
  executions: 'experiments/executions',
  artifacts: 'experiments/artifacts',
  'eval-policy': 'evaluation/policies',
  'eval-jobs': 'evaluation/jobs',
  'trustyai-monitoring': 'monitoring/trustyai',
  'distributed-workloads': 'distributed/workloads',
  inference: 'inference',
  'cluster-settings': 'admin/cluster-settings',
  'apps-enabled': 'applications/enabled',
  'apps-explore': 'applications/explore',
  'developer-learning': 'developer/learning',
  resources: 'catalog',
};

const PAGE_LABEL: Record<PageId, string> = {
  home: 'Overview',
  projects: 'Data science projects',
  workbenches: 'Workbenches',
  'notebook-images': 'Notebook images',
  'data-connections': 'Data connections',
  agents: 'AI agents',
  'llm-routes': 'LLM routes',
  retrieval: 'Retrieval',
  'serving-runtimes': 'Serving runtimes',
  'model-registry': 'Model registry',
  pipelines: 'Pipelines',
  'pipeline-runs': 'Runs',
  compute: 'Compute backends',
  datasets: 'Datasets',
  'training-jobs': 'Training jobs',
  'model-promotion': 'Model promotion',
  'experiments-runs': 'Experiments and runs',
  executions: 'Executions',
  artifacts: 'Artifacts',
  'eval-policy': 'Evaluation policies',
  'eval-jobs': 'Evaluation jobs',
  'trustyai-monitoring': 'TrustyAI monitoring',
  'distributed-workloads': 'Distributed workloads',
  inference: 'Model deployments',
  'cluster-settings': 'Cluster settings',
  'apps-enabled': 'Enabled applications',
  'apps-explore': 'Explore applications',
  'developer-learning': 'Learning hub',
  resources: 'Resources',
};

const CREATE_LABEL: Partial<Record<PageId, string>> = {
  projects: 'Data science project',
  workbenches: 'Workbench',
  'data-connections': 'Data connection',
  agents: 'AI agent',
  'llm-routes': 'LLM route',
  retrieval: 'Retrieval claim',
  pipelines: 'Pipeline',
  'pipeline-runs': 'Pipeline run',
  compute: 'Compute backend',
  datasets: 'Dataset',
  'training-jobs': 'Training job',
  'model-promotion': 'Model promotion',
  'experiments-runs': 'Experiment',
  executions: 'Execution',
  artifacts: 'Artifact',
  'eval-policy': 'Evaluation policy',
  'eval-jobs': 'Evaluation job',
  'trustyai-monitoring': 'Monitoring target',
  'distributed-workloads': 'Distributed workload',
  inference: 'Inference endpoint',
};

function defaultCreateForm(page: PageId, namespace = 'default'): CreateForm {
  return {
    page,
    name: '',
    namespace,
    displayName: '',
    description: '',
    tier: 'personal',
    llmRouteRef: 'default-chat-route',
    promptLibraryRef: '',
    provider: 'openai-compatible',
    model: 'default',
    endpoint: '',
    backendType: page === 'compute' ? 'kubernetes' : 'auto',
    gpuClass: 'nvidia-l4',
    sourceType: 'bucket',
    sourceRef: 'default-source',
    purpose: 'fine-tune',
    computeBackendRef: '',
    datasetRef: 'support-ticket-dataset',
    framework: 'transformers',
    trainingMode: 'lora',
    modelRef: 'trained-model',
    evaluationRef: 'golden-set-eval',
    stage: 'staging',
    metric: 'groundedness',
    minimum: '0.8',
    enforcement: 'block',
    policyRef: 'groundedness-and-safety',
    targetRef: 'candidate-model',
    targetKind: 'TrainingJobClaim',
    promotionRef: 'production-promotion',
    runtime: 'kserve',
    version: '1.0.0',
    source: 'manual-registration',
    requireSourceAttribution: true,
  };
}

function defaultSetupForm(): SetupForm {
  return {
    provider: 'opendatahub',
    namespaceMode: 'existing',
    namespace: 'opendatahub',
    operatorPackage: 'opendatahub-operator',
    channel: 'fast',
    source: 'community-operators',
    sourceNamespace: 'openshift-marketplace',
    dataScienceClusterName: 'default-dsc',
    components: ['dashboard', 'workbenches', 'datasciencepipelines', 'kserve', 'modelregistry', 'trustyai'],
    installInternalCrds: true,
    installOperator: false,
    createDataScienceCluster: false,
  };
}

function defaultGpuEnablementConfig(profile: string): GpuEnablementConfig {
  const defaults: Record<string, GpuEnablementConfig> = {
    nvidia: {
      namespace: 'kube-system',
      resourceName: 'nvidia.com/gpu',
      pluginImage: 'nvcr.io/nvidia/k8s-device-plugin:v0.17.3',
      runtimeClass: '',
      useRuntimeClass: false,
      nodeSelectorKey: 'kubernetes.io/os',
      nodeSelectorValue: 'linux',
      packageName: '',
      channel: '',
      catalogSource: '',
      catalogNamespace: '',
      externalEndpoint: '',
      credentialSecret: 'oah-external-gpu-credentials',
      maxConcurrency: 1,
    },
    'nvidia-operator': {
      namespace: 'nvidia-gpu-operator',
      resourceName: 'nvidia.com/gpu',
      pluginImage: '',
      runtimeClass: 'nvidia',
      useRuntimeClass: false,
      nodeSelectorKey: 'kubernetes.io/os',
      nodeSelectorValue: 'linux',
      packageName: 'gpu-operator-certified',
      channel: 'stable',
      catalogSource: 'certified-operators',
      catalogNamespace: 'openshift-marketplace',
      externalEndpoint: '',
      credentialSecret: 'oah-external-gpu-credentials',
      maxConcurrency: 1,
    },
    amd: {
      namespace: 'kube-system',
      resourceName: 'amd.com/gpu',
      pluginImage: 'rocm/k8s-device-plugin:replace-with-approved-version',
      runtimeClass: '',
      useRuntimeClass: false,
      nodeSelectorKey: 'kubernetes.io/os',
      nodeSelectorValue: 'linux',
      packageName: '',
      channel: '',
      catalogSource: '',
      catalogNamespace: '',
      externalEndpoint: '',
      credentialSecret: 'oah-external-gpu-credentials',
      maxConcurrency: 1,
    },
    intel: {
      namespace: 'kube-system',
      resourceName: 'gpu.intel.com/i915',
      pluginImage: 'intel/intel-gpu-plugin:replace-with-approved-version',
      runtimeClass: '',
      useRuntimeClass: false,
      nodeSelectorKey: 'kubernetes.io/os',
      nodeSelectorValue: 'linux',
      packageName: '',
      channel: '',
      catalogSource: '',
      catalogNamespace: '',
      externalEndpoint: '',
      credentialSecret: 'oah-external-gpu-credentials',
      maxConcurrency: 1,
    },
    generic: {
      namespace: 'opensphere-system',
      resourceName: 'vendor.opensphere.io/gpu',
      pluginImage: 'registry.opensphere.local/gpu-resource-publisher:replace-with-approved-version',
      runtimeClass: '',
      useRuntimeClass: false,
      nodeSelectorKey: 'kubernetes.io/os',
      nodeSelectorValue: 'linux',
      packageName: '',
      channel: '',
      catalogSource: '',
      catalogNamespace: '',
      externalEndpoint: '',
      credentialSecret: 'oah-external-gpu-credentials',
      maxConcurrency: 1,
    },
    external: {
      namespace: 'opensphere-system',
      resourceName: 'external.opensphere.io/gpu',
      pluginImage: '',
      runtimeClass: '',
      useRuntimeClass: false,
      nodeSelectorKey: '',
      nodeSelectorValue: '',
      packageName: '',
      channel: '',
      catalogSource: '',
      catalogNamespace: '',
      externalEndpoint: '',
      credentialSecret: 'oah-external-gpu-credentials',
      maxConcurrency: 1,
    },
    'docker-bridge': {
      namespace: 'opensphere-system',
      resourceName: 'external.opensphere.io/docker-gpu',
      pluginImage: '',
      runtimeClass: '',
      useRuntimeClass: false,
      nodeSelectorKey: '',
      nodeSelectorValue: '',
      packageName: '',
      channel: '',
      catalogSource: '',
      catalogNamespace: '',
      externalEndpoint: 'http://host.docker.internal:18080',
      credentialSecret: 'oah-external-gpu-credentials',
      maxConcurrency: 1,
    },
    'windows-service': {
      namespace: 'opensphere-system',
      resourceName: 'external.opensphere.io/windows-gpu',
      pluginImage: '',
      runtimeClass: '',
      useRuntimeClass: false,
      nodeSelectorKey: '',
      nodeSelectorValue: '',
      packageName: '',
      channel: '',
      catalogSource: '',
      catalogNamespace: '',
      externalEndpoint: 'http://host.docker.internal:18080',
      credentialSecret: 'oah-external-gpu-credentials',
      maxConcurrency: 1,
    },
    'windows-supervisor': {
      namespace: 'opensphere-system',
      resourceName: 'external.opensphere.io/windows-supervisor-gpu',
      pluginImage: '',
      runtimeClass: '',
      useRuntimeClass: false,
      nodeSelectorKey: '',
      nodeSelectorValue: '',
      packageName: '',
      channel: '',
      catalogSource: '',
      catalogNamespace: '',
      externalEndpoint: 'http://host.docker.internal:18080',
      credentialSecret: 'oah-external-gpu-credentials',
      maxConcurrency: 1,
    },
    wsl2: {
      namespace: 'opensphere-system',
      resourceName: 'external.opensphere.io/wsl2-gpu',
      pluginImage: '',
      runtimeClass: '',
      useRuntimeClass: false,
      nodeSelectorKey: '',
      nodeSelectorValue: '',
      packageName: '',
      channel: '',
      catalogSource: '',
      catalogNamespace: '',
      externalEndpoint: '',
      credentialSecret: 'oah-external-gpu-credentials',
      maxConcurrency: 1,
    },
    remote: {
      namespace: 'opensphere-system',
      resourceName: 'external.opensphere.io/remote-gpu',
      pluginImage: '',
      runtimeClass: '',
      useRuntimeClass: false,
      nodeSelectorKey: '',
      nodeSelectorValue: '',
      packageName: '',
      channel: '',
      catalogSource: '',
      catalogNamespace: '',
      externalEndpoint: '',
      credentialSecret: 'oah-external-gpu-credentials',
      maxConcurrency: 1,
    },
    colab: {
      namespace: 'opensphere-system',
      resourceName: 'external.opensphere.io/colab-gpu',
      pluginImage: '',
      runtimeClass: '',
      useRuntimeClass: false,
      nodeSelectorKey: '',
      nodeSelectorValue: '',
      packageName: '',
      channel: '',
      catalogSource: '',
      catalogNamespace: '',
      externalEndpoint: '',
      credentialSecret: 'oah-colab-bridge-credentials',
      maxConcurrency: 1,
    },
    cpu: {
      namespace: 'opensphere-system',
      resourceName: 'cpu',
      pluginImage: '',
      runtimeClass: '',
      useRuntimeClass: false,
      nodeSelectorKey: '',
      nodeSelectorValue: '',
      packageName: '',
      channel: '',
      catalogSource: '',
      catalogNamespace: '',
      externalEndpoint: '',
      credentialSecret: 'oah-external-gpu-credentials',
      maxConcurrency: 2,
    },
  };
  return { ...(defaults[profile] || defaults['nvidia']) };
}

const DEFAULT_SUMMARY: SummaryResponse = {
  phase: 'Phase 0',
  projects: [],
  counts: {
    projects: 0,
    workbenches: 0,
    llmRoutes: 0,
    agents: 0,
    modelRegistry: 0,
    servingRuntimes: 0,
    pipelines: 0,
    pipelineRuns: 0,
    trainingJobs: 0,
    experiments: 0,
    evaluationJobs: 0,
    inferenceEndpoints: 0,
    monitoringTargets: 0,
    distributedWorkloads: 0,
    enabledApplications: 0,
  },
  referenceCounts: {},
  alerts: [{ severity: 'info', message: 'Overview counts show actual cluster resources. Reference examples are labeled separately.' }],
  learningResources: [
    {
      title: 'OpenSphere AI Hub tutorial',
      provider: 'OpenSphere',
      type: 'Tutorial',
      duration: '30 minutes',
      description: 'Create a project, connect an LLM route, register an agent, and promote a model through an evaluation gate.',
      href: '#',
    },
    {
      title: 'Agent governance guide',
      provider: 'Platform team',
      type: 'Documentation',
      duration: 'Reference',
      description: 'Source attribution, tool claims, trace policies, and runtime boundaries for OpenSphere AI Hub agents.',
      href: '#',
    },
    {
      title: 'Training and promotion flow',
      provider: 'Platform team',
      type: 'How-to',
      duration: '45 minutes',
      description: 'Declare compute, datasets, training jobs, evaluation jobs, and production inference claims.',
      href: '#',
    },
  ],
};

function groupForPage(page: PageId): string | null {
  for (const node of NAV_NODES) {
    if (node.kind === 'group' && node.children.some((child) => child.id === page)) {
      return node.id;
    }
  }
  return null;
}

function phaseClass(phase: string): string {
  const normalized = (phase || '').toLowerCase();
  if (['ready', 'active', 'running', 'bound', 'passed'].some((term) => normalized.includes(term))) return 'label-success';
  if (['failed', 'error', 'blocked', 'unavailable'].some((term) => normalized.includes(term))) return 'label-danger';
  if (['pending', 'waiting', 'draft', 'planned', 'partial', 'degraded', 'warning', 'external', 'required', 'notinstalled', 'parity'].some((term) => normalized.includes(term))) return 'label-warning';
  return 'label-info';
}

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [ClarityModule, AiCarbonIcon],
  styleUrls: ['./ai-shell.element.css'],
  template: `
    <div class="ai-shell">
      <clr-vertical-nav class="ai-nav" [clrVerticalNavCollapsible]="false" aria-label="OpenSphere AI Hub navigation">
        <div class="ai-brand">
          <div>
            <strong>OpenSphere AI Hub</strong>
            <span class="label label-info">Angular</span>
          </div>
        </div>

        @for (node of navNodes; track node.id) {
          @if (node.kind === 'leaf') {
            <a clrVerticalNavLink [href]="pageHref(node.id)" [class.active]="activePage() === node.id" (click)="navigate(node.id, $event)">
              @if (node.icon) {
                <ai-cicon clrVerticalNavIcon [icon]="node.icon" [size]="16" />
              }
              {{ node.label }}
            </a>
          } @else {
            <clr-vertical-nav-group
              [clrVerticalNavGroupExpanded]="isOpen(node.id)"
              (clrVerticalNavGroupExpandedChange)="setOpen(node.id, $event)"
            >
              @if (node.icon) {
                <ai-cicon clrVerticalNavIcon [icon]="node.icon" [size]="16" />
              }
              {{ node.label }}
              <clr-vertical-nav-group-children>
                @for (child of node.children; track child.id) {
                  <a clrVerticalNavLink [href]="pageHref(child.id)" [class.active]="activePage() === child.id" (click)="navigate(child.id, $event)">
                    {{ child.label }}
                  </a>
                }
              </clr-vertical-nav-group-children>
            </clr-vertical-nav-group>
          }
        }
      </clr-vertical-nav>

      <main class="ai-main" [class.ai-main-overview]="activePage() === 'home'">
        <nav class="ai-breadcrumb" aria-label="breadcrumb">
          <a class="ai-breadcrumb-link" href="/">OpenSphere</a>
          <span class="ai-breadcrumb-separator">/</span>
          <a class="ai-breadcrumb-link" href="/p/ai" (click)="navigate('home', $event)">OpenSphere AI Hub</a>
          <span class="ai-breadcrumb-separator">/</span>
          <span class="ai-breadcrumb-current">{{ pageLabel() }}</span>
        </nav>

        <header class="ai-header">
          <div>
            <p class="ai-eyebrow">OPENSPHERE AI HUB</p>
            <div class="ai-title-row">
              <h1>{{ pageLabel() }}</h1>
              <span class="label label-info">Angular - Clarity</span>
            </div>
          </div>
          <div class="ai-header-actions">
            <span [class]="'label ' + statusClass(summary().phase)">{{ summary().phase }}</span>
            <span class="label label-info">Auto {{ operationsRefreshPeriodSeconds }}s</span>
            <span [class]="operationsRefreshStatus() === 'Live' ? 'label label-success' : 'label label-info'">{{ operationsRefreshStatus() }}</span>
            <span class="ai-footnote">Last {{ operationsLastUpdatedAt() || '-' }}</span>
            <button type="button" class="btn btn-sm btn-outline" (click)="refresh()">Refresh</button>
          </div>
        </header>

        @if (summary().alerts.length) {
          <section class="ai-alerts" aria-label="OpenSphere AI Hub alerts">
            @for (alert of summary().alerts; track alert.message) {
              <clr-alert [clrAlertType]="alertType(alert.severity)" [clrAlertClosable]="false">
                <clr-alert-item>
                  <span class="alert-text">{{ alert.message }}</span>
                </clr-alert-item>
              </clr-alert>
            }
          </section>
        }

        @if (actionMessage(); as message) {
          <section class="ai-alerts" aria-label="OpenSphere AI Hub action result">
            <clr-alert [clrAlertType]="message.type" [clrAlertClosable]="false">
              <clr-alert-item>
                <span class="alert-text">{{ message.message }}</span>
              </clr-alert-item>
            </clr-alert>
          </section>
        }

        @if (activePage() === 'home') {
          <section class="card ai-gpu-overview-card ai-clickable-card" role="button" tabindex="0" aria-label="Available GPU resources" (click)="selectClusterSettingsTab('gpu'); navigate('cluster-settings')" (keydown.enter)="selectClusterSettingsTab('gpu'); navigate('cluster-settings')">
            <div class="card-block">
              <div class="ai-gpu-overview-layout">
                <div class="ai-gpu-overview-main">
                  <p class="ai-section-kicker">AVAILABLE GPU RESOURCES</p>
                  <div class="ai-gpu-overview-count">
                    <strong>{{ overviewAvailableGpuCount() }}</strong>
                    <span>GPU(s)</span>
                  </div>
                  <div class="ai-label-row">
                    <span [class]="'label ' + statusClass(overviewGpuPhase())">{{ overviewGpuPhase() }}</span>
                    <span [class]="overviewAvailableGpuCount() ? 'label label-success' : 'label label-warning'">{{ overviewAvailableGpuCount() ? 'Ready for AI workloads' : 'No GPU resource detected' }}</span>
                    <span class="label label-info">{{ gpuInventory().summary.totalAllocatable }} Kubernetes allocatable</span>
                    <span class="label label-info">{{ overviewExternalGpuCount() }} external bridge GPU(s)</span>
                  </div>
                </div>
                <div class="ai-gpu-product">
                  <img class="ai-gpu-product-logo" [src]="gpuProductLogoUrl()" alt="NVIDIA GeForce RTX" loading="lazy" />
                  <span>Detected GPU product</span>
                  <strong>{{ overviewGpuProductName() }}</strong>
                </div>
                <div class="ai-gpu-overview-facts">
                  <div>
                    <span>GPU nodes</span>
                    <strong>{{ gpuInventory().summary.gpuNodes }}</strong>
                  </div>
                  <div>
                    <span>Ready nodes</span>
                    <strong>{{ gpuInventory().summary.readyNodes }}/{{ gpuInventory().summary.nodes }}</strong>
                  </div>
                  <div>
                    <span>Backends</span>
                    <strong>{{ overviewGpuBackends().length }}</strong>
                  </div>
                </div>
              </div>

              @if (overviewGpuBackends().length) {
                <div class="ai-gpu-overview-backends" aria-label="Registered GPU compute backends">
                  @for (backend of overviewGpuBackends(); track backend.namespace + '/' + backend.name) {
                    <div class="ai-gpu-overview-backend">
                      <div>
                        <strong>{{ backend.name }}</strong>
                        <span>{{ backend.backendType || 'external' }} · {{ backend.resourceName || 'external GPU' }}</span>
                      </div>
                      <div class="ai-chip-list">
                        <span [class]="'label ' + statusClass(backend.phase)">{{ backend.phase }}</span>
                        @if (backend.provider) {
                          <span class="label label-info">{{ backend.provider }}</span>
                        }
                        @for (gpu of backend.gpus || []; track gpu['id'] || gpu['name']) {
                          <span class="label label-success">{{ gpu['name'] || gpu['id'] }}</span>
                        }
                      </div>
                    </div>
                  }
                </div>
              } @else if (gpuInventory().nodes.length) {
                <div class="ai-gpu-overview-backends" aria-label="Kubernetes GPU resources">
                  @for (node of gpuInventory().nodes; track node.name) {
                    @for (resource of node.gpuResources; track resource.name) {
                      <div class="ai-gpu-overview-backend">
                        <div>
                          <strong>{{ resource.name }}</strong>
                          <span>{{ node.name }}</span>
                        </div>
                        <div class="ai-chip-list">
                          <span class="label label-success">{{ resource.allocatable }} allocatable</span>
                          <span class="label label-info">{{ resource.capacity }} capacity</span>
                        </div>
                      </div>
                    }
                  }
                </div>
              } @else if (gpuInventory().nextSteps.length) {
                <p class="ai-footnote">{{ gpuInventory().nextSteps[0] }}</p>
              }
            </div>
          </section>

          <section class="ai-overview-grid" aria-label="AI overview summary">
            <div class="card ai-metric-card ai-clickable-card" role="button" tabindex="0" (click)="navigate('projects')" (keydown.enter)="navigate('projects')">
              <div class="card-block">
                <h3 class="card-title">Projects</h3>
                <p class="ai-metric-sub">{{ summary().counts.projects }} active</p>
                @if (summary().referenceCounts?.projects) {
                  <span class="label label-info">{{ summary().referenceCounts?.projects }} reference</span>
                }
                <div class="ai-status-line"><span [class]="summary().counts.projects > 0 ? 'ai-bar ai-bar-success' : 'ai-bar ai-bar-warning'"><span></span></span></div>
              </div>
            </div>
            <div class="card ai-metric-card ai-clickable-card" role="button" tabindex="0" (click)="navigate('workbenches')" (keydown.enter)="navigate('workbenches')">
              <div class="card-block">
                <h3 class="card-title">Workbenches</h3>
                <p class="ai-metric-sub">{{ summary().counts.workbenches }} available</p>
                @if (summary().referenceCounts?.workbenches) {
                  <span class="label label-info">{{ summary().referenceCounts?.workbenches }} reference</span>
                }
                <div class="ai-status-line"><span class="ai-bar ai-bar-success"><span></span></span></div>
              </div>
            </div>
            <div class="card ai-metric-card ai-clickable-card" role="button" tabindex="0" (click)="navigate('inference')" (keydown.enter)="navigate('inference')">
              <div class="card-block">
                <h3 class="card-title">Deployments</h3>
                <p class="ai-metric-sub">{{ summary().counts.inferenceEndpoints }} endpoints</p>
                @if (summary().referenceCounts?.inferenceEndpoints) {
                  <span class="label label-info">{{ summary().referenceCounts?.inferenceEndpoints }} reference</span>
                }
                <div class="ai-status-line"><span [class]="summary().counts.inferenceEndpoints > 0 ? 'ai-bar ai-bar-success' : 'ai-bar ai-bar-info'"><span></span></span></div>
              </div>
            </div>
            <div class="card ai-metric-card ai-clickable-card" role="button" tabindex="0" (click)="navigate('trustyai-monitoring')" (keydown.enter)="navigate('trustyai-monitoring')">
              <div class="card-block">
                <h3 class="card-title">Monitoring</h3>
                <p class="ai-metric-sub">{{ summary().counts.monitoringTargets }} targets</p>
                @if (summary().referenceCounts?.monitoringTargets) {
                  <span class="label label-info">{{ summary().referenceCounts?.monitoringTargets }} reference</span>
                }
                <div class="ai-status-line"><span class="ai-bar ai-bar-success"><span></span></span></div>
              </div>
            </div>
          </section>

          <section class="ai-action-grid" aria-label="OpenSphere native operation status">
            <div class="card ai-panel ai-clickable-card" role="button" tabindex="0" (click)="navigate('cluster-settings')" (keydown.enter)="navigate('cluster-settings')">
              <div class="card-header">
                <h3 class="card-title">Native readiness</h3>
              </div>
              <div class="card-block">
                <div class="ai-label-row">
                  <span [class]="'label ' + statusClass(finalReadiness().nativePhase || finalReadiness().phase)">{{ finalReadiness().nativePhase || finalReadiness().phase }}</span>
                  <span [class]="'label ' + statusClass(finalReadiness().upstreamPhase || 'Pending')">Upstream {{ finalReadiness().upstreamPhase || 'Pending' }}</span>
                </div>
                <p class="ai-footnote">{{ finalReadiness().summary.nativeReady || 0 }} native ready, {{ finalReadiness().summary.nativeWarning || 0 }} warnings, {{ finalReadiness().summary.nativeFail || 0 }} failed</p>
              </div>
            </div>
            <div class="card ai-panel ai-clickable-card" role="button" tabindex="0" (click)="navigate('cluster-settings')" (keydown.enter)="navigate('cluster-settings')">
              <div class="card-header">
                <h3 class="card-title">Controller health</h3>
              </div>
              <div class="card-block">
                <div class="ai-label-row">
                  <span [class]="controllerMetrics().summary.failures ? 'label label-danger' : 'label label-success'">{{ controllerMetrics().summary.failures }} current failures</span>
                  @if (controllerMetrics().summary.historicalFailures) {
                    <span class="label label-warning">{{ controllerMetrics().summary.historicalFailures }} historical</span>
                  }
                  <span class="label label-info">{{ controllerMetrics().summary.reconciles }} reconciles</span>
                  <span class="label label-info">{{ controllerMetrics().summary.events }} events</span>
                </div>
                <p class="ai-footnote">{{ controllerMetrics().summary.controllers }} controllers reporting from {{ controllerMetrics().source || 'process' }}</p>
              </div>
            </div>
            <div class="card ai-panel ai-clickable-card" role="button" tabindex="0" (click)="navigate('cluster-settings')" (keydown.enter)="navigate('cluster-settings')">
              <div class="card-header">
                <h3 class="card-title">Audit trail</h3>
              </div>
              <div class="card-block">
                <div class="ai-label-row">
                  <span class="label label-info">{{ auditLog().summary.total }} entries</span>
                  <span [class]="auditLog().summary.activeWarnings ? 'label label-warning' : 'label label-success'">{{ auditLog().summary.activeWarnings || 0 }} active warnings</span>
                  <span class="label label-warning">{{ (auditLog().summary.historicalWarnings || 0) + (auditLog().summary.systemWarnings || 0) }} retained warnings</span>
                </div>
                <p class="ai-footnote">{{ auditLog().summary.namespaces }} namespaces, {{ auditLog().summary.kinds }} resource kinds</p>
              </div>
            </div>
          </section>

          <h2 class="ai-page-subtitle">AI details</h2>

          <section class="ai-panel-grid">
            <div class="card ai-panel">
              <div class="card-header">
                <h3 class="card-title">AI Platform Distribution</h3>
              </div>
              <div class="card-block">
                <div class="ai-stack-list">
                  <div>
                    <span>Projects</span>
                    <span class="ai-bar ai-bar-info"><span></span></span>
                    <strong>{{ summary().counts.projects }}</strong>
                  </div>
                  <div>
                    <span>Workbenches</span>
                    <span class="ai-bar ai-bar-success"><span></span></span>
                    <strong>{{ summary().counts.workbenches }}</strong>
                  </div>
                  <div>
                    <span>Pipelines</span>
                    <span class="ai-bar ai-bar-warning"><span></span></span>
                    <strong>{{ summary().counts.pipelines }}</strong>
                  </div>
                  <div>
                    <span>Experiments</span>
                    <span class="ai-bar ai-bar-info"><span></span></span>
                    <strong>{{ summary().counts.experiments }}</strong>
                  </div>
                </div>
              </div>
            </div>

            <div class="card ai-panel">
              <div class="card-header">
                <h3 class="card-title">Model Operations Health</h3>
              </div>
              <div class="card-block">
                <div class="ai-stack-list">
                  <div>
                    <span>Serving runtimes</span>
                    <span class="ai-bar ai-bar-success"><span></span></span>
                    <strong>{{ summary().counts.servingRuntimes }}</strong>
                  </div>
                  <div>
                    <span>Training jobs</span>
                    <span class="ai-bar ai-bar-info"><span></span></span>
                    <strong>{{ summary().counts.trainingJobs }}</strong>
                  </div>
                  <div>
                    <span>Evaluation jobs</span>
                    <span class="ai-bar ai-bar-warning"><span></span></span>
                    <strong>{{ summary().counts.evaluationJobs }}</strong>
                  </div>
                  <div>
                    <span>Distributed workloads</span>
                    <span class="ai-bar ai-bar-success"><span></span></span>
                    <strong>{{ summary().counts.distributedWorkloads }}</strong>
                  </div>
                </div>
              </div>
            </div>
          </section>

          <section class="ai-panel-grid">
            <div class="card ai-panel">
              <div class="card-header">
                <h3 class="card-title">Data Science Projects</h3>
              </div>
              <div class="card-block ai-compact-table">
                <table class="table table-compact">
                  <thead>
                    <tr><th>Name</th><th>Owner</th><th>Source</th><th>Status</th></tr>
                  </thead>
                  <tbody>
                    @for (project of projectCards(); track project.name) {
                      <tr>
                        <td>{{ project.displayName || project.name }}</td>
                        <td>{{ project.owner }}</td>
                        <td><span [class]="sourceClass(project)">{{ sourceLabel(project) }}</span></td>
                        <td><span [class]="'label ' + statusClass(project.phase)">{{ project.phase }}</span></td>
                      </tr>
                    }
                  </tbody>
                </table>
              </div>
            </div>

            <div class="card ai-panel">
              <div class="card-header">
                <h3 class="card-title">Learning Hub</h3>
                <span class="label label-info">Reference links</span>
              </div>
              <div class="card-block ai-learning-list">
                @for (resource of summary().learningResources.slice(0, 4); track resource.title) {
                  <a [href]="resource.href" target="_blank" rel="noreferrer">
                    <span>{{ resource.title }}</span>
                    <small>{{ resource.type }} - {{ resource.duration }}</small>
                  </a>
                }
              </div>
            </div>
          </section>

          <section class="card ai-panel ai-full-panel">
            <div class="card-header">
              <h3 class="card-title">Applications</h3>
            </div>
            <clr-datagrid>
              <clr-dg-column>Name</clr-dg-column>
              <clr-dg-column>Kind</clr-dg-column>
              <clr-dg-column>Source</clr-dg-column>
              <clr-dg-column>Status</clr-dg-column>
              <clr-dg-column>Ready</clr-dg-column>
              @for (item of resourceItems(); track item.kind + ':' + item.name) {
                <clr-dg-row>
                  <clr-dg-cell>{{ item.name }}</clr-dg-cell>
                  <clr-dg-cell>{{ item.kind }}</clr-dg-cell>
                  <clr-dg-cell><span [class]="sourceClass(item)">{{ sourceLabel(item) }}</span></clr-dg-cell>
                  <clr-dg-cell><span [class]="'label ' + statusClass(item.phase)">{{ item.phase }}</span></clr-dg-cell>
                  <clr-dg-cell>{{ item.ready ? 'Ready' : 'Not ready' }}</clr-dg-cell>
                </clr-dg-row>
              }
              @if (!resourceItems().length) {
                <clr-dg-placeholder>No application data loaded.</clr-dg-placeholder>
              }
            </clr-datagrid>
          </section>
        } @else if (activePage() === 'projects') {
          <section class="ai-section">
            <div class="ai-section-header">
              <h2>Data Science Projects</h2>
              <div class="ai-header-actions">
                <span class="label label-info">{{ projects().length }} projects</span>
                <button type="button" class="btn btn-primary btn-sm" [disabled]="saving()" (click)="openCreate()">Create</button>
              </div>
            </div>
            <div class="ai-card-grid ai-resource-grid">
              @for (project of projects(); track project.name) {
                <div class="card">
                  <div class="card-header">
                    <a class="card-title">{{ project.displayName || project.name }}</a>
                  </div>
                  <div class="card-block">
                    <p class="card-text">{{ project.description || 'Namespace-backed AI workspace' }}</p>
                    <dl class="ai-card-meta">
                      <div><dt>Created</dt><dd>{{ project.created }}</dd></div>
                      <div><dt>Owner</dt><dd>{{ project.owner }}</dd></div>
                      <div><dt>Phase</dt><dd><span [class]="'label ' + statusClass(project.phase)">{{ project.phase }}</span></dd></div>
                    </dl>
                  </div>
                </div>
              }
            </div>
          </section>
        } @else {
          <section class="ai-section">
            <div class="ai-section-header">
              <h2>{{ pageLabel() }}</h2>
              @if (supportsCreate()) {
                <button type="button" class="btn btn-primary btn-sm" [disabled]="!canCreate() || saving()" (click)="openCreate()">Create</button>
              }
            </div>
            @if (createBlockedMessage()) {
              <clr-alert clrAlertType="warning" [clrAlertClosable]="false">
                <clr-alert-item>
                  <span class="alert-text">{{ createBlockedMessage() }}</span>
                </clr-alert-item>
              </clr-alert>
            }
            @if (activePage() === 'inference') {
              <div class="card ai-action-panel">
                <div class="card-header">
                  <div class="card-title">Deployment edit</div>
                </div>
                <div class="card-block">
                  <form clrForm class="ai-inline-form">
                    <clr-input-container>
                      <label>Name</label>
                      <input clrInput name="deploymentName" [value]="createForm().name" (input)="setCreateField('name', $any($event.target).value)" />
                    </clr-input-container>
                    <clr-input-container>
                      <label>Namespace</label>
                      <input clrInput name="deploymentNamespace" [value]="createForm().namespace" (input)="setCreateField('namespace', $any($event.target).value)" />
                    </clr-input-container>
                    <clr-input-container>
                      <label>Model ref</label>
                      <input clrInput name="deploymentModelRef" [value]="createForm().modelRef" (input)="setCreateField('modelRef', $any($event.target).value)" />
                    </clr-input-container>
                    <clr-select-container>
                      <label>Runtime</label>
                      <select clrSelect name="deploymentRuntime" [value]="createForm().runtime" (change)="setCreateField('runtime', $any($event.target).value)">
                        <option value="kserve">kserve</option>
                        <option value="vllm">vllm</option>
                      </select>
                    </clr-select-container>
                    <clr-input-container>
                      <label>Promotion ref</label>
                      <input clrInput name="deploymentPromotionRef" [value]="createForm().promotionRef" (input)="setCreateField('promotionRef', $any($event.target).value)" />
                    </clr-input-container>
                    <button type="button" class="btn btn-primary btn-sm" [disabled]="saving() || !createForm().name" (click)="updateInference()">Update deployment</button>
                  </form>
                </div>
              </div>
            }
            @if (activePage() === 'model-registry') {
              <div class="card ai-action-panel">
                <div class="card-header">
                  <div class="card-title">Model versions</div>
                </div>
                <div class="card-block">
                  <div class="ai-kv-grid">
                    <div>
                      <span class="ai-kv-label">Backend</span>
                      <strong>{{ modelRegistryStatus().backend?.mode || '-' }}</strong>
                      <span [class]="'label ' + statusClass(modelRegistryStatus().summary?.phase || modelRegistryStatus().backend?.phase || 'Pending')">{{ modelRegistryStatus().summary?.phase || modelRegistryStatus().backend?.phase || 'Pending' }}</span>
                    </div>
                    <div>
                      <span class="ai-kv-label">Source</span>
                      <strong>{{ modelRegistryStatus().source?.type || '-' }}</strong>
                      <span>{{ modelRegistryStatus().source?.namespace || '-' }}/{{ modelRegistryStatus().source?.name || '-' }}</span>
                    </div>
                    <div>
                      <span class="ai-kv-label">REST coverage</span>
                      <strong>{{ modelRegistryStatus().summary?.resourcesReady || 0 }}/{{ modelRegistryStatus().summary?.resourcesTotal || 0 }}</strong>
                      <span>{{ modelRegistryStatus().summary?.upstreamVersions || 0 }} upstream versions / {{ modelRegistryStatus().summary?.artifacts || 0 }} artifacts</span>
                    </div>
                  </div>
                  @if (modelRegistryStatus().backend?.message) {
                    <p class="ai-footnote">{{ modelRegistryStatus().backend?.message }}</p>
                  }
                  @if (modelRegistryStatus().source?.endpoint) {
                    <p class="ai-footnote">{{ modelRegistryStatus().source?.endpoint }}</p>
                  }
                  <div class="ai-action-row">
                    <button type="button" class="btn btn-sm btn-outline" [disabled]="saving()" (click)="runRegistrySelfTest()">Run upstream write self-test</button>
                  </div>
                  @if (registrySelfTest()) {
                    <div class="ai-kv-grid">
                      <div>
                        <span class="ai-kv-label">Write test</span>
                        <strong>{{ registrySelfTest()?.synced ? 'Synced' : registrySelfTest()?.attempted ? 'Failed' : 'Not attempted' }}</strong>
                        <span>{{ registrySelfTest()?.message || '-' }}</span>
                      </div>
                      <div>
                        <span class="ai-kv-label">Target</span>
                        <strong>{{ registrySelfTest()?.source?.type || '-' }}</strong>
                        <span>{{ registrySelfTest()?.source?.namespace || '-' }}/{{ registrySelfTest()?.source?.name || '-' }}</span>
                      </div>
                      <div>
                        <span class="ai-kv-label">Version</span>
                        <strong>{{ registrySelfTest()?.version?.name || '-' }}</strong>
                        <span>{{ registrySelfTest()?.version?.version || '-' }}</span>
                      </div>
                    </div>
                    @if (registrySelfTest()?.upstreamSync?.steps?.length) {
                      <table class="table table-compact ai-mini-table">
                        <thead>
                          <tr><th>Write resource</th><th>Path</th><th>Status</th><th>Error</th></tr>
                        </thead>
                        <tbody>
                          @for (step of registrySelfTest()?.upstreamSync?.steps || []; track step.resource) {
                            <tr>
                              <td>{{ step.resource }}</td>
                              <td>{{ step.path }}</td>
                              <td><span [class]="step.ready ? 'label label-success' : 'label label-danger'">{{ step.ready ? 'Ready' : 'Failed' }}</span></td>
                              <td>{{ step.error || '-' }}</td>
                            </tr>
                          }
                        </tbody>
                      </table>
                    }
                  }
                  @if (modelRegistryStatus().upstream?.resources?.length) {
                    <table class="table table-compact ai-mini-table">
                      <thead>
                        <tr><th>REST resource</th><th>Path</th><th>Status</th><th>Items</th></tr>
                      </thead>
                      <tbody>
                        @for (resource of modelRegistryStatus().upstream?.resources || []; track resource.id) {
                          <tr>
                            <td>{{ resource.label }}</td>
                            <td>{{ resource.path }}</td>
                            <td><span [class]="resource.ready ? 'label label-success' : 'label label-warning'">{{ resource.ready ? 'Ready' : 'Unavailable' }}</span></td>
                            <td>{{ resource.count }}</td>
                          </tr>
                        }
                      </tbody>
                    </table>
                  }
                  <form clrForm class="ai-inline-form">
                    <clr-input-container>
                      <label>Model</label>
                      <input clrInput name="versionModel" [value]="createForm().name" (input)="setCreateField('name', $any($event.target).value)" />
                    </clr-input-container>
                    <clr-input-container>
                      <label>Version</label>
                      <input clrInput name="version" [value]="createForm().version" (input)="setCreateField('version', $any($event.target).value)" />
                    </clr-input-container>
                    <clr-select-container>
                      <label>Stage</label>
                      <select clrSelect name="versionStage" [value]="createForm().stage" (change)="setCreateField('stage', $any($event.target).value)">
                        <option value="development">development</option>
                        <option value="staging">staging</option>
                        <option value="production">production</option>
                      </select>
                    </clr-select-container>
                    <clr-input-container>
                      <label>Source</label>
                      <input clrInput name="versionSource" [value]="createForm().source" (input)="setCreateField('source', $any($event.target).value)" />
                    </clr-input-container>
                    <clr-select-container>
                      <label>Backend</label>
                      <select clrSelect name="versionBackend" [value]="createForm().backendType" (change)="setCreateField('backendType', $any($event.target).value)">
                        <option value="auto">auto</option>
                        <option value="opensphere">opensphere</option>
                        <option value="modelregistry">modelregistry</option>
                      </select>
                    </clr-select-container>
                    <button type="button" class="btn btn-primary btn-sm" [disabled]="saving() || !createForm().name" (click)="addModelVersion()">Register version</button>
                  </form>
                  @if (modelVersions().length) {
                    <table class="table table-compact ai-mini-table">
                      <thead>
                        <tr><th>Model</th><th>Version</th><th>Stage</th><th>Source</th><th>Backend</th><th>Registry</th></tr>
                      </thead>
                      <tbody>
                        @for (version of modelVersions(); track version.name + ':' + version.version) {
                          <tr><td>{{ version.name }}</td><td>{{ version.version }}</td><td>{{ version.stage }}</td><td>{{ version.source }}</td><td>{{ version.backend || '-' }}</td><td>{{ version.registry || '-' }}</td></tr>
                        }
                      </tbody>
                    </table>
                  }
                  @if (registryPromotions().length) {
                    <h3 class="ai-panel-title">Promotion history</h3>
                    <table class="table table-compact ai-mini-table">
                      <thead>
                        <tr><th>Promotion</th><th>Model</th><th>Stage</th><th>Decision</th><th>Evaluation</th><th>Metrics</th></tr>
                      </thead>
                      <tbody>
                        @for (promotion of registryPromotions(); track promotion.namespace + ':' + promotion.name) {
                          <tr>
                            <td>{{ promotion.namespace }}/{{ promotion.name }}</td>
                            <td>{{ promotion.modelName }}:{{ promotion.version }}</td>
                            <td>{{ promotion.stage }}</td>
                            <td><span [class]="'label ' + statusClass(promotion.approvalDecision || promotion.evaluationPhase || 'Pending')">{{ promotion.approvalDecision || '-' }}</span></td>
                            <td>{{ promotion.evaluationPhase || '-' }}</td>
                            <td>{{ promotion.metricCount || 0 }}</td>
                          </tr>
                        }
                      </tbody>
                    </table>
                  }
                  @if (registryEvaluationMetrics().length) {
                    <h3 class="ai-panel-title">Evaluation metrics</h3>
                    <table class="table table-compact ai-mini-table">
                      <thead>
                        <tr><th>Promotion</th><th>Metric</th><th>Value</th><th>Threshold</th><th>Result</th></tr>
                      </thead>
                      <tbody>
                        @for (metric of registryEvaluationMetrics(); track metric.id) {
                          <tr>
                            <td>{{ metric.namespace }}/{{ metric.promotionRef }}</td>
                            <td>{{ metric.metric }}</td>
                            <td>{{ metric.value }}</td>
                            <td>{{ metric.threshold ?? '-' }}</td>
                            <td><span [class]="metric.passed ? 'label label-success' : 'label label-danger'">{{ metric.passed ? 'Passed' : 'Failed' }}</span></td>
                          </tr>
                        }
                      </tbody>
                    </table>
                  }
                  @if (registryApprovalAudit().length) {
                    <h3 class="ai-panel-title">Approval audit trail</h3>
                    <table class="table table-compact ai-mini-table">
                      <thead>
                        <tr><th>Time</th><th>Promotion</th><th>Decision</th><th>Actor</th><th>Evaluation</th></tr>
                      </thead>
                      <tbody>
                        @for (entry of registryApprovalAudit(); track entry.id) {
                          <tr>
                            <td>{{ entry.recordedAt }}</td>
                            <td>{{ entry.namespace }}/{{ entry.promotionRef }}</td>
                            <td><span [class]="'label ' + statusClass(entry.decision)">{{ entry.decision }}</span></td>
                            <td>{{ entry.actor || '-' }}</td>
                            <td>{{ entry.evaluationPhase || '-' }}</td>
                          </tr>
                        }
                      </tbody>
                    </table>
                  }
                </div>
              </div>
            }
            @if (activePage() === 'pipeline-runs') {
              <div class="card ai-action-panel">
                <div class="card-header">
                  <div class="card-title">{{ operationTitle() || 'Run details' }}</div>
                </div>
                <div class="card-block">
                  @if (operationLines().length) {
                    <pre class="ai-log-output">@for (line of operationLines(); track line) {<span>{{ line }}</span>
}</pre>
                  }
                  @if (lineageItems().length) {
                    <table class="table table-compact ai-mini-table">
                      <thead>
                        <tr><th>From</th><th>To</th><th>Type</th></tr>
                      </thead>
                      <tbody>
                        @for (edge of lineageItems(); track edge.from + ':' + edge.to + ':' + edge.type) {
                          <tr><td>{{ edge.from }}</td><td>{{ edge.to }}</td><td>{{ edge.type }}</td></tr>
                        }
                      </tbody>
                    </table>
                  }
                  @if (!operationLines().length && !lineageItems().length) {
                    <p class="ai-footnote">Select Logs or Lineage from a run row.</p>
                  }
                </div>
              </div>
            }
            @if (activePage() === 'trustyai-monitoring') {
              <div class="card ai-action-panel">
                <div class="card-header">
                  <div class="card-title">Metric chart</div>
                </div>
                <div class="card-block">
                  <div class="ai-metric-list">
                    @for (metric of trustyMetrics(); track metric.metric) {
                      <div class="ai-metric-row">
                        <span>{{ metric.metric }}</span>
                        <span>{{ metric.value }} / {{ metric.threshold }}</span>
                        <span [class]="'label ' + metricStatusClass(metric.status)">{{ metric.status }}</span>
                        <span [class]="'ai-bar ' + metricBarClass(metric.status)"><span></span></span>
                      </div>
                    }
                  </div>
                  @if (trustyAlerts().length) {
                    <table class="table table-compact ai-mini-table">
                      <thead>
                        <tr><th>Rule</th><th>Severity</th><th>Metric</th><th>Samples</th><th>Message</th></tr>
                      </thead>
                      <tbody>
                        @for (alert of trustyAlerts(); track alert.id) {
                          <tr>
                            <td>{{ alert.rule }}</td>
                            <td><span [class]="alert.severity === 'critical' ? 'label label-danger' : 'label label-warning'">{{ alert.severity }}</span></td>
                            <td>{{ alert.metric }}</td>
                            <td>{{ alert.activeSamples }}</td>
                            <td>{{ alert.message }}</td>
                          </tr>
                        }
                      </tbody>
                    </table>
                  }
                  <p class="ai-footnote">{{ trustyHistory().length }} retained metric samples for the selected target.</p>
                </div>
              </div>
            }
            @if (activePage() === 'cluster-settings') {
              <clr-tabs class="ai-cluster-tabs">
                <clr-tab>
                  <button clrTabLink type="button" (click)="selectClusterSettingsTab('setup')">Setup</button>
                  <clr-tab-content *clrIfActive="clusterSettingsTab() === 'setup'"></clr-tab-content>
                </clr-tab>
                <clr-tab>
                  <button clrTabLink type="button" (click)="selectClusterSettingsTab('readiness')">Readiness</button>
                  <clr-tab-content *clrIfActive="clusterSettingsTab() === 'readiness'"></clr-tab-content>
                </clr-tab>
                <clr-tab>
                  <button clrTabLink type="button" (click)="selectClusterSettingsTab('gpu')">GPU</button>
                  <clr-tab-content *clrIfActive="clusterSettingsTab() === 'gpu'"></clr-tab-content>
                </clr-tab>
                <clr-tab>
                  <button clrTabLink type="button" (click)="selectClusterSettingsTab('demo')">Demo</button>
                  <clr-tab-content *clrIfActive="clusterSettingsTab() === 'demo'"></clr-tab-content>
                </clr-tab>
                <clr-tab>
                  <button clrTabLink type="button" (click)="selectClusterSettingsTab('operations')">Operations</button>
                  <clr-tab-content *clrIfActive="clusterSettingsTab() === 'operations'"></clr-tab-content>
                </clr-tab>
              </clr-tabs>
              <div class="card ai-action-panel" [class.ai-tab-hidden]="clusterSettingsTab() !== 'setup'">
                <div class="card-header">
                  <div class="card-title">AI Platform Setup Wizard</div>
                </div>
                <div class="card-block">
                  <div class="ai-wizard-grid">
                    <section>
                      <h3 class="ai-panel-title">Prerequisites</h3>
                      <table class="table table-compact ai-mini-table">
                        <thead>
                          <tr><th>Check</th><th>Status</th><th>Detail</th></tr>
                        </thead>
                        <tbody>
                          @for (check of setupStatus().prerequisites; track check.id) {
                            <tr>
                              <td>{{ check.label }}</td>
                              <td><span [class]="check.ready ? 'label label-success' : 'label label-warning'">{{ check.ready ? 'Ready' : 'Needs attention' }}</span></td>
                              <td>{{ check.detail }}</td>
                            </tr>
                          }
                        </tbody>
                      </table>
                    </section>
                    <section>
                      <h3 class="ai-panel-title">Installation target</h3>
                      <p class="ai-footnote">Provider presets fill the Operator package, channel, and catalog source. Change them only when your cluster uses a custom catalog.</p>
                      <form clrForm clrLayout="vertical" class="ai-setup-form">
                        <clr-select-container>
                          <label>Provider</label>
                          <select clrSelect name="setupProvider" [value]="setupForm().provider" (change)="setSetupProvider($any($event.target).value)">
                            <option value="opendatahub">Open Data Hub</option>
                            <option value="rhods">Red Hat OpenShift AI</option>
                            <option value="internal">OpenSphere internal only</option>
                          </select>
                        </clr-select-container>
                        <div class="ai-namespace-field">
                          <label class="ai-field-label">Target namespace</label>
                          <div class="btn-group btn-primary btn-sm">
                            <button type="button" class="btn" [class.active]="setupForm().namespaceMode === 'existing'" (click)="setSetupNamespaceMode('existing')">Use existing</button>
                            <button type="button" class="btn" [class.active]="setupForm().namespaceMode === 'new'" (click)="setSetupNamespaceMode('new')">Create new</button>
                          </div>
                          @if (setupForm().namespaceMode === 'existing') {
                            <clr-select-container>
                              <label>Existing namespace</label>
                              <select clrSelect name="setupNamespaceSelect" [value]="setupForm().namespace" (change)="setSetupField('namespace', $any($event.target).value)">
                                @for (namespace of setupNamespaceOptions(); track namespace) {
                                  <option [value]="namespace">{{ namespace }}</option>
                                }
                              </select>
                              <clr-control-helper>The selected namespace will be reused.</clr-control-helper>
                            </clr-select-container>
                          } @else {
                            <clr-input-container>
                              <label>New namespace</label>
                              <input clrInput name="setupNamespace" [value]="setupForm().namespace" (input)="setSetupField('namespace', $any($event.target).value)" />
                              <clr-control-helper>The wizard will create this namespace if it does not exist.</clr-control-helper>
                            </clr-input-container>
                          }
                        </div>
                        <clr-select-container>
                          <label>Operator package</label>
                          <select clrSelect name="setupPackage" [value]="setupForm().operatorPackage" (change)="setSetupField('operatorPackage', $any($event.target).value)">
                            @for (option of setupOperatorPackageOptions(); track option.value) {
                              <option [value]="option.value">{{ option.label }}</option>
                            }
                          </select>
                          <clr-control-helper>{{ setupOperatorHelper() }}</clr-control-helper>
                        </clr-select-container>
                        <clr-select-container>
                          <label>Channel</label>
                          <select clrSelect name="setupChannel" [value]="setupForm().channel" (change)="setSetupField('channel', $any($event.target).value)">
                            @for (channel of setupChannelOptions(); track channel) {
                              <option [value]="channel">{{ channel }}</option>
                            }
                          </select>
                        </clr-select-container>
                        <clr-select-container>
                          <label>Catalog source</label>
                          <select clrSelect name="setupSource" [value]="setupForm().source" (change)="setSetupField('source', $any($event.target).value)">
                            @for (source of setupCatalogSourceOptions(); track source) {
                              <option [value]="source">{{ source }}</option>
                            }
                          </select>
                        </clr-select-container>
                        <clr-input-container>
                          <label>Catalog namespace</label>
                          <input clrInput name="setupSourceNamespace" [value]="setupForm().sourceNamespace" (input)="setSetupField('sourceNamespace', $any($event.target).value)" />
                        </clr-input-container>
                        <clr-input-container>
                          <label>DataScienceCluster</label>
                          <input clrInput name="setupDsc" [value]="setupForm().dataScienceClusterName" (input)="setSetupField('dataScienceClusterName', $any($event.target).value)" />
                          <clr-control-helper>Used after ODH/RHOAI installs the DataScienceCluster CRD.</clr-control-helper>
                        </clr-input-container>
                        <div class="ai-option-list">
                          <clr-checkbox-wrapper>
                            <input type="checkbox" clrCheckbox [checked]="setupForm().installInternalCrds" (change)="setSetupField('installInternalCrds', $any($event.target).checked)" />
                            <label>Install OpenSphere foundation CRDs</label>
                          </clr-checkbox-wrapper>
                          <clr-checkbox-wrapper>
                            <input type="checkbox" clrCheckbox [checked]="setupForm().installOperator" (change)="setSetupField('installOperator', $any($event.target).checked)" />
                            <label>Install Operator subscription</label>
                          </clr-checkbox-wrapper>
                          <clr-checkbox-wrapper>
                            <input type="checkbox" clrCheckbox [checked]="setupForm().createDataScienceCluster" (change)="setSetupField('createDataScienceCluster', $any($event.target).checked)" />
                            <label>Create DataScienceCluster</label>
                          </clr-checkbox-wrapper>
                        </div>
                      </form>
                    </section>
                  </div>
                  <section class="ai-setup-components">
                    <h3 class="ai-panel-title">Components</h3>
                    <div class="ai-checkbox-grid">
                      @for (component of setupComponents; track component) {
                        <clr-checkbox-wrapper>
                          <input type="checkbox" clrCheckbox [checked]="setupForm().components.includes(component)" (change)="toggleSetupComponent(component, $any($event.target).checked)" />
                          <label>{{ component }}</label>
                        </clr-checkbox-wrapper>
                      }
                    </div>
                  </section>
                  <div class="ai-action-row">
                    <button type="button" class="btn btn-sm btn-outline" [disabled]="saving()" (click)="loadSetupStatus()">Refresh checks</button>
                    <button type="button" class="btn btn-sm btn-outline" [disabled]="saving()" (click)="previewSetupPlan()">Preview plan</button>
                    <button type="button" class="btn btn-sm btn-primary" [disabled]="saving()" (click)="runSetupInstall()">Run install</button>
                  </div>
                  @if (setupSteps().length) {
                    <table class="table table-compact ai-mini-table">
                      <thead>
                        <tr><th>Step</th><th>Phase</th><th>Detail</th></tr>
                      </thead>
                      <tbody>
                        @for (step of setupSteps(); track step.id) {
                          <tr>
                            <td>{{ step.label }}</td>
                            <td><span [class]="'label ' + statusClass(step.phase || 'Pending')">{{ step.phase || 'Planned' }}</span></td>
                            <td>{{ step.detail || step.action || '-' }}</td>
                          </tr>
                        }
                      </tbody>
                    </table>
                  }
                  @if (setupManifestPreview()) {
                    <pre class="ai-log-output">{{ setupManifestPreview() }}</pre>
                  }
                  <h3 class="ai-panel-title">CRD coverage</h3>
                  <table class="table table-compact ai-mini-table">
                    <thead>
                      <tr><th>CRD</th><th>Family</th><th>Status</th></tr>
                    </thead>
                    <tbody>
                      @for (crd of setupStatus().crds; track crd.name) {
                        <tr>
                          <td>{{ crd.label }}</td>
                          <td>{{ crd.family }}</td>
                          <td><span [class]="crd.installed ? 'label label-success' : 'label label-warning'">{{ crd.installed ? 'Installed' : 'Missing' }}</span></td>
                        </tr>
                      }
                    </tbody>
                  </table>
                </div>
              </div>
              <div class="card ai-action-panel" [class.ai-tab-hidden]="clusterSettingsTab() !== 'setup'">
                <div class="card-header">
                  <div class="card-title">ODH Operator components</div>
                </div>
                <div class="card-block">
                  <table class="table table-compact ai-mini-table">
                    <thead>
                      <tr><th>Component</th><th>Phase</th><th>Ready</th><th>Actions</th></tr>
                    </thead>
                    <tbody>
                      @for (component of odhComponents(); track component.name) {
                        <tr>
                          <td>{{ component.name }}</td>
                          <td><span [class]="'label ' + statusClass(component.phase)">{{ component.phase }}</span></td>
                          <td>{{ component.ready ? 'Ready' : 'Not ready' }}</td>
                          <td>
                            <button type="button" class="btn btn-sm btn-link" [disabled]="saving()" (click)="odhComponentAction(component, 'enable')">Enable</button>
                            <button type="button" class="btn btn-sm btn-link" [disabled]="saving()" (click)="odhComponentAction(component, 'disable')">Disable</button>
                            <button type="button" class="btn btn-sm btn-link" [disabled]="saving()" (click)="odhComponentAction(component, 'upgrade')">Upgrade</button>
                          </td>
                        </tr>
                      }
                    </tbody>
                  </table>
                </div>
              </div>
              <div class="card ai-action-panel" [class.ai-tab-hidden]="clusterSettingsTab() !== 'setup'">
                <div class="card-header">
                  <div class="card-title">OpenSphere native AI catalog</div>
                </div>
                <div class="card-block">
                  <p class="ai-footnote">OpenSphere-native replacement for the OLM/OperatorHub experience. It installs component subscriptions and plans without requiring a separate OKD cluster.</p>
                  <div class="ai-action-row">
                    <button type="button" class="btn btn-sm btn-outline" [disabled]="saving()" (click)="loadNativeCatalog()">Refresh catalog</button>
                    <button type="button" class="btn btn-sm btn-outline" [disabled]="saving()" (click)="seedNativeCatalog()">Seed catalog</button>
                    <button type="button" class="btn btn-sm btn-outline" [disabled]="saving()" (click)="reconcileWorkbenches()">Reconcile workbenches</button>
                    <button type="button" class="btn btn-sm btn-outline" [disabled]="saving()" (click)="reconcilePipelineRuns()">Reconcile pipeline runs</button>
                    <button type="button" class="btn btn-sm btn-outline" [disabled]="saving()" (click)="reconcileInferences()">Reconcile inference endpoints</button>
                    <button type="button" class="btn btn-sm btn-outline" [disabled]="saving()" (click)="reconcileEvaluations()">Reconcile evaluations</button>
                    <button type="button" class="btn btn-sm btn-outline" [disabled]="saving()" (click)="reconcileModelPromotions()">Reconcile promotions</button>
                    <button type="button" class="btn btn-sm btn-outline" [disabled]="saving()" (click)="reconcileMonitoringTargets()">Reconcile monitoring</button>
                    <button type="button" class="btn btn-sm btn-outline" [disabled]="saving()" (click)="reconcileDistributedWorkloads()">Reconcile distributed workloads</button>
                    <button type="button" class="btn btn-sm btn-primary" [disabled]="saving()" (click)="createNativeDataScienceCluster()">Create native DataScienceCluster</button>
                  </div>
                  <table class="table table-compact ai-mini-table">
                    <thead>
                      <tr><th>Component</th><th>Version</th><th>Plan</th><th>State</th><th>Actions</th></tr>
                    </thead>
                    <tbody>
                      @for (component of nativePlatform().components; track component.name) {
                        <tr>
                          <td>
                            <strong>{{ component.displayName }}</strong>
                            <p class="ai-footnote">{{ component.description }}</p>
                          </td>
                          <td>
                            {{ component.installedVersion || component.version }} / {{ component.channel }}
                            <p class="ai-footnote">target {{ component.targetVersion || component.version }}</p>
                          </td>
                          <td>
                            <span class="label label-info">{{ component.operation || 'Install' }}</span>
                            <p class="ai-footnote">rollback {{ component.rollbackVersion || '-' }}</p>
                          </td>
                          <td>
                            <span [class]="'label ' + statusClass(component.phase)">{{ component.phase }}</span>
                            <span class="label label-info">{{ component.managementState }}</span>
                          </td>
                          <td>
                            <button type="button" class="btn btn-sm btn-link" [disabled]="saving()" (click)="subscribeNativeComponent(component)">Subscribe</button>
                            <button type="button" class="btn btn-sm btn-link" [disabled]="saving()" (click)="upgradeNativeComponent(component)">Upgrade</button>
                            <button type="button" class="btn btn-sm btn-link" [disabled]="saving()" (click)="approveNativeInstallPlan(component)">Approve</button>
                            <button type="button" class="btn btn-sm btn-link" [disabled]="saving() || !component.rollbackVersion" (click)="rollbackNativeComponent(component)">Rollback</button>
                          </td>
                        </tr>
                      }
                    </tbody>
                  </table>
                  @if (!nativePlatform().components.length) {
                    <p class="ai-footnote">No native catalog data loaded yet.</p>
                  }
                </div>
              </div>
              <div class="card ai-action-panel" [class.ai-tab-hidden]="clusterSettingsTab() !== 'readiness'">
                <div class="card-header">
                  <div class="card-title">OpenSphere native readiness</div>
                </div>
                <div class="card-block">
                  <div class="ai-label-row ai-backend-summary">
                    <span [class]="'label ' + statusClass(finalReadiness().nativePhase || finalReadiness().phase)">{{ finalReadiness().nativePhase || finalReadiness().phase }}</span>
                    <span class="label label-success">{{ finalReadiness().summary.nativeReady || 0 }} native ready</span>
                    <span class="label label-warning">{{ finalReadiness().summary.nativeWarning || 0 }} native warnings</span>
                    <span class="label label-danger">{{ finalReadiness().summary.nativeFail || 0 }} native failed</span>
                    <span [class]="'label ' + statusClass(finalReadiness().readinessModel?.upstreamAdapterReadiness?.phase || finalReadiness().upstreamPhase || 'Pending')">Upstream adapter: {{ finalReadiness().readinessModel?.upstreamAdapterReadiness?.phase || finalReadiness().upstreamPhase || 'Pending' }}</span>
                    <span [class]="'label ' + statusClass(finalReadiness().readinessModel?.parityReadiness?.phase || 'NotReady')">Parity: {{ finalReadiness().readinessModel?.parityReadiness?.phase || 'NotReady' }}</span>
                    <span class="label label-warning">{{ finalReadiness().summary.upstreamNotInstalled || 0 }} upstream not installed</span>
                    <span class="ai-footnote">Generated {{ finalReadiness().generatedAt || '-' }}</span>
                  </div>
                  @if (finalReadiness().readinessModel?.parityReadiness?.evidence) {
                    <p class="ai-footnote">{{ finalReadiness().readinessModel?.parityReadiness?.evidence }}</p>
                  }
                  <table class="table table-compact ai-mini-table">
                    <thead>
                      <tr><th>Check</th><th>Scope</th><th>Status</th><th>Evidence</th><th>Next step</th></tr>
                    </thead>
                    <tbody>
                      @for (check of finalReadiness().checks; track check.id) {
                        <tr>
                          <td><strong>{{ check.label }}</strong></td>
                          <td><span [class]="check.scope === 'native' ? 'label label-success' : 'label label-info'">{{ check.scope }}</span></td>
                          <td><span [class]="'label ' + statusClass(check.status)">{{ check.status }}</span></td>
                          <td>{{ check.evidence }}</td>
                          <td>{{ check.nextStep || '-' }}</td>
                        </tr>
                      }
                    </tbody>
                  </table>
                  @if (!finalReadiness().checks.length) {
                    <p class="ai-footnote">OpenSphere native readiness has not loaded yet.</p>
                  }
                </div>
              </div>
              <div class="card ai-action-panel" [class.ai-tab-hidden]="clusterSettingsTab() !== 'readiness'">
                <div class="card-header">
                  <div class="card-title">Backend detection</div>
                </div>
                <div class="card-block">
                  <div class="ai-label-row ai-backend-summary">
                    <span [class]="'label ' + statusClass(nativeBackends().summary.phase)">{{ nativeBackends().summary.phase }}</span>
                    <span class="ai-footnote">{{ nativeBackends().summary.upstreamReady }} upstream, {{ nativeBackends().summary.fallbackReady }} fallback, {{ nativeBackends().summary.unavailable }} unavailable</span>
                  </div>
                  <table class="table table-compact ai-mini-table">
                    <thead>
                      <tr><th>Capability</th><th>Mode</th><th>Backend</th><th>Required APIs</th></tr>
                    </thead>
                    <tbody>
                      @for (backend of nativeBackends().items; track backend.id) {
                        <tr>
                          <td>
                            <strong>{{ backend.displayName }}</strong>
                            <p class="ai-footnote">{{ backend.message }}</p>
                          </td>
                          <td>
                            <span [class]="'label ' + statusClass(backend.phase)">{{ backend.phase }}</span>
                          </td>
                          <td>{{ backend.upstreamReady ? backend.upstream.join(', ') : backend.fallback }}</td>
                          <td>
                            <div class="ai-chip-list">
                              @for (crd of backend.crds; track crd.name) {
                                <span [class]="crd.installed ? 'label label-success' : crd.optional ? 'label label-info' : 'label label-warning'">{{ crd.label }}</span>
                              }
                            </div>
                          </td>
                        </tr>
                      }
                    </tbody>
                  </table>
                  @if (!nativeBackends().items.length) {
                    <p class="ai-footnote">Backend detection has not loaded yet.</p>
                  }
                </div>
              </div>
              <div class="card ai-action-panel" [class.ai-tab-hidden]="clusterSettingsTab() !== 'gpu'">
                <div class="card-header">
                  <div class="card-title">GPU resource workspace</div>
                </div>
                <div class="card-block">
                  <div class="ai-gpu-hero">
                    <div>
                      <p class="ai-eyebrow">COMPUTEBACKEND TARGET</p>
                      <h3 class="ai-gpu-heading">{{ gpuEnablementPlan()?.resourceName || gpuEnablementConfig().resourceName }}</h3>
                      <p class="ai-footnote">{{ gpuEnablementPlan()?.summary || 'Choose how OAH should attach compute for training, inference, notebook, and demo workloads.' }}</p>
                    </div>
                    <div class="ai-gpu-health">
                      <span [class]="'label ' + statusClass(gpuInventory().phase)">{{ gpuInventory().phase }}</span>
                      <span [class]="gpuInventory().ready ? 'label label-success' : 'label label-warning'">{{ gpuInventory().summary.totalAllocatable }} allocatable GPU(s)</span>
                    </div>
                  </div>
                  <div class="ai-gpu-metric-grid">
                    <div class="ai-gpu-metric">
                      <span class="ai-kv-label">GPU nodes</span>
                      <strong>{{ gpuInventory().summary.gpuNodes }}</strong>
                      <span>{{ gpuInventory().summary.readyNodes }}/{{ gpuInventory().summary.nodes }} nodes ready</span>
                    </div>
                    <div class="ai-gpu-metric">
                      <span class="ai-kv-label">Plugin integrations</span>
                      <strong>{{ gpuInventory().summary.pluginDaemonSets }}</strong>
                      <span>{{ gpuInventory().summary.pluginPods }} pod(s) detected</span>
                    </div>
                    <div class="ai-gpu-metric">
                      <span class="ai-kv-label">Configure focus</span>
                      <strong>{{ gpuEnablementPlan()?.profile || gpuEnablementProfile() }}</strong>
                      <span>{{ gpuEnablementPlan()?.mode || 'pending' }}</span>
                    </div>
                    <div class="ai-gpu-metric">
                      <span class="ai-kv-label">Diagnostics</span>
                      <strong>{{ gpuInventory().summary.diagnostics || 0 }}</strong>
                      <span>{{ gpuInventory().ready ? 'GPU ready' : 'attention required' }}</span>
                    </div>
                  </div>
                  <h3 class="ai-panel-title">Compute Backend service catalog</h3>
                  <p class="ai-footnote">These are not mutually exclusive choices. OAH can register several services, then route training, serving, notebook, batch, and fallback work to the active backend for each situation.</p>
                  <div class="ai-gpu-catalog-grid">
                    @for (service of gpuServiceCatalog(); track service.id) {
                      <article class="ai-gpu-option" [class.ai-gpu-option-active]="service.selected" [class.ai-gpu-option-aux]="!service.selectable">
                        <div class="ai-gpu-option-head">
                          <div>
                            <strong>{{ service.label }}</strong>
                            <p class="ai-footnote">{{ service.category }} - {{ service.serviceRole }}</p>
                          </div>
                          <div class="ai-gpu-option-badges">
                            @if (service.selected) {
                              <span class="label label-success">Configure focus</span>
                            }
                            @if (service.registered) {
                              <span class="label label-info">Registered</span>
                            }
                            <span [class]="'label ' + statusClass(service.phase)">{{ service.phase }}</span>
                          </div>
                        </div>
                        <p><code>{{ service.resourceName }}</code></p>
                        <p class="ai-footnote">{{ service.summary }}</p>
                        <dl class="ai-gpu-service-facts">
                          <div>
                            <dt>Workloads</dt>
                            <dd>{{ service.workloads }}</dd>
                          </div>
                          <div>
                            <dt>Verification</dt>
                            <dd>{{ service.verification }}</dd>
                          </div>
                          @if (service.endpoint) {
                            <div>
                              <dt>Endpoint</dt>
                              <dd>{{ service.endpoint }}</dd>
                            </div>
                          }
                          @if (service.backendName) {
                            <div>
                              <dt>Resource</dt>
                              <dd>{{ service.backendNamespace }}/{{ service.backendName }}</dd>
                            </div>
                          }
                        </dl>
                        <div class="ai-gpu-option-footer">
                          @if (service.selected) {
                            <button type="button" class="btn btn-sm btn-primary" disabled>Configuring</button>
                            <span class="ai-footnote">Configure below</span>
                          } @else if (service.selectable) {
                            <button type="button" class="btn btn-sm btn-link" (click)="selectGpuEnablementProfile(service.id)">Configure</button>
                            <span class="ai-footnote">Configure and verify</span>
                          } @else {
                            <button type="button" class="btn btn-sm btn-link" (click)="navigate('llm-routes')">Open routes</button>
                            <span class="ai-footnote">Not a compute backend</span>
                          }
                        </div>
                      </article>
                    }
                  </div>
                  @if (!gpuServiceCatalog().length) {
                    <p class="ai-footnote">Compute backend services are loading. Refresh the plan if this remains empty.</p>
                  }
                  <div class="ai-gpu-config-panel">
                    <div class="ai-section-header">
                      <div>
                        <h3 class="ai-panel-title">Configure focused service</h3>
                        <p class="ai-footnote">These settings belong to the service card currently in focus. Register one or more services, then use workload routing to decide which backend each workload uses.</p>
                      </div>
                      @if (gpuEnablementPlan()) {
                        <span [class]="'label ' + statusClass(gpuEnablementPlan()?.phase || 'Pending')">{{ gpuEnablementPlan()?.phase }}</span>
                      }
                    </div>
                    <form clrForm clrLayout="compact" class="ai-gpu-config-form">
                      <clr-select-container>
                        <label>Usage option</label>
                        <select clrSelect name="gpuEnablementProfileTop" [value]="gpuEnablementProfile()" (change)="selectGpuEnablementProfile($any($event.target).value)">
                          <option value="nvidia">NVIDIA device plugin</option>
                          <option value="nvidia-operator">NVIDIA GPU Operator / OLM</option>
                          <option value="amd">AMD ROCm device plugin</option>
                          <option value="intel">Intel device plugin</option>
                          <option value="generic">OpenSphere generic GPU resource</option>
                          <option value="external">Generic external GPU endpoint</option>
                          <option value="docker-bridge">Local Docker GPU Bridge</option>
                          <option value="windows-service">Windows GPU Bridge Service</option>
                          <option value="windows-supervisor">Windows Supervisor + Docker/WSL2 worker</option>
                          <option value="wsl2">WSL2 GPU Bridge</option>
                          <option value="remote">Remote external GPU backend</option>
                          <option value="colab">Google Colab / notebook bridge</option>
                          <option value="cpu">CPU fallback</option>
                        </select>
                        <clr-control-helper>This changes the focused service form only. Workload routing below decides runtime use.</clr-control-helper>
                      </clr-select-container>
                      <clr-input-container>
                        <label>Namespace</label>
                        <input clrInput name="gpuNamespaceTop" [value]="gpuEnablementConfig().namespace" (input)="setGpuEnablementConfigField('namespace', $any($event.target).value)" />
                      </clr-input-container>
                      <clr-input-container>
                        <label>Resource name</label>
                        <input clrInput name="gpuResourceNameTop" [value]="gpuEnablementConfig().resourceName" (input)="setGpuEnablementConfigField('resourceName', $any($event.target).value)" />
                      </clr-input-container>
                      @if (isDevicePluginMode()) {
                        <clr-input-container>
                          <label>Plugin image</label>
                          <input clrInput name="gpuPluginImageTop" [value]="gpuEnablementConfig().pluginImage" (input)="setGpuEnablementConfigField('pluginImage', $any($event.target).value)" />
                        </clr-input-container>
                        <clr-input-container>
                          <label>Node selector key</label>
                          <input clrInput name="gpuNodeSelectorKeyTop" [value]="gpuEnablementConfig().nodeSelectorKey" (input)="setGpuEnablementConfigField('nodeSelectorKey', $any($event.target).value)" />
                        </clr-input-container>
                        <clr-input-container>
                          <label>Node selector value</label>
                          <input clrInput name="gpuNodeSelectorValueTop" [value]="gpuEnablementConfig().nodeSelectorValue" (input)="setGpuEnablementConfigField('nodeSelectorValue', $any($event.target).value)" />
                        </clr-input-container>
                      }
                      @if (isGpuOperatorMode()) {
                        <clr-input-container>
                          <label>Operator package</label>
                          <input clrInput name="gpuOperatorPackageTop" [value]="gpuEnablementConfig().packageName" (input)="setGpuEnablementConfigField('packageName', $any($event.target).value)" />
                        </clr-input-container>
                        <clr-input-container>
                          <label>Channel</label>
                          <input clrInput name="gpuOperatorChannelTop" [value]="gpuEnablementConfig().channel" (input)="setGpuEnablementConfigField('channel', $any($event.target).value)" />
                        </clr-input-container>
                        <clr-input-container>
                          <label>Catalog source</label>
                          <input clrInput name="gpuCatalogSourceTop" [value]="gpuEnablementConfig().catalogSource" (input)="setGpuEnablementConfigField('catalogSource', $any($event.target).value)" />
                        </clr-input-container>
                        <clr-input-container>
                          <label>Catalog namespace</label>
                          <input clrInput name="gpuCatalogNamespaceTop" [value]="gpuEnablementConfig().catalogNamespace" (input)="setGpuEnablementConfigField('catalogNamespace', $any($event.target).value)" />
                        </clr-input-container>
                      }
                      @if (isDevicePluginMode() || isGpuOperatorMode()) {
                        <clr-input-container>
                          <label>RuntimeClass</label>
                          <input clrInput name="gpuRuntimeClassTop" [value]="gpuEnablementConfig().runtimeClass" (input)="setGpuEnablementConfigField('runtimeClass', $any($event.target).value)" />
                        </clr-input-container>
                        <div class="ai-option-list">
                          <clr-checkbox-wrapper>
                            <input type="checkbox" clrCheckbox [checked]="gpuEnablementConfig().useRuntimeClass" (change)="setGpuEnablementConfigField('useRuntimeClass', $any($event.target).checked)" />
                            <label>Schedule Pods with runtimeClassName</label>
                          </clr-checkbox-wrapper>
                        </div>
                      }
                      @if (isExternalGpuMode()) {
                        <clr-input-container>
                          <label>{{ gpuEnablementProfile() === 'colab' ? 'Bridge endpoint' : 'Service endpoint' }}</label>
                          <input clrInput name="gpuExternalEndpointTop" placeholder="https://gpu.example.internal" [value]="gpuEnablementConfig().externalEndpoint" (input)="setGpuEnablementConfigField('externalEndpoint', $any($event.target).value)" />
                          <clr-control-helper>{{ gpuEnablementProfile() === 'colab' ? 'OpenSphere bridge endpoint that can control a notebook runtime and report job status.' : 'Reachable compute service endpoint that implements the OAH bridge contract.' }}</clr-control-helper>
                        </clr-input-container>
                        <clr-input-container>
                          <label>Credential Secret</label>
                          <input clrInput name="gpuCredentialSecretTop" [value]="gpuEnablementConfig().credentialSecret" (input)="setGpuEnablementConfigField('credentialSecret', $any($event.target).value)" />
                          <clr-control-helper>The Secret must contain credentials accepted by the external GPU service.</clr-control-helper>
                        </clr-input-container>
                      }
                      @if (isExternalGpuMode() || isCpuFallbackMode()) {
                        <clr-input-container>
                          <label>Max concurrency</label>
                          <input clrInput type="number" min="1" name="gpuMaxConcurrencyTop" [value]="gpuEnablementConfig().maxConcurrency" (input)="setGpuEnablementConfigField('maxConcurrency', $any($event.target).valueAsNumber || 1)" />
                        </clr-input-container>
                      }
                      <button type="button" class="btn btn-sm btn-outline" [disabled]="saving()" (click)="loadGpuEnablementPlan()">Refresh plan</button>
                    </form>
                    @if (isExternalGpuMode()) {
                      <div class="ai-gpu-bridge-panel">
                        <div class="ai-section-header">
                          <div>
                            <h3 class="ai-panel-title">External bridge verification</h3>
                            <p class="ai-footnote">OAH calls the selected endpoint through the server, reads the token from the configured Secret, and reports the GPU service response here.</p>
                          </div>
                          @if (gpuBridgeProbe()) {
                            <span [class]="'label ' + statusClass(gpuBridgeProbe()?.phase || 'Pending')">{{ gpuBridgeProbe()?.phase }}</span>
                          }
                        </div>
                        <div class="ai-action-row">
                          <button type="button" class="btn btn-sm btn-outline" [disabled]="saving() || !gpuEnablementConfig().externalEndpoint" (click)="runGpuBridgeProbe('health')">Test health</button>
                          <button type="button" class="btn btn-sm btn-outline" [disabled]="saving() || !gpuEnablementConfig().externalEndpoint" (click)="runGpuBridgeProbe('capabilities')">Read capabilities</button>
                          <button type="button" class="btn btn-sm btn-primary" [disabled]="saving() || !gpuEnablementConfig().externalEndpoint" (click)="runGpuBridgeProbe('smoke')">Run smoke job</button>
                          <button type="button" class="btn btn-sm btn-success" [disabled]="saving() || !gpuEnablementConfig().externalEndpoint" (click)="runGpuBridgeProbe('register')">Register backend</button>
                          <button type="button" class="btn btn-sm btn-success" [disabled]="saving() || !gpuEnablementConfig().externalEndpoint" (click)="runGpuBridgeProbe('training-smoke')">Run training smoke</button>
                        </div>
                        @if (gpuBridgeProbe(); as probe) {
                          <div class="ai-label-row ai-backend-summary">
                            <span [class]="probe.ready ? 'label label-success' : 'label label-warning'">{{ probe.ready ? 'Ready' : 'Needs attention' }}</span>
                            <span class="label label-info">{{ probe.endpoint }}</span>
                            <span class="label label-info">{{ probe.credentialSecret }}</span>
                            <span class="ai-footnote">Checked {{ probe.checkedAt || '-' }}</span>
                          </div>
                          @if (probe.capabilities?.gpus?.length) {
                            <table class="table table-compact ai-mini-table">
                              <thead>
                                <tr><th>GPU</th><th>Driver</th><th>Memory</th><th>Utilization</th><th>Temperature</th></tr>
                              </thead>
                              <tbody>
                                @for (gpu of probe.capabilities.gpus || []; track gpu['index'] || gpu['name']) {
                                  <tr>
                                    <td><strong>{{ gpu['name'] }}</strong></td>
                                    <td>{{ gpu['driverVersion'] || '-' }}</td>
                                    <td>{{ gpu['memoryTotalMiB'] || '-' }} MiB</td>
                                    <td>{{ gpu['utilizationGpuPercent'] || 0 }}%</td>
                                    <td>{{ gpu['temperatureC'] || '-' }} C</td>
                                  </tr>
                                }
                              </tbody>
                            </table>
                          }
                          @if (probe.job) {
                            <div class="ai-label-row ai-backend-summary">
                              <span [class]="'label ' + statusClass($any(probe.job)['phase'] || probe.phase)">{{ $any(probe.job)['phase'] || probe.phase }}</span>
                              <span class="label label-info">{{ $any(probe.job)['jobType'] || 'smoke' }}</span>
                              <span class="label label-info">{{ $any(probe.job)['id'] || '-' }}</span>
                            </div>
                          }
                          @if (probe.backend) {
                            <div class="ai-label-row ai-backend-summary">
                              <span [class]="'label ' + statusClass(probe.backend.phase)">{{ probe.backend.phase }}</span>
                              <span class="label label-info">{{ probe.backend.kind }}</span>
                              <span class="label label-info">{{ probe.backend.namespace }}/{{ probe.backend.name }}</span>
                            </div>
                          }
                          @if (probe.trainingJob) {
                            <div class="ai-label-row ai-backend-summary">
                              <span [class]="'label ' + statusClass(probe.trainingJob.phase)">{{ probe.trainingJob.phase }}</span>
                              <span class="label label-info">{{ probe.trainingJob.kind }}</span>
                              <span class="label label-info">{{ probe.trainingJob.namespace }}/{{ probe.trainingJob.name }}</span>
                              @if (probe.trainingJob.externalJob) {
                                <span class="label label-info">{{ $any(probe.trainingJob.externalJob)['jobId'] || $any(probe.trainingJob.externalJob)['id'] }}</span>
                              }
                            </div>
                            @if (probe.trainingJob.externalJobLogSummary?.latest) {
                              <pre class="ai-log-output">{{ probe.trainingJob.externalJobLogSummary.latest }}</pre>
                            }
                          }
                          @if (gpuBridgeProbeLog()) {
                            <pre class="ai-log-output">{{ gpuBridgeProbeLog() }}</pre>
                          }
                        }
                      </div>
                    }
                    <div class="ai-gpu-bridge-panel">
                      <div class="ai-section-header">
                        <div>
                          <h3 class="ai-panel-title">Registered compute backends</h3>
                          <p class="ai-footnote">These ComputeBackendClaim resources are what workbenches, training jobs, distributed workloads, and inference tasks can reference.</p>
                        </div>
                        <button type="button" class="btn btn-sm btn-outline" [disabled]="saving()" (click)="loadComputeBackends()">Refresh backends</button>
                      </div>
                      @if (computeBackends().length) {
                        <table class="table table-compact ai-mini-table">
                          <thead>
                            <tr><th>Name</th><th>Backend</th><th>Endpoint</th><th>GPU / resource</th><th>Status</th><th>Message</th></tr>
                          </thead>
                          <tbody>
                            @for (backend of computeBackends(); track backend.namespace + '/' + backend.name) {
                              <tr>
                                <td>
                                  <strong>{{ backend.name }}</strong>
                                  <p class="ai-footnote">{{ backend.namespace }}</p>
                                </td>
                                <td>
                                  <span class="label label-info">{{ backend.backendType || 'unknown' }}</span>
                                  @if (backend.provider) {
                                    <span class="label label-info">{{ backend.provider }}</span>
                                  }
                                </td>
                                <td>{{ backend.endpoint || '-' }}</td>
                                <td>
                                  <strong>{{ backend.resourceName || '-' }}</strong>
                                  @if (backend.gpus?.length) {
                                    <div class="ai-chip-list">
                                      @for (gpu of backend.gpus || []; track gpu['id'] || gpu['name']) {
                                        <span class="label label-info">{{ gpu['name'] || gpu['id'] }}</span>
                                      }
                                    </div>
                                  }
                                </td>
                                <td><span [class]="'label ' + statusClass(backend.phase)">{{ backend.phase }}</span></td>
                                <td>{{ backend.message || backend.reason || backend.description || '-' }}</td>
                              </tr>
                            }
                          </tbody>
                        </table>
                      } @else {
                        <p class="ai-footnote">No ComputeBackendClaim is registered yet. Verify an external bridge, then use Register backend.</p>
                      }
                    </div>
                    <div class="ai-gpu-bridge-panel">
                      <div class="ai-section-header">
                        <div>
                          <h3 class="ai-panel-title">Workload routing</h3>
                          <p class="ai-footnote">Choose which registered backend OAH should use for each workload type. This is the operational destination of the service catalog above.</p>
                        </div>
                        <div class="ai-action-row">
                          <span [class]="'label ' + statusClass(computeRouting().phase)">{{ computeRouting().phase }}</span>
                          <button type="button" class="btn btn-sm btn-outline" [disabled]="saving()" (click)="loadComputeRouting()">Refresh routing</button>
                          <button type="button" class="btn btn-sm btn-success" [disabled]="saving()" (click)="saveComputeRouting()">Save routing</button>
                        </div>
                      </div>
                      @if (computeRouting().parseError) {
                        <clr-alert clrAlertType="warning" [clrAlertClosable]="false">
                          <clr-alert-item>
                            <span class="alert-text">{{ computeRouting().parseError }}</span>
                          </clr-alert-item>
                        </clr-alert>
                      }
                      @if (computeRouting().routes.length) {
                        <table class="table table-compact ai-mini-table ai-routing-table">
                          <thead>
                            <tr><th>Workload</th><th>Primary backend</th><th>Fallback backend</th><th>Status</th><th>Message</th></tr>
                          </thead>
                          <tbody>
                            @for (route of computeRouting().routes; track route.id) {
                              <tr>
                                <td><strong>{{ route.label }}</strong></td>
                                <td>
                                  <select clrSelect [name]="'route-primary-' + route.id" [value]="route.primary" (change)="setComputeRoutingField(route.id, 'primary', $any($event.target).value)">
                                    @for (option of computeRouting().options; track option.key) {
                                      <option [value]="option.key">{{ option.label }}</option>
                                    }
                                  </select>
                                </td>
                                <td>
                                  <select clrSelect [name]="'route-fallback-' + route.id" [value]="route.fallback" (change)="setComputeRoutingField(route.id, 'fallback', $any($event.target).value)">
                                    @for (option of computeRouting().options; track option.key) {
                                      <option [value]="option.key">{{ option.label }}</option>
                                    }
                                  </select>
                                </td>
                                <td><span [class]="'label ' + statusClass(route.phase)">{{ route.phase }}</span></td>
                                <td>{{ route.message }}</td>
                              </tr>
                            }
                          </tbody>
                        </table>
                        <div class="ai-label-row ai-backend-summary">
                          <span class="ai-footnote">Stored in {{ computeRouting().namespace }}/{{ computeRouting().name }}</span>
                          @if (computeRouting().updatedAt) {
                            <span class="ai-footnote">Updated {{ computeRouting().updatedAt }}</span>
                          }
                          @if (computeRouting().updatedBy) {
                            <span class="ai-footnote">By {{ computeRouting().updatedBy }}</span>
                          }
                        </div>
                      } @else {
                        <p class="ai-footnote">Routing options are loading. Refresh routing after ComputeBackendClaim resources are available.</p>
                      }
                    </div>
                    @if (gpuEnablementPlan()) {
                      <div class="ai-label-row ai-backend-summary">
                        <span [class]="'label ' + statusClass(gpuEnablementPlan()?.phase || 'Pending')">{{ gpuEnablementPlan()?.phase }}</span>
                        <span class="label label-info">{{ gpuEnablementPlan()?.mode }}</span>
                        <span class="label label-info">{{ gpuEnablementPlan()?.resourceName }}</span>
                        <span class="label label-info">{{ gpuEnablementPlan()?.namespace }}</span>
                        <span class="ai-footnote">Generated {{ gpuEnablementPlan()?.generatedAt || '-' }}</span>
                      </div>
                      <p class="ai-footnote">{{ gpuEnablementPlan()?.summary }}</p>
                      <table class="table table-compact ai-mini-table">
                        <thead>
                          <tr><th>Check</th><th>Status</th><th>Detail</th></tr>
                        </thead>
                        <tbody>
                          @for (check of gpuEnablementPlan()?.checks || []; track check.id) {
                            <tr>
                              <td><strong>{{ check.label }}</strong></td>
                              <td><span [class]="check.ready ? 'label label-success' : check.phase === 'Optional' ? 'label label-info' : 'label label-warning'">{{ check.phase }}</span></td>
                              <td>{{ check.detail }}</td>
                            </tr>
                          }
                        </tbody>
                      </table>
                      @if (gpuEnablementPreview()) {
                        <pre class="ai-log-output">{{ gpuEnablementPreview() }}</pre>
                      }
                    }
                  </div>
                </div>
              </div>
              <div class="card ai-action-panel" [class.ai-tab-hidden]="clusterSettingsTab() !== 'gpu'">
                <div class="card-header">
                  <div class="card-title">GPU inventory</div>
                </div>
                <div class="card-block">
                  <div class="ai-label-row ai-backend-summary">
                    <span [class]="'label ' + statusClass(gpuInventory().phase)">{{ gpuInventory().phase }}</span>
                    <span [class]="gpuInventory().ready ? 'label label-success' : 'label label-warning'">{{ gpuInventory().summary.totalAllocatable }} allocatable GPU(s)</span>
                    <span class="label label-info">{{ gpuInventory().summary.gpuNodes }} GPU node(s)</span>
                    <span class="label label-info">{{ gpuInventory().summary.pluginDaemonSets }} plugin daemonset(s)</span>
                    <span class="label label-info">{{ gpuInventory().summary.pluginPods }} plugin pod(s)</span>
                    <span class="ai-footnote">Generated {{ gpuInventory().generatedAt || '-' }}</span>
                  </div>
                  <table class="table table-compact ai-mini-table">
                    <thead>
                      <tr><th>Node</th><th>Ready</th><th>Schedulable</th><th>GPU resources</th><th>GPU scheduling labels</th></tr>
                    </thead>
                    <tbody>
                      @for (node of gpuInventory().nodes; track node.name) {
                        <tr>
                          <td><strong>{{ node.name }}</strong></td>
                          <td><span [class]="node.ready ? 'label label-success' : 'label label-warning'">{{ node.ready ? 'Ready' : 'Not ready' }}</span></td>
                          <td>{{ node.schedulable ? 'Yes' : 'No' }}</td>
                          <td>
                            @if (node.gpuResources.length) {
                              <div class="ai-chip-list">
                                @for (resource of node.gpuResources; track resource.name) {
                                  <span [class]="resource.allocatableNumber > 0 ? 'label label-success' : 'label label-warning'">{{ resource.name }} {{ resource.allocatable }}/{{ resource.capacity }}</span>
                                }
                              </div>
                            } @else {
                              <span class="ai-footnote">No GPU extended resource exposed.</span>
                            }
                          </td>
                          <td>
                            @if (gpuLabelEntries(node.gpuLabels).length) {
                              <div class="ai-chip-list">
                                @for (label of gpuLabelEntries(node.gpuLabels); track label.key) {
                                  <span class="label label-info">{{ label.key }}={{ label.value }}</span>
                                }
                              </div>
                            } @else {
                              <span class="ai-footnote">No GPU scheduling label detected.</span>
                            }
                          </td>
                        </tr>
                      }
                    </tbody>
                  </table>
                  @if (gpuInventory().pluginDaemonSets.length || gpuInventory().pluginPods.length || gpuInventory().runtimeClasses.length) {
                    <table class="table table-compact ai-mini-table">
                      <thead>
                        <tr><th>Detected integration</th><th>Namespace</th><th>Phase</th><th>Detail</th></tr>
                      </thead>
                      <tbody>
                        @for (daemonSet of gpuInventory().pluginDaemonSets; track daemonSet.namespace + '/' + daemonSet.name) {
                          <tr><td>{{ daemonSet.name }}</td><td>{{ daemonSet.namespace }}</td><td>{{ daemonSet.phase }}</td><td>DaemonSet ready {{ daemonSet.ready }}/{{ daemonSet.desired }}</td></tr>
                        }
                        @for (pod of gpuInventory().pluginPods; track pod.namespace + '/' + pod.name) {
                          <tr><td>{{ pod.name }}</td><td>{{ pod.namespace }}</td><td>{{ pod.phase }}</td><td>Node {{ pod.nodeName || '-' }}</td></tr>
                        }
                        @for (runtimeClass of gpuInventory().runtimeClasses; track runtimeClass.name) {
                          <tr><td>{{ runtimeClass.name }}</td><td>-</td><td>RuntimeClass</td><td>{{ runtimeClass.handler }}</td></tr>
                        }
                      </tbody>
                    </table>
                  }
                  @if (gpuInventory().diagnostics.length) {
                    <h3 class="ai-panel-title">Diagnostic evidence</h3>
                    <table class="table table-compact ai-mini-table">
                      <thead>
                        <tr><th>Source</th><th>Severity</th><th>Diagnosis</th><th>Evidence</th><th>Next step</th></tr>
                      </thead>
                      <tbody>
                        @for (diagnostic of gpuInventory().diagnostics; track diagnostic.namespace + '/' + diagnostic.source + '/' + diagnostic.phase) {
                          <tr>
                            <td>
                              <strong>{{ diagnostic.source }}</strong>
                              <p class="ai-footnote">{{ diagnostic.kind }} - {{ diagnostic.namespace }}{{ diagnostic.nodeName ? ' - ' + diagnostic.nodeName : '' }}</p>
                            </td>
                            <td><span [class]="diagnostic.severity === 'Error' ? 'label label-danger' : diagnostic.severity === 'Warning' ? 'label label-warning' : 'label label-info'">{{ diagnostic.severity }}</span></td>
                            <td>
                              <span [class]="'label ' + statusClass(diagnostic.phase)">{{ diagnostic.phase }}</span>
                              <p class="ai-footnote">{{ diagnostic.message }}</p>
                            </td>
                            <td>
                              <div class="ai-evidence-stack">
                                @for (line of diagnostic.evidence; track line) {
                                  <code>{{ line }}</code>
                                }
                              </div>
                            </td>
                            <td>{{ diagnostic.nextStep }}</td>
                          </tr>
                        }
                      </tbody>
                    </table>
                  }
                  @if (!gpuInventory().ready) {
                    <h3 class="ai-panel-title">Next steps</h3>
                    <ul class="list">
                      @for (step of gpuInventory().nextSteps; track step) {
                        <li>{{ step }}</li>
                      }
                    </ul>
                  }
                </div>
              </div>
              <div class="card ai-action-panel ai-tab-hidden">
                <div class="card-header">
                  <div class="card-title">GPU enablement plan</div>
                </div>
                <div class="card-block">
                  <form clrForm clrLayout="compact" class="ai-gpu-config-form">
                    <clr-select-container>
                      <label>Usage option</label>
                      <select clrSelect name="gpuEnablementProfile" [value]="gpuEnablementProfile()" (change)="selectGpuEnablementProfile($any($event.target).value)">
                        <option value="nvidia">NVIDIA device plugin</option>
                        <option value="nvidia-operator">NVIDIA GPU Operator / OLM</option>
                        <option value="amd">AMD ROCm device plugin</option>
                        <option value="intel">Intel device plugin</option>
                        <option value="generic">OpenSphere generic GPU resource</option>
                        <option value="external">Generic external GPU endpoint</option>
                        <option value="docker-bridge">Local Docker GPU Bridge</option>
                        <option value="windows-service">Windows GPU Bridge Service</option>
                        <option value="windows-supervisor">Windows Supervisor + Docker/WSL2 worker</option>
                        <option value="wsl2">WSL2 GPU Bridge</option>
                        <option value="remote">Remote external GPU backend</option>
                        <option value="colab">Google Colab / notebook bridge</option>
                        <option value="cpu">CPU fallback</option>
                      </select>
                      <clr-control-helper>This changes the focused service form only. Workload routing decides runtime use.</clr-control-helper>
                    </clr-select-container>
                    <clr-input-container>
                      <label>Namespace</label>
                      <input clrInput name="gpuNamespace" [value]="gpuEnablementConfig().namespace" (input)="setGpuEnablementConfigField('namespace', $any($event.target).value)" />
                    </clr-input-container>
                    <clr-input-container>
                      <label>Resource name</label>
                      <input clrInput name="gpuResourceName" [value]="gpuEnablementConfig().resourceName" (input)="setGpuEnablementConfigField('resourceName', $any($event.target).value)" />
                    </clr-input-container>
                    @if (isDevicePluginMode()) {
                      <clr-input-container>
                        <label>Plugin image</label>
                        <input clrInput name="gpuPluginImage" [value]="gpuEnablementConfig().pluginImage" (input)="setGpuEnablementConfigField('pluginImage', $any($event.target).value)" />
                      </clr-input-container>
                      <clr-input-container>
                        <label>Node selector key</label>
                        <input clrInput name="gpuNodeSelectorKey" [value]="gpuEnablementConfig().nodeSelectorKey" (input)="setGpuEnablementConfigField('nodeSelectorKey', $any($event.target).value)" />
                      </clr-input-container>
                      <clr-input-container>
                        <label>Node selector value</label>
                        <input clrInput name="gpuNodeSelectorValue" [value]="gpuEnablementConfig().nodeSelectorValue" (input)="setGpuEnablementConfigField('nodeSelectorValue', $any($event.target).value)" />
                      </clr-input-container>
                    }
                    @if (isGpuOperatorMode()) {
                      <clr-input-container>
                        <label>Operator package</label>
                        <input clrInput name="gpuOperatorPackage" [value]="gpuEnablementConfig().packageName" (input)="setGpuEnablementConfigField('packageName', $any($event.target).value)" />
                      </clr-input-container>
                      <clr-input-container>
                        <label>Channel</label>
                        <input clrInput name="gpuOperatorChannel" [value]="gpuEnablementConfig().channel" (input)="setGpuEnablementConfigField('channel', $any($event.target).value)" />
                      </clr-input-container>
                      <clr-input-container>
                        <label>Catalog source</label>
                        <input clrInput name="gpuCatalogSource" [value]="gpuEnablementConfig().catalogSource" (input)="setGpuEnablementConfigField('catalogSource', $any($event.target).value)" />
                      </clr-input-container>
                      <clr-input-container>
                        <label>Catalog namespace</label>
                        <input clrInput name="gpuCatalogNamespace" [value]="gpuEnablementConfig().catalogNamespace" (input)="setGpuEnablementConfigField('catalogNamespace', $any($event.target).value)" />
                      </clr-input-container>
                    }
                    @if (isDevicePluginMode() || isGpuOperatorMode()) {
                      <clr-input-container>
                        <label>RuntimeClass</label>
                        <input clrInput name="gpuRuntimeClass" [value]="gpuEnablementConfig().runtimeClass" (input)="setGpuEnablementConfigField('runtimeClass', $any($event.target).value)" />
                      </clr-input-container>
                      <div class="ai-option-list">
                        <clr-checkbox-wrapper>
                          <input type="checkbox" clrCheckbox [checked]="gpuEnablementConfig().useRuntimeClass" (change)="setGpuEnablementConfigField('useRuntimeClass', $any($event.target).checked)" />
                          <label>Schedule Pods with runtimeClassName</label>
                        </clr-checkbox-wrapper>
                      </div>
                    }
                    @if (isExternalGpuMode()) {
                      <clr-input-container>
                        <label>{{ gpuEnablementProfile() === 'colab' ? 'Bridge endpoint' : 'Service endpoint' }}</label>
                        <input clrInput name="gpuExternalEndpoint" [value]="gpuEnablementConfig().externalEndpoint" (input)="setGpuEnablementConfigField('externalEndpoint', $any($event.target).value)" />
                        <clr-control-helper>{{ gpuEnablementProfile() === 'colab' ? 'OpenSphere bridge endpoint that can control a notebook runtime and report job status.' : 'Reachable compute service endpoint that implements the OAH bridge contract.' }}</clr-control-helper>
                      </clr-input-container>
                      <clr-input-container>
                        <label>Credential Secret</label>
                        <input clrInput name="gpuCredentialSecret" [value]="gpuEnablementConfig().credentialSecret" (input)="setGpuEnablementConfigField('credentialSecret', $any($event.target).value)" />
                      </clr-input-container>
                    }
                    @if (isExternalGpuMode() || isCpuFallbackMode()) {
                      <clr-input-container>
                        <label>Max concurrency</label>
                        <input clrInput type="number" min="1" name="gpuMaxConcurrency" [value]="gpuEnablementConfig().maxConcurrency" (input)="setGpuEnablementConfigField('maxConcurrency', $any($event.target).valueAsNumber || 1)" />
                      </clr-input-container>
                    }
                    <button type="button" class="btn btn-sm btn-outline" [disabled]="saving()" (click)="loadGpuEnablementPlan()">Refresh plan</button>
                  </form>
                  @if (gpuEnablementPlan()) {
                    <div class="ai-label-row ai-backend-summary">
                      <span [class]="'label ' + statusClass(gpuEnablementPlan()?.phase || 'Pending')">{{ gpuEnablementPlan()?.phase }}</span>
                      <span class="label label-info">{{ gpuEnablementPlan()?.mode }}</span>
                      <span class="label label-info">{{ gpuEnablementPlan()?.resourceName }}</span>
                      <span class="label label-info">{{ gpuEnablementPlan()?.namespace }}</span>
                      <span class="ai-footnote">Generated {{ gpuEnablementPlan()?.generatedAt || '-' }}</span>
                    </div>
                    <p class="ai-footnote">{{ gpuEnablementPlan()?.summary }}</p>
                    <table class="table table-compact ai-mini-table">
                      <thead>
                        <tr><th>Check</th><th>Status</th><th>Detail</th></tr>
                      </thead>
                      <tbody>
                        @for (check of gpuEnablementPlan()?.checks || []; track check.id) {
                          <tr>
                            <td><strong>{{ check.label }}</strong></td>
                            <td><span [class]="check.ready ? 'label label-success' : check.phase === 'Optional' ? 'label label-info' : 'label label-warning'">{{ check.phase }}</span></td>
                            <td>{{ check.detail }}</td>
                          </tr>
                        }
                      </tbody>
                    </table>
                    <table class="table table-compact ai-mini-table">
                      <thead>
                        <tr><th>Requirement</th></tr>
                      </thead>
                      <tbody>
                        @for (item of gpuEnablementPlan()?.prerequisites || []; track item.id) {
                          <tr><td>{{ item.text }}</td></tr>
                        }
                      </tbody>
                    </table>
                    <div class="ai-label-row ai-backend-summary">
                      <span class="label label-info">{{ gpuEnablementPlan()?.operator }}</span>
                      <a [href]="gpuEnablementPlan()?.upstream" target="_blank" rel="noreferrer">Upstream reference</a>
                    </div>
                    <table class="table table-compact ai-mini-table">
                      <thead>
                        <tr><th>Verification command</th></tr>
                      </thead>
                      <tbody>
                        @for (command of gpuEnablementPlan()?.commands || []; track command) {
                          <tr><td><code>{{ command }}</code></td></tr>
                        }
                      </tbody>
                    </table>
                    @if (gpuEnablementPlan()?.warnings?.length) {
                      <ul class="list">
                        @for (warning of gpuEnablementPlan()?.warnings || []; track warning) {
                          <li>{{ warning }}</li>
                        }
                      </ul>
                    }
                    @if (gpuEnablementPreview()) {
                      <pre class="ai-log-output">{{ gpuEnablementPreview() }}</pre>
                    }
                  }
                </div>
              </div>
              <div class="card ai-action-panel" [class.ai-tab-hidden]="clusterSettingsTab() !== 'demo'">
                <div class="card-header">
                  <div class="card-title">OAH lifecycle demo plan</div>
                </div>
                <div class="card-block">
                  <div class="ai-label-row ai-backend-summary">
                    <span [class]="'label ' + statusClass(oahDemoPlan().phase)">{{ oahDemoPlan().phase }}</span>
                    <span class="label label-info">{{ oahDemoPlan().tasks.length }} task(s)</span>
                    @for (item of oahDemoPlan().evidence; track item.label) {
                      <span class="label label-info">{{ item.label }} {{ item.value }}</span>
                    }
                    <span class="ai-footnote">Generated {{ oahDemoPlan().generatedAt || '-' }}</span>
                  </div>
                  <p class="ai-footnote">{{ oahDemoPlan().summary }}</p>
                  <form clrForm clrLayout="compact" class="ai-inline-form">
                    <clr-input-container>
                      <label>Demo namespace</label>
                      <input clrInput name="demoRunNamespace" [value]="demoRunNamespace()" (input)="demoRunNamespace.set($any($event.target).value)" />
                      <clr-control-helper>Demo resources are created or updated in this namespace.</clr-control-helper>
                    </clr-input-container>
                  </form>
                  <div class="ai-action-row">
                    <button type="button" class="btn btn-sm btn-outline" [disabled]="saving()" (click)="loadOahDemoRun()">Refresh demo run</button>
                    <button type="button" class="btn btn-sm btn-outline" [disabled]="saving()" (click)="previewOahDemoRun()">Preview manifests</button>
                    <button type="button" class="btn btn-sm btn-outline" [disabled]="saving() || oahDemoPreview()?.permission?.canReset === false" (click)="resetOahDemo()">Reset demo</button>
                    <button type="button" class="btn btn-sm btn-primary" [disabled]="saving() || oahDemoPreview()?.permission?.canRun === false" (click)="runOahDemo()">Run available demo</button>
                  </div>
                  @if (oahDemoPreview()) {
                    <div class="ai-label-row ai-backend-summary">
                      <span [class]="'label ' + statusClass(oahDemoPreview()?.phase || 'Pending')">{{ oahDemoPreview()?.phase }}</span>
                      <span class="label label-success">{{ oahDemoPreview()?.summary?.ready || 0 }} ready to apply</span>
                      <span class="label label-warning">{{ oahDemoPreview()?.summary?.blockedByGpu || 0 }} blocked by GPU</span>
                      <span class="label label-warning">{{ oahDemoPreview()?.summary?.blockedByCrd || 0 }} blocked by CRD</span>
                      <span class="label label-info">{{ oahDemoPreview()?.summary?.manifests || 0 }} manifest(s)</span>
                      <span [class]="oahDemoPreview()?.permission?.canRun ? 'label label-success' : 'label label-warning'">Run permission {{ oahDemoPreview()?.permission?.phase || 'Unknown' }}</span>
                    </div>
                    @if (oahDemoPreview()?.permission) {
                      <table class="table table-compact ai-mini-table">
                        <thead>
                          <tr><th>Permission</th><th>Required</th><th>Status</th><th>Detail</th></tr>
                        </thead>
                        <tbody>
                          @for (permission of oahDemoPreview()?.permission?.checks || []; track permission.id) {
                            <tr>
                              <td><strong>{{ permission.label }}</strong></td>
                              <td>{{ permission.required ? 'Required' : 'Reset only' }}</td>
                              <td><span [class]="permission.allowed ? 'label label-success' : permission.required ? 'label label-warning' : 'label label-info'">{{ permission.allowed ? 'Allowed' : 'Blocked' }}</span></td>
                              <td>{{ permission.detail }}</td>
                            </tr>
                          }
                        </tbody>
                      </table>
                    }
                    <table class="table table-compact ai-mini-table">
                      <thead>
                        <tr><th>Stage</th><th>Preview step</th><th>Kind</th><th>Phase</th><th>Message</th></tr>
                      </thead>
                      <tbody>
                        @for (check of oahDemoPreview()?.checks || []; track check.id || check.title) {
                          <tr>
                            <td>{{ check.stage }}</td>
                            <td><strong>{{ check.title }}</strong></td>
                            <td>{{ check.kind || check.page || '-' }}</td>
                            <td><span [class]="'label ' + statusClass(check.phase)">{{ check.phase }}</span></td>
                            <td>{{ check.message || check.reason || '-' }}</td>
                          </tr>
                        }
                      </tbody>
                    </table>
                  }
                  <div class="ai-label-row ai-backend-summary">
                    <span [class]="'label ' + statusClass(oahDemoRun().phase)">{{ oahDemoRun().phase }}</span>
                    <span class="label label-success">{{ oahDemoRun().summary.ready }} ready</span>
                    <span class="label label-info">{{ oahDemoRun().summary.actual }}/{{ oahDemoRun().summary.expected }} resources</span>
                    <span class="label label-info">{{ oahDemoRun().summary.created || 0 }} created</span>
                    <span class="label label-info">{{ oahDemoRun().summary.updated || 0 }} updated</span>
                    <span class="label label-warning">{{ oahDemoRun().summary.skipped || 0 }} skipped</span>
                    <span [class]="oahDemoRun().summary.failed ? 'label label-danger' : 'label label-success'">{{ oahDemoRun().summary.failed || 0 }} failed</span>
                    <span class="ai-footnote">Namespace {{ oahDemoRun().namespace || demoRunNamespace() }}</span>
                  </div>
                  <div class="ai-action-row">
                    <button type="button" class="btn btn-sm btn-outline" [disabled]="saving()" (click)="loadOahDemoEvidence()">Refresh evidence</button>
                  </div>
                  @if (oahDemoEvidence()) {
                    <div class="ai-label-row ai-backend-summary">
                      <span [class]="'label ' + statusClass(oahDemoEvidence()?.phase || 'Pending')">{{ oahDemoEvidence()?.phase }}</span>
                      <span class="label label-info">{{ oahDemoEvidence()?.summary?.visibleResources || 0 }}/{{ oahDemoEvidence()?.summary?.totalTasks || 0 }} visible</span>
                      <span class="label label-success">{{ oahDemoEvidence()?.summary?.readyResources || 0 }} ready</span>
                      <span class="label label-info">{{ oahDemoEvidence()?.summary?.runnableWithoutGpu || 0 }} runnable without GPU</span>
                      <span class="label label-warning">{{ oahDemoEvidence()?.summary?.blockedByGpu || 0 }} GPU blocked</span>
                      <span class="ai-footnote">Evidence {{ oahDemoEvidence()?.generatedAt || '-' }}</span>
                    </div>
                    <table class="table table-compact ai-mini-table">
                      <thead>
                        <tr><th>User task</th><th>Menu</th><th>Status</th><th>Evidence</th></tr>
                      </thead>
                      <tbody>
                        @for (action of oahDemoEvidence()?.userCanDo || []; track action.id) {
                          <tr>
                            <td><strong>{{ action.label }}</strong></td>
                            <td>{{ action.menu }}</td>
                            <td><span [class]="action.enabled ? 'label label-success' : 'label label-warning'">{{ action.enabled ? 'Available' : 'Blocked' }}</span></td>
                            <td>{{ action.evidence }}</td>
                          </tr>
                        }
                      </tbody>
                    </table>
                    @if (oahDemoEvidence()?.blockedActions?.length) {
                      <table class="table table-compact ai-mini-table">
                        <thead>
                          <tr><th>Blocked GPU task</th><th>Menu</th><th>Reason</th><th>Next step</th></tr>
                        </thead>
                        <tbody>
                          @for (blocked of oahDemoEvidence()?.blockedActions || []; track blocked.id) {
                            <tr>
                              <td><strong>{{ blocked.label }}</strong></td>
                              <td>{{ blocked.menu }}</td>
                              <td><span class="label label-warning">{{ blocked.reason }}</span></td>
                              <td>{{ blocked.nextStep }}</td>
                            </tr>
                          }
                        </tbody>
                      </table>
                    }
                    <table class="table table-compact ai-mini-table">
                      <thead>
                        <tr><th>Stage</th><th>Resource evidence</th><th>Menu</th><th>Kind</th><th>Phase</th><th>Message</th></tr>
                      </thead>
                      <tbody>
                        @for (row of oahDemoEvidence()?.evidence || []; track row.id) {
                          <tr>
                            <td>{{ row.stage }}</td>
                            <td>
                              <strong>{{ row.title }}</strong>
                              @if (row.requiresGpu) {
                                <span class="label label-warning">GPU</span>
                              }
                              <p class="ai-footnote">{{ row.resource }}</p>
                            </td>
                            <td>{{ row.menu }}</td>
                            <td>{{ row.kind }}</td>
                            <td><span [class]="'label ' + statusClass(row.phase)">{{ row.phase }}</span></td>
                            <td>{{ row.message }}</td>
                          </tr>
                        }
                      </tbody>
                    </table>
                  }
                  <h3 class="ai-panel-title">Executable smoke demo</h3>
                  <div class="ai-action-row">
                    <button type="button" class="btn btn-sm btn-outline" [disabled]="saving()" (click)="loadOahDemoSmoke()">Refresh smoke status</button>
                    <button type="button" class="btn btn-sm btn-outline" [disabled]="saving()" (click)="loadOahDemoSmokeLogs()">Load smoke output</button>
                    <button type="button" class="btn btn-sm btn-outline" [disabled]="saving()" (click)="previewOahDemoSmoke()">Preview smoke jobs</button>
                    <button type="button" class="btn btn-sm btn-primary" [disabled]="saving() || oahDemoSmokePreview()?.permission?.canRun === false" (click)="runOahDemoSmoke()">Run smoke demo</button>
                  </div>
                  @if (oahDemoSmokePreview()) {
                    <div class="ai-label-row ai-backend-summary">
                      <span [class]="'label ' + statusClass(oahDemoSmokePreview()?.phase || 'Pending')">{{ oahDemoSmokePreview()?.phase }}</span>
                      <span class="label label-success">{{ oahDemoSmokePreview()?.summary?.ready || 0 }} runnable</span>
                      <span class="label label-warning">{{ oahDemoSmokePreview()?.summary?.blockedByGpu || 0 }} GPU blocked</span>
                      <span class="label label-info">{{ oahDemoSmokePreview()?.summary?.manifests || 0 }} Job manifest(s)</span>
                      <span class="ai-footnote">Image {{ oahDemoSmokePreview()?.image || '-' }}</span>
                    </div>
                    <table class="table table-compact ai-mini-table">
                      <thead>
                        <tr><th>Permission</th><th>Required</th><th>Status</th><th>Detail</th></tr>
                      </thead>
                      <tbody>
                        @for (permission of oahDemoSmokePreview()?.permission?.checks || []; track permission.id) {
                          <tr>
                            <td><strong>{{ permission.label }}</strong></td>
                            <td>{{ permission.required ? 'Required' : 'Optional' }}</td>
                            <td><span [class]="permission.allowed ? 'label label-success' : permission.required ? 'label label-warning' : 'label label-info'">{{ permission.allowed ? 'Allowed' : 'Blocked' }}</span></td>
                            <td>{{ permission.detail }}</td>
                          </tr>
                        }
                      </tbody>
                    </table>
                    <table class="table table-compact ai-mini-table">
                      <thead>
                        <tr><th>Stage</th><th>Smoke job</th><th>GPU</th><th>Phase</th><th>Message</th></tr>
                      </thead>
                      <tbody>
                        @for (check of oahDemoSmokePreview()?.checks || []; track check.id) {
                          <tr>
                            <td>{{ check.stage }}</td>
                            <td><strong>{{ check.title }}</strong></td>
                            <td>{{ check.requiresGpu ? 'Required' : 'No' }}</td>
                            <td><span [class]="'label ' + statusClass(check.phase)">{{ check.phase }}</span></td>
                            <td>{{ check.message || check.reason || '-' }}</td>
                          </tr>
                        }
                      </tbody>
                    </table>
                  }
                  @if (oahDemoSmoke()) {
                    <div class="ai-label-row ai-backend-summary">
                      <span [class]="'label ' + statusClass(oahDemoSmoke()?.phase || 'Pending')">{{ oahDemoSmoke()?.phase }}</span>
                      <span class="label label-success">{{ oahDemoSmoke()?.summary?.succeeded || 0 }} succeeded</span>
                      <span class="label label-info">{{ oahDemoSmoke()?.summary?.running || 0 }} running</span>
                      <span class="label label-warning">{{ oahDemoSmoke()?.summary?.notStarted || 0 }} not started</span>
                      <span [class]="oahDemoSmoke()?.summary?.failed ? 'label label-danger' : 'label label-success'">{{ oahDemoSmoke()?.summary?.failed || 0 }} failed</span>
                      <span class="label label-warning">{{ oahDemoSmoke()?.summary?.gpuBlocked || 0 }} GPU blocked</span>
                      <span class="ai-footnote">Smoke {{ oahDemoSmoke()?.generatedAt || '-' }}</span>
                    </div>
                    <table class="table table-compact ai-mini-table">
                      <thead>
                        <tr><th>Stage</th><th>Job</th><th>GPU</th><th>Phase</th><th>Pods</th><th>Message</th></tr>
                      </thead>
                      <tbody>
                        @for (item of oahDemoSmoke()?.items || []; track item.id) {
                          <tr>
                            <td>{{ item.stage }}</td>
                            <td>
                              <strong>{{ item.title }}</strong>
                              <p class="ai-footnote">{{ item.namespace || demoRunNamespace() }}/{{ item.name }}</p>
                            </td>
                            <td>{{ item.requiresGpu ? 'Required' : 'No' }}</td>
                            <td><span [class]="'label ' + statusClass(item.phase)">{{ item.phase }}</span></td>
                            <td>{{ item.active || 0 }}/{{ item.succeeded || 0 }}/{{ item.failed || 0 }}</td>
                            <td>{{ item.message || item.reason || '-' }}</td>
                          </tr>
                        }
                      </tbody>
                    </table>
                  }
                  @if (oahDemoSmokeLogs()) {
                    <div class="ai-label-row ai-backend-summary">
                      <span [class]="'label ' + statusClass(oahDemoSmokeLogs()?.phase || 'Pending')">{{ oahDemoSmokeLogs()?.phase }}</span>
                      <span class="label label-success">{{ oahDemoSmokeLogs()?.summary?.withLogs || 0 }} job(s) with logs</span>
                      <span class="label label-info">{{ oahDemoSmokeLogs()?.summary?.records || 0 }} parsed record(s)</span>
                      <span class="label label-info">{{ oahDemoSmokeLogs()?.summary?.lines || 0 }} line(s)</span>
                      <span class="ai-footnote">Output {{ oahDemoSmokeLogs()?.generatedAt || '-' }}</span>
                    </div>
                    <table class="table table-compact ai-mini-table">
                      <thead>
                        <tr><th>Stage</th><th>Job output</th><th>Pod</th><th>Phase</th><th>Latest line</th></tr>
                      </thead>
                      <tbody>
                        @for (log of oahDemoSmokeLogs()?.items || []; track log.id) {
                          <tr>
                            <td>{{ log.stage }}</td>
                            <td>
                              <strong>{{ log.title }}</strong>
                              @if (log.requiresGpu) {
                                <span class="label label-warning">GPU</span>
                              }
                              <p class="ai-footnote">{{ log.jobName }}</p>
                            </td>
                            <td>{{ log.pod || '-' }}</td>
                            <td><span [class]="'label ' + statusClass(log.phase)">{{ log.phase }}</span></td>
                            <td><code>{{ log.lines.length ? log.lines[log.lines.length - 1] : log.message }}</code></td>
                          </tr>
                        }
                      </tbody>
                    </table>
                  }
                  @if (smokeManifestPreview()) {
                    <pre class="ai-log-output">{{ smokeManifestPreview() }}</pre>
                  }
                  @if (smokeLogPreview()) {
                    <pre class="ai-log-output">{{ smokeLogPreview() }}</pre>
                  }
                  @if (oahDemoRun().registry) {
                    <p class="ai-footnote">Model registry: {{ oahDemoRun().registry?.phase }} {{ oahDemoRun().registry?.version?.name || '' }} {{ oahDemoRun().registry?.version?.version || '' }}</p>
                  }
                  @if (oahDemoRun().results?.length) {
                    <table class="table table-compact ai-mini-table">
                      <thead>
                        <tr><th>Stage</th><th>Demo step</th><th>Kind</th><th>Phase</th><th>Message</th></tr>
                      </thead>
                      <tbody>
                        @for (result of oahDemoRun().results; track result.id || result.step || result.title) {
                          <tr>
                            <td>{{ result.stage }}</td>
                            <td><strong>{{ result.title }}</strong></td>
                            <td>{{ result.item?.kind || result.kind || result.page || '-' }}</td>
                            <td><span [class]="'label ' + statusClass(result.phase)">{{ result.phase }}</span></td>
                            <td>{{ result.message || result.reason || result.item?.message || '-' }}</td>
                          </tr>
                        }
                      </tbody>
                    </table>
                  }
                  @if (demoManifestPreview()) {
                    <pre class="ai-log-output">{{ demoManifestPreview() }}</pre>
                  }
                  <table class="table table-compact ai-mini-table">
                    <thead>
                      <tr><th>Prerequisite</th><th>Required</th><th>Status</th><th>Detail</th></tr>
                    </thead>
                    <tbody>
                      @for (prereq of oahDemoPlan().prerequisites; track prereq.id) {
                        <tr>
                          <td><strong>{{ prereq.label }}</strong></td>
                          <td>{{ prereq.required ? 'Required' : 'Optional' }}</td>
                          <td><span [class]="prereq.ready ? 'label label-success' : prereq.required ? 'label label-warning' : 'label label-info'">{{ prereq.ready ? 'Ready' : 'Not ready' }}</span></td>
                          <td>{{ prereq.detail }}</td>
                        </tr>
                      }
                    </tbody>
                  </table>
                  <table class="table table-compact ai-mini-table">
                    <thead>
                      <tr><th>Stage</th><th>Task</th><th>OAH area</th><th>Resources</th><th>Status</th><th>Expected result</th></tr>
                    </thead>
                    <tbody>
                      @for (task of oahDemoPlan().tasks; track task.id) {
                        <tr>
                          <td>{{ task.stage }}</td>
                          <td>
                            <strong>{{ task.title }}</strong>
                            @if (task.requiresGpu) {
                              <span class="label label-warning">GPU</span>
                            }
                          </td>
                          <td>{{ task.oahArea }}</td>
                          <td>{{ task.resources.join(', ') }}</td>
                          <td><span [class]="'label ' + statusClass(task.status)">{{ task.status }}</span></td>
                          <td>{{ task.expected }}</td>
                        </tr>
                      }
                    </tbody>
                  </table>
                </div>
              </div>
              <div class="card ai-action-panel" [class.ai-tab-hidden]="clusterSettingsTab() !== 'operations'">
                <div class="card-header">
                  <div class="card-title">Controller metrics</div>
                </div>
                <div class="card-block">
                  <div class="ai-label-row ai-backend-summary">
                    <span [class]="controllerMetrics().summary.failures ? 'label label-danger' : 'label label-success'">{{ controllerMetrics().summary.failures }} current failures</span>
                    <span class="label label-warning">{{ controllerMetrics().summary.historicalFailures || 0 }} historical failures</span>
                    <span class="label label-info">{{ controllerMetrics().summary.reconciles }} reconciles</span>
                    <span class="label label-success">{{ controllerMetrics().summary.events }} events</span>
                    <span class="ai-footnote">Source {{ controllerMetrics().source || 'process' }} - started {{ controllerMetrics().startedAt || '-' }}</span>
                  </div>
                  <table class="table table-compact ai-mini-table">
                    <thead>
                      <tr><th>Controller</th><th>Phase</th><th>Backend</th><th>Total</th><th>Current failures</th><th>Historical</th><th>Avg ms</th><th>Last</th><th>Last at</th></tr>
                    </thead>
                    <tbody>
                      @for (metric of controllerMetrics().items; track metric.controller + metric.phase + metric.backend) {
                        <tr>
                          <td>{{ metric.controller }}</td>
                          <td><span [class]="'label ' + statusClass(metric.phase)">{{ metric.phase }}</span></td>
                          <td>{{ metric.backend }}</td>
                          <td>{{ metric.total }}</td>
                          <td><span [class]="metric.failures ? 'label label-danger' : 'label label-success'">{{ metric.failures }}</span></td>
                          <td><span [class]="metric.historicalFailures ? 'label label-warning' : 'label label-success'">{{ metric.historicalFailures || 0 }}</span></td>
                          <td>{{ metric.avgDurationMs }}</td>
                          <td>{{ metric.lastName || '-' }}</td>
                          <td>{{ metric.lastAt || '-' }}</td>
                        </tr>
                      }
                    </tbody>
                  </table>
                  @if (!controllerMetrics().items.length) {
                    <p class="ai-footnote">No controller metrics have been collected yet.</p>
                  }
                </div>
              </div>
              <div class="card ai-action-panel" [class.ai-tab-hidden]="clusterSettingsTab() !== 'operations'">
                <div class="card-header">
                  <div class="card-title">Controller audit log</div>
                </div>
                <div class="card-block">
                  <div class="ai-label-row ai-backend-summary">
                    <span class="label label-info">{{ auditLog().summary.total }} entries</span>
                    <span class="label label-success">{{ auditLog().summary.activeEntries || 0 }} active</span>
                    <span class="label label-warning">{{ auditLog().summary.historicalEntries || 0 }} historical</span>
                    <span class="label label-info">{{ auditLog().summary.systemEntries || 0 }} system</span>
                    <span [class]="auditLog().summary.activeWarnings ? 'label label-warning' : 'label label-success'">{{ auditLog().summary.activeWarnings || 0 }} active warnings</span>
                    <span class="label label-warning">{{ auditLog().summary.historicalWarnings || 0 }} historical warnings</span>
                    <span class="label label-info">{{ auditLog().summary.systemWarnings || 0 }} system warnings</span>
                    <span class="ai-footnote">{{ auditLog().summary.namespaces }} namespaces, {{ auditLog().summary.kinds }} kinds</span>
                  </div>
                  <form clrForm clrLayout="compact" class="ai-inline-form">
                    <clr-select-container>
                      <label>State filter</label>
                      <select clrSelect name="auditStateFilter" [value]="auditStateFilter()" (change)="auditStateFilter.set($any($event.target).value)">
                        <option value="all">All states</option>
                        <option value="active">Active resources</option>
                        <option value="historical">Historical resources</option>
                        <option value="system">System events</option>
                      </select>
                      <clr-control-helper>{{ filteredAuditEntries().length }} matching entries</clr-control-helper>
                    </clr-select-container>
                  </form>
                  <table class="table table-compact ai-mini-table">
                    <thead>
                      <tr><th>Time</th><th>Object</th><th>Resource state</th><th>Phase</th><th>Reason</th><th>Message</th></tr>
                    </thead>
                    <tbody>
                      @for (entry of filteredAuditEntries().slice(0, 8); track entry.id) {
                        <tr>
                          <td>{{ entry.time }}</td>
                          <td>{{ entry.kind }}/{{ entry.name }}</td>
                          <td><span [class]="entry.resourceState === 'active' ? 'label label-success' : entry.resourceState === 'historical' ? 'label label-warning' : 'label label-info'">{{ entry.resourceState || 'system' }}</span></td>
                          <td><span [class]="'label ' + statusClass(entry.phase)">{{ entry.phase }}</span></td>
                          <td>{{ entry.reason }}</td>
                          <td>{{ entry.message }}</td>
                        </tr>
                      }
                    </tbody>
                  </table>
                  @if (!auditLog().items.length) {
                    <p class="ai-footnote">No durable audit log entries have been recorded yet.</p>
                  }
                  @if (auditLog().items.length && !filteredAuditEntries().length) {
                    <p class="ai-footnote">No audit log entries match the selected state.</p>
                  }
                </div>
              </div>
            }
            @if (activePage() === 'training-jobs' && externalTrainingEvidence().length) {
              <section class="card ai-action-panel" aria-label="External GPU training evidence">
                <div class="card-header">
                  <div class="card-title">External GPU training evidence</div>
                </div>
                <div class="card-block">
                  <table class="table table-compact ai-mini-table">
                    <thead>
                      <tr><th>Training job</th><th>Bridge job</th><th>Backend</th><th>Endpoint</th><th>Resource</th><th>Result</th><th>Latest log</th></tr>
                    </thead>
                    <tbody>
                      @for (item of externalTrainingEvidence(); track item.namespace + '/' + item.name) {
                        <tr>
                          <td>
                            <strong>{{ item.name }}</strong>
                            <p class="ai-footnote">{{ item.namespace }}</p>
                          </td>
                          <td>
                            <strong>{{ $any(item.externalJob)?.jobId || $any(item.externalJob)?.id || '-' }}</strong>
                            <p class="ai-footnote">{{ $any(item.externalJob)?.jobType || 'smoke' }}</p>
                          </td>
                          <td>
                            <span class="label label-info">{{ item.backendType || 'external' }}</span>
                            @if (item.provider) {
                              <span class="label label-info">{{ item.provider }}</span>
                            }
                          </td>
                          <td>{{ item.endpoint || '-' }}</td>
                          <td>{{ item.resourceName || '-' }}</td>
                          <td>
                            <span [class]="'label ' + statusClass(item.phase)">{{ item.phase }}</span>
                            <p class="ai-footnote">{{ $any(item.externalJob)?.summary || item.message || '-' }}</p>
                          </td>
                          <td>
                            <code>{{ externalJobLogLine(item) || '-' }}</code>
                            @if (item.externalJobLogSummary?.gpu) {
                              <p class="ai-footnote">{{ item.externalJobLogSummary.gpu }}</p>
                            }
                            @if (item.externalJobLogSummary?.usage) {
                              <p class="ai-footnote">{{ item.externalJobLogSummary.usage }}</p>
                            }
                          </td>
                        </tr>
                      }
                    </tbody>
                  </table>
                </div>
              </section>
            }
            @if (loadingResource()) {
              <clr-alert clrAlertType="info" [clrAlertClosable]="false">
                <clr-alert-item>
                  <span class="alert-text">Loading data from OpenSphere AI Hub APIs...</span>
                </clr-alert-item>
              </clr-alert>
            } @else {
              <clr-datagrid>
                <clr-dg-column>Name</clr-dg-column>
                <clr-dg-column>Kind</clr-dg-column>
                <clr-dg-column>Namespace</clr-dg-column>
                <clr-dg-column>Source</clr-dg-column>
                @if (usesComputeBackend()) {
                  <clr-dg-column>Backend</clr-dg-column>
                }
                <clr-dg-column>Phase</clr-dg-column>
                <clr-dg-column>Detail</clr-dg-column>
                <clr-dg-column>Ready</clr-dg-column>
                <clr-dg-column>Actions</clr-dg-column>

                @for (item of resourceItems(); track item.kind + ':' + item.name) {
                  <clr-dg-row>
                    <clr-dg-cell>{{ item.name }}</clr-dg-cell>
                    <clr-dg-cell>{{ item.kind }}</clr-dg-cell>
                    <clr-dg-cell>{{ item.namespace || '-' }}</clr-dg-cell>
                    <clr-dg-cell><span [class]="sourceClass(item)">{{ sourceLabel(item) }}</span></clr-dg-cell>
                    @if (usesComputeBackend()) {
                      <clr-dg-cell>
                        <span class="label label-info">{{ computeBackendLabel(item) }}</span>
                        @if (item.computeRoutingWorkload) {
                          <p class="ai-footnote">{{ item.computeRoutingWorkload }} route</p>
                        }
                      </clr-dg-cell>
                    }
                    <clr-dg-cell><span [class]="'label ' + statusClass(item.phase)">{{ item.phase }}</span></clr-dg-cell>
                    <clr-dg-cell>{{ resourceDetail(item) }}</clr-dg-cell>
                    <clr-dg-cell>{{ item.ready ? 'Ready' : 'Not ready' }}</clr-dg-cell>
                    <clr-dg-cell>
                      @if (activePage() === 'workbenches') {
                        <button type="button" class="btn btn-sm btn-link" [disabled]="saving()" (click)="loadWorkbenchDetail(item)">Details</button>
                        <button type="button" class="btn btn-sm btn-link" [disabled]="saving()" (click)="workbenchAction(item, 'start')">Start</button>
                        <button type="button" class="btn btn-sm btn-link" [disabled]="saving()" (click)="workbenchAction(item, 'stop')">Stop</button>
                      }
                      @if (activePage() === 'data-connections') {
                        <button type="button" class="btn btn-sm btn-link" [disabled]="saving()" (click)="loadDataConnectionDetail(item)">Details</button>
                      }
                      @if (activePage() === 'pipelines') {
                        <button type="button" class="btn btn-sm btn-link" [disabled]="saving()" (click)="loadPipelineDetail(item)">Details</button>
                        <button type="button" class="btn btn-sm btn-link" [disabled]="saving()" (click)="runPipeline(item)">Run</button>
                      }
                      @if (activePage() === 'pipeline-runs') {
                        <button type="button" class="btn btn-sm btn-link" [disabled]="saving()" (click)="loadPipelineDetail(item)">Details</button>
                        <button type="button" class="btn btn-sm btn-link" [disabled]="saving()" (click)="loadPipelineLogs(item)">Logs</button>
                        <button type="button" class="btn btn-sm btn-link" [disabled]="saving()" (click)="loadPipelineLineage(item)">Lineage</button>
                        <button type="button" class="btn btn-sm btn-link" [disabled]="saving()" (click)="claimAction(item, 'retry')">Retry</button>
                      }
                      @if (activePage() === 'training-jobs' || activePage() === 'eval-jobs') {
                        <button type="button" class="btn btn-sm btn-link" [disabled]="saving()" (click)="claimAction(item, 'retry')">Retry</button>
                        <button type="button" class="btn btn-sm btn-link" [disabled]="saving()" (click)="claimAction(item, 'suspend')">Suspend</button>
                      }
                      @if (activePage() === 'model-promotion') {
                        <button type="button" class="btn btn-sm btn-link" [disabled]="saving()" (click)="claimAction(item, 'approve')">Approve</button>
                        <button type="button" class="btn btn-sm btn-link" [disabled]="saving()" (click)="claimAction(item, 'reject')">Reject</button>
                      }
                      @if (activePage() === 'distributed-workloads') {
                        <button type="button" class="btn btn-sm btn-link" [disabled]="saving()" (click)="claimAction(item, 'suspend')">Suspend</button>
                        <button type="button" class="btn btn-sm btn-link" [disabled]="saving()" (click)="claimAction(item, 'resume')">Resume</button>
                      }
                      @if (activePage() === 'inference') {
                        <button type="button" class="btn btn-sm btn-link" [disabled]="saving()" (click)="loadInferenceDetail(item)">Details</button>
                        <button type="button" class="btn btn-sm btn-link" [disabled]="saving()" (click)="editInferenceFrom(item)">Edit</button>
                      }
                      <button type="button" class="btn btn-sm btn-link" [disabled]="saving() || !canDelete(item)" (click)="deleteResource(item)">Delete</button>
                    </clr-dg-cell>
                  </clr-dg-row>
                }

                @if (!resourceItems().length) {
                  <clr-dg-placeholder>No items returned for this view.</clr-dg-placeholder>
                }

              </clr-datagrid>
              @if (activePage() === 'data-connections' && dataConnectionDetail()) {
                <section class="card ai-action-panel">
                  <div class="card-header">
                    <div class="card-title">Data connection detail</div>
                  </div>
                  <div class="card-block">
                    <div class="ai-label-row">
                      <span class="label label-info">{{ dataConnectionDetail()?.item?.namespace }}/{{ dataConnectionDetail()?.item?.name }}</span>
                      <span [class]="sourceClass(dataConnectionDetail()?.item || {})">{{ sourceLabel(dataConnectionDetail()?.item || {}) }}</span>
                      <span [class]="'label ' + statusClass(dataConnectionDetail()?.item?.phase || '')">{{ dataConnectionDetail()?.item?.phase || '-' }}</span>
                      <span class="label label-info">Secret masked</span>
                    </div>
                    <div class="ai-kv-grid">
                      <div><span>Provider</span><strong>{{ dataConnectionDetail()?.provider || '-' }}</strong></div>
                      <div><span>Endpoint</span><strong>{{ dataConnectionDetail()?.endpoint || '-' }}</strong></div>
                      <div><span>Database/Bucket</span><strong>{{ dataConnectionDetail()?.database || '-' }}</strong></div>
                      <div><span>Owner</span><strong>{{ dataConnectionDetail()?.owner || '-' }}</strong></div>
                      <div><span>Secret</span><strong>{{ dataConnectionDetail()?.secret?.namespace }}/{{ dataConnectionDetail()?.secret?.name || '-' }}</strong></div>
                      <div><span>Secret type</span><strong>{{ dataConnectionDetail()?.secret?.type || '-' }}</strong></div>
                    </div>
                    <p class="ai-footnote">{{ dataConnectionDetail()?.secret?.message || 'Credential values are not displayed.' }}</p>
                    @if (dataConnectionDetail()?.secret?.keys?.length) {
                      <div class="ai-label-row">
                        @for (key of dataConnectionDetail()?.secret?.keys || []; track key) {
                          <span class="label label-info">{{ key }}</span>
                        }
                      </div>
                    }
                    @if (dataConnectionDetail()?.usage?.length) {
                      <table class="table table-compact ai-mini-table">
                        <thead>
                          <tr><th>Using resource</th><th>Kind</th><th>Phase</th><th>Ready</th></tr>
                        </thead>
                        <tbody>
                          @for (usage of dataConnectionDetail()?.usage || []; track usage.kind + ':' + usage.name) {
                            <tr>
                              <td>{{ usage.namespace }}/{{ usage.name }}</td>
                              <td>{{ usage.kind }}</td>
                              <td>{{ usage.phase || '-' }}</td>
                              <td>{{ usage.ready ? 'Ready' : 'Not ready' }}</td>
                            </tr>
                          }
                        </tbody>
                      </table>
                    }
                    @if (dataConnectionDetail()?.conditions?.length) {
                      <table class="table table-compact ai-mini-table">
                        <thead>
                          <tr><th>Condition</th><th>Status</th><th>Reason</th><th>Message</th></tr>
                        </thead>
                        <tbody>
                          @for (condition of dataConnectionDetail()?.conditions || []; track condition.type + condition.reason) {
                            <tr><td>{{ condition.type }}</td><td>{{ condition.status }}</td><td>{{ condition.reason || '-' }}</td><td>{{ condition.message || '-' }}</td></tr>
                          }
                        </tbody>
                      </table>
                    }
                  </div>
                </section>
              }
              @if (activePage() === 'workbenches' && workbenchDetail()) {
                <section class="card ai-action-panel">
                  <div class="card-header">
                    <div class="card-title">Workbench runtime detail</div>
                  </div>
                  <div class="card-block">
                    <div class="ai-label-row">
                      <span class="label label-info">{{ workbenchDetail()?.item?.namespace }}/{{ workbenchDetail()?.item?.name }}</span>
                      <span [class]="sourceClass(workbenchDetail()?.item || {})">{{ sourceLabel(workbenchDetail()?.item || {}) }}</span>
                      <span [class]="'label ' + statusClass(workbenchDetail()?.item?.phase || '')">{{ workbenchDetail()?.item?.phase || '-' }}</span>
                    </div>
                    <div class="ai-kv-grid">
                      <div><span>Runtime</span><strong>{{ workbenchDetail()?.runtime?.name || '-' }}</strong></div>
                      <div><span>Image</span><strong>{{ workbenchDetail()?.runtime?.image || '-' }}</strong></div>
                      <div><span>Open URL</span><strong>{{ workbenchDetail()?.runtime?.proxyUrl || workbenchDetail()?.runtime?.openUrl || '-' }}</strong></div>
                      <div><span>Storage</span><strong>{{ workbenchDetail()?.storage?.name || '-' }}</strong></div>
                    </div>
                    <div class="ai-label-row">
                      <button type="button" class="btn btn-sm btn-primary" [disabled]="saving() || !workbenchDetail()?.runtime?.proxyUrl" (click)="openWorkbenchProxy()">Open</button>
                      <span [class]="workbenchDetail()?.runtime?.reachability?.ready ? 'label label-success' : 'label label-warning'">{{ workbenchDetail()?.runtime?.reachability?.phase || 'Unchecked' }}</span>
                      <span class="ai-footnote">{{ workbenchDetail()?.runtime?.reachability?.message || 'Workbench reachability has not been checked.' }}</span>
                    </div>
                    <table class="table table-compact ai-mini-table">
                      <thead>
                        <tr><th>Object</th><th>Name</th><th>Phase</th><th>Ready</th><th>Message</th></tr>
                      </thead>
                      <tbody>
                        @for (obj of workbenchRuntimeObjects(); track obj.kind + ':' + obj.name) {
                          <tr>
                            <td>{{ obj.kind }}</td>
                            <td>{{ obj.name }}</td>
                            <td>{{ obj.phase || '-' }}</td>
                            <td>{{ obj.ready ? 'Ready' : 'Not ready' }}</td>
                            <td>{{ obj.message || '-' }}</td>
                          </tr>
                        }
                        @for (pod of workbenchDetail()?.pods || []; track pod.name) {
                          <tr>
                            <td>Pod</td>
                            <td>{{ pod.name }}</td>
                            <td>{{ pod.phase || '-' }}</td>
                            <td>{{ pod.ready ? 'Ready' : 'Not ready' }}</td>
                            <td>{{ pod.message || '-' }}</td>
                          </tr>
                        }
                      </tbody>
                    </table>
                    @if (workbenchDetail()?.events?.length) {
                      <div class="ai-log-block">
                        @for (event of workbenchDetail()?.events || []; track event.time + event.reason) {
                          <code>{{ event.time }} {{ event.type }} {{ event.reason }} - {{ event.message }}</code>
                        }
                      </div>
                    }
                    @if (workbenchDetail()?.logs?.tailLines?.length) {
                      <div class="ai-log-block">
                        @for (line of workbenchDetail()?.logs?.tailLines || []; track $index) {
                          <code>{{ line }}</code>
                        }
                      </div>
                    }
                  </div>
                </section>
              }
              @if ((activePage() === 'pipelines' || activePage() === 'pipeline-runs') && pipelineDetail()) {
                <section class="card ai-action-panel">
                  <div class="card-header">
                    <div class="card-title">Pipeline detail</div>
                  </div>
                  <div class="card-block">
                    <div class="ai-label-row">
                      <span class="label label-info">{{ pipelineDetail()?.item?.namespace }}/{{ pipelineDetail()?.item?.name }}</span>
                      <span [class]="sourceClass(pipelineDetail()?.item || {})">{{ sourceLabel(pipelineDetail()?.item || {}) }}</span>
                      <span [class]="'label ' + statusClass(pipelineDetail()?.item?.phase || '')">{{ pipelineDetail()?.item?.phase || '-' }}</span>
                    </div>
                    <div class="ai-kv-grid">
                      <div><span>Pipeline</span><strong>{{ pipelineDetail()?.pipelineName || '-' }}</strong></div>
                      <div><span>Version</span><strong>{{ pipelineDetail()?.definition?.version || '-' }}</strong></div>
                      <div><span>Backend</span><strong>{{ pipelineDetail()?.backendMode || '-' }}</strong></div>
                      <div><span>Source</span><strong>{{ pipelineDetail()?.definition?.source || '-' }}</strong></div>
                    </div>
                    <div class="ai-label-row">
                      <span class="label label-info">{{ pipelineDetail()?.runs?.length || 0 }} runs</span>
                      <span class="label label-info">{{ pipelineDetail()?.experiments?.length || 0 }} experiments</span>
                      <span class="label label-info">{{ pipelineDetail()?.artifacts?.length || 0 }} artifacts</span>
                      <span class="label label-info">{{ pipelineDetail()?.lineage?.length || 0 }} lineage edges</span>
                    </div>
                    @if (pipelineDetail()?.lineage?.length) {
                      <table class="table table-compact ai-mini-table">
                        <thead>
                          <tr><th>From</th><th>To</th><th>Type</th></tr>
                        </thead>
                        <tbody>
                          @for (edge of pipelineDetail()?.lineage || []; track edge.from + edge.to + edge.type) {
                            <tr><td>{{ edge.from }}</td><td>{{ edge.to }}</td><td>{{ edge.type }}</td></tr>
                          }
                        </tbody>
                      </table>
                    }
                    @if (pipelineDetail()?.logs?.length) {
                      <div class="ai-log-block">
                        @for (line of pipelineDetail()?.logs || []; track $index) {
                          <code>{{ line }}</code>
                        }
                      </div>
                    }
                  </div>
                </section>
              }
              @if (activePage() === 'inference' && inferenceDetail()) {
                <section class="card ai-action-panel">
                  <div class="card-header">
                    <div class="card-title">Model deployment detail</div>
                  </div>
                  <div class="card-block">
                    <div class="ai-label-row">
                      <span class="label label-info">{{ inferenceDetail()?.item?.namespace }}/{{ inferenceDetail()?.item?.name }}</span>
                      <span [class]="sourceClass(inferenceDetail()?.item || {})">{{ sourceLabel(inferenceDetail()?.item || {}) }}</span>
                      <span [class]="'label ' + statusClass(inferenceDetail()?.item?.phase || '')">{{ inferenceDetail()?.item?.phase || '-' }}</span>
                      <span [class]="inferenceDetail()?.runtime?.reachability?.ready ? 'label label-success' : 'label label-warning'">{{ inferenceDetail()?.runtime?.reachability?.phase || 'Unchecked' }}</span>
                    </div>
                    <div class="ai-kv-grid">
                      <div><span>Model</span><strong>{{ inferenceDetail()?.runtime?.modelName || '-' }}</strong></div>
                      <div><span>Runtime</span><strong>{{ inferenceDetail()?.runtime?.runtime || '-' }}</strong></div>
                      <div><span>Backend</span><strong>{{ inferenceDetail()?.runtime?.backendMode || '-' }}</strong></div>
                      <div><span>Runtime object</span><strong>{{ inferenceDetail()?.runtime?.name || '-' }}</strong></div>
                      <div><span>URL</span><strong>{{ inferenceDetail()?.runtime?.url || '-' }}</strong></div>
                      <div><span>Predict URL</span><strong>{{ inferenceDetail()?.runtime?.predictUrl || '-' }}</strong></div>
                      <div><span>Model URI</span><strong>{{ inferenceDetail()?.runtime?.modelUri || '-' }}</strong></div>
                      <div><span>Image</span><strong>{{ inferenceDetail()?.runtime?.image || '-' }}</strong></div>
                    </div>
                    <p class="ai-footnote">{{ inferenceDetail()?.runtime?.reachability?.message || 'Inference reachability has not been checked.' }}</p>
                    <table class="table table-compact ai-mini-table">
                      <thead>
                        <tr><th>Object</th><th>Name</th><th>Phase</th><th>Ready</th><th>Message</th></tr>
                      </thead>
                      <tbody>
                        @for (obj of inferenceRuntimeObjects(); track obj.kind + ':' + obj.name) {
                          <tr>
                            <td>{{ obj.kind }}</td>
                            <td>{{ obj.name }}</td>
                            <td>{{ obj.phase || '-' }}</td>
                            <td>{{ obj.ready ? 'Ready' : 'Not ready' }}</td>
                            <td>{{ obj.message || '-' }}</td>
                          </tr>
                        }
                        @for (pod of inferenceDetail()?.pods || []; track pod.name) {
                          <tr>
                            <td>Pod</td>
                            <td>{{ pod.name }}</td>
                            <td>{{ pod.phase || '-' }}</td>
                            <td>{{ pod.ready ? 'Ready' : 'Not ready' }}</td>
                            <td>{{ pod.message || '-' }}</td>
                          </tr>
                        }
                      </tbody>
                    </table>
                    @if (inferenceDetail()?.conditions?.length || inferenceDetail()?.upstreamConditions?.length) {
                      <table class="table table-compact ai-mini-table">
                        <thead>
                          <tr><th>Condition</th><th>Status</th><th>Reason</th><th>Message</th></tr>
                        </thead>
                        <tbody>
                          @for (condition of inferenceDetail()?.conditions || []; track condition.type + condition.reason) {
                            <tr><td>{{ condition.type }}</td><td>{{ condition.status }}</td><td>{{ condition.reason || '-' }}</td><td>{{ condition.message || '-' }}</td></tr>
                          }
                          @for (condition of inferenceDetail()?.upstreamConditions || []; track condition.type + condition.reason) {
                            <tr><td>{{ condition.type }}</td><td>{{ condition.status }}</td><td>{{ condition.reason || '-' }}</td><td>{{ condition.message || '-' }}</td></tr>
                          }
                        </tbody>
                      </table>
                    }
                    @if (inferenceDetail()?.events?.length) {
                      <div class="ai-log-block">
                        @for (event of inferenceDetail()?.events || []; track event.time + event.reason) {
                          <code>{{ event.time }} {{ event.type }} {{ event.reason }} - {{ event.message }}</code>
                        }
                      </div>
                    }
                    @if (inferenceDetail()?.logs?.tailLines?.length) {
                      <div class="ai-log-block">
                        @for (line of inferenceDetail()?.logs?.tailLines || []; track $index) {
                          <code>{{ line }}</code>
                        }
                      </div>
                    }
                  </div>
                </section>
              }
            }
          </section>
        }

        <clr-modal [clrModalOpen]="createOpen()" (clrModalOpenChange)="createOpen.set($event)">
          <h3 class="modal-title">Create {{ createLabel() }}</h3>
          <div class="modal-body">
            <form clrForm>
              <clr-input-container>
                <label>Name</label>
                <input clrInput name="name" required [value]="createForm().name" (input)="setCreateField('name', $any($event.target).value)" />
                <clr-control-helper>DNS-1123 name, for example support-rag-agent.</clr-control-helper>
              </clr-input-container>

              @if (activePage() === 'projects') {
                <clr-input-container>
                  <label>Display name</label>
                  <input clrInput name="displayName" [value]="createForm().displayName" (input)="setCreateField('displayName', $any($event.target).value)" />
                </clr-input-container>
              } @else {
                <clr-input-container>
                  <label>Namespace</label>
                  <input clrInput name="namespace" required [value]="createForm().namespace" (input)="setCreateField('namespace', $any($event.target).value)" />
                </clr-input-container>
              }

              <clr-textarea-container>
                <label>Description</label>
                <textarea clrTextarea name="description" [value]="createForm().description" (input)="setCreateField('description', $any($event.target).value)"></textarea>
              </clr-textarea-container>

              @if (usesComputeBackend(createForm().page)) {
                <clr-select-container>
                  <label>Compute backend</label>
                  <select clrSelect name="createComputeBackendRef" [value]="createForm().computeBackendRef" (change)="setCreateField('computeBackendRef', $any($event.target).value)">
                    <option value="">Use workload routing</option>
                    @for (option of computeBackendOptionsForCreate(); track option.key) {
                      <option [value]="option.key">{{ option.label }} - {{ option.phase }}</option>
                    }
                  </select>
                  <clr-control-helper>{{ createRoutingHelper() }}</clr-control-helper>
                </clr-select-container>
              }

              @switch (activePage()) {
                @case ('workbenches') {
                  <clr-select-container>
                    <label>Notebook image</label>
                    <select clrSelect name="notebookImage" [value]="createForm().source" (change)="setCreateField('source', $any($event.target).value)">
                      <option value="standard-data-science">standard-data-science</option>
                      <option value="pytorch-gpu">pytorch-gpu</option>
                      <option value="tensorflow-gpu">tensorflow-gpu</option>
                    </select>
                  </clr-select-container>
                  <clr-input-container>
                    <label>Data connection ref</label>
                    <input clrInput name="workbenchSourceRef" [value]="createForm().sourceRef" (input)="setCreateField('sourceRef', $any($event.target).value)" />
                  </clr-input-container>
                  <clr-input-container>
                    <label>GPU class</label>
                    <input clrInput name="workbenchGpuClass" [value]="createForm().gpuClass" (input)="setCreateField('gpuClass', $any($event.target).value)" />
                  </clr-input-container>
                }
                @case ('data-connections') {
                  <clr-select-container>
                    <label>Connection type</label>
                    <select clrSelect name="connectionType" [value]="createForm().sourceType" (change)="setCreateField('sourceType', $any($event.target).value)">
                      <option value="bucket">bucket</option>
                      <option value="git">git</option>
                      <option value="database">database</option>
                      <option value="vector-store">vector-store</option>
                    </select>
                  </clr-select-container>
                  <clr-input-container>
                    <label>Source ref</label>
                    <input clrInput name="connectionSourceRef" [value]="createForm().sourceRef" (input)="setCreateField('sourceRef', $any($event.target).value)" />
                  </clr-input-container>
                  <clr-select-container>
                    <label>Purpose</label>
                    <select clrSelect name="connectionPurpose" [value]="createForm().purpose" (change)="setCreateField('purpose', $any($event.target).value)">
                      <option value="workspace">workspace</option>
                      <option value="pipeline">pipeline</option>
                      <option value="model-registry">model-registry</option>
                      <option value="monitoring">monitoring</option>
                    </select>
                  </clr-select-container>
                }
                @case ('agents') {
                  <clr-select-container>
                    <label>Tier</label>
                    <select clrSelect name="tier" [value]="createForm().tier" (change)="setCreateField('tier', $any($event.target).value)">
                      <option value="operations">operations</option>
                      <option value="company">company</option>
                      <option value="personal">personal</option>
                    </select>
                  </clr-select-container>
                  <clr-input-container>
                    <label>LLM route ref</label>
                    <input clrInput name="llmRouteRef" [value]="createForm().llmRouteRef" (input)="setCreateField('llmRouteRef', $any($event.target).value)" />
                  </clr-input-container>
                  <clr-input-container>
                    <label>Prompt library ref</label>
                    <input clrInput name="promptLibraryRef" [value]="createForm().promptLibraryRef" (input)="setCreateField('promptLibraryRef', $any($event.target).value)" />
                  </clr-input-container>
                  <clr-checkbox-container>
                    <clr-checkbox-wrapper>
                      <input type="checkbox" clrCheckbox [checked]="createForm().requireSourceAttribution" (change)="setCreateField('requireSourceAttribution', $any($event.target).checked)" />
                      <label>Require source attribution</label>
                    </clr-checkbox-wrapper>
                  </clr-checkbox-container>
                }
                @case ('llm-routes') {
                  <clr-input-container>
                    <label>Provider</label>
                    <input clrInput name="provider" [value]="createForm().provider" (input)="setCreateField('provider', $any($event.target).value)" />
                  </clr-input-container>
                  <clr-input-container>
                    <label>Model</label>
                    <input clrInput name="model" [value]="createForm().model" (input)="setCreateField('model', $any($event.target).value)" />
                  </clr-input-container>
                  <clr-input-container>
                    <label>Endpoint</label>
                    <input clrInput name="endpoint" [value]="createForm().endpoint" (input)="setCreateField('endpoint', $any($event.target).value)" />
                  </clr-input-container>
                }
                @case ('retrieval') {
                  <clr-input-container>
                    <label>Source ref</label>
                    <input clrInput name="sourceRef" [value]="createForm().sourceRef" (input)="setCreateField('sourceRef', $any($event.target).value)" />
                  </clr-input-container>
                  <clr-input-container>
                    <label>Embedding route ref</label>
                    <input clrInput name="llmRouteRef" [value]="createForm().llmRouteRef" (input)="setCreateField('llmRouteRef', $any($event.target).value)" />
                  </clr-input-container>
                }
                @case ('pipelines') {
                  <clr-input-container>
                    <label>Source ref</label>
                    <input clrInput name="pipelineSourceRef" [value]="createForm().sourceRef" (input)="setCreateField('sourceRef', $any($event.target).value)" />
                  </clr-input-container>
                  <clr-input-container>
                    <label>Dataset ref</label>
                    <input clrInput name="pipelineDatasetRef" [value]="createForm().datasetRef" (input)="setCreateField('datasetRef', $any($event.target).value)" />
                  </clr-input-container>
                  <clr-select-container>
                    <label>Framework</label>
                    <select clrSelect name="pipelineFramework" [value]="createForm().framework" (change)="setCreateField('framework', $any($event.target).value)">
                      <option value="kubeflow-pipeline">kubeflow-pipeline</option>
                      <option value="tekton">tekton</option>
                      <option value="argo">argo</option>
                    </select>
                  </clr-select-container>
                }
                @case ('pipeline-runs') {
                  <clr-select-container>
                    <label>Backend</label>
                    <select clrSelect name="pipelineRunBackend" [value]="createForm().backendType" (change)="setCreateField('backendType', $any($event.target).value)">
                      <option value="auto">auto</option>
                      <option value="opensphere">opensphere</option>
                      <option value="upstream">upstream</option>
                    </select>
                  </clr-select-container>
                  <clr-input-container>
                    <label>Pipeline ref</label>
                    <input clrInput name="runPipelineRef" [value]="createForm().sourceRef" (input)="setCreateField('sourceRef', $any($event.target).value)" />
                  </clr-input-container>
                  <clr-input-container>
                    <label>Experiment ref</label>
                    <input clrInput name="runExperimentRef" [value]="createForm().targetRef" (input)="setCreateField('targetRef', $any($event.target).value)" />
                  </clr-input-container>
                  <clr-input-container>
                    <label>Dataset ref</label>
                    <input clrInput name="runDatasetRef" [value]="createForm().datasetRef" (input)="setCreateField('datasetRef', $any($event.target).value)" />
                  </clr-input-container>
                  <clr-select-container>
                    <label>Training mode</label>
                    <select clrSelect name="runTrainingMode" [value]="createForm().trainingMode" (change)="setCreateField('trainingMode', $any($event.target).value)">
                      <option value="full">full</option>
                      <option value="lora">lora</option>
                      <option value="qlora">qlora</option>
                    </select>
                  </clr-select-container>
                }
                @case ('compute') {
                  <clr-select-container>
                    <label>Backend type</label>
                    <select clrSelect name="backendType" [value]="createForm().backendType" (change)="setCreateField('backendType', $any($event.target).value)">
                      <option value="kubernetes">kubernetes</option>
                      <option value="external-gpu">external-gpu</option>
                    </select>
                  </clr-select-container>
                  <clr-input-container>
                    <label>GPU class</label>
                    <input clrInput name="gpuClass" [value]="createForm().gpuClass" (input)="setCreateField('gpuClass', $any($event.target).value)" />
                  </clr-input-container>
                  <clr-input-container>
                    <label>Endpoint</label>
                    <input clrInput name="endpoint" [value]="createForm().endpoint" (input)="setCreateField('endpoint', $any($event.target).value)" />
                  </clr-input-container>
                }
                @case ('datasets') {
                  <clr-select-container>
                    <label>Source type</label>
                    <select clrSelect name="sourceType" [value]="createForm().sourceType" (change)="setCreateField('sourceType', $any($event.target).value)">
                      <option value="drive">drive</option>
                      <option value="mail">mail</option>
                      <option value="approval">approval</option>
                      <option value="project">project</option>
                      <option value="bucket">bucket</option>
                      <option value="git">git</option>
                    </select>
                  </clr-select-container>
                  <clr-input-container>
                    <label>Source ref</label>
                    <input clrInput name="sourceRef" [value]="createForm().sourceRef" (input)="setCreateField('sourceRef', $any($event.target).value)" />
                  </clr-input-container>
                  <clr-select-container>
                    <label>Purpose</label>
                    <select clrSelect name="purpose" [value]="createForm().purpose" (change)="setCreateField('purpose', $any($event.target).value)">
                      <option value="fine-tune">fine-tune</option>
                      <option value="eval">eval</option>
                      <option value="rag-index">rag-index</option>
                      <option value="feature-store">feature-store</option>
                    </select>
                  </clr-select-container>
                }
                @case ('training-jobs') {
                  <clr-input-container>
                    <label>Dataset ref</label>
                    <input clrInput name="datasetRef" [value]="createForm().datasetRef" (input)="setCreateField('datasetRef', $any($event.target).value)" />
                  </clr-input-container>
                  <clr-select-container>
                    <label>Framework</label>
                    <select clrSelect name="framework" [value]="createForm().framework" (change)="setCreateField('framework', $any($event.target).value)">
                      <option value="pytorch">pytorch</option>
                      <option value="transformers">transformers</option>
                      <option value="kubeflow-pipeline">kubeflow-pipeline</option>
                    </select>
                  </clr-select-container>
                  <clr-select-container>
                    <label>Training mode</label>
                    <select clrSelect name="trainingMode" [value]="createForm().trainingMode" (change)="setCreateField('trainingMode', $any($event.target).value)">
                      <option value="full">full</option>
                      <option value="lora">lora</option>
                      <option value="qlora">qlora</option>
                    </select>
                  </clr-select-container>
                }
                @case ('model-promotion') {
                  <clr-input-container>
                    <label>Model ref</label>
                    <input clrInput name="modelRef" [value]="createForm().modelRef" (input)="setCreateField('modelRef', $any($event.target).value)" />
                  </clr-input-container>
                  <clr-input-container>
                    <label>Evaluation ref</label>
                    <input clrInput name="evaluationRef" [value]="createForm().evaluationRef" (input)="setCreateField('evaluationRef', $any($event.target).value)" />
                  </clr-input-container>
                  <clr-select-container>
                    <label>Stage</label>
                    <select clrSelect name="stage" [value]="createForm().stage" (change)="setCreateField('stage', $any($event.target).value)">
                      <option value="staging">staging</option>
                      <option value="production">production</option>
                    </select>
                  </clr-select-container>
                }
                @case ('experiments-runs') {
                  <clr-input-container>
                    <label>Dataset ref</label>
                    <input clrInput name="experimentDatasetRef" [value]="createForm().datasetRef" (input)="setCreateField('datasetRef', $any($event.target).value)" />
                  </clr-input-container>
                  <clr-input-container>
                    <label>Primary metric</label>
                    <input clrInput name="experimentMetric" [value]="createForm().metric" (input)="setCreateField('metric', $any($event.target).value)" />
                  </clr-input-container>
                }
                @case ('executions') {
                  <clr-input-container>
                    <label>Experiment ref</label>
                    <input clrInput name="executionExperimentRef" [value]="createForm().targetRef" (input)="setCreateField('targetRef', $any($event.target).value)" />
                  </clr-input-container>
                  <clr-input-container>
                    <label>Pipeline run ref</label>
                    <input clrInput name="executionRunRef" [value]="createForm().sourceRef" (input)="setCreateField('sourceRef', $any($event.target).value)" />
                  </clr-input-container>
                  <clr-input-container>
                    <label>Step</label>
                    <input clrInput name="executionStep" [value]="createForm().stage" (input)="setCreateField('stage', $any($event.target).value)" />
                  </clr-input-container>
                }
                @case ('artifacts') {
                  <clr-select-container>
                    <label>Artifact type</label>
                    <select clrSelect name="artifactType" [value]="createForm().sourceType" (change)="setCreateField('sourceType', $any($event.target).value)">
                      <option value="model">model</option>
                      <option value="dataset">dataset</option>
                      <option value="metrics">metrics</option>
                      <option value="index">index</option>
                    </select>
                  </clr-select-container>
                  <clr-input-container>
                    <label>Source ref</label>
                    <input clrInput name="artifactSourceRef" [value]="createForm().sourceRef" (input)="setCreateField('sourceRef', $any($event.target).value)" />
                  </clr-input-container>
                  <clr-select-container>
                    <label>Stage</label>
                    <select clrSelect name="artifactStage" [value]="createForm().stage" (change)="setCreateField('stage', $any($event.target).value)">
                      <option value="development">development</option>
                      <option value="staging">staging</option>
                      <option value="production">production</option>
                    </select>
                  </clr-select-container>
                }
                @case ('eval-policy') {
                  <clr-input-container>
                    <label>Dataset ref</label>
                    <input clrInput name="datasetRef" [value]="createForm().datasetRef" (input)="setCreateField('datasetRef', $any($event.target).value)" />
                  </clr-input-container>
                  <clr-input-container>
                    <label>Metric</label>
                    <input clrInput name="metric" [value]="createForm().metric" (input)="setCreateField('metric', $any($event.target).value)" />
                  </clr-input-container>
                  <clr-input-container>
                    <label>Minimum</label>
                    <input clrInput name="minimum" [value]="createForm().minimum" (input)="setCreateField('minimum', $any($event.target).value)" />
                  </clr-input-container>
                  <clr-select-container>
                    <label>Enforcement</label>
                    <select clrSelect name="enforcement" [value]="createForm().enforcement" (change)="setCreateField('enforcement', $any($event.target).value)">
                      <option value="block">block</option>
                      <option value="audit">audit</option>
                    </select>
                  </clr-select-container>
                }
                @case ('eval-jobs') {
                  <clr-input-container>
                    <label>Policy ref</label>
                    <input clrInput name="policyRef" [value]="createForm().policyRef" (input)="setCreateField('policyRef', $any($event.target).value)" />
                  </clr-input-container>
                  <clr-input-container>
                    <label>Target kind</label>
                    <input clrInput name="targetKind" [value]="createForm().targetKind" (input)="setCreateField('targetKind', $any($event.target).value)" />
                  </clr-input-container>
                  <clr-input-container>
                    <label>Target ref</label>
                    <input clrInput name="targetRef" [value]="createForm().targetRef" (input)="setCreateField('targetRef', $any($event.target).value)" />
                  </clr-input-container>
                  <clr-input-container>
                    <label>Promotion ref</label>
                    <input clrInput name="promotionRef" [value]="createForm().promotionRef" (input)="setCreateField('promotionRef', $any($event.target).value)" />
                  </clr-input-container>
                }
                @case ('trustyai-monitoring') {
                  <clr-input-container>
                    <label>Target kind</label>
                    <input clrInput name="monitoringTargetKind" [value]="createForm().targetKind" (input)="setCreateField('targetKind', $any($event.target).value)" />
                  </clr-input-container>
                  <clr-input-container>
                    <label>Target ref</label>
                    <input clrInput name="monitoringTargetRef" [value]="createForm().targetRef" (input)="setCreateField('targetRef', $any($event.target).value)" />
                  </clr-input-container>
                  <clr-input-container>
                    <label>Metric</label>
                    <input clrInput name="monitoringMetric" [value]="createForm().metric" (input)="setCreateField('metric', $any($event.target).value)" />
                  </clr-input-container>
                  <clr-input-container>
                    <label>Threshold</label>
                    <input clrInput name="monitoringThreshold" [value]="createForm().minimum" (input)="setCreateField('minimum', $any($event.target).value)" />
                  </clr-input-container>
                }
                @case ('distributed-workloads') {
                  <clr-select-container>
                    <label>Backend</label>
                    <select clrSelect name="distributedBackend" [value]="createForm().backendType" (change)="setCreateField('backendType', $any($event.target).value)">
                      <option value="auto">auto</option>
                      <option value="opensphere">opensphere</option>
                      <option value="upstream">upstream</option>
                    </select>
                  </clr-select-container>
                  <clr-select-container>
                    <label>Workload type</label>
                    <select clrSelect name="distributedType" [value]="createForm().framework" (change)="setCreateField('framework', $any($event.target).value)">
                      <option value="ray">ray</option>
                      <option value="pytorch">pytorch</option>
                      <option value="jobset">jobset</option>
                    </select>
                  </clr-select-container>
                  <clr-input-container>
                    <label>Queue</label>
                    <input clrInput name="distributedQueue" [value]="createForm().sourceRef" (input)="setCreateField('sourceRef', $any($event.target).value)" />
                  </clr-input-container>
                  <clr-input-container>
                    <label>Dataset ref</label>
                    <input clrInput name="distributedDatasetRef" [value]="createForm().datasetRef" (input)="setCreateField('datasetRef', $any($event.target).value)" />
                  </clr-input-container>
                }
                @case ('inference') {
                  <clr-select-container>
                    <label>Backend</label>
                    <select clrSelect name="inferenceBackend" [value]="createForm().backendType" (change)="setCreateField('backendType', $any($event.target).value)">
                      <option value="auto">auto</option>
                      <option value="opensphere">opensphere</option>
                      <option value="upstream">upstream</option>
                    </select>
                  </clr-select-container>
                  <clr-input-container>
                    <label>Model ref</label>
                    <input clrInput name="modelRef" [value]="createForm().modelRef" (input)="setCreateField('modelRef', $any($event.target).value)" />
                  </clr-input-container>
                  <clr-input-container>
                    <label>Promotion ref</label>
                    <input clrInput name="promotionRef" [value]="createForm().promotionRef" (input)="setCreateField('promotionRef', $any($event.target).value)" />
                  </clr-input-container>
                  <clr-select-container>
                    <label>Runtime</label>
                    <select clrSelect name="runtime" [value]="createForm().runtime" (change)="setCreateField('runtime', $any($event.target).value)">
                      <option value="kserve">kserve</option>
                      <option value="vllm">vllm</option>
                    </select>
                  </clr-select-container>
                }
              }
            </form>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-outline" [disabled]="saving()" (click)="createOpen.set(false)">Cancel</button>
            <button type="button" class="btn btn-primary" [disabled]="saving() || !createForm().name" (click)="submitCreate()">
              {{ saving() ? 'Creating...' : 'Create' }}
            </button>
          </div>
        </clr-modal>
      </main>
    </div>
  `,
})
export class AiShellElement implements OnInit, OnDestroy {
  readonly operationsRefreshPeriodSeconds = 30;
  readonly navNodes = NAV_NODES;
  readonly setupComponents = ['dashboard', 'workbenches', 'datasciencepipelines', 'kserve', 'modelregistry', 'trustyai', 'kueue', 'ray'];
  readonly activePage = signal<PageId>(this.initialPage());
  readonly clusterSettingsTab = signal<ClusterSettingsTab>(this.initialClusterSettingsTab());
  readonly openGroups = signal<Set<string>>(this.initialOpenGroups());
  readonly summary = signal<SummaryResponse>(DEFAULT_SUMMARY);
  readonly projects = signal<ProjectItem[]>([]);
  readonly resourceItems = signal<ResourceItem[]>([]);
  readonly resourceMeta = signal<ResourceMeta>({ actualCount: 0, referenceCount: 0, source: 'empty' });
  readonly capabilities = signal<CapabilityItem[]>([]);
  readonly loadingResource = signal(false);
  readonly saving = signal(false);
  readonly createOpen = signal(false);
  readonly actionMessage = signal<{ type: string; message: string } | null>(null);
  readonly operationsLastUpdatedAt = signal('');
  readonly operationsRefreshStatus = signal('Waiting');
  readonly createForm = signal<CreateForm>(defaultCreateForm(this.activePage()));
  readonly operationTitle = signal('');
  readonly operationLines = signal<string[]>([]);
  readonly workbenchDetail = signal<WorkbenchDetailResponse | null>(null);
  readonly pipelineDetail = signal<PipelineDetailResponse | null>(null);
  readonly inferenceDetail = signal<InferenceDetailResponse | null>(null);
  readonly dataConnectionDetail = signal<DataConnectionDetailResponse | null>(null);
  readonly lineageItems = signal<PipelineLineageItem[]>([]);
  readonly trustyMetrics = signal<TrustyMetricItem[]>([]);
  readonly trustyAlerts = signal<TrustyAlertItem[]>([]);
  readonly trustyHistory = signal<TrustyHistoryItem[]>([]);
  readonly modelVersions = signal<ModelVersionItem[]>([]);
  readonly modelRegistryStatus = signal<RegistryStatusResponse>({});
  readonly registryPromotions = signal<RegistryPromotionItem[]>([]);
  readonly registryApprovalAudit = signal<RegistryApprovalAuditItem[]>([]);
  readonly registryEvaluationMetrics = signal<RegistryEvaluationMetricItem[]>([]);
  readonly registrySelfTest = signal<RegistrySelfTestResponse | null>(null);
  readonly odhComponents = signal<ResourceItem[]>([]);
  readonly nativePlatform = signal<NativePlatformResponse>({ components: [], subscriptions: [], installPlans: [], dataScienceClusters: [] });
  readonly nativeBackends = signal<NativeBackendsResponse>({ summary: { upstreamReady: 0, fallbackReady: 0, unavailable: 0, total: 0, phase: 'Pending' }, items: [] });
  readonly computeBackends = signal<ResourceItem[]>([]);
  readonly gpuInventory = signal<GpuInventoryResponse>({ phase: 'Pending', ready: false, generatedAt: '', summary: { nodes: 0, readyNodes: 0, gpuNodes: 0, totalCapacity: 0, totalAllocatable: 0, pluginPods: 0, pluginDaemonSets: 0, runtimeClasses: 0, diagnostics: 0 }, nodes: [], pluginPods: [], pluginDaemonSets: [], runtimeClasses: [], diagnostics: [], nextSteps: [] });
  readonly gpuEnablementProfile = signal('nvidia');
  readonly gpuEnablementConfig = signal<GpuEnablementConfig>(defaultGpuEnablementConfig('nvidia'));
  readonly gpuEnablementPlan = signal<GpuEnablementPlanResponse | null>(null);
  readonly gpuEnablementPreview = signal('');
  readonly gpuBridgeProbe = signal<GpuBridgeProbeResponse | null>(null);
  readonly gpuBridgeProbeLog = signal('');
  readonly computeRouting = signal<ComputeRoutingResponse>({ namespace: 'opensphere-system', name: 'oah-compute-routing', phase: 'Pending', ready: false, options: [], routes: [] });
  readonly oahDemoPlan = signal<OahDemoPlanResponse>({ title: 'OpenSphere AI Hub GPU lifecycle demo', acronym: 'OAH', phase: 'Pending', generatedAt: '', summary: '', prerequisites: [], evidence: [], tasks: [] });
  readonly demoRunNamespace = signal('oah-gpu-lifecycle-demo');
  readonly oahDemoRun = signal<DemoRunStatusResponse>({ namespace: 'oah-gpu-lifecycle-demo', phase: 'NotStarted', generatedAt: '', summary: { expected: 0, actual: 0, ready: 0, missingCrds: 0 }, items: [] });
  readonly oahDemoPreview = signal<DemoRunPreviewResponse | null>(null);
  readonly oahDemoEvidence = signal<DemoRunEvidenceResponse | null>(null);
  readonly oahDemoSmoke = signal<DemoSmokeStatusResponse | null>(null);
  readonly oahDemoSmokePreview = signal<DemoSmokePreviewResponse | null>(null);
  readonly oahDemoSmokeLogs = signal<DemoSmokeLogsResponse | null>(null);
  readonly smokeManifestPreview = signal('');
  readonly smokeLogPreview = signal('');
  readonly demoManifestPreview = signal('');
  readonly controllerMetrics = signal<ControllerMetricsResponse>({ startedAt: '', summary: { controllers: 0, reconciles: 0, failures: 0, events: 0 }, items: [], events: [] });
  readonly auditLog = signal<AuditLogResponse>({ summary: { total: 0, warnings: 0, namespaces: 0, kinds: 0, activeEntries: 0, historicalEntries: 0, systemEntries: 0, activeWarnings: 0, historicalWarnings: 0, systemWarnings: 0 }, items: [] });
  readonly auditStateFilter = signal('all');
  readonly finalReadiness = signal<FinalReadinessResponse>({ phase: 'Pending', generatedAt: '', summary: { pass: 0, warning: 0, fail: 0, externalRequired: 0, total: 0 }, checks: [] });
  readonly setupForm = signal<SetupForm>(defaultSetupForm());
  readonly setupStatus = signal<SetupStatusResponse>({ prerequisites: [], crds: [], operators: { olmAvailable: false, subscriptions: [], csvs: [] }, namespaces: [], dataScienceClusters: [] });
  readonly setupSteps = signal<SetupStepItem[]>([]);
  readonly setupManifestPreview = signal('');
  readonly setupNamespaceOptions = computed(() => {
    const defaults = ['opensphere-system', 'opendatahub', 'redhat-ods-operator', 'redhat-ods-applications'];
    return Array.from(new Set([...defaults, ...this.setupStatus().namespaces, this.setupForm().namespace].filter(Boolean))).sort();
  });
  readonly pageLabel = computed(() => PAGE_LABEL[this.activePage()]);
  readonly projectCards = computed(() => this.projects().slice(0, 2));
  readonly filteredAuditEntries = computed(() => {
    const filter = this.auditStateFilter();
    const items = this.auditLog().items;
    if (filter === 'all') return items;
    return items.filter((entry) => (entry.resourceState || 'system') === filter);
  });
  readonly createLabel = computed(() => CREATE_LABEL[this.activePage()] || 'resource');
  readonly externalTrainingEvidence = computed(() => {
    if (this.activePage() !== 'training-jobs') return [];
    return this.resourceItems().filter((item) => item.backendType === 'external' || !!item.externalJob);
  });
  readonly overviewGpuBackends = computed(() => {
    const externalTypes = new Set(['external', 'docker-bridge', 'windows-service', 'windows-supervisor', 'wsl2-bridge', 'remote', 'notebook-bridge', 'cpu']);
    return this.computeBackends().filter((item) => {
      const type = (item.backendType || '').toLowerCase();
      return externalTypes.has(type) || !!item.endpoint || !!item.resourceName || !!item.gpus?.length;
    });
  });
  readonly overviewExternalGpuCount = computed(() => this.overviewGpuBackends().reduce((sum, backend) => sum + (backend.gpus?.length || 0), 0));
  readonly overviewAvailableGpuCount = computed(() => (this.gpuInventory().summary.totalAllocatable || 0) + this.overviewExternalGpuCount());
  readonly overviewGpuPhase = computed(() => this.overviewAvailableGpuCount() > 0 ? 'Ready' : this.gpuInventory().phase);
  readonly overviewGpuProducts = computed(() => this.overviewGpuBackends().flatMap((backend) => backend.gpus || []));
  readonly overviewGpuProductName = computed(() => String(this.overviewGpuProducts()[0]?.['name'] || this.overviewGpuBackends()[0]?.provider || 'External GPU backend'));
  readonly gpuServiceCatalog = computed<GpuCatalogServiceItem[]>(() => {
    const alternatives = this.gpuEnablementPlan()?.alternatives || [];
    const active = this.gpuEnablementProfile();
    const computeBackends = this.computeBackends();
    const items: GpuCatalogServiceItem[] = alternatives.map((option) => {
      const meta = this.gpuServiceMeta(option.id, option.mode);
      const backend = computeBackends.find((item) => this.backendMatchesGpuOption(item, option));
      const phase = backend?.phase || this.gpuOptionPhase(option);
      return {
        ...option,
        ...meta,
        phase,
        ready: backend?.ready === true || this.gpuServiceReadyPhase(phase),
        selected: option.id === active,
        selectable: true,
        registered: !!backend,
        endpoint: backend?.endpoint,
        backendName: backend?.name,
        backendNamespace: backend?.namespace,
      };
    });
    items.push({
      id: 'model-api-router',
      label: 'Model API Router / LiteLLM route',
      mode: 'model-api-router',
      resourceName: 'llm-route.opensphere.io',
      summary: 'Use this when the model is already running elsewhere and OAH only needs to route inference API calls.',
      category: 'AI service',
      serviceRole: 'Separate service',
      workloads: 'Inference API routing, model list, completion tests',
      verification: 'Model list and completion test',
      phase: 'SeparateService',
      ready: true,
      selected: false,
      selectable: false,
      registered: false,
    });
    return items;
  });
  readonly currentCapability = computed(() => this.capabilities().find((item) => item.page === this.activePage()));
  readonly installedKinds = computed(() => new Set(this.capabilities().filter((item) => item.installed).map((item) => item.kind)));
  readonly supportsCreate = computed(() => !!CREATE_LABEL[this.activePage()]);
  readonly canCreate = computed(() => {
    const page = this.activePage();
    if (!CREATE_LABEL[page]) return false;
    if (page === 'projects') return true;
    return this.currentCapability()?.installed === true;
  });
  readonly createBlockedMessage = computed(() => {
    const page = this.activePage();
    if (!CREATE_LABEL[page]) return '';
    const cap = this.currentCapability();
    if (page !== 'projects' && cap && !cap.installed) return `${cap.kind} CRD is not installed: ${cap.crdName}`;
    return '';
  });
  private operationsRefreshTimer: ReturnType<typeof setInterval> | null = null;
  private operationsRefreshInFlight = false;
  private readonly popStateHandler = (): void => this.applyRouteFromLocation();

  ngOnInit(): void {
    if (typeof window !== 'undefined') {
      window.addEventListener('popstate', this.popStateHandler);
    }
    void this.refresh().finally(() => this.startOperationsAutoRefresh());
  }

  ngOnDestroy(): void {
    if (typeof window !== 'undefined') {
      window.removeEventListener('popstate', this.popStateHandler);
    }
    this.stopOperationsAutoRefresh();
  }

  statusClass(phase: string): string {
    return phaseClass(phase);
  }

  resourceDetail(item: ResourceItem): string {
    if (item.finalizing) return 'Cleaning up child resources';
    if (item.nextRetryAt) return `Retry ${item.retryCount || 1} at ${item.nextRetryAt}`;
    if (item.computeRoutingBackend) return `Routed ${item.computeRoutingWorkload || 'workload'} to ${item.computeRoutingBackend}`;
    if (item.computeBackendRef) return `Compute backend ${item.computeBackendRef}`;
    if (item.externalJob) return `External job ${item.externalJob['jobId'] || item.externalJob['id'] || '-'} ${item.externalJob['phase'] || item.phase}: ${item.externalJob['summary'] || item.message || '-'}`;
    if (item.reason && item.message) return `${item.reason}: ${item.message}`;
    return item.reason || item.message || item.description || '-';
  }

  usesComputeBackend(page: PageId = this.activePage()): boolean {
    return ['workbenches', 'pipelines', 'pipeline-runs', 'training-jobs', 'inference', 'distributed-workloads'].includes(page);
  }

  workloadRouteId(page: PageId): string {
    if (page === 'training-jobs') return 'training';
    if (page === 'inference') return 'serving';
    if (page === 'workbenches') return 'notebooks';
    if (page === 'pipelines' || page === 'pipeline-runs') return 'pipelines';
    if (page === 'distributed-workloads') return 'distributed';
    return '';
  }

  workloadRouteForPage(page: PageId = this.activePage()): ComputeRoutingRoute | null {
    const id = this.workloadRouteId(page);
    return this.computeRouting().routes.find((route) => route.id === id) || null;
  }

  routedBackendKeyForPage(page: PageId = this.activePage()): string {
    const route = this.workloadRouteForPage(page);
    if (!route) return '';
    if (route.primary && route.primary !== 'auto' && route.primary !== 'cpu-fallback') return route.primary;
    return route.primaryBackend?.key || '';
  }

  computeBackendOptionsForCreate(): ComputeRoutingOption[] {
    return (this.computeRouting().options || []).filter((option) => option.key !== 'auto' && option.key !== 'cpu-fallback');
  }

  applyCreateRoutingDefault(form: CreateForm): CreateForm {
    if (!this.usesComputeBackend(form.page) || form.computeBackendRef) return form;
    return { ...form, computeBackendRef: this.routedBackendKeyForPage(form.page) };
  }

  createRoutingHelper(): string {
    const route = this.workloadRouteForPage(this.createForm().page);
    if (!route) return 'No workload route is loaded yet. Leave empty to let the server apply routing at create time.';
    return `${route.label}: primary ${route.primary}, fallback ${route.fallback}.`;
  }

  computeBackendLabel(item: ResourceItem): string {
    return item.computeRoutingBackend || item.computeBackendRef || item.resourceName || item.backendType || '-';
  }

  externalJobLogLine(item: ResourceItem): string {
    if (item.externalJobLogSummary?.latest) return item.externalJobLogSummary.latest;
    const lines = item.externalJobLogs?.lines || [];
    const values = lines.map((line) => typeof line === 'string' ? line : String(line?.['line'] || '')).filter(Boolean);
    return values.find((line) => /MiB\s*\/|RTX|GeForce|NVIDIA-SMI|Default/.test(line)) || values[values.length - 1] || String(item.externalJobLogs?.text || '');
  }

  workbenchRuntimeObjects(): K8sObjectSummary[] {
    const detail = this.workbenchDetail();
    return [detail?.deployment, detail?.service, detail?.storage].filter((item): item is K8sObjectSummary => !!item);
  }

  inferenceRuntimeObjects(): K8sObjectSummary[] {
    const detail = this.inferenceDetail();
    return [detail?.inferenceService, detail?.deployment, detail?.service].filter((item): item is K8sObjectSummary => !!item);
  }

  alertType(severity: string): string {
    const normalized = (severity || '').toLowerCase();
    if (normalized.includes('error') || normalized.includes('danger')) return 'danger';
    if (normalized.includes('warn')) return 'warning';
    if (normalized.includes('success')) return 'success';
    return 'info';
  }

  metricStatusClass(status: string): string {
    return phaseClass(status);
  }

  metricBarClass(status: string): string {
    const normalized = (status || '').toLowerCase();
    if (normalized.includes('warn') || normalized.includes('risk')) return 'ai-bar-warning';
    if (normalized.includes('fail') || normalized.includes('error')) return 'ai-bar-warning';
    return 'ai-bar-success';
  }

  isGpuOperatorMode(): boolean {
    return this.gpuEnablementProfile() === 'nvidia-operator';
  }

  isExternalGpuMode(): boolean {
    return ['external', 'docker-bridge', 'windows-service', 'windows-supervisor', 'wsl2', 'remote', 'colab'].includes(this.gpuEnablementProfile());
  }

  isCpuFallbackMode(): boolean {
    return this.gpuEnablementProfile() === 'cpu';
  }

  isDevicePluginMode(): boolean {
    return !this.isGpuOperatorMode() && !this.isExternalGpuMode() && !this.isCpuFallbackMode();
  }

  selectGpuEnablementProfile(profile: string): void {
    this.gpuEnablementProfile.set(profile);
    this.gpuEnablementConfig.set(defaultGpuEnablementConfig(profile));
    void this.loadGpuEnablementPlan();
  }

  setGpuEnablementConfigField<K extends keyof GpuEnablementConfig>(field: K, value: GpuEnablementConfig[K]): void {
    this.gpuEnablementConfig.update((config) => ({ ...config, [field]: value }));
  }

  gpuOptionPhase(option: { id: string; mode: string; resourceName: string }): string {
    if (option.id === this.gpuEnablementProfile()) return this.gpuEnablementPlan()?.phase || 'Selected';
    if (option.mode === 'cpu-fallback') return 'Fallback';
    if (option.mode.startsWith('external')) return 'Configurable';
    const hasAllocatableResource = this.gpuInventory().nodes.some((node) =>
      (node.gpuResources || []).some((resource) => resource.name === option.resourceName && resource.allocatableNumber > 0),
    );
    if (hasAllocatableResource) return 'Ready';
    if (option.id === 'nvidia' && (this.gpuInventory().summary.pluginPods || 0) > 0) return 'Detected';
    return 'SetupRequired';
  }

  gpuServiceMeta(id: string, mode: string): Pick<GpuCatalogServiceItem, 'category' | 'serviceRole' | 'workloads' | 'verification'> {
    if (id === 'docker-bridge') {
      return {
        category: 'Local external compute',
        serviceRole: 'Docker bridge backend',
        workloads: 'Training smoke, batch inference, local GPU jobs',
        verification: 'Bridge health, capabilities, nvidia-smi smoke, job evidence',
      };
    }
    if (id === 'windows-service') {
      return {
        category: 'Windows external compute',
        serviceRole: 'Installed service backend',
        workloads: 'Windows-host GPU jobs and diagnostics',
        verification: 'Service health, endpoint reachability, capabilities, smoke job',
      };
    }
    if (id === 'windows-supervisor') {
      return {
        category: 'Windows external compute',
        serviceRole: 'Supervisor backend',
        workloads: 'Docker/WSL2 worker jobs, training smoke, batch work',
        verification: 'Supervisor health, worker status, capabilities, job evidence',
      };
    }
    if (id === 'wsl2') {
      return {
        category: 'WSL2 external compute',
        serviceRole: 'WSL2 bridge backend',
        workloads: 'Linux CUDA jobs through WSL2 bridge',
        verification: 'Endpoint health, capabilities, smoke job, WSL bridge logs',
      };
    }
    if (id === 'remote') {
      return {
        category: 'Remote external compute',
        serviceRole: 'Remote backend',
        workloads: 'Shared GPU pool, batch inference, training jobs',
        verification: 'TLS/health, capabilities, latency, smoke job',
      };
    }
    if (id === 'external') {
      return {
        category: 'External compute',
        serviceRole: 'Generic bridge backend',
        workloads: 'Training smoke, batch inference, external GPU jobs',
        verification: 'Endpoint health, capabilities, smoke job, job evidence',
      };
    }
    if (id === 'colab') {
      return {
        category: 'Notebook compute',
        serviceRole: 'Bridge backend',
        workloads: 'Notebook experiments and demo jobs',
        verification: 'Bridge session liveness, capabilities, limited smoke',
      };
    }
    if (id === 'cpu') {
      return {
        category: 'Fallback compute',
        serviceRole: 'Fallback backend',
        workloads: 'CPU smoke, preprocessing, evaluation, governance demos',
        verification: 'CPU scheduling and small smoke job',
      };
    }
    if (mode === 'operator') {
      return {
        category: 'Native Kubernetes GPU',
        serviceRole: 'Managed GPU stack',
        workloads: 'Training, serving, distributed workloads, notebooks',
        verification: 'OLM subscription, device plugin, node allocatable, sample scheduling',
      };
    }
    return {
      category: 'Native Kubernetes GPU',
      serviceRole: 'Device plugin backend',
      workloads: 'Training, serving, distributed workloads, notebooks',
      verification: 'Device plugin, node allocatable, sample scheduling',
    };
  }

  backendMatchesGpuOption(backend: ResourceItem, option: { id: string; mode: string; resourceName: string }): boolean {
    if (!backend) return false;
    if (backend.resourceName && backend.resourceName === option.resourceName) return true;
    const backendType = (backend.backendType || '').toLowerCase();
    if (option.id === 'external') return backendType === 'external';
    if (option.id === 'docker-bridge') return backendType === 'docker-bridge';
    if (option.id === 'windows-service') return backendType === 'windows-service';
    if (option.id === 'windows-supervisor') return backendType === 'windows-supervisor';
    if (option.id === 'wsl2') return backendType === 'wsl2-bridge';
    if (option.id === 'remote') return backendType === 'remote';
    if (option.id === 'colab') return backendType === 'notebook-bridge';
    if (option.id === 'cpu') return backendType === 'cpu' || backend.resourceName === 'cpu';
    return false;
  }

  gpuServiceReadyPhase(phase: string): boolean {
    return /ready|configured|detected|fallback/i.test(phase || '') && !/required|missing|invalid|unavailable/i.test(phase || '');
  }

  gpuLabelEntries(labels: Record<string, string>): Array<{ key: string; value: string }> {
    return Object.entries(labels || {}).map(([key, value]) => ({ key, value }));
  }

  sourceLabel(item: { source?: string; backendMode?: string; reference?: boolean }): string {
    if (item.reference) return 'Reference';
    const backendMode = (item.backendMode || '').toLowerCase();
    if (backendMode === 'native') return 'Native';
    if (backendMode === 'upstream-adapter') return 'Upstream adapter';
    if (backendMode === 'parity') return 'Parity';
    if (backendMode === 'external') return 'External';
    const source = (item.source || '').toLowerCase();
    if (source === 'cluster') return 'Actual';
    if (source === 'native') return 'Native';
    if (source === 'upstream') return 'Upstream';
    return item.source || 'Actual';
  }

  sourceClass(item: { source?: string; backendMode?: string; reference?: boolean }): string {
    if (item.reference) return 'label label-info';
    const backendMode = (item.backendMode || '').toLowerCase();
    if (backendMode === 'upstream-adapter') return 'label label-warning';
    if (backendMode === 'parity') return 'label label-success';
    if (backendMode === 'external') return 'label label-info';
    return 'label label-success';
  }

  isOpen(id: string): boolean {
    return this.openGroups().has(id);
  }

  setOpen(id: string, open: boolean): void {
    this.openGroups.update((current) => {
      const next = new Set(current);
      if (open) {
        next.add(id);
      } else {
        next.delete(id);
      }
      return next;
    });
  }

  pageHref(page: PageId): string {
    return this.routeUrl(page);
  }

  navigate(page: PageId, event?: Event): void {
    event?.preventDefault();
    this.setActivePage(page, true);
  }

  selectClusterSettingsTab(tab: ClusterSettingsTab): void {
    this.clusterSettingsTab.set(tab);
    if (this.activePage() !== 'cluster-settings') {
      this.setActivePage('cluster-settings', true);
      return;
    }
    this.writeRoute('cluster-settings', true, tab);
  }

  private setActivePage(page: PageId, pushUrl: boolean): void {
    this.activePage.set(page);
    this.actionMessage.set(null);
    const group = groupForPage(page);
    if (group) {
      this.openGroups.update((current) => new Set(current).add(group));
    }
    if (pushUrl) {
      this.writeRoute(page, true);
    }
    if (page === 'home') {
      void this.loadHomeOperations();
    } else if (page !== 'projects') {
      void this.fetchResourcePage(page);
    }
  }

  /** 표준: `/p/<id>/서브패스` (콘솔 라우터가 `/p/` 네임스페이스만 소유 — bare `/ai/...`는 legacy, 제거됨).
   * currentUiRoute()는 'ai' 세그먼트를 값으로 찾아 그 뒤를 취하므로 접두사 변경에 영향받지 않는다. */
  private routeUrl(page: PageId, tab = this.clusterSettingsTab()): string {
    const route = PAGE_ROUTE[page];
    const tabRoute = page === 'cluster-settings' && tab !== 'setup' ? `/${CLUSTER_SETTINGS_TAB_ROUTE[tab]}` : '';
    return route ? `/p/ai/${route}${tabRoute}` : '/p/ai';
  }

  private writeRoute(page: PageId, push: boolean, tab = this.clusterSettingsTab()): void {
    if (typeof window === 'undefined') return;
    const nextUrl = this.routeUrl(page, tab);
    if (`${window.location.pathname}${window.location.search}${window.location.hash}` === nextUrl) return;
    const state = { page, tab };
    if (push) {
      window.history.pushState(state, '', nextUrl);
    } else {
      window.history.replaceState(state, '', nextUrl);
    }
  }

  private applyRouteFromLocation(): void {
    const page = this.initialPage();
    if (page === 'cluster-settings') {
      this.clusterSettingsTab.set(this.initialClusterSettingsTab());
    }
    this.setActivePage(page, false);
  }

  openCreate(): void {
    if (!this.canCreate()) {
      this.actionMessage.set({ type: 'info', message: this.createBlockedMessage() || 'This view uses page-specific actions instead of direct resource creation.' });
      return;
    }
    const namespace = this.projects()[0]?.name || this.setupForm().namespace || 'default';
    this.createForm.set(this.applyCreateRoutingDefault(defaultCreateForm(this.activePage(), namespace)));
    this.createOpen.set(true);
  }

  canDelete(item: ResourceItem): boolean {
    return this.installedKinds().has(item.kind) && !item.finalizing;
  }

  setCreateField<K extends keyof CreateForm>(field: K, value: CreateForm[K]): void {
    this.createForm.update((current) => ({ ...current, [field]: value }));
  }

  async submitCreate(): Promise<void> {
    if (this.saving()) return;
    this.saving.set(true);
    this.actionMessage.set(null);
    try {
      const res = await this.hostFetch(`${this.apiBase}/actions/create`, {
        method: 'POST',
        headers: this.actionHeaders(),
        body: JSON.stringify(this.createForm()),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.message || data.error || `Create failed with HTTP ${res.status}`);
      this.createOpen.set(false);
      const routed = data.routedBackend?.key ? ` Routed to ${data.routedBackend.key}.` : '';
      this.actionMessage.set({ type: 'success', message: `${this.createLabel()} created: ${data.created?.name || this.createForm().name}.${routed}` });
      await this.refresh();
    } catch (error) {
      this.actionMessage.set({ type: 'danger', message: error instanceof Error ? error.message : String(error) });
    } finally {
      this.saving.set(false);
    }
  }

  async deleteResource(item: ResourceItem): Promise<void> {
    const name = item.name;
    const namespace = item.namespace || this.createForm().namespace || this.projects()[0]?.name || 'default';
    if (!name || !window.confirm(`Delete ${item.kind}/${name} from ${namespace}?`)) return;

    this.saving.set(true);
    this.actionMessage.set(null);
    try {
      const res = await this.hostFetch(`${this.apiBase}/actions/delete`, {
        method: 'DELETE',
        headers: this.actionHeaders(),
        body: JSON.stringify({ page: this.activePage(), kind: item.kind, name, namespace }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.message || data.error || `Delete failed with HTTP ${res.status}`);
      this.actionMessage.set({ type: 'success', message: `${item.kind}/${name} deleted.` });
      await this.fetchResourcePage(this.activePage());
      await this.fetchSummary();
    } catch (error) {
      this.actionMessage.set({ type: 'danger', message: error instanceof Error ? error.message : String(error) });
    } finally {
      this.saving.set(false);
    }
  }

  async workbenchAction(item: ResourceItem, action: 'start' | 'stop'): Promise<void> {
    await this.runOperation(
      `${this.apiBase}/operations/workbenches`,
      { name: item.name, namespace: item.namespace || this.createForm().namespace, action },
      `${item.kind}/${item.name} ${action} requested.`,
      () => this.fetchResourcePage('workbenches'),
    );
  }

  async loadWorkbenchDetail(item: ResourceItem): Promise<void> {
    this.saving.set(true);
    this.actionMessage.set(null);
    try {
      const params = new URLSearchParams({
        name: item.name,
        namespace: item.namespace || this.createForm().namespace,
      });
      const res = await this.hostFetch(`${this.apiBase}/workbenches/detail?${params.toString()}`, { headers: this.actionHeaders() });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.message || data.error || `Workbench detail failed with HTTP ${res.status}`);
      this.workbenchDetail.set(data as WorkbenchDetailResponse);
      this.actionMessage.set({ type: 'success', message: `Loaded workbench detail: ${item.namespace || this.createForm().namespace}/${item.name}.` });
    } catch (error) {
      this.actionMessage.set({ type: 'danger', message: error instanceof Error ? error.message : String(error) });
    } finally {
      this.saving.set(false);
    }
  }

  async openWorkbenchProxy(): Promise<void> {
    const detail = this.workbenchDetail();
    const proxyUrl = detail?.runtime?.proxyUrl;
    if (!proxyUrl) return;
    this.saving.set(true);
    this.actionMessage.set(null);
    try {
      const session = await this.hostFetch(`${this.apiBase}/api/session`, { headers: this.actionHeaders() });
      const data = await session.json().catch(() => ({}));
      if (!session.ok) throw new Error(data.error || `Workbench session failed with HTTP ${session.status}`);
      const href = proxyUrl.startsWith('http') ? proxyUrl : `${this.apiBase}${proxyUrl}`;
      window.open(href, '_blank', 'noopener,noreferrer');
      this.actionMessage.set({ type: 'success', message: `Opening workbench runtime: ${detail?.runtime?.namespace}/${detail?.runtime?.name}.` });
    } catch (error) {
      this.actionMessage.set({ type: 'danger', message: error instanceof Error ? error.message : String(error) });
    } finally {
      this.saving.set(false);
    }
  }

  async loadDataConnectionDetail(item: ResourceItem): Promise<void> {
    this.saving.set(true);
    this.actionMessage.set(null);
    try {
      const params = new URLSearchParams({
        name: item.name,
        namespace: item.namespace || this.createForm().namespace,
      });
      const res = await this.hostFetch(`${this.apiBase}/data-connections/detail?${params.toString()}`, { headers: this.actionHeaders() });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.message || data.error || `Data connection detail failed with HTTP ${res.status}`);
      this.dataConnectionDetail.set(data as DataConnectionDetailResponse);
      this.actionMessage.set({ type: 'success', message: `Loaded data connection detail: ${item.namespace || this.createForm().namespace}/${item.name}.` });
    } catch (error) {
      this.actionMessage.set({ type: 'danger', message: error instanceof Error ? error.message : String(error) });
    } finally {
      this.saving.set(false);
    }
  }

  async runPipeline(item: ResourceItem): Promise<void> {
    await this.runOperation(
      `${this.apiBase}/operations/pipelines/run`,
      { name: item.name, namespace: item.namespace || this.createForm().namespace, datasetRef: this.createForm().datasetRef, trainingMode: this.createForm().trainingMode },
      `Pipeline run requested: ${item.name}`,
      () => this.fetchResourcePage('pipeline-runs'),
    );
  }

  async loadPipelineDetail(item: ResourceItem): Promise<void> {
    this.saving.set(true);
    this.actionMessage.set(null);
    try {
      const params = new URLSearchParams({
        name: item.name,
        namespace: item.namespace || this.createForm().namespace,
        kind: item.kind === 'PipelineRunClaim' ? 'PipelineRunClaim' : 'PipelineClaim',
      });
      const res = await this.hostFetch(`${this.apiBase}/pipelines/detail?${params.toString()}`, { headers: this.actionHeaders() });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.message || data.error || `Pipeline detail failed with HTTP ${res.status}`);
      this.pipelineDetail.set(data as PipelineDetailResponse);
      this.actionMessage.set({ type: 'success', message: `Loaded pipeline detail: ${item.namespace || this.createForm().namespace}/${item.name}.` });
    } catch (error) {
      this.actionMessage.set({ type: 'danger', message: error instanceof Error ? error.message : String(error) });
    } finally {
      this.saving.set(false);
    }
  }

  async loadInferenceDetail(item: ResourceItem): Promise<void> {
    this.saving.set(true);
    this.actionMessage.set(null);
    try {
      const params = new URLSearchParams({
        name: item.name,
        namespace: item.namespace || this.createForm().namespace,
        kind: item.kind === 'InferenceService' ? 'InferenceService' : 'InferenceClaim',
      });
      const res = await this.hostFetch(`${this.apiBase}/inference/detail?${params.toString()}`, { headers: this.actionHeaders() });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.message || data.error || `Inference detail failed with HTTP ${res.status}`);
      this.inferenceDetail.set(data as InferenceDetailResponse);
      this.actionMessage.set({ type: 'success', message: `Loaded model deployment detail: ${item.namespace || this.createForm().namespace}/${item.name}.` });
    } catch (error) {
      this.actionMessage.set({ type: 'danger', message: error instanceof Error ? error.message : String(error) });
    } finally {
      this.saving.set(false);
    }
  }

  async claimAction(item: ResourceItem, action: 'retry' | 'suspend' | 'resume' | 'approve' | 'reject'): Promise<void> {
    await this.runOperation(
      `${this.apiBase}/operations/claims`,
      { page: this.activePage(), kind: item.kind, name: item.name, namespace: item.namespace || this.createForm().namespace, action },
      `${item.kind}/${item.name} ${action} requested.`,
      () => this.fetchResourcePage(this.activePage()),
    );
  }

  editInferenceFrom(item: ResourceItem): void {
    this.createForm.update((current) => ({
      ...current,
      page: 'inference',
      name: item.name,
      namespace: item.namespace || current.namespace,
    }));
    this.actionMessage.set({ type: 'info', message: `${item.kind}/${item.name} loaded for edit.` });
  }

  async updateInference(): Promise<void> {
    const form = this.createForm();
    await this.runOperation(
      `${this.apiBase}/operations/inference`,
      {
        name: form.name,
        namespace: form.namespace,
        runtime: form.runtime,
        modelRef: form.modelRef,
        promotionRef: form.promotionRef,
      },
      `Inference deployment updated: ${form.name}`,
      () => this.fetchResourcePage('inference'),
    );
  }

  async loadPipelineLogs(item?: ResourceItem): Promise<void> {
    const params = this.itemParams(item);
    try {
      const res = await this.hostFetch(`${this.apiBase}/pipeline/runs/logs?${params}`);
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `Logs failed with HTTP ${res.status}`);
      this.operationTitle.set(`Logs - ${data.name || item?.name || 'latest run'}`);
      this.operationLines.set(data.lines ?? []);
      this.lineageItems.set([]);
    } catch (error) {
      this.actionMessage.set({ type: 'danger', message: error instanceof Error ? error.message : String(error) });
    }
  }

  async loadPipelineLineage(item?: ResourceItem): Promise<void> {
    const params = this.itemParams(item);
    try {
      const res = await this.hostFetch(`${this.apiBase}/pipeline/runs/lineage?${params}`);
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `Lineage failed with HTTP ${res.status}`);
      this.operationTitle.set(`Lineage - ${data.name || item?.name || 'latest run'}`);
      this.lineageItems.set(data.items ?? []);
      this.operationLines.set([]);
    } catch (error) {
      this.actionMessage.set({ type: 'danger', message: error instanceof Error ? error.message : String(error) });
    }
  }

  async addModelVersion(): Promise<void> {
    const form = this.createForm();
    await this.runOperation(
      `${this.apiBase}/models/registry/versions`,
      { name: form.name, version: form.version, stage: form.stage, source: form.source, backend: form.backendType },
      `Model version registered: ${form.name}:${form.version}`,
      () => this.loadModelVersions(),
    );
  }

  async runRegistrySelfTest(): Promise<void> {
    if (this.saving()) return;
    this.saving.set(true);
    this.actionMessage.set(null);
    try {
      const form = this.createForm();
      const res = await this.hostFetch(`${this.apiBase}/models/registry/upstream/self-test`, {
        method: 'POST',
        headers: this.actionHeaders(),
        body: JSON.stringify({
          backend: form.backendType,
          modelName: form.name || 'opensphere-selftest',
          version: form.version || undefined,
          stage: form.stage || 'validation',
          source: form.source || 'opensphere-upstream-write-self-test',
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `Registry self-test failed with HTTP ${res.status}`);
      this.registrySelfTest.set(data as RegistrySelfTestResponse);
      this.actionMessage.set({ type: data.synced ? 'success' : 'warning', message: data.message || 'Registry upstream write self-test completed.' });
      await this.loadModelVersions();
    } catch (error) {
      this.actionMessage.set({ type: 'danger', message: error instanceof Error ? error.message : String(error) });
    } finally {
      this.saving.set(false);
    }
  }

  async odhComponentAction(item: ResourceItem, action: 'enable' | 'disable' | 'upgrade'): Promise<void> {
    await this.runOperation(
      `${this.apiBase}/admin/odh-components/action`,
      { name: item.name, action },
      `ODH component ${action} requested: ${item.name}`,
      () => this.loadOdhComponents(),
    );
  }

  async loadNativeCatalog(): Promise<void> {
    try {
      const res = await this.hostFetch(`${this.apiBase}/admin/native/catalog`, { headers: this.actionHeaders() });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `Native catalog failed with HTTP ${res.status}`);
      this.nativePlatform.set(data as NativePlatformResponse);
    } catch (error) {
      this.actionMessage.set({ type: 'danger', message: error instanceof Error ? error.message : String(error) });
    }
  }

  async loadNativeBackends(): Promise<void> {
    try {
      const res = await this.hostFetch(`${this.apiBase}/admin/native/backends`, { headers: this.actionHeaders() });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `Backend detection failed with HTTP ${res.status}`);
      this.nativeBackends.set(data as NativeBackendsResponse);
    } catch (error) {
      this.actionMessage.set({ type: 'danger', message: error instanceof Error ? error.message : String(error) });
    }
  }

  async loadComputeBackends(): Promise<void> {
    try {
      const res = await this.hostFetch(`${this.apiBase}/training/compute`);
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `Compute backend list failed with HTTP ${res.status}`);
      this.computeBackends.set((data.items ?? []) as ResourceItem[]);
    } catch (error) {
      this.computeBackends.set([]);
      this.actionMessage.set({ type: 'danger', message: error instanceof Error ? error.message : String(error) });
    }
  }

  async loadComputeRouting(): Promise<void> {
    try {
      const res = await this.hostFetch(`${this.apiBase}/admin/native/compute-routing`, { headers: this.actionHeaders() });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `Compute routing failed with HTTP ${res.status}`);
      this.computeRouting.set(data as ComputeRoutingResponse);
    } catch (error) {
      this.actionMessage.set({ type: 'danger', message: error instanceof Error ? error.message : String(error) });
    }
  }

  setComputeRoutingField(routeId: string, field: 'primary' | 'fallback', value: string): void {
    this.computeRouting.update((current) => ({
      ...current,
      routes: current.routes.map((route) => route.id === routeId ? { ...route, [field]: value } : route),
    }));
  }

  async saveComputeRouting(): Promise<void> {
    this.saving.set(true);
    this.actionMessage.set(null);
    try {
      const res = await this.hostFetch(`${this.apiBase}/admin/native/compute-routing`, {
        method: 'POST',
        headers: this.actionHeaders(),
        body: JSON.stringify({ routes: this.computeRouting().routes.map((route) => ({ id: route.id, primary: route.primary, fallback: route.fallback })) }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || data.message || `Compute routing save failed with HTTP ${res.status}`);
      this.computeRouting.set(data as ComputeRoutingResponse);
      this.actionMessage.set({ type: 'success', message: 'OAH workload routing saved.' });
      await this.loadComputeBackends();
    } catch (error) {
      this.actionMessage.set({ type: 'danger', message: error instanceof Error ? error.message : String(error) });
    } finally {
      this.saving.set(false);
    }
  }

  async loadControllerMetrics(): Promise<void> {
    try {
      const res = await this.hostFetch(`${this.apiBase}/admin/native/controller-metrics`, { headers: this.actionHeaders() });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `Controller metrics failed with HTTP ${res.status}`);
      this.controllerMetrics.set(data as ControllerMetricsResponse);
    } catch (error) {
      this.actionMessage.set({ type: 'danger', message: error instanceof Error ? error.message : String(error) });
    }
  }

  async loadAuditLog(): Promise<void> {
    try {
      const res = await this.hostFetch(`${this.apiBase}/admin/native/audit-log`, { headers: this.actionHeaders() });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `Audit log failed with HTTP ${res.status}`);
      this.auditLog.set(data as AuditLogResponse);
    } catch (error) {
      this.actionMessage.set({ type: 'danger', message: error instanceof Error ? error.message : String(error) });
    }
  }

  async loadFinalReadiness(): Promise<void> {
    try {
      const res = await this.hostFetch(`${this.apiBase}/admin/native/final-readiness`, { headers: this.actionHeaders() });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `Final readiness failed with HTTP ${res.status}`);
      this.finalReadiness.set(data as FinalReadinessResponse);
    } catch (error) {
      this.actionMessage.set({ type: 'danger', message: error instanceof Error ? error.message : String(error) });
    }
  }

  async loadGpuInventory(): Promise<void> {
    try {
      const res = await this.hostFetch(`${this.apiBase}/admin/native/gpu-inventory`, { headers: this.actionHeaders() });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `GPU inventory failed with HTTP ${res.status}`);
      this.gpuInventory.set(data as GpuInventoryResponse);
    } catch (error) {
      this.actionMessage.set({ type: 'danger', message: error instanceof Error ? error.message : String(error) });
    }
  }

  async loadGpuEnablementPlan(): Promise<void> {
    try {
      const config = this.gpuEnablementConfig();
      const params = new URLSearchParams({
        profile: this.gpuEnablementProfile(),
        namespace: config.namespace,
        resourceName: config.resourceName,
        pluginImage: config.pluginImage,
        runtimeClass: config.runtimeClass,
        useRuntimeClass: String(config.useRuntimeClass),
        nodeSelectorKey: config.nodeSelectorKey,
        nodeSelectorValue: config.nodeSelectorValue,
        packageName: config.packageName,
        channel: config.channel,
        catalogSource: config.catalogSource,
        catalogNamespace: config.catalogNamespace,
        externalEndpoint: config.externalEndpoint,
        credentialSecret: config.credentialSecret,
        maxConcurrency: String(config.maxConcurrency),
      });
      const res = await this.hostFetch(`${this.apiBase}/admin/native/gpu-enablement-plan?${params.toString()}`, { headers: this.actionHeaders() });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `GPU enablement plan failed with HTTP ${res.status}`);
      this.gpuEnablementPlan.set(data as GpuEnablementPlanResponse);
      this.gpuEnablementPreview.set(JSON.stringify(data.manifests || [], null, 2));
    } catch (error) {
      this.actionMessage.set({ type: 'danger', message: error instanceof Error ? error.message : String(error) });
    }
  }

  gpuBridgeRequestBody(): Record<string, string | number> {
    const config = this.gpuEnablementConfig();
    return {
      profile: this.gpuEnablementProfile(),
      endpoint: config.externalEndpoint,
      namespace: config.namespace,
      credentialSecret: config.credentialSecret,
      resourceName: config.resourceName,
      maxConcurrency: config.maxConcurrency,
    };
  }

  async runGpuBridgeProbe(kind: 'health' | 'capabilities' | 'smoke' | 'register' | 'training-smoke'): Promise<void> {
    try {
      this.saving.set(true);
      const res = await this.hostFetch(`${this.apiBase}/admin/native/gpu-bridge/${kind}`, {
        method: 'POST',
        headers: { ...this.actionHeaders(), 'content-type': 'application/json' },
        body: JSON.stringify(this.gpuBridgeRequestBody()),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `${kind} probe failed with HTTP ${res.status}`);
      this.gpuBridgeProbe.set(data as GpuBridgeProbeResponse);
      const lines = (data.logs?.lines || []) as string[];
      this.gpuBridgeProbeLog.set(lines.length ? lines.join('\n') : JSON.stringify(data, null, 2));
      this.actionMessage.set({ type: data.ready ? 'success' : 'warning', message: `GPU bridge ${kind} probe: ${data.phase || 'completed'}` });
      if (kind === 'register' || kind === 'training-smoke') {
        await Promise.all([this.loadGpuEnablementPlan(), this.loadNativeBackends(), this.loadComputeBackends(), this.fetchResourcePage('training-jobs')]);
      }
    } catch (error) {
      this.actionMessage.set({ type: 'danger', message: error instanceof Error ? error.message : String(error) });
    } finally {
      this.saving.set(false);
    }
  }

  async loadOahDemoPlan(): Promise<void> {
    try {
      const res = await this.hostFetch(`${this.apiBase}/admin/native/demo-plan`, { headers: this.actionHeaders() });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `OAH demo plan failed with HTTP ${res.status}`);
      this.oahDemoPlan.set(data as OahDemoPlanResponse);
      if (data.gpu) this.gpuInventory.set(data.gpu as GpuInventoryResponse);
    } catch (error) {
      this.actionMessage.set({ type: 'danger', message: error instanceof Error ? error.message : String(error) });
    }
  }

  async loadOahDemoRun(): Promise<void> {
    try {
      const params = new URLSearchParams({ namespace: this.demoRunNamespace() });
      const res = await this.hostFetch(`${this.apiBase}/admin/native/demo-run?${params.toString()}`, { headers: this.actionHeaders() });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `OAH demo run status failed with HTTP ${res.status}`);
      this.oahDemoRun.set(data as DemoRunStatusResponse);
    } catch (error) {
      this.actionMessage.set({ type: 'danger', message: error instanceof Error ? error.message : String(error) });
    }
  }

  async previewOahDemoRun(): Promise<void> {
    try {
      const params = new URLSearchParams({ namespace: this.demoRunNamespace() });
      const res = await this.hostFetch(`${this.apiBase}/admin/native/demo-run/preview?${params.toString()}`, { headers: this.actionHeaders() });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `OAH demo preview failed with HTTP ${res.status}`);
      this.oahDemoPreview.set(data as DemoRunPreviewResponse);
      this.demoManifestPreview.set(JSON.stringify(data.manifests || [], null, 2));
    } catch (error) {
      this.actionMessage.set({ type: 'danger', message: error instanceof Error ? error.message : String(error) });
    }
  }

  async loadOahDemoEvidence(): Promise<void> {
    try {
      const params = new URLSearchParams({ namespace: this.demoRunNamespace() });
      const res = await this.hostFetch(`${this.apiBase}/admin/native/demo-run/evidence?${params.toString()}`, { headers: this.actionHeaders() });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `OAH demo evidence failed with HTTP ${res.status}`);
      this.oahDemoEvidence.set(data as DemoRunEvidenceResponse);
    } catch (error) {
      this.actionMessage.set({ type: 'danger', message: error instanceof Error ? error.message : String(error) });
    }
  }

  async loadOahDemoSmoke(): Promise<void> {
    try {
      const params = new URLSearchParams({ namespace: this.demoRunNamespace() });
      const res = await this.hostFetch(`${this.apiBase}/admin/native/demo-smoke?${params.toString()}`, { headers: this.actionHeaders() });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `OAH smoke status failed with HTTP ${res.status}`);
      this.oahDemoSmoke.set(data as DemoSmokeStatusResponse);
    } catch (error) {
      this.actionMessage.set({ type: 'danger', message: error instanceof Error ? error.message : String(error) });
    }
  }

  async loadOahDemoSmokeLogs(): Promise<void> {
    try {
      const params = new URLSearchParams({ namespace: this.demoRunNamespace() });
      const res = await this.hostFetch(`${this.apiBase}/admin/native/demo-smoke/logs?${params.toString()}`, { headers: this.actionHeaders() });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `OAH smoke logs failed with HTTP ${res.status}`);
      this.oahDemoSmokeLogs.set(data as DemoSmokeLogsResponse);
      this.smokeLogPreview.set(JSON.stringify(data.items || [], null, 2));
    } catch (error) {
      this.actionMessage.set({ type: 'danger', message: error instanceof Error ? error.message : String(error) });
    }
  }

  async previewOahDemoSmoke(): Promise<void> {
    try {
      const params = new URLSearchParams({ namespace: this.demoRunNamespace() });
      const res = await this.hostFetch(`${this.apiBase}/admin/native/demo-smoke/preview?${params.toString()}`, { headers: this.actionHeaders() });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `OAH smoke preview failed with HTTP ${res.status}`);
      this.oahDemoSmokePreview.set(data as DemoSmokePreviewResponse);
      this.smokeManifestPreview.set(JSON.stringify(data.manifests || [], null, 2));
    } catch (error) {
      this.actionMessage.set({ type: 'danger', message: error instanceof Error ? error.message : String(error) });
    }
  }

  async runOahDemoSmoke(): Promise<void> {
    if (this.saving()) return;
    this.saving.set(true);
    this.actionMessage.set(null);
    try {
      const res = await this.hostFetch(`${this.apiBase}/admin/native/demo-smoke`, {
        method: 'POST',
        headers: this.actionHeaders(),
        body: JSON.stringify({ namespace: this.demoRunNamespace() }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || data.message || `OAH smoke run failed with HTTP ${res.status}`);
      this.oahDemoSmoke.set((data.status || data) as DemoSmokeStatusResponse);
      this.actionMessage.set({ type: data.summary?.failed ? 'warning' : 'success', message: `OAH smoke demo started: ${data.summary?.created || 0} job(s), ${data.summary?.skipped || 0} skipped.` });
      await Promise.all([this.loadOahDemoSmoke(), this.loadOahDemoSmokeLogs(), this.loadOahDemoEvidence(), this.loadControllerMetrics(), this.loadAuditLog(), this.loadFinalReadiness()]);
    } catch (error) {
      this.actionMessage.set({ type: 'danger', message: error instanceof Error ? error.message : String(error) });
    } finally {
      this.saving.set(false);
    }
  }

  async runOahDemo(): Promise<void> {
    if (this.saving()) return;
    this.saving.set(true);
    this.actionMessage.set(null);
    try {
      const res = await this.hostFetch(`${this.apiBase}/admin/native/demo-run`, {
        method: 'POST',
        headers: this.actionHeaders(),
        body: JSON.stringify({ namespace: this.demoRunNamespace() }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || data.message || `OAH demo run failed with HTTP ${res.status}`);
      this.oahDemoRun.set(data as DemoRunStatusResponse);
      this.actionMessage.set({ type: data.summary?.failed ? 'warning' : 'success', message: `OAH demo run completed: ${data.summary?.created || 0} created, ${data.summary?.updated || 0} updated, ${data.summary?.skipped || 0} skipped.` });
      await Promise.all([this.fetchSummary(), this.fetchResourcePage(this.activePage()), this.loadOahDemoPlan(), this.loadGpuInventory(), this.loadOahDemoEvidence(), this.loadOahDemoSmoke(), this.loadOahDemoSmokeLogs(), this.loadControllerMetrics(), this.loadAuditLog(), this.loadFinalReadiness()]);
      this.oahDemoRun.set(data as DemoRunStatusResponse);
    } catch (error) {
      this.actionMessage.set({ type: 'danger', message: error instanceof Error ? error.message : String(error) });
    } finally {
      this.saving.set(false);
    }
  }

  async resetOahDemo(): Promise<void> {
    if (this.saving()) return;
    this.saving.set(true);
    this.actionMessage.set(null);
    try {
      const res = await this.hostFetch(`${this.apiBase}/admin/native/demo-run/reset`, {
        method: 'POST',
        headers: this.actionHeaders(),
        body: JSON.stringify({ namespace: this.demoRunNamespace() }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || data.message || `OAH demo reset failed with HTTP ${res.status}`);
      this.oahDemoRun.set(data as DemoRunStatusResponse);
      this.demoManifestPreview.set('');
      this.oahDemoPreview.set(null);
      this.actionMessage.set({ type: data.summary?.failed ? 'warning' : 'success', message: `OAH demo reset completed: ${data.summary?.deleted || 0} deleted, ${data.summary?.notFound || 0} already absent, ${data.summary?.failed || 0} failed.` });
      await Promise.all([this.fetchSummary(), this.fetchResourcePage(this.activePage()), this.loadOahDemoRun(), this.loadOahDemoEvidence(), this.loadOahDemoSmoke(), this.loadOahDemoSmokeLogs(), this.loadControllerMetrics(), this.loadAuditLog(), this.loadFinalReadiness()]);
    } catch (error) {
      this.actionMessage.set({ type: 'danger', message: error instanceof Error ? error.message : String(error) });
    } finally {
      this.saving.set(false);
    }
  }

  async seedNativeCatalog(): Promise<void> {
    await this.runOperation(
      `${this.apiBase}/admin/native/catalog/seed`,
      {},
      'OpenSphere native AI catalog seeded.',
      async () => {
        await this.loadNativeCatalog();
        await this.loadNativeBackends();
        await this.loadControllerMetrics();
        await this.loadAuditLog();
        await this.loadFinalReadiness();
      },
    );
  }

  async subscribeNativeComponent(component: NativeComponentItem): Promise<void> {
    await this.runOperation(
      `${this.apiBase}/admin/native/subscriptions`,
      { component: component.name, channel: component.channel, version: component.version, installPlanApproval: 'Automatic' },
      `OpenSphere native component subscribed: ${component.displayName}`,
      async () => {
        await this.loadNativeCatalog();
        await this.loadNativeBackends();
        await this.loadControllerMetrics();
        await this.loadAuditLog();
      },
    );
  }

  async approveNativeInstallPlan(component: NativeComponentItem): Promise<void> {
    await this.runOperation(
      `${this.apiBase}/admin/native/installplans/approve`,
      { name: `${component.name}-install`, component: component.name },
      `OpenSphere native install plan approved: ${component.displayName}`,
      async () => {
        await this.loadNativeCatalog();
        await this.loadNativeBackends();
        await this.loadControllerMetrics();
        await this.loadAuditLog();
      },
    );
  }

  async upgradeNativeComponent(component: NativeComponentItem): Promise<void> {
    await this.runOperation(
      `${this.apiBase}/admin/native/installplans/upgrade`,
      { component: component.name },
      `OpenSphere native upgrade plan created: ${component.displayName}`,
      async () => {
        await this.loadNativeCatalog();
        await this.loadControllerMetrics();
        await this.loadAuditLog();
      },
    );
  }

  async rollbackNativeComponent(component: NativeComponentItem): Promise<void> {
    await this.runOperation(
      `${this.apiBase}/admin/native/installplans/rollback`,
      { component: component.name, rollbackVersion: component.rollbackVersion },
      `OpenSphere native rollback plan created: ${component.displayName}`,
      async () => {
        await this.loadNativeCatalog();
        await this.loadControllerMetrics();
        await this.loadAuditLog();
      },
    );
  }

  async createNativeDataScienceCluster(): Promise<void> {
    const components = Object.fromEntries(this.nativePlatform().components.map((component) => [component.name, { managementState: 'Managed' }]));
    await this.runOperation(
      `${this.apiBase}/admin/native/datasciencecluster`,
      { name: 'default-ai', components },
      'OpenSphere native DataScienceCluster requested.',
      async () => {
        await this.loadNativeCatalog();
        await this.loadNativeBackends();
        await this.loadControllerMetrics();
        await this.loadAuditLog();
        await this.loadSetupStatus();
      },
    );
  }

  async reconcileWorkbenches(): Promise<void> {
    await this.runOperation(
      `${this.apiBase}/admin/native/reconcile/workbenches`,
      {},
      'Workbench reconcile requested.',
      async () => {
        await this.fetchResourcePage('workbenches');
        await this.loadControllerMetrics();
        await this.loadAuditLog();
      },
    );
  }

  async reconcilePipelineRuns(): Promise<void> {
    await this.runOperation(
      `${this.apiBase}/admin/native/reconcile/pipelineruns`,
      {},
      'Pipeline run reconcile requested.',
      async () => {
        await this.fetchResourcePage('pipeline-runs');
        await this.loadControllerMetrics();
        await this.loadAuditLog();
      },
    );
  }

  async reconcileInferences(): Promise<void> {
    await this.runOperation(
      `${this.apiBase}/admin/native/reconcile/inferences`,
      {},
      'Inference endpoint reconcile requested.',
      async () => {
        await this.fetchResourcePage('inference');
        await this.loadControllerMetrics();
        await this.loadAuditLog();
      },
    );
  }

  async reconcileEvaluations(): Promise<void> {
    await this.runOperation(
      `${this.apiBase}/admin/native/reconcile/evaluations`,
      {},
      'Evaluation job reconcile requested.',
      async () => {
        await this.fetchResourcePage('eval-jobs');
        await this.fetchResourcePage('model-promotion');
        await this.loadModelVersions();
        await this.loadControllerMetrics();
        await this.loadAuditLog();
      },
    );
  }

  async reconcileModelPromotions(): Promise<void> {
    await this.runOperation(
      `${this.apiBase}/admin/native/reconcile/promotions`,
      {},
      'Model promotion reconcile requested.',
      async () => {
        await this.fetchResourcePage('model-promotion');
        await this.loadModelVersions();
        await this.loadControllerMetrics();
        await this.loadAuditLog();
      },
    );
  }

  async reconcileMonitoringTargets(): Promise<void> {
    await this.runOperation(
      `${this.apiBase}/admin/native/reconcile/monitoring`,
      {},
      'Monitoring target reconcile requested.',
      async () => {
        await this.fetchResourcePage('trustyai-monitoring');
        await this.loadTrustyMetrics(this.resourceItems()[0]);
        await this.loadControllerMetrics();
        await this.loadAuditLog();
      },
    );
  }

  async reconcileDistributedWorkloads(): Promise<void> {
    await this.runOperation(
      `${this.apiBase}/admin/native/reconcile/distributed`,
      {},
      'Distributed workload reconcile requested.',
      async () => {
        await this.fetchResourcePage('distributed-workloads');
        await this.loadControllerMetrics();
        await this.loadAuditLog();
      },
    );
  }

  setSetupField<K extends keyof SetupForm>(field: K, value: SetupForm[K]): void {
    this.setupForm.update((current) => ({ ...current, [field]: value }));
  }

  setSetupNamespaceMode(mode: string): void {
    this.setupForm.update((current) => {
      if (mode === 'new') {
        return { ...current, namespaceMode: mode, namespace: current.namespace || 'opendatahub' };
      }
      const namespace = this.setupNamespaceOptions().includes(current.namespace) ? current.namespace : this.setupNamespaceOptions()[0] || 'opensphere-system';
      return { ...current, namespaceMode: 'existing', namespace };
    });
  }

  setupOperatorPackageOptions(): Array<{ label: string; value: string }> {
    const provider = this.setupForm().provider;
    if (provider === 'rhods') {
      return [
        { label: 'rhods-operator (Red Hat OpenShift AI)', value: 'rhods-operator' },
        { label: 'Custom package', value: this.setupForm().operatorPackage },
      ];
    }
    if (provider === 'internal') {
      return [{ label: 'None - OpenSphere CRDs only', value: '' }];
    }
    return [
      { label: 'opendatahub-operator (Open Data Hub)', value: 'opendatahub-operator' },
      { label: 'Custom package', value: this.setupForm().operatorPackage },
    ];
  }

  setupChannelOptions(): string[] {
    const provider = this.setupForm().provider;
    const defaults = provider === 'rhods' ? ['stable', 'stable-2.16', 'eus-2.16'] : provider === 'internal' ? ['none'] : ['fast', 'stable', 'odh-nightlies'];
    return Array.from(new Set([...defaults, this.setupForm().channel].filter(Boolean)));
  }

  setupCatalogSourceOptions(): string[] {
    const provider = this.setupForm().provider;
    const defaults = provider === 'rhods' ? ['redhat-operators', 'certified-operators'] : provider === 'internal' ? ['none'] : ['community-operators', 'operatorhubio-catalog', 'redhat-operators'];
    return Array.from(new Set([...defaults, this.setupForm().source].filter(Boolean)));
  }

  setupOperatorHelper(): string {
    const provider = this.setupForm().provider;
    if (provider === 'rhods') return 'Preset for Red Hat OpenShift AI. Use redhat-operators unless your cluster has a mirrored catalog.';
    if (provider === 'internal') return 'No Operator is installed. Only OpenSphere foundation CRDs are applied.';
    return 'Preset for upstream Open Data Hub. Use a custom value only for a mirrored or private Operator catalog.';
  }

  setSetupProvider(provider: string): void {
    this.setupForm.update((current) => {
      if (provider === 'rhods') {
        return { ...current, provider, namespaceMode: 'existing', namespace: 'redhat-ods-operator', operatorPackage: 'rhods-operator', source: 'redhat-operators', channel: 'stable', sourceNamespace: 'openshift-marketplace' };
      }
      if (provider === 'internal') {
        return { ...current, provider, namespaceMode: 'existing', namespace: 'opensphere-system', operatorPackage: '', source: 'none', channel: 'none', installOperator: false, createDataScienceCluster: false };
      }
      return { ...current, provider, namespaceMode: 'existing', namespace: 'opendatahub', operatorPackage: 'opendatahub-operator', source: 'community-operators', channel: 'fast', sourceNamespace: 'openshift-marketplace' };
    });
  }

  toggleSetupComponent(component: string, checked: boolean): void {
    this.setupForm.update((current) => {
      const set = new Set(current.components);
      if (checked) {
        set.add(component);
      } else {
        set.delete(component);
      }
      return { ...current, components: Array.from(set) };
    });
  }

  async loadSetupStatus(): Promise<void> {
    try {
      const res = await this.hostFetch(`${this.apiBase}/admin/setup/status`, { headers: this.actionHeaders() });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `Setup status failed with HTTP ${res.status}`);
      this.setupStatus.set(data as SetupStatusResponse);
      if (data.nativePlatform) this.nativePlatform.set(data.nativePlatform as NativePlatformResponse);
    } catch (error) {
      this.actionMessage.set({ type: 'danger', message: error instanceof Error ? error.message : String(error) });
    }
  }

  async previewSetupPlan(): Promise<void> {
    this.saving.set(true);
    this.actionMessage.set(null);
    try {
      const res = await this.hostFetch(`${this.apiBase}/admin/setup/plan`, {
        method: 'POST',
        headers: this.actionHeaders(),
        body: JSON.stringify(this.setupForm()),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `Setup plan failed with HTTP ${res.status}`);
      this.setupSteps.set(data.steps ?? []);
      this.setupManifestPreview.set(JSON.stringify(data.manifests ?? [], null, 2));
    } catch (error) {
      this.actionMessage.set({ type: 'danger', message: error instanceof Error ? error.message : String(error) });
    } finally {
      this.saving.set(false);
    }
  }

  async runSetupInstall(): Promise<void> {
    this.saving.set(true);
    this.actionMessage.set(null);
    try {
      const res = await this.hostFetch(`${this.apiBase}/admin/setup/install`, {
        method: 'POST',
        headers: this.actionHeaders(),
        body: JSON.stringify(this.setupForm()),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `Setup install failed with HTTP ${res.status}`);
      this.setupSteps.set(data.steps ?? []);
      if (data.status) this.setupStatus.set(data.status as SetupStatusResponse);
      this.actionMessage.set({ type: 'success', message: 'AI platform setup run completed. Review step status below.' });
      await this.fetchCapabilities();
      await this.fetchResourcePage(this.activePage());
    } catch (error) {
      this.actionMessage.set({ type: 'danger', message: error instanceof Error ? error.message : String(error) });
    } finally {
      this.saving.set(false);
    }
  }

  private async runOperation(url: string, payload: unknown, successMessage: string, refresh?: () => Promise<void>): Promise<void> {
    if (this.saving()) return;
    this.saving.set(true);
    this.actionMessage.set(null);
    try {
      const res = await this.hostFetch(url, {
        method: 'POST',
        headers: this.actionHeaders(),
        body: JSON.stringify(payload),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.message || data.error || `Operation failed with HTTP ${res.status}`);
      this.actionMessage.set({ type: data.reference ? 'info' : 'success', message: successMessage });
      if (refresh) await refresh();
      await this.fetchSummary();
    } catch (error) {
      this.actionMessage.set({ type: 'danger', message: error instanceof Error ? error.message : String(error) });
    } finally {
      this.saving.set(false);
    }
  }

  private itemParams(item?: ResourceItem): string {
    const params = new URLSearchParams();
    if (item?.name) params.set('name', item.name);
    if (item?.namespace) params.set('namespace', item.namespace);
    return params.toString();
  }

  private async loadModelVersions(): Promise<void> {
    try {
      const [versionsRes, upstreamRes] = await Promise.all([
        this.hostFetch(`${this.apiBase}/models/registry/versions`),
        this.hostFetch(`${this.apiBase}/models/registry/upstream`),
      ]);
      const versionsData = await versionsRes.json().catch(() => ({}));
      const upstreamData = await upstreamRes.json().catch(() => ({}));
      if (!versionsRes.ok) throw new Error(versionsData.error || `Versions failed with HTTP ${versionsRes.status}`);
      if (!upstreamRes.ok) throw new Error(upstreamData.error || `Registry status failed with HTTP ${upstreamRes.status}`);
      this.modelVersions.set(versionsData.items ?? []);
      this.registryPromotions.set(versionsData.promotions ?? []);
      this.registryApprovalAudit.set(versionsData.approvalAudit ?? []);
      this.registryEvaluationMetrics.set(versionsData.evaluationMetrics ?? []);
      this.modelRegistryStatus.set(upstreamData);
    } catch {
      this.modelVersions.set([]);
      this.registryPromotions.set([]);
      this.registryApprovalAudit.set([]);
      this.registryEvaluationMetrics.set([]);
      this.modelRegistryStatus.set({});
    }
  }

  private async loadTrustyMetrics(item?: ResourceItem): Promise<void> {
    const params = new URLSearchParams();
    if (item?.name) params.set('target', item.name);
    try {
      const res = await this.hostFetch(`${this.apiBase}/monitoring/trustyai/metrics?${params.toString()}`);
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `Metrics failed with HTTP ${res.status}`);
      this.trustyMetrics.set(data.items ?? []);
      this.trustyAlerts.set(data.alerts ?? []);
      this.trustyHistory.set(data.history ?? []);
    } catch {
      this.trustyMetrics.set([]);
      this.trustyAlerts.set([]);
      this.trustyHistory.set([]);
    }
  }

  private async loadOdhComponents(): Promise<void> {
    try {
      const res = await this.hostFetch(`${this.apiBase}/admin/odh-components`);
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `ODH components failed with HTTP ${res.status}`);
      this.odhComponents.set(data.items ?? []);
    } catch {
      this.odhComponents.set([]);
    }
  }

  private async loadPageDetails(page: PageId): Promise<void> {
    if (page !== 'pipeline-runs') {
      this.operationTitle.set('');
      this.operationLines.set([]);
      this.lineageItems.set([]);
    }
    if (page === 'model-registry') await this.loadModelVersions();
    if (page === 'trustyai-monitoring') await this.loadTrustyMetrics(this.resourceItems()[0]);
    if (page === 'cluster-settings') {
      await Promise.all([this.loadOdhComponents(), this.loadSetupStatus(), this.loadNativeCatalog(), this.loadNativeBackends(), this.loadComputeBackends(), this.loadComputeRouting(), this.loadControllerMetrics(), this.loadAuditLog(), this.loadFinalReadiness(), this.loadGpuInventory(), this.loadGpuEnablementPlan(), this.loadOahDemoPlan(), this.loadOahDemoRun(), this.loadOahDemoEvidence(), this.loadOahDemoSmoke(), this.loadOahDemoSmokeLogs()]);
    }
  }

  private async loadHomeOperations(): Promise<void> {
    await Promise.all([
      this.fetchResourcePage('apps-enabled'),
      this.loadComputeBackends(),
    ]);
    this.markOperationsRefreshed();
  }

  private startOperationsAutoRefresh(): void {
    if (this.operationsRefreshTimer) return;
    this.operationsRefreshTimer = setInterval(() => {
      void this.refreshOperations('auto');
    }, this.operationsRefreshPeriodSeconds * 1000);
  }

  private stopOperationsAutoRefresh(): void {
    if (!this.operationsRefreshTimer) return;
    clearInterval(this.operationsRefreshTimer);
    this.operationsRefreshTimer = null;
  }

  private async refreshOperations(trigger: 'auto' | 'manual'): Promise<void> {
    if (this.operationsRefreshInFlight) return;
    if (trigger === 'auto' && this.saving()) return;
    this.operationsRefreshInFlight = true;
    this.operationsRefreshStatus.set(trigger === 'auto' ? 'Auto refreshing' : 'Refreshing');
    try {
      const page = this.activePage();
      if (page === 'home') {
        await Promise.all([this.fetchSummary(), this.fetchProjects(), this.fetchResourcePage('apps-enabled'), this.loadComputeBackends()]);
      } else if (page === 'cluster-settings') {
        await Promise.all([this.fetchSummary(), this.loadFinalReadiness(), this.loadControllerMetrics(), this.loadAuditLog()]);
        await Promise.all([this.loadSetupStatus(), this.loadNativeCatalog(), this.loadNativeBackends(), this.loadComputeBackends(), this.loadComputeRouting(), this.loadGpuInventory(), this.loadGpuEnablementPlan(), this.loadOahDemoPlan(), this.loadOahDemoRun(), this.loadOahDemoEvidence(), this.loadOahDemoSmoke(), this.loadOahDemoSmokeLogs()]);
      } else if (page === 'trustyai-monitoring') {
        await Promise.all([this.fetchSummary(), this.loadFinalReadiness(), this.loadControllerMetrics(), this.loadAuditLog()]);
        await this.loadTrustyMetrics(this.resourceItems()[0]);
      } else {
        await this.fetchSummary();
      }
      this.markOperationsRefreshed();
    } finally {
      this.operationsRefreshInFlight = false;
    }
  }

  private markOperationsRefreshed(): void {
    this.operationsLastUpdatedAt.set(new Date().toLocaleTimeString());
    this.operationsRefreshStatus.set('Live');
  }

  private actionHeaders(): Record<string, string> {
    return { 'content-type': 'application/json' };
  }

  private hostFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    if (typeof window === 'undefined') return Promise.reject(new Error('browser Host API unavailable'));
    const w = window as Window & {
      __OPENSPHERE_HOST_CONTEXTS__?: Record<string, { api?: { fetch?: (target: RequestInfo | URL, options?: RequestInit) => Promise<Response> } }>;
    };
    const mediated = w.__OPENSPHERE_HOST_CONTEXTS__?.['ai']?.api?.fetch;
    return mediated ? mediated(input, init) : window.fetch(input, init);
  }

  async refresh(): Promise<void> {
    await Promise.all([this.fetchSummary(), this.fetchProjects(), this.fetchCapabilities()]);
    const page = this.activePage();
    if (page === 'home') {
      await this.loadHomeOperations();
    } else if (page !== 'projects') {
      await this.fetchResourcePage(page);
      if (page === 'cluster-settings' || page === 'trustyai-monitoring') {
        this.markOperationsRefreshed();
      }
    }
  }

  private get apiBase(): string {
    if (typeof window === 'undefined') return '';
    const w = window as Window & { __OSP_AI_API_BASE__?: string; __OSP_NG_API_BASE__?: string };
    return (w.__OSP_AI_API_BASE__ || w.__OSP_NG_API_BASE__ || '').replace(/\/$/, '');
  }

  gpuProductLogoUrl(): string {
    return `${this.apiBase || '/api/plugins/ai'}/app/assets/brand/triangles-opensphere-logo.webp`;
  }

  private async fetchSummary(): Promise<void> {
    try {
      const res = await this.hostFetch(`${this.apiBase}/summary`);
      if (!res.ok) return;
      this.summary.set(await res.json() as SummaryResponse);
    } catch {
      this.summary.set(DEFAULT_SUMMARY);
    }
  }

  private async fetchProjects(): Promise<void> {
    try {
      const res = await this.hostFetch(`${this.apiBase}/projects`);
      if (!res.ok) return;
      const data = await res.json() as ProjectListResponse;
      this.projects.set(data.items ?? []);
    } catch {
      this.projects.set([]);
    }
  }

  private async fetchCapabilities(): Promise<void> {
    try {
      const res = await this.hostFetch(`${this.apiBase}/capabilities`);
      if (!res.ok) return;
      const data = await res.json() as CapabilityResponse;
      this.capabilities.set(data.items ?? []);
    } catch {
      this.capabilities.set([]);
    }
  }

  private async fetchResourcePage(page: PageId): Promise<void> {
    const path = RESOURCE_PATH[page];
      if (!path) {
        this.resourceItems.set([]);
        this.resourceMeta.set({ actualCount: 0, referenceCount: 0, source: 'empty' });
        return;
      }

    this.loadingResource.set(true);
    try {
      const res = await this.hostFetch(`${this.apiBase}/${path}`);
      if (!res.ok) {
        this.resourceItems.set([]);
        this.resourceMeta.set({ actualCount: 0, referenceCount: 0, source: 'empty' });
        return;
      }
      const data = await res.json() as ResourceListResponse;
      this.resourceItems.set(data.items ?? []);
      this.resourceMeta.set({
        actualCount: data.actualCount ?? (data.items ?? []).filter((item) => !item.reference).length,
        referenceCount: data.referenceCount ?? (data.items ?? []).filter((item) => item.reference).length,
        source: data.source || 'empty',
        sourceBreakdown: data.sourceBreakdown,
        backendModes: data.backendModes,
        readinessModel: data.readinessModel,
      });
      await this.loadPageDetails(page);
    } catch {
      this.resourceItems.set([]);
      this.resourceMeta.set({ actualCount: 0, referenceCount: 0, source: 'empty' });
    } finally {
      this.loadingResource.set(false);
    }
  }

  private initialPage(): PageId {
    if (typeof window === 'undefined') return 'home';
    const route = this.currentUiRoute();
    const match = Object.entries(PAGE_ROUTE)
      .filter(([, value]) => value && (route === value || route.startsWith(`${value}/`)))
      .sort((a, b) => b[1].length - a[1].length)[0];
    if (match) return match[0] as PageId;
    return 'home';
  }

  private initialClusterSettingsTab(): ClusterSettingsTab {
    if (typeof window === 'undefined') return 'setup';
    const route = this.currentUiRoute();
    const base = PAGE_ROUTE['cluster-settings'];
    if (route === base) return 'setup';
    if (!route.startsWith(`${base}/`)) return 'setup';
    const tabRoute = route.slice(base.length + 1).split('/')[0];
    const match = Object.entries(CLUSTER_SETTINGS_TAB_ROUTE).find(([, value]) => value === tabRoute);
    return match ? match[0] as ClusterSettingsTab : 'setup';
  }

  private currentUiRoute(): string {
    if (typeof window === 'undefined') return '';
    const parts = window.location.pathname.split('/').filter(Boolean);
    const aiIndex = parts.indexOf('ai');
    if (aiIndex >= 0) return parts.slice(aiIndex + 1).join('/');
    return parts.join('/');
  }

  private initialOpenGroups(): Set<string> {
    const group = groupForPage(this.initialPage());
    return group ? new Set([group]) : new Set();
  }
}
