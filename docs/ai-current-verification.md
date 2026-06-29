# OpenSphere AI current verification

Date: 2026-06-27

## Runtime

- Deployed image: `localhost:5000/ai:v76`
- Namespace: `opensphere-system`
- Deployment: `ai`
- UI plugin package digest: `v76`

## Native readiness

- `/admin/native/final-readiness`
  - `nativePhase`: `Ready`
  - `upstreamPhase`: `ParityNotInstalled`
  - Native checks: `7 ready`, `0 warning`, `0 failed`
  - Upstream parity checks: `4 not installed`

The remaining upstream parity gaps are expected on the current cluster because ODH/RHOAI Operator, OLM/OperatorHub, DataScienceCluster, and upstream Model Registry are not installed. They do not block the OpenSphere-native runtime.

## Actual data coverage

All main `/ai` operational pages currently return cluster-backed data with `referenceCount: 0`.

| Area | Endpoint | Actual |
| --- | --- | ---: |
| Projects | `/projects` | 2 |
| Workbenches | `/workbenches` | 1 |
| Data connections | `/workbenches/data-connections` | 1 |
| Agents | `/resources/agents` | 1 |
| LLM routes | `/foundation/routes` | 2 |
| Retrieval | `/foundation/retrieval` | 1 |
| Pipelines | `/pipelines` | 1 |
| Pipeline runs | `/pipeline/runs` | 1 |
| Compute | `/training/compute` | 1 |
| Datasets | `/training/datasets` | 1 |
| Training jobs | `/training/jobs` | 1 |
| Model promotions | `/models/promotions` | 1 |
| Experiments | `/experiments/runs` | 1 |
| Executions | `/experiments/executions` | 1 |
| Artifacts | `/experiments/artifacts` | 1 |
| Evaluation policies | `/evaluation/policies` | 1 |
| Evaluation jobs | `/evaluation/jobs` | 1 |
| Monitoring | `/monitoring/trustyai` | 1 |
| Distributed workloads | `/distributed/workloads` | 1 |
| Inference | `/inference` | 1 |

## Controller coverage

Native controllers now reconcile both executable and declaration-style resources.

Executable controllers:

- `WorkbenchClaim` -> PVC, Deployment, Service
- `PipelineRunClaim` -> Kubernetes Job or upstream pipeline adapter
- `InferenceClaim` -> Deployment/Service or upstream KServe adapter
- `MonitoringTarget` -> metric status/history/alerts
- `DistributedWorkloadClaim` -> Kubernetes Job or upstream Kueue/Ray adapter
- `EvaluationJob` -> metrics and pass/fail status
- `ModelPromotionClaim` -> approval, promotion, registry, audit, evaluation metrics

Declaration-style status controllers:

- `AIAgent`
- `DataConnectionClaim`
- `LLMRouteClaim`
- `VectorRetrievalClaim`
- `PipelineClaim`
- `ComputeBackendClaim`
- `DatasetClaim`
- `TrainingJobClaim`
- `EvaluationPolicy`
- `ExperimentClaim`
- `ExecutionClaim`
- `ArtifactClaim`

All declaration-style resources are patched through their Kubernetes `/status` subresources after RBAC update. The UI also reads the annotation fallback for older clusters or temporarily restricted CRDs.

## Verification evidence

Last checked against the running pod:

- All operational list endpoints returned `source: cluster`.
- All operational list endpoints returned `referenceCount: 0`.
- No returned operational item was in a not-ready state.
- `/admin/native/audit-log` reported:
  - `activeEntries: 19`
  - `activeWarnings: 0`
  - `kinds: 20`
- `/models/registry/upstream` reported:
  - `summary.phase: FallbackReady`
  - `summary.mode: opensphere`
  - `summary.ready: true`
  - `source.type: opensphere-configmap`

## UI rules

Verification commands:

- `rg -n "style=|\\[ngStyle\\]" src/app frontend/src/app`
- `node --check server.js`
- `npm.cmd run build`
- `npm.cmd run build` in `frontend`

Results:

- No inline `style=` or `[ngStyle]` usage found in the Angular source paths.
- Server syntax check passed.
- Root Angular production build passed.
- Frontend Angular production build passed.
