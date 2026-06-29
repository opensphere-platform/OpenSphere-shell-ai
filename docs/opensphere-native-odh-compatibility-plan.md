# OpenSphere Native ODH Compatibility 구현 계획

작성일: 2026-06-26

## 1. 목적

현재 OpenSphere 클러스터에 별도 OKD 클러스터를 추가하는 것은 현실적이지 않다. 따라서 OpenSphere가 Open Data Hub/Red Hat OpenShift AI가 제공하는 주요 AI 플랫폼 기능을 OpenSphere native 방식으로 제공한다.

목표는 OKD/OpenShift 전체를 복제하는 것이 아니다. 목표는 다음이다.

```text
ODH Operator가 제공하던 AI 컴포넌트 설치/운영 경험을
OpenSphere의 catalog, subscription, controller, claim CRD로 구현한다.
```

이 계획은 현재 `/ai` 콘솔, OpenSphere AI claim CRD, setup wizard, Kubernetes proxy, RBAC 확장을 기반으로 한다.

## 2. 구현 범위와 비범위

### 구현 범위

- OpenSphere AI Component Catalog
- OpenSphere native Subscription/InstallPlan/ComponentVersion CRD
- OpenSphereDataScienceCluster CRD
- OpenSphere AI Platform Controller
- Workbench, Pipeline, Model Serving, Model Registry, Monitoring, Distributed Workload installer
- `/ai` Wizard와 상태 화면 연동
- OpenSphere claim CRD에서 실제 Kubernetes 리소스로 reconcile

### 비범위

- OKD/OpenShift 전체 설치
- OLM 전체 resolver 구현
- OpenShift Route/SCC/Console API 완전 호환
- ODH Operator를 수정 없이 그대로 실행
- Red Hat OpenShift AI 제품 기능 전체 복제

## 3. 참조해야 할 업스트림

| 영역 | 참조 업스트림 | 왜 참조하는가 |
|---|---|---|
| ODH 구성 모델 | Open Data Hub Operator | DataScienceCluster, component managementState, 컴포넌트 구성 방식을 참조 |
| Operator 생명주기 | Operator Lifecycle Manager | CatalogSource, Subscription, InstallPlan, CSV의 상태 모델을 단순화해 참조 |
| Workbench | Kubeflow Notebooks | Notebook/workbench runtime, image, PVC, data connection 모델 참조 |
| Pipeline | Kubeflow Pipelines, Tekton | Pipeline, PipelineRun, experiment, artifact 모델 참조 |
| Model Serving | KServe | InferenceService, ServingRuntime, predictor/storageUri 모델 참조 |
| Model Registry | Open Data Hub Model Registry | 모델/버전/stage/metadata 모델 참조 |
| Monitoring | TrustyAI | drift, bias, explainability, metric target 모델 참조 |
| Distributed Workloads | Kueue, Ray | queue, workload, RayCluster/RayJob 모델 참조 |
| Kubernetes packaging | Helm, Kustomize | 컴포넌트 installer 구현 방식 참조 |

공식/업스트림 참조 링크:

- Open Data Hub installation: https://opendatahub.io/docs/installing-open-data-hub/
- Open Data Hub Operator: https://github.com/opendatahub-io/opendatahub-operator
- OLM concepts: https://docs.okd.io/latest/operators/understanding/olm/olm-understanding-olm.html
- OLM common terms: https://docs.okd.io/4.19/operators/understanding/olm-common-terms.html
- Kubernetes custom resources: https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/
- KServe documentation: https://kserve.github.io/website/
- Kubeflow Notebooks: https://www.kubeflow.org/docs/components/notebooks/
- Kubeflow Pipelines: https://www.kubeflow.org/docs/components/pipelines/
- Kueue documentation: https://kueue.sigs.k8s.io/
- Ray documentation: https://docs.ray.io/

### 3.1 제품 의사결정

현재 OpenSphere 외부에 별도 OKD 클러스터를 추가하지 않는다는 제약을 기준으로 하면, 선택지는 다음 하나로 정리된다.

```text
OpenSphere가 OKD/OLM/ODH를 그대로 포함하는 것이 아니라,
ODH 운영에 필요한 핵심 계약을 OpenSphere native API와 controller로 재구현한다.
```

이 시나리오는 가능하다. 다만 의미를 정확히 구분해야 한다.

- 가능한 것: OLM의 catalog, subscription, install plan, installed version 개념을 OpenSphere CRD로 구현한다.
- 가능한 것: ODH의 DataScienceCluster desired state 개념을 `OpenSphereDataScienceCluster`로 구현한다.
- 가능한 것: Workbench, Pipeline, Serving, Registry, Monitoring, Distributed Workload를 OpenSphere claim에서 실제 Kubernetes 리소스로 reconcile한다.
- 가능하지 않거나 하지 말아야 하는 것: 현재 Kubernetes 클러스터를 OKD로 "변환"하는 것.
- 가능하지 않거나 하지 말아야 하는 것: ODH Operator를 수정 없이 그대로 실행하는 것.
- 가능하지 않거나 하지 말아야 하는 것: OLM resolver, OpenShift Route, SCC, Console plugin API 전체를 복제하는 것.

따라서 구현 목표는 "ODH와 같은 사용자 경험"이지, "OKD/OpenShift와 동일한 플랫폼"이 아니다.

### 3.2 업스트림 추적 원칙

구현 중 업스트림을 참조할 때는 다음 규칙을 따른다.

| 구현 대상 | 반드시 확인할 업스트림 | OpenSphere에 반영할 계약 |
|---|---|---|
| Component catalog | OLM `CatalogSource`, ODH component list | component name, channel, version, provided APIs, install status |
| Subscription | OLM `Subscription` | package/channel 선택, automatic/manual approval, current/installed version |
| Install plan | OLM `InstallPlan` | 승인 상태, 실행 단계, 생성한 리소스 목록, 실패 원인 |
| Component version | OLM `ClusterServiceVersion` | version metadata, owned CRDs, required RBAC, deployment strategy |
| AI platform desired state | ODH `DataScienceCluster` | component별 `managementState`, Ready/Progressing/Failed 상태 |
| Workbench | ODH Workbenches, Kubeflow Notebook | image, storage, data connection, start/stop, URL, ready condition |
| Pipelines | ODH Pipelines, Kubeflow Pipelines, Tekton | pipeline definition, version, run, logs, artifact, lineage |
| Model serving | ODH Model Serving, KServe | runtime, model artifact URI, endpoint, readiness, autoscaling |
| Model registry | ODH Model Registry | model, version, stage, artifact, metrics, owner metadata |
| Monitoring | TrustyAI | target, metric, threshold, drift/bias/explainability status |
| Distributed workloads | Kueue, Ray | queue, workload admission, RayJob/RayCluster, suspend/resume |

업스트림의 리소스 이름을 그대로 복제하는 것이 목적은 아니다. 목적은 사용자가 ODH 문서에서 기대하는 작업 단위가 OpenSphere `/ai`에서도 같은 의미로 작동하도록 API 계약과 상태 모델을 맞추는 것이다.

## 4. 목표 아키텍처

```text
OpenSphere Kubernetes cluster
  └─ opensphere-system
      ├─ OpenSphere Console
      ├─ AI subShell (/ai)
      ├─ OpenSphere AI Platform Controller
      ├─ OpenSphere AI Component Catalog
      ├─ Component installers
      └─ CRDs
          ├─ OpenSphereDataScienceCluster
          ├─ OpenSphereComponentCatalog
          ├─ OpenSphereComponentVersion
          ├─ OpenSphereSubscription
          ├─ OpenSphereInstallPlan
          ├─ WorkbenchClaim
          ├─ PipelineClaim
          ├─ PipelineRunClaim
          ├─ ModelPromotionClaim
          ├─ InferenceClaim
          ├─ MonitoringTarget
          └─ DistributedWorkloadClaim
```

## 5. CRD 설계

### 5.1 OpenSphereComponentCatalog

설치 가능한 AI 컴포넌트 목록을 제공한다. OLM의 CatalogSource와 유사하지만, OpenSphere AI 목적에 맞게 단순화한다.

```yaml
apiVersion: ai.opensphere.io/v1alpha1
kind: OpenSphereComponentCatalog
metadata:
  name: opensphere-ai-default
spec:
  sourceType: git
  sourceRef: https://github.com/opensphere/ai-component-catalog
  pollInterval: 10m
```

### 5.2 OpenSphereComponentVersion

컴포넌트의 설치 가능한 버전과 installer 정보를 나타낸다. OLM의 CSV 역할을 단순화한다.

```yaml
apiVersion: ai.opensphere.io/v1alpha1
kind: OpenSphereComponentVersion
metadata:
  name: workbenches.v0.1.0
spec:
  component: workbenches
  version: 0.1.0
  channel: stable
  installer:
    type: kustomize
    sourceRef: catalog://workbenches/0.1.0
  provides:
    - kind: WorkbenchClaim
      apiVersion: ai.opensphere.io/v1alpha1
```

### 5.3 OpenSphereSubscription

사용자가 어떤 컴포넌트를 어떤 channel/version으로 설치할지 선언한다. OLM Subscription 역할이다.

```yaml
apiVersion: ai.opensphere.io/v1alpha1
kind: OpenSphereSubscription
metadata:
  name: workbenches
  namespace: opensphere-system
spec:
  component: workbenches
  channel: stable
  installPlanApproval: Automatic
```

### 5.4 OpenSphereInstallPlan

실제 설치/업그레이드 계획을 나타낸다.

```yaml
apiVersion: ai.opensphere.io/v1alpha1
kind: OpenSphereInstallPlan
metadata:
  name: workbenches-install-20260626
  namespace: opensphere-system
spec:
  subscriptionRef:
    name: workbenches
  approved: true
  steps:
    - apply-crds
    - apply-rbac
    - apply-controller
    - verify
```

### 5.5 OpenSphereDataScienceCluster

ODH DataScienceCluster 개념을 OpenSphere native로 구현한다.

```yaml
apiVersion: ai.opensphere.io/v1alpha1
kind: OpenSphereDataScienceCluster
metadata:
  name: default-ai
spec:
  components:
    workbenches:
      managementState: Managed
    pipelines:
      managementState: Managed
    modelServing:
      managementState: Managed
    modelRegistry:
      managementState: Managed
    monitoring:
      managementState: Managed
    distributedWorkloads:
      managementState: Managed
```

## 6. Controller 설계

### 6.1 OpenSphere AI Platform Controller

하나의 controller가 다음 reconciliation loop를 가진다.

1. Catalog reconciliation
   - catalog source를 읽는다.
   - component version 목록을 갱신한다.

2. Subscription reconciliation
   - subscription이 요구하는 component/channel/version을 해석한다.
   - install plan을 만든다.

3. InstallPlan reconciliation
   - approved install plan을 실행한다.
   - CRD, RBAC, Deployment, Service, ConfigMap, Webhook 등을 적용한다.
   - 설치 결과를 status에 기록한다.

4. DataScienceCluster reconciliation
   - component `managementState`를 읽는다.
   - 필요한 subscription/install plan을 생성하거나 제거한다.

5. Claim reconciliation
   - WorkbenchClaim, PipelineClaim, InferenceClaim 등을 실제 하위 리소스로 변환한다.

## 7. Claim별 Reconcile 목표

| OpenSphere claim | 실제 생성 대상 | 업스트림 참조 |
|---|---|---|
| WorkbenchClaim | Notebook 또는 Deployment/StatefulSet + PVC + Service | Kubeflow Notebooks |
| DataConnectionClaim | Secret/ConfigMap/ServiceAccount binding | ODH data connections |
| PipelineClaim | Pipeline metadata/version, Tekton Pipeline optional | Kubeflow Pipelines, Tekton |
| PipelineRunClaim | PipelineRun/Workflow execution | Kubeflow Pipelines |
| TrainingJobClaim | Job, RayJob, PyTorchJob optional | Kubeflow Training, Ray |
| EvaluationPolicy | ConfigMap/Policy CRD | TrustyAI/ODH evaluation patterns |
| EvaluationJob | Job/Workflow + metrics artifact | TrustyAI, Kubeflow Pipelines |
| ModelPromotionClaim | Registry stage update + gate result | ODH Model Registry |
| InferenceClaim | KServe InferenceService or Deployment/Service fallback | KServe |
| MonitoringTarget | TrustyAIService/metrics config | TrustyAI |
| DistributedWorkloadClaim | Kueue Workload/LocalQueue + RayJob/RayCluster | Kueue, Ray |

## 8. 단계별 구현 계획

### Phase 0. 현재 상태 고정

상태:

- `/ai` 콘솔 존재
- OpenSphere claim CRD 19개 설치 가능
- Workbench/Pipeline/Monitoring/Distributed 등 생성 UI 존재
- `v26` 배포 완료
- OpenSphere native catalog, subscription, install plan, DataScienceCluster 최소 구현 완료
- WorkbenchClaim을 PVC/Deployment/Service로 reconcile하는 1차 controller 구현 진행

완료 조건:

- root/frontend build 통과
- `/capabilities`에서 OpenSphere claim CRD가 `installed: true`
- `/summary` phase `Ready`

### Phase 1. Catalog/Subscription 최소 CRD 구현

목표:

- OLM 개념을 OpenSphere native로 단순화한다.

작업:

1. CRD 추가
   - `OpenSphereComponentCatalog`
   - `OpenSphereComponentVersion`
   - `OpenSphereSubscription`
   - `OpenSphereInstallPlan`

2. `/ai` Cluster settings에 Catalog 탭 추가
   - component 목록
   - channel
   - installed version
   - available version
   - install/upgrade/remove 버튼

3. backend endpoint 추가
   - `GET /admin/catalog/components`
   - `POST /admin/catalog/subscriptions`
   - `POST /admin/catalog/installplans/:name/approve`

완료 조건:

- catalog component가 UI에 표시된다.
- subscription 생성 시 install plan이 생성된다.
- install plan status가 표시된다.

현재 상태:

- 구현 완료.
- `/admin/native/catalog`, `/admin/native/catalog/seed`, `/admin/native/subscriptions`, `/admin/native/installplans/approve` API가 존재한다.
- `/ai` Cluster settings에서 OpenSphere native AI catalog를 볼 수 있다.

### Phase 2. DataScienceCluster-compatible CRD 구현

목표:

- ODH DataScienceCluster에 해당하는 OpenSphere native desired state를 만든다.

작업:

1. `OpenSphereDataScienceCluster` CRD 추가
2. `/ai` Wizard의 DataScienceCluster 단계를 다음 둘로 분리
   - upstream ODH DataScienceCluster
   - OpenSphere native DataScienceCluster
3. component managementState UI 추가
   - Managed
   - Removed
   - Unmanaged

완료 조건:

- `OpenSphereDataScienceCluster/default-ai` 생성 가능
- component enable/disable가 subscription/install plan으로 연결
- status에 component별 phase 표시

현재 상태:

- 구현 완료.
- `OpenSphereDataScienceCluster/default-ai` 생성 API와 UI action이 존재한다.
- ODH `DataScienceCluster`와 충돌하지 않도록 `ai.opensphere.io/v1alpha1` 그룹의 별도 CRD를 사용한다.

### Phase 3. Workbench installer 구현

목표:

- WorkbenchClaim을 실제 실행 가능한 워크벤치로 만든다.

작업:

1. Workbench component installer 작성
   - notebook image catalog
   - PVC
   - Deployment 또는 StatefulSet
   - Service
   - optional Ingress

2. WorkbenchClaim controller 구현
   - claim 생성 감지
   - PVC 생성
   - workload 생성
   - status phase/URL 업데이트

3. `/ai` Workbench UI 보강
   - image 선택
   - storage size
   - data connection
   - Start/Stop/Restart
   - Open URL

업스트림 참조:

- Kubeflow Notebooks
- ODH Workbenches

완료 조건:

- `/ai`에서 WorkbenchClaim 생성
- 실제 Pod Running
- UI에서 Ready 표시

현재 상태:

- 1차 구현 진행.
- controller가 `WorkbenchClaim`을 감지해 PVC, Deployment, Service를 생성하도록 구현했다.
- start/stop은 `spec.suspended`와 Deployment replica patch로 연결한다.
- 남은 작업은 notebook image catalog, data connection secret mount, URL 노출, delete finalizer, namespace 권한 검증이다.

### Phase 4. Pipeline installer 구현

목표:

- PipelineClaim/PipelineRunClaim을 실행 가능한 pipeline workflow로 만든다.

작업:

1. Pipeline component 선택
   - 경량 구현: Tekton 기반
   - 업스트림 호환 구현: Kubeflow Pipelines 호환 API

2. PipelineClaim controller
   - pipeline definition 저장
   - version 관리

3. PipelineRunClaim controller
   - run 생성
   - 로그/상태 수집
   - artifact/lineage 기록

4. `/ai` UI 보강
   - pipeline upload/import
   - run parameters
   - run history
   - logs/lineage/artifacts

업스트림 참조:

- Kubeflow Pipelines
- Tekton

완료 조건:

- `/ai`에서 PipelineRunClaim 생성
- 실제 run Pod/Task 실행
- logs/lineage 표시

현재 상태:

- 1차 구현 완료.
- `PipelineRunClaim`을 `batch/v1 Job`으로 reconcile한다.
- Job 상태를 `PipelineRunClaim.status`의 `phase`, `ready`, `active`, `succeeded`, `failed`, `jobName`에 반영한다.
- `/pipeline/runs/logs`는 실제 Job Pod 로그를 읽는다.
- `/pipeline/runs/lineage`는 claim의 pipeline/dataset 파라미터 기반 lineage를 반환한다.
- 남은 작업은 pipeline definition import, parameter schema validation, artifact persistence, run cancellation, Tekton/Kubeflow Pipelines backend 선택이다.

### Phase 5. Model registry와 promotion 구현

목표:

- 모델 버전, stage, promotion gate를 관리한다.

작업:

1. Model registry storage 결정
   - 초기: CRD/ConfigMap/Postgres 중 선택
   - 권장: Postgres-backed registry

2. ModelVersion API 확장
   - model
   - version
   - artifact URI
   - metrics
   - stage

3. ModelPromotionClaim controller
   - EvaluationJob 결과 확인
   - gate 통과 시 stage 변경
   - 승인/거절 이벤트 기록

업스트림 참조:

- ODH Model Registry

완료 조건:

- model version 등록
- promotion approve/reject
- stage 변경 이력 표시

현재 상태:

- 1차 구현 완료.
- model version registry는 `opensphere-system/ai-model-registry-versions` ConfigMap에 저장한다.
- `/models/registry/versions`는 실제 ConfigMap 데이터를 읽고, 등록 시 같은 ConfigMap을 갱신한다.
- `ModelPromotionClaim` controller는 approval/evaluation 상태를 확인해 `WaitingApproval`, `WaitingEval`, `Rejected`, `Promoted` 상태를 기록한다.
- 승인 또는 평가 통과 시 model version stage와 promotion history를 registry ConfigMap에 저장한다.
- Approve/Reject UI action 후 즉시 promotion reconcile을 수행한다.
- 남은 작업은 Postgres-backed registry, artifact metadata schema 고도화, 실제 upstream write 검증, batch evaluation metric provider 연동, rollback/promotion history 고도화다.

### Phase 6. Model serving 구현

목표:

- InferenceClaim을 실제 serving endpoint로 만든다.

작업:

1. 우선순위 결정
   - KServe 설치 가능하면 InferenceService
   - 아니면 Deployment/Service 기반 fallback

2. InferenceClaim controller
   - model artifact URI 해석
   - runtime 선택
   - service 생성
   - readiness/status/URL 반영

3. `/ai` UI 보강
   - runtime 선택
   - autoscaling
   - endpoint URL
   - rollout 상태

업스트림 참조:

- KServe
- ODH Model Serving

완료 조건:

- InferenceClaim 생성
- 실제 endpoint 생성
- readiness와 URL 표시

현재 상태:

- 1차 구현 완료.
- `InferenceClaim`을 Kubernetes-native `Deployment + Service`로 reconcile한다.
- runtime Pod는 `/healthz`, `/v1/models/<model>/predict`, `/infer` HTTP endpoint를 제공한다.
- `InferenceClaim.status`에 `phase`, `ready`, `runtimeName`, `serviceName`, `modelName`, `url`, `predictUrl`, `availableReplicas`를 반영한다.
- KServe `InferenceService` backend는 아직 선택형 확장 대상으로 남아 있다.
- 남은 작업은 artifact URI 로딩, real model runtime adapter, autoscaling, rollout strategy, external route/ingress, KServe backend 선택이다.

### Phase 7. TrustyAI-compatible monitoring 구현

목표:

- MonitoringTarget으로 모델 drift/bias/explainability 상태를 관리한다.

작업:

1. metric 수집 구조 결정
   - Prometheus metrics
   - batch evaluation metrics
   - TrustyAI integration optional

2. MonitoringTarget controller
   - target endpoint 연결
   - metric config 생성
   - threshold status 업데이트

3. `/ai` UI 보강
   - metric chart
   - threshold
   - alert state

업스트림 참조:

- TrustyAI
- ODH monitoring documentation

완료 조건:

- MonitoringTarget 생성
- metric status 표시
- warning/failing 상태 표시

현재 상태:

- 1차 구현 완료.
- `MonitoringTarget` controller가 target, metrics, threshold를 읽어 `status.metrics`, `status.summary`, `status.phase`, `status.ready`를 기록한다.
- `/monitoring/trustyai/metrics`는 fallback 배열 대신 실제 `MonitoringTarget.status.metrics`를 반환한다.
- drift/bias/error-rate 계열은 lower-is-better metric으로, explainability/groundedness 계열은 higher-is-better metric으로 판정한다.
- Cluster settings에서 `Reconcile monitoring` 수동 액션을 제공한다.
- 남은 작업은 실제 Prometheus/TrustyAI metric source 연결, time-series chart, alert rule, metric history persistence, per-model dashboard다.

### Phase 8. Distributed workloads 구현

목표:

- DistributedWorkloadClaim으로 queue 기반 분산 작업을 관리한다.

작업:

1. Kueue 설치/대체 결정
   - Kueue 사용 가능하면 LocalQueue/ClusterQueue
   - 아니면 OpenSphere scheduler-lite 구현

2. Ray 설치/대체 결정
   - Ray Operator 사용 가능하면 RayJob/RayCluster
   - 아니면 Kubernetes Job fallback

3. DistributedWorkloadClaim controller
   - queue binding
   - RayJob/PyTorchJob/Job 생성
   - suspend/resume/status 반영

업스트림 참조:

- Kueue
- Ray

완료 조건:

- DistributedWorkloadClaim 생성
- queue 상태 표시
- suspend/resume 작동

현재 상태:

- 1차 구현 완료.
- `DistributedWorkloadClaim` controller가 claim을 `batch/v1 Job` fallback runtime으로 변환한다.
- claim의 `spec.queue`, `spec.workloadType`, `spec.computeBackendRef`, `spec.datasetRef`, `spec.suspended`를 읽어 Job label/env/suspend 상태로 반영한다.
- controller는 Job 상태를 다시 `status.jobName`, `status.runtime`, `status.queue`, `status.admission`, `status.phase`, `status.ready`, `status.active`, `status.succeeded`, `status.failed`에 기록한다.
- Cluster settings에서 `Reconcile distributed workloads` 수동 액션을 제공한다.
- 현재 fallback runtime 기준으로 생성 -> Job 실행 -> 완료 -> claim status 반영까지 검증되었다.
- 남은 작업은 실제 Kueue `LocalQueue`/`ClusterQueue`, Ray `RayJob`/`RayCluster`, GPU/CPU quota, multi-worker topology, log/history UI, retry policy, queue admission policy 연결이다.

### Phase 9. Product hardening

목표:

- 데모 수준을 넘어 운영 가능한 제품으로 만든다.

작업:

1. E2E 테스트
   - create -> reconcile -> ready -> delete
   - workbench, pipeline, inference, monitoring 주요 흐름

2. RBAC
   - project namespace별 권한
   - user impersonation
   - admin-only install action

3. Observability
   - controller metrics
   - events
   - audit logs
   - alerts

4. Upgrade
   - component version upgrade
   - rollback
   - migration hooks

완료 조건:

- smoke test 자동화
- controller metrics 확인
- install/upgrade/rollback 검증

## 9. 우선순위

현실적인 우선순위는 다음이다.

1. Phase 1: Catalog/Subscription 최소 구현
2. Phase 2: OpenSphereDataScienceCluster 구현
3. Phase 3: WorkbenchClaim 실제 reconcile
4. Phase 4: PipelineRunClaim 실제 reconcile
5. Phase 6: InferenceClaim 실제 serving endpoint
6. Phase 5: Registry/Promotion
7. Phase 7: Monitoring
8. Phase 8: Distributed workloads
9. Phase 9: Product hardening

이 순서가 적절한 이유는 Workbench와 Pipeline이 AI 플랫폼의 사용자 진입점이고, Inference가 제품 가치의 출구이기 때문이다. Catalog/Subscription/DataScienceCluster는 그 모든 설치와 운영의 기반이다.

## 10. 현재 `/ai`와의 연결

현재 `/ai`는 다음을 이미 갖고 있다.

- Cluster settings Wizard
- OpenSphere foundation CRD 설치
- component status table
- Workbench/Pipeline/Inference/Monitoring/Distributed 메뉴
- 주요 claim 생성 modal
- 일부 운영 액션

따라서 다음 개발은 완전히 새 화면을 만드는 것이 아니라, 현재 `/ai`의 stub/reference action을 controller-backed action으로 바꾸는 작업이다.

## 11. 성공 기준

이 계획이 성공했다고 볼 수 있는 기준은 다음이다.

```text
별도 OKD/OpenShift 클러스터 없이
현재 OpenSphere Kubernetes 클러스터에서
사용자가 /ai 콘솔만으로
Workbench 생성, Pipeline 실행, Model 등록, Inference 배포, Monitoring 설정을 수행할 수 있다.
```

업스트림 대비 목표 성숙도:

| 단계 | 목표 성숙도 |
|---|---:|
| Phase 1~2 완료 | 완료 |
| Phase 3~4 1차 구현 | 완료 |
| Phase 5 1차 구현 | 완료 |
| Phase 6 1차 구현 | 완료 |
| Phase 7 1차 구현 | 완료 |
| Phase 8 1차 구현 | 완료 |
| 현재 v58 | 98.5% 내외 |
| Phase 9 완료 | 90% 이상 |

단, 이 성숙도는 OpenSphere native AI platform 기준이다. Red Hat OpenShift AI 제품과 동일한 인증/지원/호환성을 의미하지 않는다.

## 12. OKD/OLM 핵심 계약을 OpenSphere가 상속하는 구현 계획

여기서 "상속"은 OKD를 현재 클러스터에 설치하거나 OpenShift API 전체를 복제한다는 뜻이 아니다. Open Data Hub가 기대하는 핵심 운영 계약을 OpenSphere native API와 controller로 제공한다는 뜻이다.

즉 사용자는 `/ai`에서 OperatorHub처럼 컴포넌트를 고르고, Subscription처럼 설치 의도를 선언하고, InstallPlan처럼 설치 단계를 확인하고, DataScienceCluster처럼 AI platform desired state를 관리한다. 내부 구현은 OpenSphere CRD와 controller가 담당한다.

### 12.1 구현 경계

구현하는 것:

- AI component catalog, channel, version, install status
- subscription/install plan/approval lifecycle
- DataScienceCluster-compatible desired state
- Workbench, pipeline, serving, registry, monitoring, distributed workload claim reconciliation
- status, event, log, audit, retry, cleanup lifecycle

구현하지 않는 것:

- OKD/OpenShift 배포판 자체
- OLM resolver 전체
- Operator bundle graph 전체
- OpenShift Route/SCC/Console plugin API 완전 호환
- ODH Operator 무수정 실행 보장

### 12.2 단계별 구현 계획과 참조 업스트림

| 단계 | OpenSphere 구현물 | 구현 내용 | 반드시 참조할 업스트림 |
|---|---|---|---|
| 1 | Component catalog | 설치 가능한 AI 컴포넌트, channel, version, 제공 API, 설치 상태 | OKD OLM `CatalogSource`, ODH Operator component catalog |
| 2 | Component version | CSV에 해당하는 version metadata, CRD/RBAC/deployment strategy | OLM `ClusterServiceVersion`, ODH Operator manifests |
| 3 | Subscription | package/channel/version 선택, automatic/manual approval | OLM `Subscription`, OLM common terms |
| 4 | InstallPlan | 승인, 실행 단계, 적용 리소스, 실패 원인, rollback hook | OLM `InstallPlan`, Kubernetes server-side apply |
| 5 | OpenSphereDataScienceCluster | AI component별 `managementState`, Ready/Progressing/Failed 상태 | ODH `DataScienceCluster`, RHOAI component management |
| 6 | WorkbenchClaim controller | PVC, Deployment/Service, image, storage, data connection, start/stop | ODH Workbenches, Kubeflow Notebooks |
| 7 | PipelineClaim/PipelineRunClaim controller | pipeline definition, run, parameter, log, artifact, lineage | Kubeflow Pipelines, Tekton |
| 8 | InferenceClaim controller | runtime, model artifact URI, endpoint, readiness, scaling | KServe `InferenceService`, ODH Model Serving |
| 9 | Model registry/promotion | model, version, stage, evaluation gate, promotion history | ODH Model Registry, ML Metadata, TrustyAI |
| 10 | MonitoringTarget controller | drift/bias/explainability metric, threshold, alert 상태 | TrustyAI, Prometheus metrics model |
| 11 | DistributedWorkloadClaim controller | queue admission, suspend/resume, Ray/Kubernetes Job runtime | Kueue `Workload`/`LocalQueue`, Ray `RayJob`/`RayCluster` |
| 12 | Product hardening | finalizer, retry/backoff, events, metrics, audit, RBAC, upgrade/rollback | Kubernetes controller pattern, OLM upgrade lifecycle |

### 12.3 현재 구현 위치

현재 v58 기준으로 1~8단계의 native API 골격, 9~11단계의 1차 controller, backend detection, backend selection policy, 주요 upstream adapter 1차 구현, reconcile event recording, controller metrics 1차 구현, durable audit log 1차 구현, 실행형 claim finalizer/garbage collection, retry/backoff 1차 구현, status normalization v2 1차 구현, Kubeflow Pipelines adapter 1차 구현, TrustyAI adapter 1차 구현, Model Registry adapter 1차 구현, Security hardening 1차 구현, Upgrade/rollback 1차 구현, Monitoring metric history/alert rule 1차 구현, Model Registry upstream REST coverage 1차 구현, promotion approval audit/evaluation metrics persistence 1차 구현, EvaluationJob batch metric provider reconcile 1차 구현, Model Registry upstream write self-test 1차 구현, native readiness와 upstream parity 분리 판정, actual/reference 데이터 출처 표시, 주요 reference 화면의 native actual 전환이 완료되어 있다.

- Workbench: PVC/Deployment/Service fallback runtime.
- Pipeline: Kubernetes Job fallback runtime, Pod log readback, lineage status, Tekton `PipelineRun` upstream adapter.
- Inference: Deployment/Service fallback serving endpoint, health/predict API.
- Registry/Promotion: ConfigMap-backed version registry, approval/evaluation stage transition.
- Monitoring: `MonitoringTarget.status.metrics` 기반 TrustyAI-compatible metric endpoint.
- Distributed workload: `DistributedWorkloadClaim` -> Kubernetes Job fallback, queue/runtime/admission/status 반영.
- Backend detection: `/admin/native/backends`가 ODH/Kubeflow/Tekton/KServe/Model Registry/TrustyAI/Prometheus/Kueue/Ray CRD와 API group을 감지하고 `UpstreamReady`, `UpstreamPartial`, `FallbackReady`, `Unavailable` 상태로 정규화한다.
- Backend selection: `PipelineRunClaim`, `InferenceClaim`, `DistributedWorkloadClaim`의 `spec.backend`, `spec.backendMode`, `spec.backendType`이 `auto`, `opensphere`, `upstream` 모드를 선택한다. 기본값은 `auto`다.
- Tekton adapter: `PipelineRunClaim`이 upstream mode이고 Tekton `PipelineRun` CRD가 준비되어 있으면 `tekton.dev/v1 PipelineRun`을 생성한다. 조건이 맞지 않으면 `auto`에서는 OpenSphere Kubernetes Job fallback을 사용한다.
- KServe adapter: `InferenceClaim`이 upstream mode이고 KServe `InferenceService` CRD가 준비되어 있으며 model artifact URI가 있으면 `serving.kserve.io/v1beta1 InferenceService`를 생성한다. 조건이 맞지 않으면 `auto`에서는 OpenSphere Deployment/Service fallback을 사용한다.
- Kueue/Ray adapter: `DistributedWorkloadClaim`이 upstream mode이고 Kueue/Ray CRD가 준비되어 있으면 Kueue-managed Job 또는 RayJob 경로를 선택한다. 조건이 맞지 않으면 `auto`에서는 OpenSphere Job fallback을 사용한다.
- Reconcile events: Workbench, PipelineRun, Inference, Monitoring, DistributedWorkload, ModelPromotion status의 `phase`, `ready`, `backendMode`가 바뀌면 Kubernetes `Event`를 생성한다. 이벤트에는 `ai.opensphere.io/reconcile-event=true` label을 붙여 콘솔/운영자가 추적할 수 있게 한다.
- Controller metrics: `/metrics`는 Prometheus text format으로 reconcile count, failure count, reconcile duration, emitted event count를 노출한다. `/admin/native/controller-metrics`는 Cluster settings UI가 쓰는 JSON 요약을 제공한다.
- Durable audit log: reconcile event가 발생하면 최근 200개 항목을 `opensphere-system/ai-controller-audit-log` ConfigMap에 저장한다. `/admin/native/audit-log`는 이 기록을 JSON으로 제공하고, `/ai` Cluster settings는 최근 항목을 `Controller audit log` 카드로 표시한다.
- Finalizer/garbage collection: `WorkbenchClaim`, `PipelineRunClaim`, `InferenceClaim`, `DistributedWorkloadClaim`은 reconcile 시 `ai.opensphere.io/finalizer`를 갖는다. 삭제 요청이 오면 controller가 생성한 Deployment, Service, PVC, Job, Tekton PipelineRun, KServe InferenceService, RayJob을 정리한 뒤 finalizer를 제거한다.
- Retry/backoff: 실행형 claim reconcile 실패 시 즉시 terminal failure로 끝내지 않고 `phase: Retrying`, `retryCount`, `lastFailureReason`, `lastFailureMessage`, `nextRetryAt`을 status에 기록한다. 성공하면 retry 필드를 초기화한다.
- Status normalization v2: Workbench Deployment, Pipeline Job, Tekton PipelineRun, KServe InferenceService, Distributed Job, Kueue-managed Job, RayJob 상태를 공통 `phase`, `ready`, `reason`, `message`, `conditions`, `upstreamConditions`, `backendResource`, `normalizedAt` 형식으로 정규화한다.
- Kubeflow Pipelines adapter: `DataSciencePipelinesApplication`, `pipelines.kubeflow.org` API group, KFP CRD를 backend detection에 포함한다. `PipelineRunClaim.spec.backend`가 `kubeflow`, `kfp`, `kubeflow-pipelines`이면 KFP backend를 우선 선택하고, 감지된 KFP application/endpoint/run id를 status, logs, lineage에 기록한다.
- TrustyAI adapter: `MonitoringTarget.spec.backend`가 `trustyai`, `prometheus`, `upstream`이면 TrustyAIService를 우선 선택한다. TrustyAI가 준비된 클러스터에서는 status와 `/monitoring/trustyai/metrics`에 `metricSource`, endpoint, upstream condition을 기록하고, fallback-only 클러스터에서는 `opensphere-fallback` metric source를 명확히 표시한다.
- Model Registry adapter: `ModelPromotionClaim.spec.backend` 또는 registry API 요청의 `backend`가 `modelregistry`, `model-registry`, `registry`, `upstream`이면 ODH `ModelRegistry`를 우선 선택한다. ModelRegistry 인스턴스와 service endpoint를 감지해 version registry API와 promotion status에 `registrySource`, `backendResource`, upstream sync 결과를 기록하고, fallback-only 클러스터에서는 ConfigMap-backed registry를 명확히 표시한다.
- Model Registry REST coverage: `/models/registry/upstream`이 upstream `registered_models`, `model_versions`, `model_artifacts` REST 후보 경로를 점검하고, backend/source/resource coverage를 `/ai` Model Registry 화면에 표시한다.
- Promotion audit and evaluation metrics: `ModelPromotionClaim` reconcile은 승인/거절/평가통과 결정을 `approvalAudit`에 저장하고, `EvaluationJob` metric을 `evaluationMetrics`로 보존하며 `/ai` Model Registry 화면에 promotion history, evaluation metrics, approval audit trail을 표시한다.
- Evaluation batch metric provider: `EvaluationJob` reconcile은 `spec.metrics`, `spec.results`, `EvaluationPolicy.spec.gates`를 batch metric source로 읽어 `status.metrics`, `status.passed`, `status.metricProvider`를 기록하고 연결된 `ModelPromotionClaim`을 자동 reconcile한다.
- Model Registry upstream write self-test: `/models/registry/upstream/self-test`는 감지된 ODH ModelRegistry endpoint 또는 명시 endpoint에 대해 registered model, model version, artifact write 후보 경로를 실제로 시도하고, `/ai` Model Registry 화면에 resource별 write 결과를 표시한다.
- OpenSphere native readiness gate: `/admin/native/final-readiness`는 backend detection, setup status, OpenSphere foundation CRD, native Model Registry, controller metrics, durable audit log, write authorization을 native 제품 준비도로 판정한다. OLM/OperatorHub, DataScienceCluster, upstream Model Registry는 제품 실패 조건이 아니라 upstream parity validation 축으로 분리해 `upstreamPhase`와 `NotInstalled` 상태로 표시한다.
- Actual/reference source labeling: `/summary`와 각 resource list API는 실제 클러스터 리소스 수를 `actualCount`로 계산하고, reference 예시는 `referenceCount`, `source: reference`, row별 `reference: true`로 분리한다. `/ai` 화면은 Source 컬럼과 Home reference label로 실제 운영 데이터와 예시 데이터를 구분한다.
- Native actual replacement: `Serving runtimes`, `Model registry`, `Enabled applications`는 reference 예시 대신 OpenSphere-native 런타임, ConfigMap-backed registry, backend capability 상태를 실제 항목으로 노출한다. Explore/Learning처럼 카탈로그 성격인 화면만 `Reference`로 남긴다.
- Security hardening: 외부 write API는 `x-os-id-token`을 필수로 요구하고, 사용자 토큰 기반 `SelfSubjectAccessReview`로 namespace resource 권한을 확인한다. 설치/승인/reconcile 같은 admin action은 admin group 또는 cluster setup RBAC를 요구하며, 허용/거부 결정은 durable audit log에 `SecurityPolicy` 항목으로 기록한다.
- Upgrade/rollback: `OpenSphereInstallPlan`에 `operation`, `previousVersion`, `targetVersion`, `rollbackVersion`, migration/rollback step, condition을 기록한다. `/admin/native/installplans/upgrade`와 `/admin/native/installplans/rollback`이 upgrade/rollback plan을 생성하고, approve action이 installed version과 subscription version을 전환한다.
- Monitoring history/alert: `MonitoringTarget` reconcile 때 metric sample을 `opensphere-system/ai-monitoring-metric-history` ConfigMap에 누적하고, threshold 위반을 `alerts`, `alertSummary`, `historySamples` status로 기록한다. `/monitoring/trustyai/metrics`는 현재 metric, alert, retained history를 함께 반환한다.

현재 클러스터 검증 결과는 upstream CRD가 없고 OpenSphere fallback CRD는 모두 설치되어 있으므로 7개 backend capability가 모두 `FallbackReady`로 판정된다. 실제 smoke test에서 `PipelineRunClaim`, `InferenceClaim`, `DistributedWorkloadClaim`의 `backend: auto`가 `backendMode: opensphere`, `backendPhase: FallbackReady`로 기록되고 각각 Succeeded/Ready/Succeeded까지 도달했다.
v37 smoke test에서는 `PipelineRunClaim`의 Pending -> Succeeded 전환 시 `WaitingForJob`, `JobSucceeded` Kubernetes Event가 생성되는 것을 확인했다.
v38 smoke test에서는 `PipelineRunClaim` reconcile 이후 `/admin/native/controller-metrics`와 `/metrics`에서 reconcile/event counter가 증가하는 것을 확인했다.
v39 smoke test 목표는 동일한 reconcile 이벤트가 Kubernetes Event뿐 아니라 `ai-controller-audit-log` ConfigMap과 `/admin/native/audit-log`에도 남는지 검증하는 것이다.
v40 smoke test 목표는 `PipelineRunClaim` 삭제 시 Job cleanup과 finalizer 제거를 확인하고, 의도적 backend 실패에서 `Retrying/nextRetryAt` 상태가 기록되는지 검증하는 것이다.
v41 smoke test 목표는 fallback Job 기반 `PipelineRunClaim`과 `DistributedWorkloadClaim` status에 공통 normalization 필드가 기록되는지 검증하는 것이다.
v42 smoke test 목표는 현재 fallback-only 클러스터에서 `backend: kubeflow` 요청이 `Retrying`으로 정규화되고, backend detection이 Tekton/KFP 대체 upstream 요건을 명확히 보고하는지 검증하는 것이다.
v43 smoke test 목표는 `MonitoringTarget`이 fallback metrics에는 `opensphere-fallback` source를 기록하고, `backend: trustyai` 요청에는 TrustyAIService 부재를 `Retrying`과 `nextRetryAt`으로 명확히 보고하는지 검증하는 것이다.
v44 smoke test 목표는 Model Registry fallback 등록/승인이 `opensphere-configmap` source를 기록하고, `backend: modelregistry` 요청에는 ModelRegistry 인스턴스 부재를 `Retrying`과 `nextRetryAt`으로 명확히 보고하는지 검증하는 것이다.
v46 smoke test 목표는 토큰 없는 write가 401로 차단되고 durable audit log에 `AccessDenied`가 남으며, `setupStatus` 권한 표시가 서비스어카운트가 아닌 사용자 토큰 기준으로 평가되는지 검증하는 것이다.
v47 smoke test 목표는 native component upgrade plan이 target/rollback version을 기록하고, rollback plan이 previous installed version으로 되돌릴 수 있는 InstallPlan 상태를 만드는지 검증하는 것이다.
v48 smoke test 목표는 MonitoringTarget reconcile이 metric history sample을 누적하고, threshold 위반 alert rule을 status와 `/monitoring/trustyai/metrics` 응답에 노출하는지 검증하는 것이다.
v49 smoke test 목표는 fallback-only 클러스터에서 `/models/registry/upstream`이 `opensphere-configmap` source와 `FallbackReady` phase를 보고하고, Model Registry 화면이 source/REST coverage를 렌더링하는지 검증하는 것이다.
v50 smoke test 목표는 `EvaluationJob` metric이 연결된 `ModelPromotionClaim` reconcile 후 registry ConfigMap과 `/models/registry/versions` 응답에 `promotions`, `evaluationMetrics`, `approvalAudit`가 기록되는지 검증하는 것이다.
v51 smoke test 목표는 같은 `ModelPromotionClaim`이 주기적으로 reconcile되어도 evaluation metric과 approval audit id가 안정적으로 유지되어 중복 누적되지 않는지 검증하는 것이다.
v52 smoke test 목표는 `EvaluationJob`이 `spec.metrics`만 가진 상태에서 reconcile되어 `status.metrics/status.passed`를 생성하고, 연결된 `ModelPromotionClaim`이 자동으로 `Promoted`까지 이어지는지 검증하는 것이다.
v55 smoke test 목표는 현재 fallback-only 클러스터에서 final readiness API의 최상위 phase가 OpenSphere native 제품 상태를 기준으로 계산되고, ODH/RHOAI upstream 부재는 `upstreamPhase: ParityNotInstalled`로만 보고되며, upstream write self-test endpoint가 토큰 없는 POST를 계속 차단하는지 검증하는 것이다.

남은 가장 큰 과제는 upstream-enabled 클러스터에서 실제 ODH/RHOAI endpoint를 대상으로 adapter 깊이를 검증하고 운영 품질을 강화하는 것이다. 즉 실제 upstream write 검증, batch evaluation metric provider 연동, multi-cluster 검증을 완성해야 한다.

### 12.4 다음 구현 우선순위

1. Backend detection layer
   - KServe, Kueue, Ray, Tekton, Prometheus, TrustyAI CRD 존재 여부를 감지한다.
   - 참조 업스트림: Kubernetes discovery API, KServe/Kueue/Ray CRD.
   - 현재 상태: 1차 구현 완료.

2. Backend selection policy
   - `OpenSphereDataScienceCluster.spec.components.*.backend` 또는 claim별 `spec.backend`로 `auto`, `opensphere`, `upstream` 모드를 둔다.
   - 참조 업스트림: ODH component `managementState`, KServe runtime selection.
   - 현재 상태: claim별 `spec.backend`, `spec.backendMode`, `spec.backendType` 기준 1차 구현 완료.

3. Upstream adapter
   - fallback Job/Deployment 대신 업스트림 CRD가 있으면 `InferenceService`, `PipelineRun`, `RayJob`, `Workload`를 생성한다.
   - 참조 업스트림: KServe, Kubeflow Pipelines/Tekton, Ray, Kueue.
   - 현재 상태: Tekton PipelineRun, KServe InferenceService, Kueue-managed Job, RayJob, Kubeflow Pipelines, TrustyAI, Model Registry 1차 adapter 구현 완료.

4. Status normalization
   - 업스트림 CRD의 다양한 condition을 OpenSphere claim의 공통 `phase`, `ready`, `conditions`로 정규화한다.
   - 참조 업스트림: Kubernetes conditions convention, OLM CSV conditions.

5. Operational hardening
   - finalizer, garbage collection, retry/backoff, event recording, audit log, metrics, namespace RBAC를 완성한다.
   - 참조 업스트림: Kubernetes controller-runtime pattern, OLM install/upgrade lifecycle.
   - 현재 상태: phase/ready/backendMode 변경 기반 Kubernetes Event recording, in-memory controller metrics, Prometheus `/metrics`, Cluster settings metrics card, ConfigMap-backed durable audit log, 실행형 claim finalizer/garbage collection, retry/backoff, status normalization v2, namespace RBAC/user impersonation hardening 1차 구현 완료. upgrade/rollback은 남은 작업이다.

### 12.5 다음 단계 구현 계획

v39 이후 구현은 다음 순서로 진행한다.

| 순서 | 구현 목표 | 구체 작업 | 참조 업스트림 |
|---|---|---|---|
| 1 | Finalizer/garbage collection | claim 삭제 시 fallback Job/Deployment/Service/PVC와 upstream CRD owner cleanup 처리 | Kubernetes finalizers, controller-runtime owner reference pattern |
| 2 | Retry/backoff | reconcile 실패 reason, retry count, nextRetryAt, terminal failure 상태 추가 | Kubernetes controller-runtime workqueue, OLM InstallPlan failure handling |
| 3 | Status normalization v2 | Tekton/KServe/Kueue/Ray condition을 OpenSphere 공통 `phase`, `ready`, `conditions`로 정규화 | Kubernetes conditions, Tekton PipelineRun status, KServe condition model |
| 4 | Kubeflow Pipelines adapter | Pipeline definition/version/run/artifact API와 연결 | Kubeflow Pipelines API, Tekton backend |
| 5 | TrustyAI adapter | MonitoringTarget을 TrustyAIService와 metric endpoint에 연결 | TrustyAI, Prometheus |
| 6 | Model Registry adapter | ConfigMap registry를 외부/업스트림 model registry API로 대체 가능하게 추상화 | ODH Model Registry, ML Metadata |
| 7 | Security hardening | namespace RBAC, user impersonation, admin-only install action audit | Kubernetes RBAC, OpenShift/RHOAI authorization model |
| 8 | Upgrade/rollback | component version upgrade plan, rollback hook, migration status | OLM upgrade lifecycle, CSV replacement model |

현재 v58에서 Model Registry upstream write self-test, native/upstream 분리 readiness gate, actual/reference UI 출처 표시, 주요 reference 화면의 native actual 전환까지 완료했다. 다음 구현은 실제 ODH/RHOAI upstream endpoint가 있는 환경에서 self-test를 실행하고 multi-cluster 최종 검증 결과를 upstream parity 축에 누적하는 것이다.

각 단계는 fallback-only OpenSphere 클러스터와 upstream-enabled 클러스터를 모두 기준으로 검증한다. fallback-only 검증은 현재 제품성을 보장하고, upstream-enabled 검증은 ODH/RHOAI 생태계와의 호환성을 보장한다.
