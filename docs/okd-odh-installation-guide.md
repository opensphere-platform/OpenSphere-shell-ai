# OKD 기반 Open Data Hub 설치와 OpenSphere AI 연동 가이드

작성일: 2026-06-26

## 1. 결론

현재 연결된 Kubernetes 클러스터에는 Open Data Hub Operator를 정식 방식으로 설치할 수 없다.

이유는 Open Data Hub Operator가 일반 Kubernetes 애플리케이션처럼 `Deployment` 하나로 끝나는 구성요소가 아니라, OpenShift/OKD의 Operator Lifecycle Manager, OperatorHub, Route, OpenShift 보안 모델, DataScienceCluster 리소스를 전제로 하는 플랫폼 Operator이기 때문이다.

현재 클러스터 확인 결과는 다음과 같다.

```powershell
kubectl api-resources | Select-String -Pattern "subscriptions|operatorgroups|clusterserviceversions|catalogsources|operatorhub|datascienceclusters"
kubectl get ns openshift-marketplace openshift-operators opendatahub redhat-ods-operator redhat-ods-applications 2>$null
kubectl get clusterversion 2>$null
kubectl get crd | Select-String -Pattern "operators.coreos.com|datasciencecluster|opendatahub|rhods"
```

위 명령에서 의미 있는 결과가 나오지 않았다. 즉 현재 클러스터에는 다음이 없다.

- OLM API: `operators.coreos.com`
- Operator 설치 리소스: `Subscription`, `OperatorGroup`, `ClusterServiceVersion`, `CatalogSource`
- OpenShift 기본 namespace: `openshift-marketplace`, `openshift-operators`
- OpenShift 클러스터 식별 리소스: `ClusterVersion`
- ODH/RHOAI 핵심 CRD: `DataScienceCluster`, `DSCInitialization`

따라서 해결 방법은 현재 일반 Kubernetes 클러스터에 ODH Operator를 억지로 올리는 것이 아니라, OKD 클러스터를 준비한 뒤 그 위에 Open Data Hub Operator를 설치하는 것이다.

## 2. 왜 OKD가 필요한가

OKD는 Red Hat OpenShift의 커뮤니티 배포판이다. Kubernetes를 기반으로 하지만, 단순 Kubernetes보다 다음 요소를 기본 플랫폼 기능으로 제공한다.

- 웹 콘솔
- 인증/권한 통합
- Route 기반 애플리케이션 노출
- 이미지 레지스트리와 빌드/배포 도구
- 모니터링
- 노드 구성/업그레이드 관리
- Operator 관리

Open Data Hub는 이 OpenShift/OKD 계열 플랫폼 위에서 동작하도록 설계되어 있다. ODH 문서는 Operator 설치, ODH 컴포넌트 설치, Dashboard, Workbench, Pipeline, Model Serving, TrustyAI, Distributed Workloads 같은 기능을 Operator와 DataScienceCluster 중심으로 설명한다.

즉 OKD는 단순히 “무료 OpenShift 대체품”이 아니라, Open Data Hub가 기대하는 플랫폼 기능을 제공하는 기반이다.

## 3. 핵심 구성요소의 의미

### OKD

OKD는 OpenShift의 오픈소스 커뮤니티 배포판이다. 일반 Kubernetes 위에 OpenShift 콘솔, Route, Operator 관리, 클러스터 관리 기능을 올린 플랫폼이다.

OpenSphere AI 입장에서 OKD는 다음 역할을 한다.

- ODH Operator를 설치할 수 있는 기반
- ODH Dashboard와 Workbench를 노출하는 Route 제공
- DataScienceCluster가 실제 AI/ML 컴포넌트를 배치할 대상 클러스터
- 우리 `/ai` Wizard가 Operator 설치와 DataScienceCluster 생성을 실행할 수 있는 환경

### OLM

OLM은 Operator Lifecycle Manager의 약자다. OKD 문서에 따르면 OLM은 Kubernetes native application, 즉 Operator와 그 서비스의 설치, 업데이트, 생명주기를 관리한다.

OLM이 없으면 `Subscription`, `OperatorGroup`, `ClusterServiceVersion` 같은 리소스를 만들 수 없고, 결과적으로 Open Data Hub Operator를 OperatorHub 방식으로 설치할 수 없다.

### Operator

Operator는 Kubernetes 애플리케이션을 설치하고 운영하는 컨트롤러다. 단순 YAML 묶음이 아니라, CRD를 감시하면서 원하는 상태와 실제 상태를 맞추는 소프트웨어다.

Open Data Hub Operator는 `DataScienceCluster` 같은 리소스를 보고 Dashboard, Workbench, Pipelines, KServe, Model Registry, TrustyAI, Kueue, Ray 등의 컴포넌트를 설치/관리한다.

### OperatorHub

OperatorHub는 설치 가능한 Operator 카탈로그를 보여주는 콘솔/카탈로그 경험이다. 내부적으로는 `CatalogSource`, package, channel, bundle, CSV 같은 OLM 개념과 연결된다.

### CatalogSource

CatalogSource는 Operator 목록을 제공하는 소스다. 예를 들어 `community-operators`는 커뮤니티 Operator 패키지들을 제공하는 카탈로그다.

ODH Operator 설치에서 보통 다음 값이 사용된다.

```text
Catalog source: community-operators
Catalog namespace: openshift-marketplace
Operator package: opendatahub-operator
Channel: fast 또는 stable
```

### Subscription

Subscription은 “이 Operator package를 이 channel에서 계속 설치/업데이트하라”는 선언이다.

예를 들어 `opendatahub-operator`를 `fast` channel로 구독하면 OLM이 적절한 CSV와 관련 리소스를 설치한다.

### OperatorGroup

OperatorGroup은 특정 namespace에 설치된 Operator가 어떤 namespace 범위를 감시할지 정한다.

ODH Operator는 보통 Operator 설치 namespace에 OperatorGroup을 만들고, 이후 DataScienceCluster가 클러스터/애플리케이션 namespace에 컴포넌트를 배포한다.

### ClusterServiceVersion

CSV는 OLM이 관리하는 Operator 버전/메타데이터다. 설치된 Operator의 실제 버전, 상태, 권한, 제공 CRD 등을 나타낸다.

CSV가 `Succeeded` 상태가 되어야 Operator가 정상 설치된 것으로 본다.

### CRD

CRD는 Kubernetes API를 확장하는 리소스 정의다. `DataScienceCluster`, `Notebook`, `InferenceService`, `TrustyAIService`, `ModelRegistry` 같은 리소스는 CRD가 있어야 생성할 수 있다.

현재 우리가 OpenSphere 쪽에서 만든 `WorkbenchClaim`, `PipelineClaim`, `InferenceClaim`도 CRD다. 차이는 다음과 같다.

- OpenSphere claim CRD: 우리 AI orchestration 계층
- ODH/업스트림 CRD: 실제 Workbench, Pipeline, Model Serving, TrustyAI 등을 운영하는 업스트림 계층

### DSCInitialization

DSCInitialization은 ODH 2 계열에서 Data Science Cluster 초기 설정을 담당한다. 대표적으로 ODH 애플리케이션 namespace를 지정한다.

예:

```yaml
apiVersion: dscinitialization.opendatahub.io/v2
kind: DSCInitialization
metadata:
  name: default-dsci
spec:
  applicationsNamespace: opendatahub
```

### DataScienceCluster

DataScienceCluster는 ODH/OpenShift AI의 핵심 구성 선언이다. 어떤 컴포넌트를 켤지 정의한다.

예:

```yaml
apiVersion: datasciencecluster.opendatahub.io/v2
kind: DataScienceCluster
metadata:
  name: default-dsc
spec:
  components:
    dashboard:
      managementState: Managed
    workbenches:
      managementState: Managed
    datasciencepipelines:
      managementState: Managed
    kserve:
      managementState: Managed
    modelregistry:
      managementState: Managed
    trustyai:
      managementState: Managed
    kueue:
      managementState: Managed
    ray:
      managementState: Managed
```

`Managed`는 Operator가 해당 컴포넌트를 설치하고 관리한다는 뜻이다.

## 4. OKD 설치 선택지

### 선택지 A: Single Node OKD

개발/검증용으로 가장 현실적인 선택이다. 하나의 물리 서버나 VM에 OKD를 단일 노드로 설치한다.

장점:

- ODH 설치 테스트에 충분한 OpenShift/OKD API 제공
- OLM, OperatorHub, Route, Console 확인 가능
- 우리 `/ai` Wizard 검증에 적합

단점:

- AI 워크로드까지 돌리려면 메모리와 디스크가 많이 필요
- GPU 테스트는 별도 장비/드라이버/Operator가 필요
- 운영 HA 환경은 아님

실무 권장 사양:

```text
CPU: 8 vCPU 이상
Memory: 최소 32 GB, ODH/AI 테스트는 64 GB 권장
Disk: 200 GB 이상 권장
Network: 고정 IP 권장
DNS: api, api-int, *.apps 레코드 필요
```

### 선택지 B: Assisted Installer

OKD 문서는 Assisted Installer를 가장 쉬운 설치 방식으로 설명한다. 웹 기반으로 클러스터 설정을 만들고, 사전 검증을 수행한 뒤 설치 ISO를 생성하는 방식이다.

장점:

- pre-flight validation 제공
- 네트워크가 인터넷에 연결된 환경에 적합
- 설치 실수를 줄일 수 있음

### 선택지 C: Agent-based Installer

제한망 또는 disconnected 환경에 적합하다. 설치 ISO를 로컬에서 만들고, agent가 클러스터를 설치한다.

장점:

- 제한망/사설망에 적합
- GitOps 방식으로 설치 설정 관리 가능

단점:

- Assisted Installer보다 준비 과정이 많음

### 선택지 D: Bare metal / platform agnostic UPI

이미 가상화, 베어메탈, 사설 클라우드 인프라가 준비되어 있을 때 쓴다.

장점:

- 자유도가 높음
- 실제 운영과 유사한 구조 가능

단점:

- DNS, 로드밸런서, DHCP/static IP, bootstrap, control plane 구성을 직접 책임져야 함

## 5. OKD 설치 전 체크리스트

### 5.1 DNS

OKD는 클러스터 API와 애플리케이션 Route를 DNS로 접근한다.

예를 들어 cluster name이 `okd`, base domain이 `lab.local`이면 다음이 필요하다.

```text
api.okd.lab.local       -> OKD API IP
api-int.okd.lab.local   -> OKD 내부 API IP
*.apps.okd.lab.local    -> OKD ingress/router IP
```

Single Node OKD에서는 세 레코드가 같은 노드 IP를 가리키는 구성이 가능하다.

### 5.2 인증서

개발 환경에서는 기본 self-signed 인증서로 시작할 수 있다. 운영 또는 사내 배포에서는 사내 CA 또는 신뢰 가능한 인증서를 준비해야 한다.

### 5.3 스토리지

ODH Workbench, Pipeline, Model Registry, TrustyAI는 PVC를 사용한다. 따라서 기본 StorageClass가 필요하다.

설치 후 확인:

```bash
oc get storageclass
oc get storageclass -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.metadata.annotations.storageclass\.kubernetes\.io/is-default-class}{"\n"}{end}'
```

### 5.4 GPU

GPU는 ODH 설치의 필수는 아니다. 하지만 모델 학습/서빙을 제대로 하려면 NVIDIA GPU Operator, Node Feature Discovery, 드라이버, runtime 설정이 필요하다.

초기에는 GPU 없이 Dashboard, Workbench, Pipeline, Registry, TrustyAI 기본 흐름을 먼저 검증하는 것이 좋다.

## 6. OKD 설치 후 기본 검증

설치 후 `oc` CLI로 로그인한다.

```bash
oc login https://api.<cluster>.<base-domain>:6443
```

기본 상태 확인:

```bash
oc get clusterversion
oc get nodes
oc get co
oc get ns openshift-marketplace openshift-operators
oc api-resources | grep operators.coreos.com
```

OLM 확인:

```bash
oc api-resources | grep -E 'subscriptions|operatorgroups|clusterserviceversions|catalogsources'
oc get catalogsource -A
```

정상 기대값:

- `clusterversion` 존재
- `openshift-marketplace` namespace 존재
- `openshift-operators` namespace 존재
- `subscriptions.operators.coreos.com` API 존재
- `operatorgroups.operators.coreos.com` API 존재
- `clusterserviceversions.operators.coreos.com` API 존재
- `catalogsources.operators.coreos.com` API 존재

## 7. Open Data Hub Operator 설치

### 7.1 웹 콘솔 방식

1. OKD 웹 콘솔에 cluster-admin으로 로그인한다.
2. Operators -> OperatorHub로 이동한다.
3. `Open Data Hub Operator`를 검색한다.
4. package가 `opendatahub-operator`인지 확인한다.
5. channel은 보통 `fast` 또는 문서에서 권장하는 channel을 선택한다.
6. 설치 namespace는 `openshift-operators` 또는 별도 `opendatahub` namespace를 선택한다.
7. 설치 후 Installed Operators에서 CSV 상태가 `Succeeded`인지 확인한다.

확인 명령:

```bash
oc get subscription -A | grep -i opendatahub
oc get csv -A | grep -i opendatahub
oc get crd | grep -E 'datasciencecluster|dscinitialization'
```

### 7.2 YAML 방식

OperatorHub/OLM API가 준비되어 있으면 다음 형태로 설치할 수 있다.

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: opendatahub
---
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  name: opendatahub-operator-group
  namespace: opendatahub
spec:
  targetNamespaces:
    - opendatahub
---
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: opendatahub-operator
  namespace: opendatahub
spec:
  name: opendatahub-operator
  channel: fast
  source: community-operators
  sourceNamespace: openshift-marketplace
```

적용:

```bash
oc apply -f odh-operator-subscription.yaml
```

상태 확인:

```bash
oc get sub -n opendatahub
oc get csv -n opendatahub
oc describe sub opendatahub-operator -n opendatahub
```

## 8. ODH 컴포넌트 설치

Operator가 설치된 뒤 `DSCInitialization`과 `DataScienceCluster`를 만든다.

```yaml
apiVersion: dscinitialization.opendatahub.io/v2
kind: DSCInitialization
metadata:
  name: default-dsci
spec:
  applicationsNamespace: opendatahub
---
apiVersion: datasciencecluster.opendatahub.io/v2
kind: DataScienceCluster
metadata:
  name: default-dsc
spec:
  components:
    dashboard:
      managementState: Managed
    workbenches:
      managementState: Managed
    datasciencepipelines:
      managementState: Managed
    kserve:
      managementState: Managed
    modelregistry:
      managementState: Managed
    trustyai:
      managementState: Managed
    kueue:
      managementState: Managed
    ray:
      managementState: Managed
```

적용:

```bash
oc apply -f odh-dsc.yaml
```

확인:

```bash
oc get dsci
oc get dsc
oc describe dsc default-dsc
oc get pods -n opendatahub
oc get route -A | grep -i dashboard
```

## 9. 우리 OpenSphere AI와 연결하는 방식

OKD와 ODH가 준비되면 우리 `/ai` Wizard는 다음을 수행할 수 있다.

1. OLM API 존재 확인
2. `opendatahub-operator` Subscription 생성
3. DataScienceCluster CRD 존재 확인
4. `DataScienceCluster` 생성 또는 patch
5. ODH 컴포넌트 상태 조회
6. OpenSphere AI claim CRD와 업스트림 CRD를 함께 표시

현재 `/ai` Wizard에서 쓸 값:

```text
Provider: Open Data Hub
Target namespace: opendatahub
Operator package: opendatahub-operator
Channel: fast
Catalog source: community-operators
Catalog namespace: openshift-marketplace
DataScienceCluster: default-dsc
Install OpenSphere foundation CRDs: checked
Install Operator subscription: checked
Create DataScienceCluster: checked
```

이 값들이 임의의 문자열이 아닌 이유:

- `opendatahub-operator`: ODH Operator package 이름
- `fast`: ODH Operator update channel
- `community-operators`: OKD/OpenShift OperatorHub에서 community operator를 제공하는 catalog source
- `openshift-marketplace`: CatalogSource들이 위치하는 OpenShift namespace
- `default-dsc`: ODH 컴포넌트 desired state를 담는 DataScienceCluster 이름

## 10. 설치 후 사용 흐름

ODH 설치 후 사용자는 다음 순서로 AI/ML 작업을 수행한다.

1. Data Science Project 생성
2. Workbench 생성
3. Data connection 연결
4. Notebook/JupyterLab 또는 code-server 접속
5. Pipeline 정의/업로드
6. Pipeline run 실행
7. Model artifact 저장
8. Model Registry에 등록
9. KServe/Model Serving으로 모델 배포
10. TrustyAI로 drift, bias, explainability 모니터링
11. Kueue/Ray 기반 distributed workload 실행

우리 OpenSphere AI는 이 흐름 위에 다음 추상화를 추가한다.

- `WorkbenchClaim`
- `PipelineClaim`
- `PipelineRunClaim`
- `TrainingJobClaim`
- `EvaluationPolicy`
- `EvaluationJob`
- `ModelPromotionClaim`
- `InferenceClaim`
- `MonitoringTarget`
- `DistributedWorkloadClaim`

즉 사용자는 업스트림 리소스의 세부 YAML을 직접 모두 알지 않아도, OpenSphere claim을 통해 더 높은 수준의 AI 운영 요청을 만들 수 있다. 이후 OpenSphere controller가 claim을 실제 ODH/KServe/Kueue/Ray 리소스로 reconcile해야 한다.

## 11. 현재 프로젝트 기준 남은 구현 과제

현재 `/ai`는 OKD/ODH가 준비된 환경을 감지하고, Operator 설치와 DataScienceCluster 생성을 시도할 수 있다. 또한 OpenSphere claim CRD는 설치되어 있다.

하지만 완전한 제품이 되려면 다음이 더 필요하다.

1. OpenSphere AI controller 구현
   - `WorkbenchClaim` -> Kubeflow `Notebook`
   - `PipelineClaim` -> Kubeflow Pipeline metadata/version
   - `PipelineRunClaim` -> PipelineRun
   - `InferenceClaim` -> KServe `InferenceService`
   - `MonitoringTarget` -> TrustyAI metric/service 설정
   - `DistributedWorkloadClaim` -> Kueue/Ray/Training Operator 리소스

2. OKD/ODH E2E 테스트 환경
   - OKD SNO 또는 3-node OKD
   - ODH Operator 설치
   - DataScienceCluster 컴포넌트 전체 enable
   - `/ai` Wizard와 실제 리소스 상태 비교

3. 운영 품질
   - GitOps 설치 매니페스트
   - 백업/복구
   - 업그레이드 검증
   - 사용자 RBAC/프로젝트 권한
   - 네트워크/인증/인증서 처리

## 12. 권장 실행 계획

### 1단계: OKD SNO 준비

개발 검증용 단일 노드 OKD를 준비한다.

목표:

- OLM API 확보
- OperatorHub 확보
- ODH Operator 설치 가능 상태 확보

### 2단계: ODH Operator 설치

OperatorHub 또는 YAML Subscription 방식으로 `opendatahub-operator`를 설치한다.

목표:

- CSV `Succeeded`
- `DataScienceCluster` CRD 생성
- `DSCInitialization` CRD 생성

### 3단계: DataScienceCluster 생성

ODH Dashboard, Workbenches, Pipelines, KServe, Model Registry, TrustyAI, Kueue, Ray를 `Managed`로 설정한다.

목표:

- ODH Dashboard Route 접속
- Workbench 생성 가능
- Pipeline 기능 확인
- Serving runtime 확인

### 4단계: OpenSphere AI 연결

우리 `/ai` Wizard에서 같은 설정을 인식하고, OpenSphere claim과 ODH 리소스가 같이 보이는지 확인한다.

목표:

- `/ai` Cluster settings에서 OLM ready
- DataScienceCluster ready
- ODH components ready
- Workbench/Pipeline/Serving/Monitoring 메뉴가 실제 리소스를 읽음

### 5단계: Controller 구현

OpenSphere claim을 실제 ODH 리소스로 변환하는 controller를 구현한다.

목표:

- `/ai`에서 WorkbenchClaim 생성
- controller가 Notebook 생성
- Notebook ready 상태가 `/ai`에 반영
- 동일 패턴으로 Pipeline, Inference, Monitoring 확장

## 13. 참고 문서

- OKD installation overview: https://docs.okd.io/latest/installing/overview/index.html
- OKD OLM concepts: https://docs.okd.io/latest/operators/understanding/olm/olm-understanding-olm.html
- OKD Operator glossary: https://docs.okd.io/4.19/operators/understanding/olm-common-terms.html
- OKD single-node installation: https://docs.okd.io/latest/installing/installing_sno/install-sno-installing-sno.html
- Open Data Hub installation: https://opendatahub.io/docs/installing-open-data-hub/
- Open Data Hub Operator repository: https://github.com/opendatahub-io/opendatahub-operator

## 14. 별도 OKD 클러스터 없이 OpenSphere가 호환 계층을 제공하는 전략

현실 제약상 OpenSphere 외부에 별도 OKD 클러스터를 추가하는 것이 어렵다면, 다음 대안이 가능하다.

```text
OKD 전체를 설치하지 않는다.
대신 OpenSphere가 ODH 설치와 운영에 필요한 일부 플랫폼 역할을 직접 제공한다.
```

이 전략은 "OKD를 OpenSphere에 설치한다"는 뜻이 아니다. OKD는 Kubernetes 배포판이므로 기존 Kubernetes 클러스터에 몇 개의 Deployment를 추가한다고 OKD가 되지 않는다. 이 전략의 의미는 OpenSphere가 OKD/OpenShift의 일부 기능을 OpenSphere native 방식으로 재구현한다는 뜻이다.

정확히 말하면 OpenSphere가 상속해야 하는 것은 OKD 제품 전체가 아니라 Open Data Hub 운영에 필요한 핵심 계약이다.

- OperatorHub처럼 설치 가능한 AI 컴포넌트를 보여주는 계약.
- CatalogSource처럼 컴포넌트 package/channel/version을 제공하는 계약.
- Subscription처럼 사용자가 설치 의도를 선언하는 계약.
- InstallPlan처럼 설치 단계와 승인 상태를 추적하는 계약.
- DataScienceCluster처럼 AI 플랫폼 컴포넌트 desired state를 선언하는 계약.
- ODH Operator처럼 desired state를 실제 Kubernetes 리소스로 reconcile하는 계약.

이 관점에서는 별도 OKD 클러스터를 만들지 않아도 된다. 대신 현재 OpenSphere Kubernetes 클러스터 안에서 위 계약을 OpenSphere CRD, controller, `/ai` 콘솔로 제공한다.

### 14.1 가능한 범위

OpenSphere에서 현실적으로 구현 가능한 범위는 다음이다.

| OKD/OpenShift 역할 | OpenSphere 대체 방식 |
|---|---|
| OperatorHub | OpenSphere AI Component Catalog |
| CatalogSource | OpenSphere catalog registry 또는 GitOps catalog |
| Subscription | `OpenSphereSubscription` CRD |
| InstallPlan | `OpenSphereInstallPlan` CRD |
| ClusterServiceVersion | `OpenSphereComponentVersion` CRD |
| DataScienceCluster | `OpenSphereDataScienceCluster` 또는 DataScienceCluster-compatible CRD |
| ODH Operator reconcile | OpenSphere AI Platform Controller |
| ODH component install | Helm/Kustomize/manifest 기반 component installer |

이 방식은 OLM 전체를 복제하지 않는다. OLM의 핵심 사용 경험인 "카탈로그에서 컴포넌트를 선택하고, 버전을 고르고, 설치/업데이트 상태를 추적한다"는 부분만 OpenSphere AI 목적에 맞게 구현한다.

### 14.2 피해야 할 범위

다음 범위까지 구현하려고 하면 사실상 OKD/OpenShift를 재구현하는 일이 된다.

- OpenShift Route 완전 호환
- OpenShift SCC 완전 호환
- OpenShift Console plugin API 완전 호환
- OLM resolver, bundle graph, dependency graph 전체 구현
- ODH Operator를 수정 없이 그대로 실행하는 것

특히 ODH Operator는 OpenShift/OKD 전제를 포함할 수 있으므로, 현재 Kubernetes 클러스터에서 ODH Operator 자체를 그대로 돌리는 전략은 성공 가능성이 낮다.

### 14.3 권장 아키텍처

권장 구조는 다음과 같다.

```text
Current Kubernetes cluster
  └─ OpenSphere Platform
      ├─ OpenSphere AI Console (/ai)
      ├─ OpenSphere AI Component Catalog
      ├─ OpenSphere AI Platform Controller
      ├─ OpenSphereSubscription
      ├─ OpenSphereInstallPlan
      ├─ OpenSphereComponentVersion
      ├─ OpenSphereDataScienceCluster
      ├─ OpenSphere AI claim CRDs
      │   ├─ WorkbenchClaim
      │   ├─ PipelineClaim
      │   ├─ PipelineRunClaim
      │   ├─ InferenceClaim
      │   ├─ MonitoringTarget
      │   └─ DistributedWorkloadClaim
      └─ Component installers
          ├─ Kubeflow Notebooks-compatible workbench layer
          ├─ Kubeflow Pipelines-compatible workflow layer
          ├─ KServe-compatible model serving layer
          ├─ Model Registry layer
          ├─ TrustyAI-compatible monitoring layer
          ├─ Kueue-compatible scheduling layer
          └─ Ray-compatible distributed workload layer
```

### 14.4 이 전략에서 DataScienceCluster의 의미

ODH의 `DataScienceCluster`는 어떤 AI 컴포넌트를 켤지 선언하는 desired state 리소스다. OpenSphere도 같은 개념이 필요하다.

OpenSphere native 방식에서는 다음 둘 중 하나를 선택한다.

1. `DataScienceCluster` 이름과 spec 구조를 최대한 호환한다.
2. `OpenSphereDataScienceCluster`라는 별도 CRD를 만들고, ODH 호환 필드를 포함한다.

권장안은 2번이다. 이유는 ODH CRD와 이름이 같으면 향후 실제 ODH Operator와 충돌할 수 있기 때문이다. 대신 spec은 다음처럼 ODH와 유사하게 둔다.

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

### 14.5 구현 철학

이 전략은 업스트림을 버리는 것이 아니다. 업스트림을 다음처럼 참조한다.

- ODH Operator: 컴포넌트 구성 모델과 DataScienceCluster 개념 참조
- OLM: catalog, subscription, install plan, version 상태 모델 참조
- Kubeflow Notebooks: Workbench runtime과 Notebook CRD 모델 참조
- Kubeflow Pipelines: Pipeline, run, artifact, experiment 모델 참조
- KServe: InferenceService, ServingRuntime 모델 참조
- TrustyAI: monitoring/explainability 개념 참조
- Kueue/Ray: distributed workload scheduling과 runtime 모델 참조

OpenSphere는 이 업스트림을 직접 그대로 vendor copy하지 않고, OpenSphere claim과 controller를 통해 필요한 부분을 Kubernetes-native 방식으로 연결한다.

### 14.6 문서 연결

이 전략의 단계별 구현 계획은 다음 문서를 따른다.

- `docs/opensphere-native-odh-compatibility-plan.md`

### 14.7 실행 판단

현재 OpenSphere 프로젝트 기준의 판단은 다음이다.

```text
별도 OKD 클러스터를 추가하지 않는다.
현재 OpenSphere Kubernetes 클러스터 안에서
OpenSphere native ODH compatibility layer를 구현한다.
```

이 판단의 이유는 다음과 같다.

- ODH Operator를 정식으로 사용하려면 OKD/OpenShift의 OLM, OperatorHub, Route, 보안 모델이 필요하다.
- 현재 OpenSphere 외부에 별도 OKD 클러스터를 추가하는 것은 운영 복잡도와 비용이 크다.
- 기존 Kubernetes 클러스터에 컨테이너 몇 개를 추가한다고 OKD가 되는 것은 아니다.
- 따라서 OKD 자체를 설치하는 대신, ODH가 제공하던 AI 플랫폼의 핵심 사용자 경험과 API 계약을 OpenSphere가 직접 제공하는 것이 현실적이다.

이 방식은 제품 방향을 다음처럼 바꾼다.

| 기존 정석 경로 | OpenSphere native 경로 |
|---|---|
| OKD/OpenShift 설치 | 현재 OpenSphere Kubernetes 사용 |
| OLM/OperatorHub 사용 | OpenSphere AI Component Catalog 사용 |
| ODH Operator 설치 | OpenSphere AI Platform Controller 사용 |
| DataScienceCluster 생성 | OpenSphereDataScienceCluster 생성 |
| ODH CRD 직접 사용 | OpenSphere claim CRD를 통해 추상화 |
| ODH dashboard 중심 운영 | OpenSphere `/ai` 콘솔 중심 운영 |

### 14.8 단계별 구현 계획

1단계: OpenSphere native catalog layer

- `OpenSphereComponentCatalog`, `OpenSphereComponentVersion`로 설치 가능한 AI 컴포넌트를 표현한다.
- OLM의 `CatalogSource`, `ClusterServiceVersion` 개념을 참조한다.
- 참조 업스트림: OKD OLM, Open Data Hub Operator.

2단계: Subscription/install plan layer

- `OpenSphereSubscription`, `OpenSphereInstallPlan`으로 컴포넌트 설치 요청과 승인 상태를 표현한다.
- OLM의 `Subscription`, `InstallPlan` 개념을 참조한다.
- 참조 업스트림: OKD OLM common terms.

3단계: DataScienceCluster-compatible desired state

- `OpenSphereDataScienceCluster`로 dashboard, workbenches, pipelines, kserve, model registry, trustyai, kueue, ray에 해당하는 component desired state를 표현한다.
- ODH의 `DataScienceCluster.spec.components.*.managementState` 구조를 참조한다.
- 참조 업스트림: Open Data Hub Operator, Red Hat OpenShift AI DataScienceCluster 문서.

4단계: Workbench runtime

- `WorkbenchClaim`을 PVC, Deployment/StatefulSet, Service, URL 상태로 reconcile한다.
- image catalog, storage, data connection, start/stop/restart를 구현한다.
- 참조 업스트림: ODH Workbenches, Kubeflow Notebooks.

5단계: Pipeline runtime

- `PipelineClaim`, `PipelineRunClaim`을 실행 가능한 workflow로 reconcile한다.
- 초기에는 Tekton 또는 Kubernetes Job 기반으로 시작하고, 이후 Kubeflow Pipelines 호환 API를 확장한다.
- 참조 업스트림: Kubeflow Pipelines, Tekton.

6단계: Model serving/runtime

- `InferenceClaim`을 KServe `InferenceService` 또는 Deployment/Service fallback으로 reconcile한다.
- runtime, model artifact URI, endpoint URL, readiness, rollout 상태를 `/ai`에 표시한다.
- 참조 업스트림: KServe, ODH Model Serving.

7단계: Registry, promotion, evaluation

- 모델 버전, stage, metrics, evaluation gate, promotion history를 구현한다.
- `ModelPromotionClaim`, `EvaluationPolicy`, `EvaluationJob`을 연결한다.
- 참조 업스트림: ODH Model Registry, TrustyAI, Kubeflow Pipelines.

8단계: Monitoring and distributed workloads

- `MonitoringTarget`으로 drift, bias, explainability, threshold 상태를 관리한다.
- `DistributedWorkloadClaim`으로 queue, Ray job, training job 실행 상태를 관리한다.
- 참조 업스트림: TrustyAI, Kueue, Ray.

9단계: Product hardening

- controller metrics, event, audit log, retry/backoff, finalizer, namespace RBAC, upgrade/rollback을 구현한다.
- 생성부터 삭제까지 E2E smoke test를 자동화한다.
- 참조 업스트림: Kubernetes controller pattern, CRD status subresource, OLM upgrade lifecycle.

### 14.9 구현 단계별 업스트림 추적표

OpenSphere native 경로를 구현할 때 참조해야 하는 업스트림은 다음처럼 고정한다.

| OpenSphere 구현 단계 | 참조 업스트림 | 참조해야 할 핵심 개념 |
|---|---|---|
| Component catalog | OKD OLM, Open Data Hub Operator | CatalogSource, package, channel, component list |
| Component version | OLM ClusterServiceVersion | version metadata, owned CRDs, required permissions, install strategy |
| Subscription | OLM Subscription | package/channel subscription, approval mode, currentCSV |
| Install plan | OLM InstallPlan | approval, install steps, failed reason, retry/rollback |
| DataScienceCluster-compatible state | ODH Operator, RHOAI | `DataScienceCluster.spec.components.*.managementState`, Ready/Progressing/Failed |
| Workbench runtime | ODH Workbenches, Kubeflow Notebooks | runtime image, storage, notebook/workbench lifecycle, data connection |
| Pipeline runtime | Kubeflow Pipelines, Tekton | pipeline definition, run, parameter, artifact, log, lineage |
| Model serving | KServe, ODH Model Serving | InferenceService, ServingRuntime, predictor, model artifact URI, readiness |
| Model registry/promotion | ODH Model Registry, ML Metadata | model, version, stage, metrics, owner, promotion history |
| Monitoring | TrustyAI, Prometheus | metric target, drift/bias/explainability, threshold, alert |
| Distributed workloads | Kueue, Ray | queue admission, Workload, LocalQueue, RayJob, RayCluster, suspend/resume |
| Hardening | Kubernetes controller pattern, OLM lifecycle | status subresource, conditions, events, finalizers, retry/backoff, upgrade |

### 14.10 OpenSphere native 구현 로드맵

이 로드맵은 별도 OKD 클러스터를 추가하지 않는다는 운영 제약을 전제로 한다.

1. Foundation API 확정
   - `OpenSphereComponentCatalog`, `OpenSphereComponentVersion`, `OpenSphereSubscription`, `OpenSphereInstallPlan`, `OpenSphereDataScienceCluster`를 OpenSphere AI의 설치/운영 기본 API로 고정한다.
   - 사용자는 `/ai` Wizard에서 namespace, provider, package, channel, catalog source, DataScienceCluster 이름을 선택한다.

2. Controller reconcile 공통화
   - 모든 claim controller가 `desired -> actual -> status` 흐름을 따른다.
   - 공통 status는 `phase`, `ready`, `observedGeneration`, `conditions`, `lastReconciledAt`를 사용한다.

3. Fallback runtime 완성
   - 업스트림 CRD가 없는 현재 클러스터에서도 Workbench, Pipeline, Inference, Monitoring, Distributed workload가 동작해야 한다.
   - 이 단계는 현재 OpenSphere 클러스터에서 즉시 사용 가능한 제품성을 만든다.

4. Upstream backend detection
   - KServe, Kueue, Ray, Tekton, TrustyAI, Prometheus CRD/API가 있는지 감지한다.
   - 감지 결과를 `/ai` Cluster settings와 component status에 표시한다.
   - 현재 상태: `/admin/native/backends`와 Cluster settings의 Backend detection 카드로 1차 구현 완료.

5. Upstream adapter 추가
   - upstream backend가 있으면 fallback Deployment/Job 대신 해당 업스트림 CRD를 생성한다.
   - 예: `InferenceClaim -> InferenceService`, `DistributedWorkloadClaim -> Kueue Workload + RayJob`.
   - 현재 상태: Tekton `PipelineRun`, KServe `InferenceService`, Kueue-managed Job, Ray `RayJob` 1차 adapter 구현 완료.

6. Status normalization
   - 업스트림마다 다른 condition/status를 OpenSphere claim status로 정규화한다.
   - `/ai` 사용자는 backend가 fallback인지 upstream인지와 무관하게 같은 방식으로 상태를 본다.

7. 운영 품질 강화
   - namespace RBAC, impersonation, audit log, finalizer, garbage collection, retry/backoff, metrics, alert, upgrade/rollback을 완성한다.
   - 현재 상태: claim status의 phase/ready/backendMode 변경 시 Kubernetes Event를 남기는 1차 event recording 구현 완료.
   - 현재 상태: `/metrics` Prometheus endpoint와 `/admin/native/controller-metrics` JSON endpoint, Cluster settings metrics card 구현 완료.
   - 현재 상태: reconcile 이벤트를 `opensphere-system/ai-controller-audit-log` ConfigMap에 최근 200개까지 저장하고 `/admin/native/audit-log`와 Cluster settings audit card에서 조회하는 durable audit log 1차 구현 완료.
   - 현재 상태: `WorkbenchClaim`, `PipelineRunClaim`, `InferenceClaim`, `DistributedWorkloadClaim`에 finalizer/garbage collection과 retry/backoff status 1차 구현 완료.
   - 현재 상태: Workbench Deployment, Pipeline Job, Tekton PipelineRun, KServe InferenceService, Distributed Job, Kueue-managed Job, RayJob 상태를 공통 `phase`, `ready`, `reason`, `message`, `conditions`, `upstreamConditions`, `backendResource`, `normalizedAt` 형식으로 정규화하는 status normalization v2 1차 구현 완료.
   - 현재 상태: Kubeflow Pipelines adapter 1차 구현 완료. ODH `DataSciencePipelinesApplication`, `pipelines.kubeflow.org` API group, KFP CRD를 감지하고, KFP backend가 선택되면 run id/application/endpoint를 status, logs, lineage에 기록한다.

8. 호환성 검증
   - fallback-only 클러스터와 upstream-enabled 클러스터를 모두 E2E 테스트한다.
   - 각 claim에 대해 create -> reconcile -> ready/succeeded -> update -> delete 흐름을 자동화한다.

### 14.11 현재 구현 상태

현재 프로젝트에는 다음이 반영되어 있다.

- OpenSphere foundation AI CRD 설치 경로.
- `/ai` Cluster settings setup wizard.
- OpenSphere native component catalog UI.
- `OpenSphereComponentCatalog`, `OpenSphereComponentVersion`, `OpenSphereSubscription`, `OpenSphereInstallPlan`, `OpenSphereDataScienceCluster` CRD/API.
- WorkbenchClaim을 PVC/Deployment/Service로 변환하는 1차 controller.
- PipelineRunClaim을 Kubernetes Job으로 변환하고 실제 Pod 로그를 `/ai`에서 읽는 1차 controller.
- InferenceClaim을 Kubernetes-native Deployment/Service endpoint로 변환하고 `/healthz`, `/predict`를 제공하는 1차 controller.
- Model version registry와 promotion history를 ConfigMap에 저장하고, ModelPromotionClaim approve/evaluation 결과를 registry stage로 반영하는 1차 controller.
- MonitoringTarget status metrics를 생성하고 `/monitoring/trustyai/metrics`에서 실제 target metrics를 반환하는 TrustyAI-compatible 1차 controller.
- DistributedWorkloadClaim을 Kubernetes Job fallback runtime으로 변환하고 queue, runtime, admission, Job phase를 claim status에 반영하는 1차 controller.
- Backend detection API와 UI. 현재 클러스터에서는 upstream ODH/KServe/Kueue/Ray/Tekton/TrustyAI CRD가 없고 OpenSphere fallback CRD는 준비되어 있어 7개 capability가 `FallbackReady`로 판정된다.
- Backend selection policy. claim별 `spec.backend`, `spec.backendMode`, `spec.backendType`이 `auto`, `opensphere`, `upstream` 선택을 지원한다.
- Tekton/KServe/Kueue/Ray upstream adapter. 현재 클러스터에는 upstream CRD가 없으므로 smoke test에서는 `backend: auto`가 OpenSphere fallback을 선택했고, PipelineRunClaim은 Succeeded, InferenceClaim은 Ready, DistributedWorkloadClaim은 Succeeded까지 도달했다.
- Kubernetes Event recording. Workbench, PipelineRun, Inference, Monitoring, DistributedWorkload, ModelPromotion reconcile 상태가 바뀌면 `ai.opensphere.io/reconcile-event=true` label이 붙은 Event를 남긴다. v37 smoke test에서 PipelineRunClaim의 Pending/Succeeded 전환 이벤트를 확인했다.
- Controller metrics. `/metrics`는 reconcile count, failure count, duration, emitted event count를 Prometheus format으로 노출하고, Cluster settings는 `/admin/native/controller-metrics`를 통해 controller별 reconcile 상태를 표시한다. v38 smoke test에서 reconcile/event counter 증가를 확인했다.
- Durable audit log. `/admin/native/audit-log`는 reconcile event 기록을 JSON으로 제공하고, `/ai` Cluster settings는 `Controller audit log` 카드로 최근 항목을 표시한다. 저장소는 `opensphere-system/ai-controller-audit-log` ConfigMap이며 최근 200개 항목을 유지한다.
- Finalizer/garbage collection. 실행형 claim은 `ai.opensphere.io/finalizer`를 갖고, 삭제 요청 시 controller가 생성한 Deployment, Service, PVC, Job, Tekton PipelineRun, KServe InferenceService, RayJob을 정리한 뒤 finalizer를 제거한다.
- Retry/backoff. 실행형 claim reconcile 실패 시 `phase: Retrying`, `retryCount`, `lastFailureReason`, `lastFailureMessage`, `nextRetryAt`을 status에 기록한다. `/ai` resource table은 이 내용을 Detail 컬럼으로 표시한다.
- Status normalization v2. 실행형 claim은 backend 종류와 무관하게 공통 status shape를 갖는다. `/ai`는 `phase`, `ready`, `reason`, `message`를 우선 표시하고, 운영자는 `upstreamConditions`, `backendResource`, `normalizedAt`으로 원본 upstream 상태 추적이 가능하다.
- Kubeflow Pipelines adapter. `PipelineRunClaim.spec.backend`가 `kubeflow`, `kfp`, `kubeflow-pipelines`이면 KFP backend를 우선한다. KFP가 없으면 `Retrying` 상태로 명확히 표시하고, KFP가 있으면 KFP application/endpoint/run id를 claim status와 lineage/log API에 연결한다.
- TrustyAI adapter. `MonitoringTarget.spec.backend`가 `trustyai`, `prometheus`, `upstream`이면 TrustyAIService를 우선한다. TrustyAI가 있으면 metric source, endpoint, upstream condition을 status와 `/monitoring/trustyai/metrics`에 기록하고, 없으면 `Retrying`과 `nextRetryAt`으로 설치 필요 상태를 표시한다.
- Model Registry adapter. `ModelPromotionClaim.spec.backend` 또는 registry API 요청의 `backend`가 `modelregistry`, `model-registry`, `registry`, `upstream`이면 ODH `ModelRegistry`를 우선한다. ModelRegistry 인스턴스와 service endpoint를 감지해 registry source와 sync 결과를 status/API 응답에 기록하고, 없으면 ConfigMap-backed registry로 fallback하거나 강제 upstream 요청에는 `Retrying`을 표시한다.
- Security hardening. 외부 write API는 사용자 `x-os-id-token`을 요구하고, namespace resource write는 Kubernetes `SelfSubjectAccessReview`로 확인한다. 설치/승인/reconcile 같은 admin action은 admin group 또는 cluster setup RBAC를 요구하고, 허용/거부 결정은 durable audit log에 남긴다.
- Upgrade/rollback. `OpenSphereInstallPlan`은 install, upgrade, rollback operation과 previous/target/rollback version, migration step, rollback hook, condition을 기록한다. approve action은 installed version과 subscription version을 전환한다.
- Monitoring history/alert. `MonitoringTarget` reconcile은 metric sample을 ConfigMap history에 누적하고, threshold 위반을 alert rule 상태로 기록한다. `/monitoring/trustyai/metrics`는 current metrics, alerts, retained history를 함께 제공한다.

남은 핵심 과제는 다음이다.

- Workbench URL 노출과 data connection mount.
- Pipeline definition import, parameter schema validation, artifact persistence.
- Inference real model runtime adapter, artifact URI loading, autoscaling, KServe backend selection.
- Model Registry 실제 upstream write 검증, batch evaluation metric provider 연동, artifact metadata schema 고도화.
- Prometheus/TrustyAI metric history persistence, alert rule.
- Model Registry upstream adapter.
- namespace RBAC, user impersonation hardening, upgrade/rollback.

### 14.12 v39 이후 단계별 구현 계획

현재 방향은 "OKD 클러스터를 별도로 추가하지 않고, OKD/OLM/ODH의 핵심 계약을 OpenSphere native layer로 재구현한다"이다. 이에 따라 다음 구현 단계와 참조 업스트림을 고정한다.

| 순서 | 구현 단계 | 왜 필요한가 | 구체 구현 | 참조 업스트림 |
|---|---|---|---|---|
| 1 | Finalizer와 garbage collection | claim 삭제 후 Job/Deployment/Service/PVC 또는 upstream CRD가 남으면 운영 오염이 생긴다. | 모든 claim에 finalizer를 붙이고 삭제 시 생성 리소스를 정리한다. | Kubernetes finalizers, controller-runtime owner reference pattern |
| 2 | Retry/backoff | 일시적인 이미지 pull, quota, upstream API 실패를 즉시 terminal failure로 처리하면 운영자가 복구하기 어렵다. | status에 retryCount, lastFailureReason, nextRetryAt을 추가하고 backoff를 적용한다. | Kubernetes controller workqueue, OLM InstallPlan failure model |
| 3 | Status normalization v2 | Tekton, KServe, Kueue, Ray의 condition 형식이 달라 `/ai`가 일관된 상태를 보여주기 어렵다. | upstream condition을 OpenSphere 공통 `phase`, `ready`, `conditions`로 정규화한다. | Kubernetes conditions, Tekton PipelineRun status, KServe conditions |
| 4 | Kubeflow Pipelines adapter | ODH의 pipeline 경험은 단순 Job 실행보다 pipeline definition, artifact, lineage가 중요하다. | PipelineClaim/PipelineRunClaim을 Kubeflow Pipelines API 또는 Tekton backend와 연결한다. | Kubeflow Pipelines, Tekton |
| 5 | TrustyAI adapter | 모니터링은 status mock이 아니라 drift/bias/explainability metric source와 연결되어야 한다. | MonitoringTarget을 TrustyAI metric endpoint와 Prometheus query로 연결한다. | TrustyAI, Prometheus |
| 6 | Model Registry adapter | ConfigMap registry는 1차 구현에는 충분하지만 운영 모델 registry로는 한계가 있다. | registry backend interface를 만들고 ODH Model Registry/외부 registry를 선택 가능하게 한다. | ODH Model Registry, ML Metadata |
| 7 | Security hardening | 설치, 승인, 모델 배포는 namespace와 사용자 권한에 따라 제한되어야 한다. | namespace RBAC, user impersonation, admin-only install action, audit trail을 강화한다. | Kubernetes RBAC, OpenShift/RHOAI authorization |
| 8 | Upgrade/rollback | AI component는 version upgrade와 실패 시 rollback이 필요하다. | component version upgrade plan, migration hook, rollback action, upgrade status를 추가한다. | OLM CSV replacement, InstallPlan lifecycle |

이 단계들은 OpenSphere 제품 안에서 구현해야 하는 항목이다. OKD/OLM을 그대로 설치하는 절차가 아니라, 업스트림에서 검증된 개념과 상태 모델을 OpenSphere API와 controller가 재현하는 방식이다.

v58 기준으로 1번부터 8번, metric history/alert rule 1차 구현, Model Registry upstream REST coverage 1차 구현, promotion approval audit/evaluation metrics persistence 1차 구현, 반복 reconcile 중복 방지, EvaluationJob batch metric provider reconcile 1차 구현, Model Registry upstream write self-test 1차 구현, native readiness와 upstream parity 분리 판정, actual/reference UI 출처 표시, 주요 reference 화면의 native actual 전환은 완료 상태다. 다음 구현 우선순위는 실제 ODH/RHOAI upstream endpoint 환경에서 self-test를 실행하고 multi-cluster 최종 검증 결과를 upstream parity 축에 누적하는 것이다.
