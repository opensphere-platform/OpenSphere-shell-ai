# ai — kind: subShell (F/E + B/E 수직 도메인)

kind: subShell  ·  hostRef: main  ·  tier 2 (host = 도메인 B/E 소유자)
frontend/ : opensphere-ai-shell/ui (in-tree)
backend/  : ai-orchestrator + ai-eval + ai-training (P4)
note: 
정본: 00-V2-구조설계.md §3

## Main Shell 표준 통합 계약

OpenSphere AI Hub는 `OpenSphere-shell-template`의 Production subShell 기준을 적용합니다.

| 항목 | AI Hub 구현 |
|---|---|
| Canonical ID / host | `ai` / `main` |
| Page | `/p/ai/*` |
| API | `/api/plugins/ai` |
| CLI | `os ai` · `/admin/native/agent-tools` |
| Manual | `ui-shell/manual/ai.ko.md` 런타임 등록 |
| Search | Main Shell 통합 검색 provider |
| Notification | frontend 활성화 알림 + backend durable event 경로 |
| Readiness | `/healthz`, `/readyz`, `/api/status` |
| Contract | `/api/contract`, `/openapi.json` |
| Observability | `opensphere.v1` stdout JSON, `/metrics`, W3C trace context |

HTTP 요청은 correlation ID, operation ID, trace ID를 응답 헤더와 구조화 로그에 함께 기록합니다.
토큰·자격 증명·요청 본문 전체는 로그에 남기지 않습니다.

```bash
npm ci
npm run test:contracts
npm run build
```

## OCI 설치 계약

AI Hub는 서명된 `ModulePackageV1`과 `ai-domain-operator-v1` Host permission profile로 설치합니다.
`os extensions install`은 Console namespace에 AI workload를 만들고, Host가 고정한 최소권한
ClusterRole과 `opensphere-system` 한정 RoleBinding을 연결합니다. 기존 `uipluginpackage.yaml`과
`rbac.yaml`은 레거시 설치 rollback 자료이며 OCI 설치 입력으로 적용하지 않습니다.

운영 설치는 Platform Support Profile Ready와 PFS Established가 선행되어야 합니다. AI operand/CRD는
PFS·AI domain lifecycle이 소유하며, descriptor가 임의의 cluster RBAC 또는 upstream operator 설치를
주입하지 않습니다.

Host Controller에는 `AI_WORKBENCH_IMAGE`를 승인된 immutable OCI digest로 설정해야 합니다. 값이
없거나 digest가 아니면 AI workload의 `/readyz`는 503을 반환하며 activation이 fail-closed 됩니다.

```powershell
os extensions inspect ghcr.io/opensphere-platform/opensphere-shell-ai:edge
os extensions install ghcr.io/opensphere-platform/opensphere-shell-ai:edge --reason "AI Hub 검증 설치"
os extensions activate ai
os ai readiness
```
