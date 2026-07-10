# OpenSphere Console + AI subShell 업그레이드 완료 리포트

- 기준일: 2026-07-11 (Asia/Seoul)
- 기준 명세: `CONSTITUTION-0003-SHELL-HOSTING-INTEGRATION`
- 대상: OpenSphere Console, OpenSphere SDK, OpenSphere AI subShell
- 판정: 빌드·배포·브라우저 E2E 검증 완료

## 1. 아키텍처 결론

OpenSphere Console은 Backbone을 선택적으로 덧붙이는 UI가 아니라, Backbone의 내구 상태 저장 능력을 기둥으로 삼아 서는 관리 평면이다. PostgreSQL 감사·설정 상태, RustFS 오브젝트 저장소, Gitea config-as-code가 Console의 상태저장 베이스를 구성한다. 그 위에서 Main Shell이 Host Contract와 라우팅·API·검색·알림 경계를 소유하고, subShell과 plugin이 명시적으로 연결된다.

따라서 올바른 구성 순서는 다음과 같다.

1. Backbone이 내구 데이터·감사·오브젝트·설정 이력 기둥을 제공한다.
2. Main Shell이 인증, Host Contract, guest 격리와 공통 UX를 제공한다.
3. subShell이 자신의 `/p/<id>/*` 경계 안에서 독립 제품 영역을 구성한다.
4. plugin은 선언된 capability와 contribution으로 세부 기능을 연결한다.

이번 배포에서 Backbone의 PostgreSQL, RustFS, Gitea가 모두 `Ready 1/1`임을 Console 관리 화면에서 확인했다. 감사 로그에는 `ext:ai / started / ai / info` 이벤트가 내구 감사 경로로 기록됐다.

## 2. Console 정상화 및 `/manage/*` 복구

- 브라우저 `id_token`의 실제 만료 상태를 기준으로 세션을 복원하도록 인증 수명주기를 수정했다.
- 인증이 필요한 `/manage` 라우트에 명시적 guard를 적용했다.
- API가 401을 반환하고 토큰이 유효하지 않을 때 중복 없이 재인증하도록 수정했다.
- Console Controller, Console Backend, Identity, OAA Gateway와 Backbone 서비스의 JWKS 원본을 BFF가 발행하는 OpenSphere Auth 키로 정합화했다.
- Monitoring CRD가 없는 환경에서 Kubernetes API의 text/plain 404를 JSON으로 강제 파싱하던 Dupa 오류를 제거했다.
- Main Shell의 guest 라우팅을 Angular Router 소유 경계로 통합했다. subShell이 `window.history`를 직접 소유하지 않고 Host의 `routing` context를 사용한다.

브라우저 검증 결과:

- `/manage/backbone`: PostgreSQL, RustFS, Gitea 모두 Ready
- `/manage/observability`: 미설치 구성요소를 오류가 아닌 `미설치` 상태로 표시
- `/manage/console-admins`: 사용자와 내구 감사 로그 정상 표시
- `/p/ai/models/registry`: 직접 딥링크 및 새로고침 정상
- 글로벌 검색 `Model` → AI 검색 contribution → `/p/ai/models/registry` 이동 후 `Model registry` 화면 전환 정상

## 3. OpenSphere AI 표본 Production subShell

AI를 Constitution 0003의 표본 subShell로 승격했다.

- 패키지 종류: `subShell`
- 버전: `1.0.0`
- Host API: `1.0.0`
- Host 호환 범위: `>=1.0.0 <2.0.0`
- capability: page register, API proxy, navigation, search, frontend notification
- contribution: page, navigation, API, CLI, manual, search, notification, logs, metrics, traces
- signed manifest 및 entry digest 검증
- Host-owned routing context 소비 및 deactivate cleanup
- 동일 출처 API client, correlation ID, mutation idempotency key 사용
- `/readyz`, `/openapi.json`, `/search`, `/manual/source`, `/operations/ledger` 제공
- CLI 계약 `/admin/native/agent-tools` 제공
- 구조화 JSON HTTP 로그와 보안 감사 이벤트 제공
- 변경 요청의 correlation/idempotency 헤더 누락 시 fail-closed
- Kanidm JWKS TLS는 검증을 끄지 않고 현재 Kanidm Dev CA를 명시적으로 신뢰

Registry 판정:

- phase: `Activated`
- workload: `Ready`
- manifest/signature/entry digest: `Verified`
- permissions: `Approved`
- page, navigation, API, CLI, manual, search, notification, logs, metrics, traces: 모두 `Ready`
- 직전 digest를 `previousDigest`로 보존하여 rollback 가능

## 4. 최종 배포 산출물

- Console: `sha256:2a8bbe207cd543f77d9cc0fb6728b3a90cc61c2fb8d77a4fe7f750edec4760e1`
- Dupa Controller: `sha256:f5358401d659ce0a4c7fd68fed107829fdaf4cfa1ae663e98262d4871a72837c`
- Console Backend: `sha256:00c117da6b5840c0d50eb1ec35cf0ef4e4eb3712c9a0c70b21a33f6c86230f10`
- AI subShell: `sha256:a65af5151f049ad3b1dbd070a2f7a05d89779226f8736814170ba11d32a9e613`
- AI manifest SHA-256: `fd2039f2e852d9d70e345f2d33bf1edc9ab2d8202fbbf458025bba6df9dd177b`
- AI entry SHA-256: `37181a2bc8ee73b18374420c62b5757c2b254a130d7581a2d9503a6d491a416e`

Console과 AI는 각각 2 replica가 최종 digest로 Ready이며 restart는 0이다.

## 5. 검증 결과

- Console Node test: 50 passed, 0 failed
- SDK TypeScript typecheck/build: passed
- AI RBAC regression: passed
- AI support-services regression: passed
- AI Constitution 0003 contract: passed
- Docker production build: Console/AI passed
- 브라우저 인증·관리·검색·딥링크 E2E: passed
- AI `/readyz` 및 OpenAPI 버전: HTTP 200, `1.0.0`
- AI 관리자 CLI manifest 및 operation ledger: 브라우저 인증으로 HTTP 200
- mutation header gate: idempotency key 누락 시 HTTP 400
- AI 이미지 취약점: 0 Critical / 0 High / 0 Medium / 0 Low
- Console 이미지 취약점: 0 Critical / 0 High / 2 Medium / 2 Low

Console의 Medium/Low 4건은 Alpine 패키지 `busybox`, `freetype`, `libxml2`에 있으며 스캔 시점에 upstream 수정 버전이 없다. Critical/High는 없으며, 기반 이미지 수정판이 발행되면 재빌드·재스캔 대상으로 추적한다.

## 6. 최종 판정

Console은 Backbone을 베이스로 정상 기동하며 `/manage/*` 관리 기능이 복구됐다. AI는 Main Shell의 Host Contract를 따르는 서명된 Production subShell로 등록·활성화됐고, 검색·내비게이션·API·CLI·매뉴얼·알림·관측성 계약을 모두 제공한다. 이 구현을 후속 subShell의 참조 표본으로 사용할 수 있다.
