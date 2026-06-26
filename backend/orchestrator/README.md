# opensphere-ai-orchestrator

OpenSphere-Platform 컴포넌트 — **Plane P4 · kind operator**

R2D2 AI Agent Orchestrator. PolyON 의 3-tier agent 운영 모델을 OpenSphere P4 Intelligence 로 계승한다.

## Implemented API skeleton

- `AIAgent`
  - `operations`, `company`, `personal` tier
  - foundation-ai `LLMRouteClaim` 참조
  - source attribution 필수 정책
- `PromptLibrary`
  - prompt bundle/version 선언
- `ToolClaim`
  - agent tool 접근 선언
  - OPA(Open Policy Agent) policy gate 참조
- `AgentTracePolicy`
  - Langfuse/OTLP trace sink 와 retention 정책

## Boundary

- 포함: agent runtime, prompt governance, tool policy, source attribution, agent trace.
- 제외: LLM provider 설치, vector index 운영, model training lifecycle.
