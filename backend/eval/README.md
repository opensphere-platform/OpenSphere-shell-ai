# opensphere-ai-eval

OpenSphere-Platform 컴포넌트 — **Plane P4 · kind operator**

Golden-set 평가 하니스. Accuracy, groundedness, safety, latency gate 를 배포 전 CI(Continuous Integration)에 붙여 model promotion 을 차단하거나 허용한다.

## Implemented API skeleton

- `EvaluationPolicy`
  - golden-set dataset 과 gate 기준 선언
  - `enforcement`: `audit`, `block`
- `EvaluationJob`
  - model, inference, route 등 평가 대상 실행 선언
  - 통과 결과를 `ModelPromotionClaim` 이 참조한다.

## Boundary

- `ai-eval` 은 배포 전 gate 의 단일 권위다.
- TrustyAI 는 `opensphere-ai-training` 내부 runtime drift/bias monitoring 이며 배포 차단 권위가 아니다.
