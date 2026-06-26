# opensphere-ai-training

OpenSphere-Platform 컴포넌트 — **Plane P4 · kind operator**

AI MLOps/Training substrate. PolyON 의 AI Training Platform 전략축을 OpenSphere P4 Intelligence 로 계승한다.

## Implemented API skeleton

- `AITrainingStack`
  - KServe + vLLM
  - MLflow
  - Feast
  - TrustyAI
- `ComputeBackendClaim`
  - K8s(Kubernetes) GPU node pool 또는 external GPU backend 추상화
- `DatasetClaim`
  - Drive, Mail, Approval, Project, Bucket, Git 원천을 dataset 으로 선언
- `TrainingJobClaim`
  - PyTorch, Transformers, Kubeflow pipeline 기반 학습 job 선언
- `ModelPromotionClaim`
  - `ai-eval` gate 통과 모델만 staging/production 으로 승격
- `InferenceClaim`
  - 승인된 모델 serving endpoint 선언

## Boundary

- 포함: MLOps substrate, dataset, compute backend, training, promotion, inference 선언.
- 제외: 배포 전 golden-set gate 권위(`opensphere-ai-eval`), LLM route substrate(`opensphere-foundation-ai`), agent runtime(`opensphere-ai-orchestrator`).
