// +groupName=ai.opensphere.io
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	GroupVersion  = schema.GroupVersion{Group: "ai.opensphere.io", Version: "v1alpha1"}
	SchemeBuilder = runtime.NewSchemeBuilder(func(s *runtime.Scheme) error {
		s.AddKnownTypes(GroupVersion,
			&AITrainingStack{}, &AITrainingStackList{},
			&ComputeBackendClaim{}, &ComputeBackendClaimList{},
			&DatasetClaim{}, &DatasetClaimList{},
			&TrainingJobClaim{}, &TrainingJobClaimList{},
			&ModelPromotionClaim{}, &ModelPromotionClaimList{},
			&InferenceClaim{}, &InferenceClaimList{},
		)
		metav1.AddToGroupVersion(s, GroupVersion)
		return nil
	})
	AddToScheme = SchemeBuilder.AddToScheme
)

// AITrainingStackSpec 는 AI MLOps/Training substrate 선언이다.
//
// D-2 운영 plane 신설(arch-001 §7 step 7):
// KServe+vLLM(서빙, ADR-070) · MLflow(lineage, ADR-071) · Feast(feature store, ADR-082)
// · TrustyAI(bias/drift 게이트, ADR-072)
//
// ai-eval(golden-set CI 게이트) 과 역할 경계:
//   - ai-eval: 배포 전 golden-set 검증 (CI gate)
//   - TrustyAI(여기): 런타임 bias/drift/eval 모니터링
type AITrainingStackSpec struct {
	// Serving 은 모델 서빙 설정이다 (KServe + vLLM).
	// +optional
	Serving *ModelServingSpec `json:"serving,omitempty"`

	// Lineage 는 MLflow 실험 추적 설정이다 (ADR-071).
	// +optional
	Lineage *MLflowSpec `json:"lineage,omitempty"`

	// FeatureStore 는 Feast feature store 설정이다 (ADR-082).
	// +optional
	FeatureStore *FeastSpec `json:"featureStore,omitempty"`

	// TrustyAI 는 runtime bias/drift 모니터링 설정이다 (ADR-072).
	// +optional
	TrustyAI *TrustyAISpec `json:"trustyAI,omitempty"`
}

// ComputeBackendClaimSpec 는 학습/추론 compute backend 추상화 선언이다.
type ComputeBackendClaimSpec struct {
	// BackendType 은 K8s GPU node pool 또는 외부 GPU 서버를 표현한다.
	// +kubebuilder:validation:Enum=kubernetes;external-gpu
	BackendType string `json:"backendType"`

	// GPUClass 는 nvidia-l4, nvidia-a100 같은 GPU class 이름이다.
	// +optional
	GPUClass string `json:"gpuClass,omitempty"`

	// Endpoint 는 external-gpu backend 의 API endpoint 다.
	// +optional
	Endpoint string `json:"endpoint,omitempty"`
}

// DatasetClaimSpec 는 학습 데이터셋 선언이다.
type DatasetClaimSpec struct {
	// SourceType 은 PolyON 업무 데이터 원천을 OpenSphere 데이터셋으로 끌어오는 유형이다.
	// +kubebuilder:validation:Enum=drive;mail;approval;project;bucket;git
	SourceType string `json:"sourceType"`

	// SourceRef 는 원천 시스템의 객체 참조다.
	SourceRef ObjectRef `json:"sourceRef"`

	// Purpose 는 fine-tune, eval, rag-index 같은 사용 목적이다.
	// +kubebuilder:validation:Enum=fine-tune;eval;rag-index;feature-store
	Purpose string `json:"purpose,omitempty"`
}

// TrainingJobClaimSpec 는 모델 학습 job 선언이다.
type TrainingJobClaimSpec struct {
	DatasetRef        ObjectRef `json:"datasetRef"`
	ComputeBackendRef ObjectRef `json:"computeBackendRef"`

	// Framework 는 pytorch, transformers, kubeflow-pipeline 등 실행 framework 다.
	// +kubebuilder:validation:Enum=pytorch;transformers;kubeflow-pipeline
	Framework string `json:"framework,omitempty"`

	// TrainingMode 는 full, lora, qlora 같은 학습 모드다.
	// +kubebuilder:validation:Enum=full;lora;qlora
	TrainingMode string `json:"trainingMode,omitempty"`
}

// ModelPromotionClaimSpec 는 평가 통과 모델의 승격 선언이다.
type ModelPromotionClaimSpec struct {
	ModelRef ObjectRef `json:"modelRef"`

	// EvaluationRef 는 ai-eval EvaluationJob 참조다.
	EvaluationRef ObjectRef `json:"evaluationRef"`

	// Stage 는 승격 대상 stage 다.
	// +kubebuilder:validation:Enum=staging;production
	Stage string `json:"stage"`
}

// InferenceClaimSpec 는 승인된 모델 serving endpoint 선언이다.
type InferenceClaimSpec struct {
	ModelRef ObjectRef `json:"modelRef"`

	// PromotionRef 는 production/staging 배포를 허용한 ModelPromotionClaim 참조다.
	PromotionRef ObjectRef `json:"promotionRef"`

	// Runtime 은 kserve, vllm 같은 serving runtime 이다.
	// +kubebuilder:validation:Enum=kserve;vllm
	Runtime string `json:"runtime,omitempty"`
}

// ObjectRef 는 OpenSphere CR 참조다.
type ObjectRef struct {
	APIVersion string `json:"apiVersion,omitempty"`
	Kind       string `json:"kind,omitempty"`
	Name       string `json:"name"`
	Namespace  string `json:"namespace,omitempty"`
}

// ModelServingSpec 은 KServe + vLLM 서빙 설정이다.
type ModelServingSpec struct {
	// Enabled=true 면 KServe 를 배포한다.
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`
	// vLLM=true 면 vLLM 런타임을 등록한다.
	// +kubebuilder:default=false
	VLLMRuntime bool `json:"vllmRuntime,omitempty"`
}

// MLflowSpec 은 MLflow 설정이다.
type MLflowSpec struct {
	// Enabled=true 면 MLflow 를 배포한다.
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`
	// ArtifactStore 는 MLflow artifact 저장소 (RustFS S3).
	// +optional
	ArtifactStore string `json:"artifactStore,omitempty"`
}

// FeastSpec 은 Feast feature store 설정이다.
type FeastSpec struct {
	// Enabled=true 면 Feast 를 배포한다.
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`
}

// TrustyAISpec 은 TrustyAI 런타임 모니터링 설정이다.
// ai-eval 의 CI gate 와 역할 분리: 이것은 프로덕션 런타임 드리프트 감지.
type TrustyAISpec struct {
	// Enabled=true 면 TrustyAI 를 배포한다.
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`
	// BiasThreshold 는 bias 알람 임계값이다 (0.0~1.0).
	// +optional
	BiasThreshold *float64 `json:"biasThreshold,omitempty"`
}

// AITrainingStackStatus 는 AI Training 스택 상태다.
type AITrainingStackStatus struct {
	// Ready=true 면 전체 스택 준비 완료.
	Ready bool `json:"ready,omitempty"`
	// MLflowEndpoint 는 MLflow UI/API 엔드포인트다.
	// +optional
	MLflowEndpoint string `json:"mlflowEndpoint,omitempty"`
	// Conditions 는 상태 조건이다.
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// ClaimStatus 는 AI training lifecycle claim 공통 상태다.
type ClaimStatus struct {
	Ready      bool               `json:"ready,omitempty"`
	Phase      string             `json:"phase,omitempty"`
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// AITrainingStack 은 AI MLOps/Training substrate CR 이다.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=ait
// +kubebuilder:printcolumn:name="Ready",type=boolean,JSONPath=`.status.ready`
type AITrainingStack struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              AITrainingStackSpec   `json:"spec,omitempty"`
	Status            AITrainingStackStatus `json:"status,omitempty"`
}

// AITrainingStackList 는 AITrainingStack 목록이다.
// +kubebuilder:object:root=true
type AITrainingStackList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AITrainingStack `json:"items"`
}

// ComputeBackendClaim 은 GPU/compute backend 추상화 CR 이다.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=compute
type ComputeBackendClaim struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ComputeBackendClaimSpec `json:"spec,omitempty"`
	Status            ClaimStatus             `json:"status,omitempty"`
}

// ComputeBackendClaimList 는 ComputeBackendClaim 목록이다.
// +kubebuilder:object:root=true
type ComputeBackendClaimList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ComputeBackendClaim `json:"items"`
}

// DatasetClaim 은 업무 데이터 원천을 학습/평가/RAG 데이터셋으로 선언하는 CR 이다.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=dataset
type DatasetClaim struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              DatasetClaimSpec `json:"spec,omitempty"`
	Status            ClaimStatus      `json:"status,omitempty"`
}

// DatasetClaimList 는 DatasetClaim 목록이다.
// +kubebuilder:object:root=true
type DatasetClaimList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DatasetClaim `json:"items"`
}

// TrainingJobClaim 은 모델 학습 job 선언 CR 이다.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=train
type TrainingJobClaim struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              TrainingJobClaimSpec `json:"spec,omitempty"`
	Status            ClaimStatus          `json:"status,omitempty"`
}

// TrainingJobClaimList 는 TrainingJobClaim 목록이다.
// +kubebuilder:object:root=true
type TrainingJobClaimList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TrainingJobClaim `json:"items"`
}

// ModelPromotionClaim 은 ai-eval gate 통과 모델만 stage 로 승격하는 CR 이다.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=promote
type ModelPromotionClaim struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ModelPromotionClaimSpec `json:"spec,omitempty"`
	Status            ClaimStatus             `json:"status,omitempty"`
}

// ModelPromotionClaimList 는 ModelPromotionClaim 목록이다.
// +kubebuilder:object:root=true
type ModelPromotionClaimList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ModelPromotionClaim `json:"items"`
}

// InferenceClaim 은 승인된 모델 serving endpoint 선언 CR 이다.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=infer
type InferenceClaim struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              InferenceClaimSpec `json:"spec,omitempty"`
	Status            ClaimStatus        `json:"status,omitempty"`
}

// InferenceClaimList 는 InferenceClaim 목록이다.
// +kubebuilder:object:root=true
type InferenceClaimList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []InferenceClaim `json:"items"`
}

func (o *AITrainingStack) DeepCopyObject() runtime.Object {
	if o == nil {
		return nil
	}
	out := new(AITrainingStack)
	*out = *o
	o.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	return out
}
func (o *AITrainingStackList) DeepCopyObject() runtime.Object {
	if o == nil {
		return nil
	}
	out := new(AITrainingStackList)
	*out = *o
	o.ListMeta.DeepCopyInto(&out.ListMeta)
	if o.Items != nil {
		out.Items = make([]AITrainingStack, len(o.Items))
		copy(out.Items, o.Items)
	}
	return out
}
func (o *ComputeBackendClaim) DeepCopyObject() runtime.Object {
	if o == nil {
		return nil
	}
	out := new(ComputeBackendClaim)
	*out = *o
	o.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	return out
}
func (o *ComputeBackendClaimList) DeepCopyObject() runtime.Object {
	if o == nil {
		return nil
	}
	out := new(ComputeBackendClaimList)
	*out = *o
	o.ListMeta.DeepCopyInto(&out.ListMeta)
	if o.Items != nil {
		out.Items = make([]ComputeBackendClaim, len(o.Items))
		copy(out.Items, o.Items)
	}
	return out
}
func (o *DatasetClaim) DeepCopyObject() runtime.Object {
	if o == nil {
		return nil
	}
	out := new(DatasetClaim)
	*out = *o
	o.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	return out
}
func (o *DatasetClaimList) DeepCopyObject() runtime.Object {
	if o == nil {
		return nil
	}
	out := new(DatasetClaimList)
	*out = *o
	o.ListMeta.DeepCopyInto(&out.ListMeta)
	if o.Items != nil {
		out.Items = make([]DatasetClaim, len(o.Items))
		copy(out.Items, o.Items)
	}
	return out
}
func (o *TrainingJobClaim) DeepCopyObject() runtime.Object {
	if o == nil {
		return nil
	}
	out := new(TrainingJobClaim)
	*out = *o
	o.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	return out
}
func (o *TrainingJobClaimList) DeepCopyObject() runtime.Object {
	if o == nil {
		return nil
	}
	out := new(TrainingJobClaimList)
	*out = *o
	o.ListMeta.DeepCopyInto(&out.ListMeta)
	if o.Items != nil {
		out.Items = make([]TrainingJobClaim, len(o.Items))
		copy(out.Items, o.Items)
	}
	return out
}
func (o *ModelPromotionClaim) DeepCopyObject() runtime.Object {
	if o == nil {
		return nil
	}
	out := new(ModelPromotionClaim)
	*out = *o
	o.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	return out
}
func (o *ModelPromotionClaimList) DeepCopyObject() runtime.Object {
	if o == nil {
		return nil
	}
	out := new(ModelPromotionClaimList)
	*out = *o
	o.ListMeta.DeepCopyInto(&out.ListMeta)
	if o.Items != nil {
		out.Items = make([]ModelPromotionClaim, len(o.Items))
		copy(out.Items, o.Items)
	}
	return out
}
func (o *InferenceClaim) DeepCopyObject() runtime.Object {
	if o == nil {
		return nil
	}
	out := new(InferenceClaim)
	*out = *o
	o.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	return out
}
func (o *InferenceClaimList) DeepCopyObject() runtime.Object {
	if o == nil {
		return nil
	}
	out := new(InferenceClaimList)
	*out = *o
	o.ListMeta.DeepCopyInto(&out.ListMeta)
	if o.Items != nil {
		out.Items = make([]InferenceClaim, len(o.Items))
		copy(out.Items, o.Items)
	}
	return out
}
