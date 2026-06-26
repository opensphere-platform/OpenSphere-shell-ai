// +groupName=eval.ai.opensphere.io
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// EvaluationPolicySpec 는 golden-set 배포 gate 정책이다.
type EvaluationPolicySpec struct {
	// DatasetRef 는 golden set dataset 참조다.
	DatasetRef ObjectRef `json:"datasetRef"`

	// Gates 는 통과해야 하는 평가 gate 목록이다.
	Gates []EvaluationGate `json:"gates,omitempty"`

	// Enforcement 는 gate 실패 시 처리 방식이다.
	// +kubebuilder:validation:Enum=audit;block
	// +kubebuilder:default=block
	Enforcement string `json:"enforcement,omitempty"`
}

// EvaluationGate 는 단일 평가 기준이다.
type EvaluationGate struct {
	// Metric 은 accuracy, groundedness, safety, latency 같은 지표 이름이다.
	Metric string `json:"metric"`

	// Minimum 은 점수형 지표의 최소값이다.
	// +optional
	Minimum *float64 `json:"minimum,omitempty"`

	// Maximum 은 latency 같은 지표의 최대값이다.
	// +optional
	Maximum *float64 `json:"maximum,omitempty"`
}

// EvaluationJobSpec 는 특정 모델/route에 대한 평가 실행 선언이다.
type EvaluationJobSpec struct {
	// TargetRef 는 평가 대상 모델, inference, route 참조다.
	TargetRef ObjectRef `json:"targetRef"`

	// PolicyRef 는 적용할 EvaluationPolicy 참조다.
	PolicyRef ObjectRef `json:"policyRef"`

	// PromotionRef 는 통과 시 열 수 있는 ModelPromotionClaim 참조다.
	// +optional
	PromotionRef *ObjectRef `json:"promotionRef,omitempty"`
}

// ObjectRef 는 OpenSphere CR 참조다.
type ObjectRef struct {
	APIVersion string `json:"apiVersion,omitempty"`
	Kind       string `json:"kind,omitempty"`
	Name       string `json:"name"`
	Namespace  string `json:"namespace,omitempty"`
}

// EvaluationJobStatus 는 평가 실행 결과다.
type EvaluationJobStatus struct {
	Ready bool `json:"ready,omitempty"`
	// Passed=true 면 gate를 통과했다.
	Passed bool `json:"passed,omitempty"`
	// ScoreSummary 는 metric별 점수 요약이다.
	ScoreSummary map[string]float64 `json:"scoreSummary,omitempty"`
	Conditions   []metav1.Condition `json:"conditions,omitempty"`
}

// EvaluationPolicyStatus 는 policy 검증 상태다.
type EvaluationPolicyStatus struct {
	Ready      bool               `json:"ready,omitempty"`
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// EvaluationJob 은 배포 전 golden-set 평가 gate 실행 CR 이다.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=evaljob
// +kubebuilder:printcolumn:name="Passed",type=boolean,JSONPath=`.status.passed`
type EvaluationJob struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              EvaluationJobSpec   `json:"spec,omitempty"`
	Status            EvaluationJobStatus `json:"status,omitempty"`
}

// EvaluationJobList 는 EvaluationJob 목록이다.
// +kubebuilder:object:root=true
type EvaluationJobList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EvaluationJob `json:"items"`
}

// EvaluationPolicy 는 golden-set gate 정책 CR 이다.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=evalpolicy
// +kubebuilder:printcolumn:name="Ready",type=boolean,JSONPath=`.status.ready`
type EvaluationPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              EvaluationPolicySpec   `json:"spec,omitempty"`
	Status            EvaluationPolicyStatus `json:"status,omitempty"`
}

// EvaluationPolicyList 는 EvaluationPolicy 목록이다.
// +kubebuilder:object:root=true
type EvaluationPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EvaluationPolicy `json:"items"`
}

func (o *EvaluationJob) DeepCopyObject() runtime.Object {
	if o == nil {
		return nil
	}
	out := new(EvaluationJob)
	*out = *o
	o.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	return out
}

func (o *EvaluationJobList) DeepCopyObject() runtime.Object {
	if o == nil {
		return nil
	}
	out := new(EvaluationJobList)
	*out = *o
	o.ListMeta.DeepCopyInto(&out.ListMeta)
	if o.Items != nil {
		out.Items = make([]EvaluationJob, len(o.Items))
		copy(out.Items, o.Items)
	}
	return out
}

func (o *EvaluationPolicy) DeepCopyObject() runtime.Object {
	if o == nil {
		return nil
	}
	out := new(EvaluationPolicy)
	*out = *o
	o.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	return out
}

func (o *EvaluationPolicyList) DeepCopyObject() runtime.Object {
	if o == nil {
		return nil
	}
	out := new(EvaluationPolicyList)
	*out = *o
	o.ListMeta.DeepCopyInto(&out.ListMeta)
	if o.Items != nil {
		out.Items = make([]EvaluationPolicy, len(o.Items))
		copy(out.Items, o.Items)
	}
	return out
}
