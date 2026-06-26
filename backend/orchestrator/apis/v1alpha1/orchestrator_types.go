// +groupName=orchestrator.ai.opensphere.io
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// AIAgentSpec 는 OpenSphere agent runtime 선언이다.
type AIAgentSpec struct {
	// Tier 는 PolyON 3-tier agent 모델을 계승한다.
	// +kubebuilder:validation:Enum=operations;company;personal
	Tier string `json:"tier"`

	// LLMRouteRef 는 foundation-ai 의 LLMRouteClaim 참조다.
	LLMRouteRef ObjectRef `json:"llmRouteRef"`

	// PromptLibraryRef 는 agent 가 사용할 prompt library 참조다.
	// +optional
	PromptLibraryRef *ObjectRef `json:"promptLibraryRef,omitempty"`

	// ToolRefs 는 agent 에 허용된 ToolClaim 목록이다.
	// +optional
	ToolRefs []ObjectRef `json:"toolRefs,omitempty"`

	// RequireSourceAttribution=true 면 grounded source 없는 응답을 차단한다.
	// +kubebuilder:default=true
	RequireSourceAttribution bool `json:"requireSourceAttribution,omitempty"`
}

// PromptLibrarySpec 는 prompt bundle 선언이다.
type PromptLibrarySpec struct {
	// Version 은 prompt bundle 버전이다.
	Version string `json:"version,omitempty"`

	// Prompts 는 prompt 이름과 템플릿 참조 목록이다.
	Prompts []PromptRef `json:"prompts,omitempty"`
}

// PromptRef 는 단일 prompt 참조다.
type PromptRef struct {
	Name      string `json:"name"`
	ConfigMap string `json:"configMap,omitempty"`
	Key       string `json:"key,omitempty"`
}

// ToolClaimSpec 는 agent tool 접근 선언이다.
type ToolClaimSpec struct {
	// ToolType 은 http, kubernetes, workflow, mcp 같은 tool 유형이다.
	// +kubebuilder:validation:Enum=http;kubernetes;workflow;mcp
	ToolType string `json:"toolType"`

	// PolicyRef 는 OPA policy bundle 또는 Policy CR 참조다.
	PolicyRef ObjectRef `json:"policyRef"`

	// AuditLevel 은 tool 호출 감사 수준이다.
	// +kubebuilder:validation:Enum=metadata;input-output;blocked-only
	// +kubebuilder:default=metadata
	AuditLevel string `json:"auditLevel,omitempty"`
}

// AgentTracePolicySpec 는 agent trace 저장과 전파 정책이다.
type AgentTracePolicySpec struct {
	// SinkRef 는 Langfuse/OTLP capability 참조다.
	SinkRef ObjectRef `json:"sinkRef"`

	// RetentionDays 는 agent trace 보관 기간이다.
	// +kubebuilder:default=30
	RetentionDays int `json:"retentionDays,omitempty"`
}

// ObjectRef 는 OpenSphere CR 참조다.
type ObjectRef struct {
	APIVersion string `json:"apiVersion,omitempty"`
	Kind       string `json:"kind,omitempty"`
	Name       string `json:"name"`
	Namespace  string `json:"namespace,omitempty"`
}

// CommonStatus 는 orchestrator API 공통 상태다.
type CommonStatus struct {
	Ready      bool               `json:"ready,omitempty"`
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// AIAgent 는 R2D2/Company/Personal agent runtime 선언 CR 이다.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=agent
// +kubebuilder:printcolumn:name="Tier",type=string,JSONPath=`.spec.tier`
// +kubebuilder:printcolumn:name="Ready",type=boolean,JSONPath=`.status.ready`
type AIAgent struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              AIAgentSpec  `json:"spec,omitempty"`
	Status            CommonStatus `json:"status,omitempty"`
}

// AIAgentList 는 AIAgent 목록이다.
// +kubebuilder:object:root=true
type AIAgentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AIAgent `json:"items"`
}

// PromptLibrary 는 agent prompt bundle 선언 CR 이다.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=prompts
type PromptLibrary struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              PromptLibrarySpec `json:"spec,omitempty"`
	Status            CommonStatus      `json:"status,omitempty"`
}

// PromptLibraryList 는 PromptLibrary 목록이다.
// +kubebuilder:object:root=true
type PromptLibraryList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PromptLibrary `json:"items"`
}

// ToolClaim 은 agent tool 접근과 OPA gate 정책 선언 CR 이다.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=tool
type ToolClaim struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ToolClaimSpec `json:"spec,omitempty"`
	Status            CommonStatus  `json:"status,omitempty"`
}

// ToolClaimList 는 ToolClaim 목록이다.
// +kubebuilder:object:root=true
type ToolClaimList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ToolClaim `json:"items"`
}

// AgentTracePolicy 는 agent trace 저장 정책 CR 이다.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=agenttrace
type AgentTracePolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              AgentTracePolicySpec `json:"spec,omitempty"`
	Status            CommonStatus         `json:"status,omitempty"`
}

// AgentTracePolicyList 는 AgentTracePolicy 목록이다.
// +kubebuilder:object:root=true
type AgentTracePolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AgentTracePolicy `json:"items"`
}

func (o *AIAgent) DeepCopyObject() runtime.Object {
	if o == nil {
		return nil
	}
	out := new(AIAgent)
	*out = *o
	o.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	return out
}
func (o *AIAgentList) DeepCopyObject() runtime.Object {
	if o == nil {
		return nil
	}
	out := new(AIAgentList)
	*out = *o
	o.ListMeta.DeepCopyInto(&out.ListMeta)
	if o.Items != nil {
		out.Items = make([]AIAgent, len(o.Items))
		copy(out.Items, o.Items)
	}
	return out
}
func (o *PromptLibrary) DeepCopyObject() runtime.Object {
	if o == nil {
		return nil
	}
	out := new(PromptLibrary)
	*out = *o
	o.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	return out
}
func (o *PromptLibraryList) DeepCopyObject() runtime.Object {
	if o == nil {
		return nil
	}
	out := new(PromptLibraryList)
	*out = *o
	o.ListMeta.DeepCopyInto(&out.ListMeta)
	if o.Items != nil {
		out.Items = make([]PromptLibrary, len(o.Items))
		copy(out.Items, o.Items)
	}
	return out
}
func (o *ToolClaim) DeepCopyObject() runtime.Object {
	if o == nil {
		return nil
	}
	out := new(ToolClaim)
	*out = *o
	o.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	return out
}
func (o *ToolClaimList) DeepCopyObject() runtime.Object {
	if o == nil {
		return nil
	}
	out := new(ToolClaimList)
	*out = *o
	o.ListMeta.DeepCopyInto(&out.ListMeta)
	if o.Items != nil {
		out.Items = make([]ToolClaim, len(o.Items))
		copy(out.Items, o.Items)
	}
	return out
}
func (o *AgentTracePolicy) DeepCopyObject() runtime.Object {
	if o == nil {
		return nil
	}
	out := new(AgentTracePolicy)
	*out = *o
	o.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	return out
}
func (o *AgentTracePolicyList) DeepCopyObject() runtime.Object {
	if o == nil {
		return nil
	}
	out := new(AgentTracePolicyList)
	*out = *o
	o.ListMeta.DeepCopyInto(&out.ListMeta)
	if o.Items != nil {
		out.Items = make([]AgentTracePolicy, len(o.Items))
		copy(out.Items, o.Items)
	}
	return out
}
