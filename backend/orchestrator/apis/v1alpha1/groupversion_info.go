// +kubebuilder:object:generate=true
// +groupName=orchestrator.ai.opensphere.io
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	GroupVersion  = schema.GroupVersion{Group: "orchestrator.ai.opensphere.io", Version: "v1alpha1"}
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)
	AddToScheme   = SchemeBuilder.AddToScheme
)

func addKnownTypes(s *runtime.Scheme) error {
	s.AddKnownTypes(GroupVersion,
		&AIAgent{}, &AIAgentList{},
		&PromptLibrary{}, &PromptLibraryList{},
		&ToolClaim{}, &ToolClaimList{},
		&AgentTracePolicy{}, &AgentTracePolicyList{},
	)
	metav1.AddToGroupVersion(s, GroupVersion)
	return nil
}
