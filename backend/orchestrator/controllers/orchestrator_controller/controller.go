// Package orchestrator_controller 는 AI agent orchestration reconciler 다.
package orchestrator_controller

import (
	"context"
	"log/slog"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	orchestratorv1alpha1 "github.com/opensphere/ai-orchestrator/apis/v1alpha1"
)

// Reconciler 는 agent, prompt, tool, trace policy 를 수렴한다.
type Reconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Logger *slog.Logger
}

// SetupWithManager 는 orchestrator CR watch 를 등록한다.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	for _, setup := range []func(ctrl.Manager) error{
		r.setupAIAgent,
		r.setupPromptLibrary,
		r.setupToolClaim,
		r.setupAgentTracePolicy,
	} {
		if err := setup(mgr); err != nil {
			return err
		}
	}
	return nil
}

func (r *Reconciler) setupAIAgent(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(&orchestratorv1alpha1.AIAgent{}).Complete(&AIAgentReconciler{Reconciler: r})
}

func (r *Reconciler) setupPromptLibrary(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(&orchestratorv1alpha1.PromptLibrary{}).Complete(&PromptLibraryReconciler{Reconciler: r})
}

func (r *Reconciler) setupToolClaim(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(&orchestratorv1alpha1.ToolClaim{}).Complete(&ToolClaimReconciler{Reconciler: r})
}

func (r *Reconciler) setupAgentTracePolicy(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(&orchestratorv1alpha1.AgentTracePolicy{}).Complete(&AgentTracePolicyReconciler{Reconciler: r})
}

// AIAgentReconciler 는 AIAgent 를 reconcile 한다.
type AIAgentReconciler struct{ *Reconciler }

func (r *AIAgentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	obj := &orchestratorv1alpha1.AIAgent{}
	if err := r.Get(ctx, req.NamespacedName, obj); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	return ctrl.Result{}, r.markReady(ctx, obj)
}

// PromptLibraryReconciler 는 PromptLibrary 를 reconcile 한다.
type PromptLibraryReconciler struct{ *Reconciler }

func (r *PromptLibraryReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	obj := &orchestratorv1alpha1.PromptLibrary{}
	if err := r.Get(ctx, req.NamespacedName, obj); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	return ctrl.Result{}, r.markReady(ctx, obj)
}

// ToolClaimReconciler 는 ToolClaim 을 reconcile 한다.
type ToolClaimReconciler struct{ *Reconciler }

func (r *ToolClaimReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	obj := &orchestratorv1alpha1.ToolClaim{}
	if err := r.Get(ctx, req.NamespacedName, obj); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	return ctrl.Result{}, r.markReady(ctx, obj)
}

// AgentTracePolicyReconciler 는 AgentTracePolicy 를 reconcile 한다.
type AgentTracePolicyReconciler struct{ *Reconciler }

func (r *AgentTracePolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	obj := &orchestratorv1alpha1.AgentTracePolicy{}
	if err := r.Get(ctx, req.NamespacedName, obj); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	return ctrl.Result{}, r.markReady(ctx, obj)
}

func (r *Reconciler) markReady(ctx context.Context, obj client.Object) error {
	patch := client.MergeFrom(obj.DeepCopyObject().(client.Object))
	switch o := obj.(type) {
	case *orchestratorv1alpha1.AIAgent:
		o.Status.Ready = true
	case *orchestratorv1alpha1.PromptLibrary:
		o.Status.Ready = true
	case *orchestratorv1alpha1.ToolClaim:
		o.Status.Ready = true
	case *orchestratorv1alpha1.AgentTracePolicy:
		o.Status.Ready = true
	}
	return r.Status().Patch(ctx, obj, patch)
}
