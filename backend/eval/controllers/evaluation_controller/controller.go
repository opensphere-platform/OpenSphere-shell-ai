// Package evaluation_controller 는 golden-set evaluation gate reconciler 다.
package evaluation_controller

import (
	"context"
	"log/slog"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	evalv1alpha1 "github.com/opensphere/ai-eval/apis/v1alpha1"
)

// Reconciler 는 EvaluationPolicy 와 EvaluationJob 을 수렴한다.
type Reconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Logger *slog.Logger
}

// SetupWithManager 는 evaluation gate watch 를 등록한다.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := ctrl.NewControllerManagedBy(mgr).
		For(&evalv1alpha1.EvaluationPolicy{}).
		Complete(&EvaluationPolicyReconciler{Reconciler: r}); err != nil {
		return err
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&evalv1alpha1.EvaluationJob{}).
		Complete(&EvaluationJobReconciler{Reconciler: r})
}

// EvaluationPolicyReconciler 는 EvaluationPolicy 를 검증한다.
type EvaluationPolicyReconciler struct {
	*Reconciler
}

// Reconcile 는 policy type skeleton 단계에서 Ready 만 표시한다.
func (r *EvaluationPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	policy := &evalv1alpha1.EvaluationPolicy{}
	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	patch := client.MergeFrom(policy.DeepCopyObject().(client.Object))
	policy.Status.Ready = true
	return ctrl.Result{}, r.Status().Patch(ctx, policy, patch)
}

// EvaluationJobReconciler 는 EvaluationJob 을 실행한다.
type EvaluationJobReconciler struct {
	*Reconciler
}

// Reconcile 는 runner 구현 전까지 gate 를 Passed=false 로 보수적으로 유지한다.
func (r *EvaluationJobReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	job := &evalv1alpha1.EvaluationJob{}
	if err := r.Get(ctx, req.NamespacedName, job); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	patch := client.MergeFrom(job.DeepCopyObject().(client.Object))
	job.Status.Ready = true
	job.Status.Passed = false
	return ctrl.Result{}, r.Status().Patch(ctx, job, patch)
}
