// Package aitraining_controller 는 AI MLOps lifecycle reconciler 다.
package aitraining_controller

import (
	"context"
	"log/slog"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	aiv1alpha1 "github.com/opensphere/ai-training/apis/v1alpha1"
)

// Reconciler 는 AITrainingStack 과 lifecycle claim 을 수렴한다.
type Reconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Logger *slog.Logger
}

// SetupWithManager 는 AI training CR watch 를 등록한다.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	for _, setup := range []func(ctrl.Manager) error{
		r.setupAITrainingStack,
		r.setupComputeBackendClaim,
		r.setupDatasetClaim,
		r.setupTrainingJobClaim,
		r.setupModelPromotionClaim,
		r.setupInferenceClaim,
	} {
		if err := setup(mgr); err != nil {
			return err
		}
	}
	return nil
}

func (r *Reconciler) setupAITrainingStack(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(&aiv1alpha1.AITrainingStack{}).Complete(&AITrainingStackReconciler{Reconciler: r})
}

func (r *Reconciler) setupComputeBackendClaim(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(&aiv1alpha1.ComputeBackendClaim{}).Complete(&ComputeBackendClaimReconciler{Reconciler: r})
}

func (r *Reconciler) setupDatasetClaim(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(&aiv1alpha1.DatasetClaim{}).Complete(&DatasetClaimReconciler{Reconciler: r})
}

func (r *Reconciler) setupTrainingJobClaim(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(&aiv1alpha1.TrainingJobClaim{}).Complete(&TrainingJobClaimReconciler{Reconciler: r})
}

func (r *Reconciler) setupModelPromotionClaim(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(&aiv1alpha1.ModelPromotionClaim{}).Complete(&ModelPromotionClaimReconciler{Reconciler: r})
}

func (r *Reconciler) setupInferenceClaim(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(&aiv1alpha1.InferenceClaim{}).Complete(&InferenceClaimReconciler{Reconciler: r})
}

// AITrainingStackReconciler 는 substrate stack 을 reconcile 한다.
type AITrainingStackReconciler struct{ *Reconciler }

func (r *AITrainingStackReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	obj := &aiv1alpha1.AITrainingStack{}
	if err := r.Get(ctx, req.NamespacedName, obj); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	patch := client.MergeFrom(obj.DeepCopyObject().(client.Object))
	obj.Status.Ready = true
	if obj.Spec.Lineage != nil && obj.Spec.Lineage.Enabled {
		obj.Status.MLflowEndpoint = "mlflow pending operand"
	}
	return ctrl.Result{}, r.Status().Patch(ctx, obj, patch)
}

type ComputeBackendClaimReconciler struct{ *Reconciler }
type DatasetClaimReconciler struct{ *Reconciler }
type TrainingJobClaimReconciler struct{ *Reconciler }
type ModelPromotionClaimReconciler struct{ *Reconciler }
type InferenceClaimReconciler struct{ *Reconciler }

func (r *ComputeBackendClaimReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	obj := &aiv1alpha1.ComputeBackendClaim{}
	if err := r.Get(ctx, req.NamespacedName, obj); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	return ctrl.Result{}, r.markClaimReady(ctx, obj, "Bound")
}

func (r *DatasetClaimReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	obj := &aiv1alpha1.DatasetClaim{}
	if err := r.Get(ctx, req.NamespacedName, obj); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	return ctrl.Result{}, r.markClaimReady(ctx, obj, "Indexed")
}

func (r *TrainingJobClaimReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	obj := &aiv1alpha1.TrainingJobClaim{}
	if err := r.Get(ctx, req.NamespacedName, obj); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	return ctrl.Result{}, r.markClaimReady(ctx, obj, "PendingRunner")
}

func (r *ModelPromotionClaimReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	obj := &aiv1alpha1.ModelPromotionClaim{}
	if err := r.Get(ctx, req.NamespacedName, obj); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	return ctrl.Result{}, r.markClaimReady(ctx, obj, "AwaitingEvaluation")
}

func (r *InferenceClaimReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	obj := &aiv1alpha1.InferenceClaim{}
	if err := r.Get(ctx, req.NamespacedName, obj); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	return ctrl.Result{}, r.markClaimReady(ctx, obj, "PendingRuntime")
}

func (r *Reconciler) markClaimReady(ctx context.Context, obj client.Object, phase string) error {
	patch := client.MergeFrom(obj.DeepCopyObject().(client.Object))
	switch o := obj.(type) {
	case *aiv1alpha1.ComputeBackendClaim:
		o.Status.Ready = true
		o.Status.Phase = phase
	case *aiv1alpha1.DatasetClaim:
		o.Status.Ready = true
		o.Status.Phase = phase
	case *aiv1alpha1.TrainingJobClaim:
		o.Status.Ready = true
		o.Status.Phase = phase
	case *aiv1alpha1.ModelPromotionClaim:
		o.Status.Ready = true
		o.Status.Phase = phase
	case *aiv1alpha1.InferenceClaim:
		o.Status.Ready = true
		o.Status.Phase = phase
	}
	return r.Status().Patch(ctx, obj, patch)
}
