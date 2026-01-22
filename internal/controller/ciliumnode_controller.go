package controller

import (
	"context"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/niklasbeierl/nodeCryptor/internal/state"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// CiliumNodeReconciler reconciles CiliumNode objects
type CiliumNodeReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	state  state.State
}

// NewCiliumNodeReconciler creates a new CiliumNode reconciler
func NewCiliumNodeReconciler(
	client client.Client,
	scheme *runtime.Scheme,
	state state.State,
) *CiliumNodeReconciler {
	return &CiliumNodeReconciler{
		Client: client,
		Scheme: scheme,
		state:  state,
	}
}

// +kubebuilder:rbac:groups=cilium.io,resources=ciliumnodes,verbs=get;list;watch
// +kubebuilder:rbac:groups=cilium.io,resources=ciliumnodes/status,verbs=get

// Reconcile handles CiliumNode reconciliation
func (r *CiliumNodeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var node ciliumv2.CiliumNode
	if err := r.Get(ctx, req.NamespacedName, &node); err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("CiliumNode deleted", "name", req.Name)
			r.state.DeleteNode(req.Name)
			return ctrl.Result{}, nil
		}
		logger.Error(err, "unable to fetch CiliumNode")
		return ctrl.Result{}, err
	}

	r.state.SetNode(&node)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager
func (r *CiliumNodeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&ciliumv2.CiliumNode{}).
		Complete(r)
}
