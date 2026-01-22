package main

import (
	"flag"
	"os"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/niklasbeierl/nodeCryptor/internal/controller"
	netlinkwatcher "github.com/niklasbeierl/nodeCryptor/internal/netlink"
	"github.com/niklasbeierl/nodeCryptor/internal/reconciler"
	"github.com/niklasbeierl/nodeCryptor/internal/state"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(ciliumv2.AddToScheme(scheme))
}

func main() {
	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	var nodeName string
	var controlPlaneExemptPorts string
	var healthProbeBindAddress string
	var metricsServerBindAddress string
	var noopRoute string
	flag.StringVar(&nodeName, "node-name", "", "Name of the node (falls back to NODE_NAME env var)")
	flag.StringVar(&controlPlaneExemptPorts, "control-plane-exempt-ports", "2379-2380,6443", "Comma-separated list of ports/ranges to exempt from encryption for control-plane nodes")
	flag.StringVar(&healthProbeBindAddress, "health-probe-bind-address", ":8083", "Health probe bind address")
	flag.StringVar(&metricsServerBindAddress, "metrics-server-bind-address", ":8084", "Metrics server bind address")
	flag.StringVar(&noopRoute, "noop-route", "", "Add a noop route to the specified destination")
	flag.Parse()

	if nodeName == "" {
		nodeName = os.Getenv("NODE_NAME")
	}
	if nodeName == "" {
		setupLog.Error(nil, "node name must be specified via -node-name flag or NODE_NAME env var")
		os.Exit(1)
	}

	// Parse exempt port ranges
	opts := reconciler.DefaultOptions()
	var err error
	opts.ControlPlaneExemptPorts, err = reconciler.ParsePortRanges(controlPlaneExemptPorts)
	if err != nil {
		setupLog.Error(err, "invalid control-plane-exempt-ports")
		os.Exit(1)
	}

	opts.NoopRouteTarget = noopRoute

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		HealthProbeBindAddress: healthProbeBindAddress,
		LeaderElection:         false,
		Metrics: metricsserver.Options{
			BindAddress: metricsServerBindAddress,
		},
	})
	if err != nil {
		setupLog.Error(err, "unable to create manager")
		os.Exit(1)
	}

	// Initialize state store
	stateStore := state.NewStore(ctrl.Log)

	// Setup CiliumNode controller
	if err = controller.NewCiliumNodeReconciler(
		mgr.GetClient(),
		mgr.GetScheme(),
		stateStore,
	).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "CiliumNode")
		os.Exit(1)
	}

	// Setup netlink watcher
	netlinkWatcher := netlinkwatcher.NewWatcher(stateStore)
	if err = mgr.Add(netlinkWatcher); err != nil {
		setupLog.Error(err, "unable to add netlink watcher")
		os.Exit(1)
	}

	// Setup reconciliation loop
	reconcilerLoop := reconciler.New(
		stateStore,
		nodeName,
		opts,
	)
	if err = mgr.Add(reconcilerLoop); err != nil {
		setupLog.Error(err, "unable to add reconciler")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
