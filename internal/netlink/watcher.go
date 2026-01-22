package netlink

import (
	"context"
	"fmt"

	ciliumwg "github.com/cilium/cilium/pkg/wireguard/types"
	"github.com/go-logr/logr"
	"github.com/niklasbeierl/nodeCryptor/internal/state"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// LinkWatcher subscribes to netlink events and dispatches them to handlers.
// Implements manager.Runnable interface for controller-runtime integration.
type LinkWatcher struct {
	state state.State
	log   logr.Logger
}

var _ manager.Runnable = &LinkWatcher{}

// NewWatcher creates a new netlink event watcher
func NewWatcher(state state.State) *LinkWatcher {
	return &LinkWatcher{
		state: state,
		log:   ctrl.Log.WithName("netlink-watcher"),
	}
}

// Start implements manager.Runnable - begins watching netlink events.
// This method blocks until the context is cancelled.
func (w *LinkWatcher) Start(ctx context.Context) error {
	w.log.Info("starting netlink watcher")

	if err := w.watchLinks(ctx); err != nil && ctx.Err() == nil {
		w.log.Error(err, "link watcher error")
		return err
	}

	w.log.Info("netlink watcher stopped")
	return nil
}

// NeedLeaderElection returns false - netlink events are node-local
// and should be watched on every node, not just the leader.
func (w *LinkWatcher) NeedLeaderElection() bool {
	return false
}

// watchLinks subscribes to link (interface) events
func (w *LinkWatcher) watchLinks(ctx context.Context) error {
	linkCh := make(chan netlink.LinkUpdate)
	done := make(chan struct{})
	defer close(done)

	options := netlink.LinkSubscribeOptions{
		ListExisting: true,
	}
	if err := netlink.LinkSubscribeWithOptions(linkCh, done, options); err != nil {
		return fmt.Errorf("failed to subscribe to link events: %w", err)
	}

	w.log.Info("subscribed to link events")

	for {
		select {
		case <-ctx.Done():
			return nil
		case update, ok := <-linkCh:
			if !ok {
				return fmt.Errorf("link event channel closed unexpectedly")
			}

			link := update.Link
			attrs := link.Attrs()

			if attrs.Name != ciliumwg.IfaceName {
				continue
			}

			switch update.Header.Type {
			case unix.RTM_NEWLINK:
				w.state.AddLink(link)
			case unix.RTM_DELLINK:
				w.state.DeleteLink()
			default:
				w.state.UpdateLink(link)
			}
		}
	}
}
