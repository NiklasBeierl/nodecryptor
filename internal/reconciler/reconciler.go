package reconciler

import (
	"context"
	"errors"
	"net"
	"strings"
	"syscall"
	"time"

	ciliumDefaults "github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/go-logr/logr"
	"github.com/niklasbeierl/nodeCryptor/internal/state"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/util/sets"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

type NodeType int

const (
	NodeTypeUnknown NodeType = iota
	NodeTypeControlPlane
	NodeTypeWorker
)

func (t NodeType) String() string {
	return [...]string{"unknown", "controlplane", "worker"}[t]
}

const (
	forceEncryptTable = 100
	exemptPrio        = 200
	encryptPrio       = exemptPrio + 1
)

// Reconciler runs the async reconciliation loop
type Reconciler struct {
	state              state.State
	wasReady           bool
	lastSeenGeneration uint
	readyRoutes        sets.Set[string]
	readyExempts       sets.Set[string]
	localNode          string
	localType          NodeType
	options            Options
	log                logr.Logger
}

var _ manager.Runnable = &Reconciler{}

// New creates a new reconciler
func New(
	store state.State,
	localNode string,
	opts Options,
) *Reconciler {
	return &Reconciler{
		state:        store,
		localNode:    localNode,
		readyRoutes:  make(sets.Set[string]),
		readyExempts: make(sets.Set[string]),
		options:      opts,
		log:          ctrl.Log.WithName("reconciler"),
	}
}

// Start implements manager.Runnable
func (r *Reconciler) Start(ctx context.Context) error {
	r.log.Info("starting reconciliation loop",
		"interval", r.options.Interval,
		"maxInterval", r.options.MaxInterval,
	)

	stateChanges := r.state.Subscribe()
	ticker := time.NewTicker(r.options.MaxInterval)
	defer ticker.Stop()

	// Run initial reconciliation
	r.reconcile(ctx)

	for {
		select {
		case <-ctx.Done():
			r.log.Info("reconciliation loop stopped")
			return nil
		case <-stateChanges:
			r.debounceAndReconcile(ctx, ticker)
		case <-ticker.C:
			r.reconcile(ctx)
		}
	}
}

func (r *Reconciler) debounceAndReconcile(ctx context.Context, ticker *time.Ticker) {
	timer := time.NewTimer(r.options.Interval)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			r.reconcile(ctx)
			ticker.Reset(r.options.MaxInterval)
			return
		}
	}
}

func (r *Reconciler) reconcile(ctx context.Context) {
	start := time.Now()

	// Might not be necessary,
	// but the reconciliation is debounced and should be pretty quick
	r.state.Lock()
	defer r.state.Unlock()

	encryptIPs := make(map[string]*net.IPNet)
	exemptIPs := make(map[string]*net.IPNet)
	needSetup := false
	var nodeType NodeType

	for nodeName, node := range *r.state.GetNodes() {
		if node.Labels["node-role.kubernetes.io/control-plane"] == "true" {
			nodeType = NodeTypeControlPlane
		} else {
			nodeType = NodeTypeWorker
		}

		if nodeName == r.localNode {
			if r.localType == NodeTypeUnknown {
				r.localType = nodeType
			} else if r.localType != nodeType {
				r.log.Info("local node type changed, need setup", "from", r.localType, "to", nodeType)
				needSetup = true
				r.localType = nodeType
			}
			continue
		}

		for _, cidr := range node.Spec.IPAM.PodCIDRs {
			dst := parseIPv4OrCIDR(cidr)
			if dst != nil {
				encryptIPs[cidr] = dst
			}
		}
		for _, addrspec := range node.Spec.Addresses {
			if addrspec.Type == "InternalIP" {
				addr := addrspec.IP
				dstNet := parseIPv4OrCIDR(addr)
				if dstNet != nil {
					encryptIPs[addr] = dstNet
					if nodeType == NodeTypeControlPlane {
						exemptIPs[addr] = dstNet
					}
				}
			}
		}
	}

	var isReady bool

	newAttrs := r.state.GetLinkAttrs()

	isReady = newAttrs != nil && (newAttrs.Flags&net.FlagUp != 0) && r.localType != NodeTypeUnknown

	generation := r.state.GetLinkGeneration()
	if generation != r.lastSeenGeneration {
		r.wasReady = false
		r.readyRoutes = make(sets.Set[string])
	}
	r.lastSeenGeneration = generation

	if isReady && !r.wasReady {
		r.log.Info("became ready, need setup")
		needSetup = true
	} else if !isReady && r.wasReady {
		r.log.Info("interface went down")
		r.wasReady = false
		// Interface going down deletes the route, causing the table and rules to be
		// garbage collected
		r.readyRoutes = make(sets.Set[string])
		// Exempts are not affected, they direct traffic to the main table
		return
	} else if !isReady && !r.wasReady {
		// wasn't ready, isn't ready, nothing left to do here
		return
	}

	if needSetup {
		r.setup()
		r.wasReady = true
		r.log.Info("setup done")
	}

	var err error
	for dst := range sets.KeySet(exemptIPs).Difference(r.readyExempts) {
		dstNet := exemptIPs[dst]
		err = nil
		for _, rule := range r.buildExemptRules(dstNet) {
			if err = r.ensureRule(rule); err != nil {
				break
			}
		}
		if err == nil {
			r.readyExempts.Insert(dst)
		}

	}
	for dst := range sets.KeySet(encryptIPs).Difference(r.readyRoutes) {
		dstNet := encryptIPs[dst]
		err = nil
		if err = r.ensureRule(buildEncryptionRule(dstNet)); err == nil {
			r.readyRoutes.Insert(dst)
		}
	}

	for obsoleteDst := range r.readyRoutes.Difference(sets.KeySet(encryptIPs)) {
		dstNet := parseIPv4OrCIDR(obsoleteDst)
		err = nil
		if err = r.ensureRuleRemoved(buildEncryptionRule(dstNet)); err == nil {
			r.readyRoutes.Delete(obsoleteDst)
		}
	}

	for obsoleteDst := range r.readyExempts.Difference(sets.KeySet(exemptIPs)) {
		dstNet := parseIPv4OrCIDR(obsoleteDst)
		err = nil
		for _, rule := range r.buildExemptRules(dstNet) {
			if err = r.ensureRuleRemoved(rule); err != nil {
				break
			}
		}
		if err == nil {
			r.readyExempts.Delete(obsoleteDst)
		}
	}

	r.log.V(1).Info("reconciliation complete",
		"duration", time.Since(start),
	)
}

func (r *Reconciler) deployCiliumHack() {
	noop := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{Name: "noop"},
	}
	if err := netlink.LinkAdd(noop); err != nil && !errors.Is(err, syscall.EEXIST) {
		r.log.Error(err, "failed to add noop link")
		return
	}

	noopLink, err := netlink.LinkByName("noop")
	if err != nil {
		r.log.Error(err, "failed to get noop link")
		return
	}

	if err := netlink.LinkSetUp(noopLink); err != nil {
		r.log.Error(err, "failed to set noop link up")
	}

	var dst *net.IPNet
	if dst = parseIPv4OrCIDR(r.options.NoopRouteTarget); dst == nil {
		r.log.Error(err, "failed to parse noop route target", "target", r.options.NoopRouteTarget)
		return
	}

	noopRoute := &netlink.Route{
		LinkIndex: noopLink.Attrs().Index,
		Dst:       dst,
	}
	if err := netlink.RouteAdd(noopRoute); err != nil && !errors.Is(err, syscall.EEXIST) {
		r.log.Error(err, "failed to add noop route")
	}
}

// NeedLeaderElection returns false - reconciliation is node-local
func (r *Reconciler) NeedLeaderElection() bool {
	return false
}

func buildRule(dst *net.IPNet, exempt bool) *netlink.Rule {
	rule := netlink.NewRule()
	rule.Dst = dst
	if exempt {
		rule.Table = unix.RT_TABLE_MAIN
		rule.Priority = exemptPrio
	} else {
		rule.Table = forceEncryptTable
		rule.Priority = encryptPrio
	}
	return rule
}

func buildEncryptionRule(dst *net.IPNet) *netlink.Rule {
	return buildRule(dst, false)
}

func (r Reconciler) buildExemptRules(dst *net.IPNet) []*netlink.Rule {
	rules := make([]*netlink.Rule, 0)
	for _, portRange := range r.options.ControlPlaneExemptPorts {
		rule := buildRule(dst, true)
		rule.Dport = &portRange
		rules = append(rules, rule)
	}
	return rules
}

func parseIPv4OrCIDR(s string) *net.IPNet {
	if strings.Contains(s, "/") {
		ip, ipNet, err := net.ParseCIDR(s)
		if err != nil || ip.To4() == nil {
			return nil
		}
		return ipNet
	}
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil {
		return nil
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
}

func (r *Reconciler) ensureRule(rule *netlink.Rule) error {
	r.log.Info("adding rule:", "rule", rule)
	err := netlink.RuleAdd(rule)
	// If the rule already exists that is fine
	if err != nil && !errors.Is(err, syscall.EEXIST) {
		r.log.Error(err, "failed to add rule", "rule", rule)
		return err
	}

	return nil
}

func (r *Reconciler) ensureRuleRemoved(rule *netlink.Rule) error {
	r.log.Info("removing rule:", "rule", rule)
	err := netlink.RuleDel(rule)
	// If the rule is already gone that is fine
	if err != nil && !errors.Is(err, syscall.ENOENT) {
		r.log.Error(err, "failed to remove rule", "rule", rule)
		return err
	}
	return nil
}

func (r *Reconciler) setup() {
	// ip route add default dev cilium_wg0 scope link table 100
	route := &netlink.Route{
		LinkIndex: r.state.GetLinkAttrs().Index,
		Scope:     netlink.SCOPE_LINK,
		Dst: &net.IPNet{
			IP:   net.ParseIP("0.0.0.0"),
			Mask: net.CIDRMask(0, 32),
		},
		Table: forceEncryptTable,
	}

	err := netlink.RouteAdd(route)
	if err != nil && !errors.Is(err, syscall.EEXIST) {
		r.log.Error(err, "failed to add route", "route", route)
	}

	var rule *netlink.Rule
	var rules []*netlink.Rule

	// ip rule add fwmark 0xe00 lookup main priority 0
	rule = netlink.NewRule()
	rule.Mark = ciliumDefaults.MagicMarkEncrypt
	rule.Table = unix.RT_TABLE_MAIN
	rule.Priority = 0
	rules = append(rules, rule)

	for _, portRange := range r.options.ControlPlaneExemptPorts {
		rule = netlink.NewRule()
		// Comes from localhost on an exempt range
		rule.Sport = &portRange
		rule.IifName = "lo"
		rule.Table = unix.RT_TABLE_MAIN
		rule.Priority = exemptPrio
		rules = append(rules, rule)
	}

	for _, rule := range rules {
		switch r.localType {
		case NodeTypeControlPlane:
			_ = r.ensureRule(rule)
		case NodeTypeWorker:
			_ = r.ensureRuleRemoved(rule)
		default:
			panic("called setup while local node type was not known")
		}

	}

	if r.options.NoopRouteTarget != "" {
		r.log.Info("deploying noop route")
		r.deployCiliumHack()
	}
}
