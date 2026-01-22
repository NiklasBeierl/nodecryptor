package state

import (
	"sync"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/go-logr/logr"
	"github.com/vishvananda/netlink"
)

// State provides thread-safe access to the operator's state
type State interface {
	// Link operations (single cilium_wg0 interface)
	GetLinkAttrs() *netlink.LinkAttrs
	GetLinkGeneration() uint
	AddLink(link netlink.Link)
	UpdateLink(link netlink.Link)
	DeleteLink()

	// Node operations
	SetNode(node *ciliumv2.CiliumNode)
	GetNode(node string) (*ciliumv2.CiliumNode, bool)
	GetNodes() *map[string]*ciliumv2.CiliumNode
	DeleteNode(name string)

	// Lock/Unlock during changes and reconciliation
	Lock()
	Unlock()

	// Subscribe returns a channel that receives notifications on state changes
	Subscribe() <-chan struct{}

	// Close cleans up resources
	Close()
}

// state is the default thread-safe in-memory implementation
type state struct {
	mu          sync.RWMutex
	wgLinkAttrs *netlink.LinkAttrs
	wgLinkGen   uint
	nodes       map[string]*ciliumv2.CiliumNode
	subscribers []chan struct{}
	subMu       sync.Mutex
	log         logr.Logger
}

func (s *state) GetNodes() *map[string]*ciliumv2.CiliumNode {
	return &s.nodes
}

func (s *state) GetNode(node string) (*ciliumv2.CiliumNode, bool) {
	n, ok := s.nodes[node]
	return n, ok
}

// NewStore creates a new in-memory state state
func NewStore(log logr.Logger) State {
	return &state{
		nodes:       make(map[string]*ciliumv2.CiliumNode),
		subscribers: make([]chan struct{}, 0),
		log:         log.WithName("state-state"),
	}
}

func (s *state) GetLinkGeneration() uint {
	return s.wgLinkGen
}

func (s *state) GetLinkAttrs() *netlink.LinkAttrs {
	return s.wgLinkAttrs
}

func (s *state) AddLink(link netlink.Link) {
	s.mu.Lock()
	s.wgLinkGen = s.wgLinkGen + 1%(^uint(0))
	s.wgLinkAttrs = link.Attrs()
	s.mu.Unlock()
	s.notify()
}

func (s *state) UpdateLink(link netlink.Link) {
	s.mu.Lock()
	newAttrs := link.Attrs()
	s.wgLinkAttrs = newAttrs
	s.mu.Unlock()
	s.notify()
}

func (s *state) DeleteLink() {
	s.mu.Lock()
	s.wgLinkAttrs = nil
	s.mu.Unlock()
	s.notify()
}

func (s *state) SetNode(node *ciliumv2.CiliumNode) {
	s.mu.Lock()
	s.nodes[node.Name] = node
	s.mu.Unlock()
	s.notify()
}

func (s *state) DeleteNode(name string) {
	s.mu.Lock()
	delete(s.nodes, name)
	s.mu.Unlock()
	s.notify()
}

func (s *state) Lock() {
	s.mu.RLock()
}

func (s *state) Unlock() {
	s.mu.RUnlock()
}

func (s *state) Subscribe() <-chan struct{} {
	s.subMu.Lock()
	defer s.subMu.Unlock()
	ch := make(chan struct{}, 1)
	s.subscribers = append(s.subscribers, ch)
	return ch
}

func (s *state) notify() {
	s.subMu.Lock()
	defer s.subMu.Unlock()
	for _, ch := range s.subscribers {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func (s *state) Close() {
	s.subMu.Lock()
	defer s.subMu.Unlock()
	for _, ch := range s.subscribers {
		close(ch)
	}
	s.subscribers = nil
}
