package reconciler

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
)

const (
	MaxPort = math.MaxUint16
	MinPort = 1
)

// Options configures the reconciler behavior
type Options struct {
	// Interval is the minimum time between reconciliation runs
	Interval time.Duration

	// MaxInterval is the maximum time between reconciliations
	MaxInterval time.Duration

	// ControlPlaneExemptPorts are port ranges exempted from encryption for control-plane nodes
	ControlPlaneExemptPorts []netlink.RulePortRange

	// Add a route to a dummy device
	NoopRouteTarget string
}

// DefaultOptions returns sensible defaults
func DefaultOptions() Options {
	return Options{
		Interval:        1 * time.Second,
		MaxInterval:     30 * time.Second,
		NoopRouteTarget: "",
	}
}

// ParsePortRanges parses a comma-separated list of ports and port ranges.
// Examples: "443, 6443", "443", "2379-2382", "2379-2382,6443, 443"
// Returns an error if the format is invalid or ports are out of range (1-65535).
func ParsePortRanges(s string) ([]netlink.RulePortRange, error) {
	if s == "" {
		return []netlink.RulePortRange{}, nil
	}

	var ranges []netlink.RulePortRange
	parts := strings.Split(s, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Port range
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range format: %s", part)
			}

			start, err := parsePort(rangeParts[0])
			if err != nil {
				return nil, fmt.Errorf("invalid start port in range %s: %w", part, err)
			}

			end, err := parsePort(rangeParts[1])
			if err != nil {
				return nil, fmt.Errorf("invalid end port in range %s: %w", part, err)
			}

			if start > end {
				return nil, fmt.Errorf("start port %d is greater than end port %d in range %s", start, end, part)
			}

			ranges = append(ranges, netlink.RulePortRange{Start: start, End: end})
		} else { // Single port
			port, err := parsePort(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port %s: %w", part, err)
			}

			ranges = append(ranges, netlink.RulePortRange{Start: port, End: port})
		}
	}

	return ranges, nil
}

func parsePort(s string) (uint16, error) {
	s = strings.TrimSpace(s)
	port, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, err
	}
	if port < MinPort || port > MaxPort {
		return 0, fmt.Errorf("port %d out of range (%-%)", port, MinPort, MaxPort)
	}
	return uint16(port), nil
}
