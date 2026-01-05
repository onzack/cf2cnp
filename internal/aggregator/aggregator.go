package aggregator

import (
	"fmt"
	"sort"
	"strings"

	"github.com/hubble-policy-gen/internal/flow"
)

// AggregatedFlow represents flows grouped by source/destination
type AggregatedFlow struct {
	Direction          string            // INGRESS or EGRESS
	SourceNamespace    string            // Source pod namespace
	SourceLabels       map[string]string // Filtered source labels
	SourceEntity       string            // Reserved entity for source (remote-node, host, etc.)
	IsSourceEntity     bool              // True if source is a reserved entity
	DestNamespace      string            // Destination pod namespace
	DestLabels         map[string]string // Filtered destination labels
	DestFQDNs          []string          // Destination FQDNs for world traffic
	DestIPs            []string          // Destination IPs for CIDR-based rules
	DestEntity         string            // Reserved entity (kube-apiserver, host, world, etc.)
	Ports              []PortInfo        // Aggregated ports
	IsWorldTraffic     bool              // True if destination is "world"
	IsDestEntityTraffic bool             // True if destination is a reserved entity
	IsReply            bool              // True if this is a reply packet
}

// PortInfo represents a port and protocol combination
type PortInfo struct {
	Port     int
	Protocol string
}

// AggregateFlows groups flows by source/destination and aggregates ports
func AggregateFlows(flows []*flow.ParsedFlow) []*AggregatedFlow {
	// Use a map to group flows by their key
	aggregationMap := make(map[string]*AggregatedFlow)

	for _, f := range flows {
		key := generateAggregationKey(f)

		if existing, exists := aggregationMap[key]; exists {
			// Add port to existing aggregated flow if not already present
			port := PortInfo{Port: f.Port, Protocol: f.Protocol}
			if !containsPort(existing.Ports, port) {
				existing.Ports = append(existing.Ports, port)
			}
			// Add FQDNs if not already present
			for _, fqdn := range f.DestFQDNs {
				if !containsString(existing.DestFQDNs, fqdn) {
					existing.DestFQDNs = append(existing.DestFQDNs, fqdn)
				}
			}
			// Add destination IP if not already present
			if f.DestIP != "" && !containsString(existing.DestIPs, f.DestIP) {
				existing.DestIPs = append(existing.DestIPs, f.DestIP)
			}
		} else {
			// Create new aggregated flow
			var destIPs []string
			if f.DestIP != "" {
				destIPs = []string{f.DestIP}
			}
			aggregated := &AggregatedFlow{
				Direction:          f.Direction,
				SourceNamespace:    f.SourceNamespace,
				SourceLabels:       copyLabels(f.SourceLabels),
				SourceEntity:       f.SourceEntity,
				IsSourceEntity:     f.IsSourceEntity,
				DestNamespace:      f.DestNamespace,
				DestLabels:         copyLabels(f.DestLabels),
				DestFQDNs:          append([]string{}, f.DestFQDNs...),
				DestIPs:            destIPs,
				DestEntity:         f.DestEntity,
				Ports:              []PortInfo{{Port: f.Port, Protocol: f.Protocol}},
				IsWorldTraffic:     f.IsWorldTraffic,
				IsDestEntityTraffic: f.IsDestEntityTraffic,
				IsReply:            f.IsReply,
			}
			aggregationMap[key] = aggregated
		}
	}

	// Convert map to slice
	result := make([]*AggregatedFlow, 0, len(aggregationMap))
	for _, agg := range aggregationMap {
		// Sort ports for consistent output
		sort.Slice(agg.Ports, func(i, j int) bool {
			if agg.Ports[i].Port != agg.Ports[j].Port {
				return agg.Ports[i].Port < agg.Ports[j].Port
			}
			return agg.Ports[i].Protocol < agg.Ports[j].Protocol
		})
		// Sort FQDNs for consistent output
		sort.Strings(agg.DestFQDNs)
		result = append(result, agg)
	}

	// Sort result for consistent output
	sort.Slice(result, func(i, j int) bool {
		return generateAggregationKey(parsedFlowFromAggregated(result[i])) <
			generateAggregationKey(parsedFlowFromAggregated(result[j]))
	})

	return result
}

// generateAggregationKey creates a unique key for grouping flows
func generateAggregationKey(f *flow.ParsedFlow) string {
	var parts []string
	parts = append(parts, f.Direction)
	parts = append(parts, f.SourceNamespace)
	parts = append(parts, labelsToString(f.SourceLabels))
	
	// Include source entity in key for entity-based traffic
	if f.IsSourceEntity {
		parts = append(parts, f.SourceEntity)
	}
	
	parts = append(parts, f.DestNamespace)
	parts = append(parts, labelsToString(f.DestLabels))
	
	// Include destination entity in key for entity-based traffic
	if f.IsDestEntityTraffic {
		parts = append(parts, f.DestEntity)
	}
	
	if f.IsWorldTraffic {
		// For world traffic, include FQDNs in the key
		fqdns := append([]string{}, f.DestFQDNs...)
		sort.Strings(fqdns)
		parts = append(parts, strings.Join(fqdns, ","))
	}

	return strings.Join(parts, "|")
}

// labelsToString converts a label map to a sorted string for consistent keys
func labelsToString(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}

	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, labels[k]))
	}
	return strings.Join(parts, ",")
}

// copyLabels creates a copy of the labels map
func copyLabels(labels map[string]string) map[string]string {
	result := make(map[string]string, len(labels))
	for k, v := range labels {
		result[k] = v
	}
	return result
}

// containsPort checks if a port is already in the slice
func containsPort(ports []PortInfo, port PortInfo) bool {
	for _, p := range ports {
		if p.Port == port.Port && p.Protocol == port.Protocol {
			return true
		}
	}
	return false
}

// containsString checks if a string is in the slice
func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

// parsedFlowFromAggregated creates a minimal ParsedFlow for key generation
func parsedFlowFromAggregated(agg *AggregatedFlow) *flow.ParsedFlow {
	return &flow.ParsedFlow{
		Direction:          agg.Direction,
		SourceNamespace:    agg.SourceNamespace,
		SourceLabels:       agg.SourceLabels,
		SourceEntity:       agg.SourceEntity,
		IsSourceEntity:     agg.IsSourceEntity,
		DestNamespace:      agg.DestNamespace,
		DestLabels:         agg.DestLabels,
		DestFQDNs:          agg.DestFQDNs,
		DestEntity:         agg.DestEntity,
		IsWorldTraffic:     agg.IsWorldTraffic,
		IsDestEntityTraffic: agg.IsDestEntityTraffic,
		IsReply:            agg.IsReply,
	}
}

