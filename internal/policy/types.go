package policy

// CiliumNetworkPolicy represents a Cilium Network Policy
type CiliumNetworkPolicy struct {
	APIVersion string   `yaml:"apiVersion"`
	Kind       string   `yaml:"kind"`
	Metadata   Metadata `yaml:"metadata"`
	Spec       Spec     `yaml:"spec"`
}

// Metadata contains policy metadata
type Metadata struct {
	Name      string `yaml:"name"`
	Namespace string `yaml:"namespace"`
}

// Spec contains the policy specification
type Spec struct {
	Description      string        `yaml:"description,omitempty"`
	EndpointSelector LabelSelector `yaml:"endpointSelector"`
	Ingress          []IngressRule `yaml:"ingress,omitempty"`
	Egress           []EgressRule  `yaml:"egress,omitempty"`
}

// LabelSelector for selecting endpoints
type LabelSelector struct {
	MatchLabels map[string]string `yaml:"matchLabels,omitempty"`
}

// IngressRule represents an ingress rule
type IngressRule struct {
	FromEndpoints []LabelSelector `yaml:"fromEndpoints,omitempty"`
	FromEntities  []string        `yaml:"fromEntities,omitempty"`
	ToPorts       []PortRule      `yaml:"toPorts,omitempty"`
}

// EgressRule represents an egress rule
type EgressRule struct {
	ToEndpoints []LabelSelector `yaml:"toEndpoints,omitempty"`
	ToEntities  []string        `yaml:"toEntities,omitempty"`
	ToCIDR      []string        `yaml:"toCIDR,omitempty"`
	ToFQDNs     []FQDNSelector  `yaml:"toFQDNs,omitempty"`
	ToPorts     []PortRule      `yaml:"toPorts,omitempty"`
}

// FQDNSelector for selecting FQDNs
type FQDNSelector struct {
	MatchName    string `yaml:"matchName,omitempty"`
	MatchPattern string `yaml:"matchPattern,omitempty"`
}

// PortRule represents port rules
type PortRule struct {
	Ports []Port    `yaml:"ports,omitempty"`
	Rules *DNSRules `yaml:"rules,omitempty"`
}

// Port represents a single port
type Port struct {
	Port     string `yaml:"port"`
	Protocol string `yaml:"protocol"`
}

// DNSRules for DNS policy rules
type DNSRules struct {
	DNS []DNSRule `yaml:"dns,omitempty"`
}

// DNSRule represents a DNS rule
type DNSRule struct {
	MatchPattern string `yaml:"matchPattern,omitempty"`
	MatchName    string `yaml:"matchName,omitempty"`
}

