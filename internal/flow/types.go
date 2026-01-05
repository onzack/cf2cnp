package flow

// HubbleFlowData represents the top-level structure of a Hubble flow JSON file
type HubbleFlowData struct {
	Flow     Flow   `json:"flow"`
	NodeName string `json:"node_name"`
	Time     string `json:"time"`
}

// Flow represents the flow data from Hubble
type Flow struct {
	Time             string    `json:"time"`
	UUID             string    `json:"uuid"`
	Verdict          string    `json:"verdict"`
	Ethernet         Ethernet  `json:"ethernet"`
	IP               IP        `json:"IP"`
	L4               L4        `json:"l4"`
	Source           Endpoint  `json:"source"`
	Destination      Endpoint  `json:"destination"`
	Type             string    `json:"Type"`
	NodeName         string    `json:"node_name"`
	NodeLabels       []string  `json:"node_labels"`
	DestinationNames []string  `json:"destination_names"`
	EventType        EventType `json:"event_type"`
	TrafficDirection string    `json:"traffic_direction"`
	IsReply          bool      `json:"is_reply"`
	Summary          string    `json:"Summary"`
}

// Ethernet contains MAC address information
type Ethernet struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
}

// IP contains IP address information
type IP struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	IPVersion   string `json:"ipVersion"`
}

// L4 contains Layer 4 protocol information
type L4 struct {
	TCP *TCPInfo `json:"TCP,omitempty"`
	UDP *UDPInfo `json:"UDP,omitempty"`
}

// TCPInfo contains TCP-specific information
type TCPInfo struct {
	SourcePort      int      `json:"source_port"`
	DestinationPort int      `json:"destination_port"`
	Flags           TCPFlags `json:"flags"`
}

// TCPFlags contains TCP flag information
type TCPFlags struct {
	SYN bool `json:"SYN,omitempty"`
	ACK bool `json:"ACK,omitempty"`
	FIN bool `json:"FIN,omitempty"`
	RST bool `json:"RST,omitempty"`
	PSH bool `json:"PSH,omitempty"`
	URG bool `json:"URG,omitempty"`
}

// UDPInfo contains UDP-specific information
type UDPInfo struct {
	SourcePort      int `json:"source_port"`
	DestinationPort int `json:"destination_port"`
}

// Endpoint represents a source or destination endpoint in the flow
type Endpoint struct {
	ID          int        `json:"ID,omitempty"`
	Identity    int        `json:"identity"`
	ClusterName string     `json:"cluster_name,omitempty"`
	Namespace   string     `json:"namespace,omitempty"`
	Labels      []string   `json:"labels"`
	PodName     string     `json:"pod_name,omitempty"`
	Workloads   []Workload `json:"workloads,omitempty"`
}

// Workload represents workload information
type Workload struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

// EventType represents the event type information
type EventType struct {
	Type int `json:"type"`
}

// ParsedFlow represents a parsed and processed flow with extracted information
type ParsedFlow struct {
	UUID               string            // Flow UUID from Hubble
	Direction          string            // INGRESS or EGRESS
	SourceNamespace    string            // Source pod namespace
	SourceLabels       map[string]string // Filtered source labels
	SourceEntity       string            // Reserved entity for source (remote-node, host, etc.)
	IsSourceEntity     bool              // True if source is a reserved entity
	DestNamespace      string            // Destination pod namespace
	DestLabels         map[string]string // Filtered destination labels
	DestFQDNs          []string          // Destination FQDNs for world traffic
	DestIP             string            // Destination IP for CIDR-based rules
	DestEntity         string            // Reserved entity (kube-apiserver, host, world, etc.)
	Protocol           string            // TCP or UDP
	Port               int               // Destination port
	IsWorldTraffic     bool              // True if destination is "world"
	IsDestEntityTraffic bool             // True if destination is a reserved entity
	IsReply            bool              // True if this is a reply packet
}

