package policy

import (
	"bytes"
	"fmt"

	"gopkg.in/yaml.v3"
)

// YOLONamespacePolicy generates a CiliumNetworkPolicy that allows all traffic
// within the same namespace. This is an easter egg policy - use with caution!
func YOLONamespacePolicy(namespace string) *CiliumNetworkPolicy {
	return &CiliumNetworkPolicy{
		APIVersion: "cilium.io/v2",
		Kind:       "CiliumNetworkPolicy",
		Metadata: Metadata{
			Name:      "yolo-allow-all-in-namespace",
			Namespace: namespace,
		},
		Spec: Spec{
			Description: fmt.Sprintf("YOLO! Allow all traffic within the %s namespace.", namespace),
			EndpointSelector: LabelSelector{
				MatchLabels: map[string]string{},
			},
			Ingress: []IngressRule{
				{
					FromEndpoints: []LabelSelector{
						{MatchLabels: map[string]string{}},
					},
				},
			},
			Egress: []EgressRule{
				{
					ToEndpoints: []LabelSelector{
						{MatchLabels: map[string]string{}},
					},
				},
			},
		},
	}
}

// YOLONamespacePolicyYAML generates the YOLO policy as YAML bytes
func YOLONamespacePolicyYAML(namespace string) ([]byte, error) {
	policy := YOLONamespacePolicy(namespace)

	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)

	if err := encoder.Encode(policy); err != nil {
		return nil, fmt.Errorf("failed to encode YOLO policy to YAML: %w", err)
	}

	if err := encoder.Close(); err != nil {
		return nil, fmt.Errorf("failed to close YAML encoder: %w", err)
	}

	return buf.Bytes(), nil
}

