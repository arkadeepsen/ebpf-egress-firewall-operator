/*
Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// EbpfEgressFirewall describes the egress firewall rules for a Namespace.
// Traffic from pod will be checked against the rules. By default, if
// there are no EbpfEgressFirewall, or no rule matches the traffic, then the
// traffic will be allowed.
type EbpfEgressFirewall struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   EbpfEgressFirewallSpec   `json:"spec,omitempty"`
	Status EbpfEgressFirewallStatus `json:"status,omitempty"`
}

// EbpfEgressFirewallSpec defines the desired state of EbpfEgressFirewall
type EbpfEgressFirewallSpec struct {
	// allowRules specify the list of rules for allowing connections.
	AllowRules []AllowRule `json:"allowRules,omitempty"`
	// denyRules specify the list of rules for denying connections.
	DenyRules []DenyRule `json:"denyRules,omitempty"`
}

// AllowRule defines a rule to allow connections.
type AllowRule struct {
	// ports specify what ports and protocols the rule applies to
	// +optional
	Ports []FirewallPort `json:"ports,omitempty"`
	// to is the target that traffic is allowed/denied to
	To AllowRuleDestination `json:"to"`
}

// DenyRule defines a rule to deny connections.
type DenyRule struct {
	// ports specify what ports and protocols the rule applies to
	// +optional
	Ports []FirewallPort `json:"ports,omitempty"`
	// to is the target that traffic is allowed/denied to
	To DenyRuleDestination `json:"to"`
}

// FirewallPort specifies the port to allow or deny traffic to
type FirewallPort struct {
	// protocol (tcp, udp, sctp) that the traffic must match.
	// +kubebuilder:validation:Pattern=^TCP|UDP|SCTP$
	Protocol string `json:"protocol"`
	// port that the traffic must match
	// +kubebuilder:validation:Minimum:=1
	// +kubebuilder:validation:Maximum:=65535
	Port int32 `json:"port"`
}

// AllowRuleDestination is the target that traffic is allowed to
type AllowRuleDestination struct {
	// +kubebuilder:validation:Enum:="CIDR";"DNS";"Node"
	// +kubebuilder:validation:Required
	DestinationType string `json:"destinationType,omitempty"`
	// CIDR is the configuration for CIDR destination.
	// +optional.
	CIDR *CIDRConfig `json:"cidr,omitempty"`
	// DNS is the configuration for DNS destination.
	// +optional.
	DNS *DNSConfig `json:"dns,omitempty"`
	// Node is the configuration for Node destination.
	// +optional.
	Node *NodeConfig `json:"node,omitempty"`
}

// DenyRuleDestination is the target that traffic is denied to
type DenyRuleDestination struct {
	// +kubebuilder:validation:Enum:="CIDR";"Node"
	// +kubebuilder:validation:Required
	DestinationType string `json:"destinationType,omitempty"`
	// CIDR is the configuration for CIDR destination.
	// +optional.
	CIDR *CIDRConfig `json:"cidr,omitempty"`
	// Node is the configuration for Node destination.
	// +optional.
	Node *NodeConfig `json:"node,omitempty"`
}

type CIDRConfig struct {
	// cidrSelector is the CIDR range to allow/deny traffic to.
	// +kubebuilder:validation:Format=cidr
	CIDRSelector string `json:"cidrSelector"`
}

type DNSConfig struct {
	// dnsName is the domain name to allow/deny traffic to.
	// +kubebuilder:validation:Pattern=`^(\*\.)?([a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?\.)+[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?\.?$`
	DNSName string `json:"dnsName"`
}

type NodeConfig struct {
	// nodeSelector will allow/deny traffic to the Kubernetes node IP of selected nodes.
	NodeSelector *metav1.LabelSelector `json:"nodeSelector"`
}

// EbpfEgressFirewallStatus defines the observed state of EbpfEgressFirewall
type EbpfEgressFirewallStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

//+kubebuilder:object:root=true

// EbpfEgressFirewallList contains a list of EbpfEgressFirewall
type EbpfEgressFirewallList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EbpfEgressFirewall `json:"items"`
}

func init() {
	SchemeBuilder.Register(&EbpfEgressFirewall{}, &EbpfEgressFirewallList{})
}
