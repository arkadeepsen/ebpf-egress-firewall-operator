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
	DenyRules []AllowRule `json:"denyRules,omitempty"`
}

// AllowRule defines a rule to allow connections.
type AllowRule struct {
	CommonRule `json:",inline"`
}

// DenyRule defines a rule to deny connections.
type DenyRule struct {
	CommonRule `json:",inline"`
}

// CommonRule defines the fields shared by AllowRule and DenyRule.
type CommonRule struct {
	// ports specify what ports and protocols the rule applies to
	// +optional
	Ports []FirewallPort `json:"ports,omitempty"`
	// cidrSelector is the CIDR range to allow/deny traffic to.
	// +kubebuilder:validation:Pattern=`^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([0-9]|[1-2][0-9]|3[0-2])$|^s*((([0-9A-Fa-f]{1,4}:){7}(:|([0-9A-Fa-f]{1,4})))|(([0-9A-Fa-f]{1,4}:){6}:([0-9A-Fa-f]{1,4})?)|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){0,1}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){0,2}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){0,3}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){0,4}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){0,5}):([0-9A-Fa-f]{1,4})?))|(:(:|((:[0-9A-Fa-f]{1,4}){1,7}))))(%.+)?s*/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8])$`
	CIDRSelector string `json:"cidrSelector,omitempty"`
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
