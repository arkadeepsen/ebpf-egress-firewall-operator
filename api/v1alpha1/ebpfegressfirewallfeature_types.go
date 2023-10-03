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

// EbpfEgressFirewallFeature is the Schema for the ebpfegressfirewallfeatures API
type EbpfEgressFirewallFeature struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   EbpfEgressFirewallFeatureSpec   `json:"spec,omitempty"`
	Status EbpfEgressFirewallFeatureStatus `json:"status,omitempty"`
}

// EbpfEgressFirewallFeatureSpec defines the desired state of EbpfEgressFirewallFeature
type EbpfEgressFirewallFeatureSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Foo is an example field of EbpfEgressFirewallFeature. Edit ebpfegressfirewallfeature_types.go to remove/update
	Foo string `json:"foo,omitempty"`
}

// EbpfEgressFirewallFeatureStatus defines the observed state of EbpfEgressFirewallFeature
type EbpfEgressFirewallFeatureStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

//+kubebuilder:object:root=true

// EbpfEgressFirewallFeatureList contains a list of EbpfEgressFirewallFeature
type EbpfEgressFirewallFeatureList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EbpfEgressFirewallFeature `json:"items"`
}

func init() {
	SchemeBuilder.Register(&EbpfEgressFirewallFeature{}, &EbpfEgressFirewallFeatureList{})
}
