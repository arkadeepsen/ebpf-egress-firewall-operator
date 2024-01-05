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

package webhooks

import (
	"context"
	"fmt"

	firewallv1alpha1 "github.com/arkadeepsen/ebpf-egress-firewall-operator/api/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	MaxRuleCount = 8000
)

type EbpfEgressFirewallWebhook struct {
	Cache cache.Cache
}

// log is for logging in this package.
var ebpfegressfirewalllog = logf.Log.WithName("ebpfegressfirewall-resource")

func (r *EbpfEgressFirewallWebhook) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		WithValidator(r).
		For(&firewallv1alpha1.EbpfEgressFirewall{}).
		Complete()
}

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
//+kubebuilder:webhook:path=/validate-firewall-arkadeepsen-io-v1alpha1-ebpfegressfirewall,mutating=false,failurePolicy=fail,sideEffects=None,groups=firewall.arkadeepsen.io,resources=ebpfegressfirewalls,verbs=create;update,versions=v1alpha1,name=vebpfegressfirewall.kb.io,admissionReviewVersions=v1

var _ webhook.CustomValidator = &EbpfEgressFirewallWebhook{}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (r *EbpfEgressFirewallWebhook) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	warnings := []string{}
	var errs []error

	ebpfEfObj, ok := obj.(*firewallv1alpha1.EbpfEgressFirewall)
	if !ok {
		ebpfegressfirewalllog.Info("Object is not of type EbpfEgressFirewall", "object", obj)
		return warnings, fmt.Errorf("object is not of type EbpfEgressFirewall")
	}

	ebpfegressfirewalllog.Info("validate create", "name", ebpfEfObj.Name)

	numWarnings, numError := r.validateNum(ctx, ebpfEfObj.Namespace, 0)
	warnings = append(warnings, numWarnings...)
	errs = append(errs, numError)

	specWarnings, specError := r.validateSpec(&ebpfEfObj.Spec)
	warnings = append(warnings, specWarnings...)
	errs = append(errs, specError)

	return warnings, errors.NewAggregate(errs)
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (r *EbpfEgressFirewallWebhook) ValidateUpdate(ctx context.Context, oldObj runtime.Object, newObj runtime.Object) (admission.Warnings, error) {
	warnings := []string{}
	var errs []error

	ebpfEfObj, ok := newObj.(*firewallv1alpha1.EbpfEgressFirewall)
	if !ok {
		ebpfegressfirewalllog.Info("Object is not of type EbpfEgressFirewall", "object", newObj)
		return warnings, fmt.Errorf("object is not of type EbpfEgressFirewall")
	}

	ebpfegressfirewalllog.Info("validate update", "name", ebpfEfObj.Name)

	if oldObj == nil {
		ebpfegressfirewalllog.Info("Cannot update nil EbpfEgressFirewall object", "object", oldObj)
		return warnings, fmt.Errorf("cannot update nil EbpfEgressFirewall object")
	}

	numWarnings, numError := r.validateNum(ctx, ebpfEfObj.Namespace, 1)
	warnings = append(warnings, numWarnings...)
	errs = append(errs, numError)

	specWarnings, specError := r.validateSpec(&ebpfEfObj.Spec)
	warnings = append(warnings, specWarnings...)
	errs = append(errs, specError)

	return warnings, errors.NewAggregate(errs)
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (r *EbpfEgressFirewallWebhook) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	return nil, nil
}

func (r *EbpfEgressFirewallWebhook) validateNum(ctx context.Context, namespace string, num int) (admission.Warnings, error) {
	warnings := []string{}

	ebpfEfList := &firewallv1alpha1.EbpfEgressFirewallList{}
	if err := r.Cache.List(ctx, ebpfEfList, &client.ListOptions{
		Namespace: namespace,
	}); err != nil {
		return warnings, err
	}

	if len(ebpfEfList.Items) != num {
		return warnings, fmt.Errorf("only one EbpfEgressFirewall object is permitted per namespace")
	}

	return nil, nil
}

func (r *EbpfEgressFirewallWebhook) validateSpec(spec *firewallv1alpha1.EbpfEgressFirewallSpec) (admission.Warnings, error) {
	warnings := []string{}
	var err error

	if len(spec.AllowRules)+len(spec.DenyRules) > MaxRuleCount {
		return warnings, fmt.Errorf("the rule count (%d) for EbpfEgressFirewall exceeds the maximum limit (%d)",
			len(spec.AllowRules)+len(spec.DenyRules), MaxRuleCount)
	}

	for _, allowRule := range spec.AllowRules {
		switch allowRule.To.DestinationType {
		case firewallv1alpha1.CIDR:
			if allowRule.To.CIDR == nil {
				err = fmt.Errorf("%s is required for allow rule when destination type is %s", firewallv1alpha1.CIDR, firewallv1alpha1.CIDR)
			}
		case firewallv1alpha1.DNS:
			if allowRule.To.DNS == nil {
				err = fmt.Errorf("%s is required for allow rule when destination type is %s", firewallv1alpha1.DNS, firewallv1alpha1.DNS)
			}
		case firewallv1alpha1.Node:
			if allowRule.To.Node == nil {
				err = fmt.Errorf("%s is required for allow rule when destination type is %s", firewallv1alpha1.Node, firewallv1alpha1.Node)
			}
		default:
			err = fmt.Errorf("unsupported destination type for allow rule: %s", allowRule.To.DestinationType)
		}
	}

	for _, denyRules := range spec.DenyRules {
		switch denyRules.To.DestinationType {
		case firewallv1alpha1.CIDR:
			if denyRules.To.CIDR == nil {
				err = fmt.Errorf("%s is required for deny rule when destination type is %s", firewallv1alpha1.CIDR, firewallv1alpha1.CIDR)
			}
		case firewallv1alpha1.Node:
			if denyRules.To.Node == nil {
				err = fmt.Errorf("%s is required for deny rule when destination type is %s", firewallv1alpha1.Node, firewallv1alpha1.Node)
			}
		default:
			err = fmt.Errorf("unsupported destination type for deny rule: %s", denyRules.To.DestinationType)
		}
	}

	return warnings, err
}
