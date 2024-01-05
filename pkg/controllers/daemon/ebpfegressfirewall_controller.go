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

package controllers

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	firewallv1alpha1 "github.com/arkadeepsen/ebpf-egress-firewall-operator/api/v1alpha1"
	ocpnetworkv1alpha1 "github.com/openshift/api/network/v1alpha1"
)

// EbpfEgressFirewallReconciler reconciles a EbpfEgressFirewall object
type EbpfEgressFirewallReconciler struct {
	Client client.Client
	Scheme *runtime.Scheme
	Cache  cache.Cache
	Config Config

	dnsNameObjMap     map[string]dnsNameInfo
	ebpfEfDNSNamesMap map[types.NamespacedName]sets.Set[string]
}

type Config struct {
	DNSNameResolverNamespace string
}

type dnsNameInfo struct {
	objName                  string
	ebpfEfObjNamespacedNames sets.Set[types.NamespacedName]
}

// SetupWithManager sets up the controller with the Manager.
func (r *EbpfEgressFirewallReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.dnsNameObjMap = make(map[string]dnsNameInfo)
	r.ebpfEfDNSNamesMap = make(map[types.NamespacedName]sets.Set[string])

	return ctrl.NewControllerManagedBy(mgr).
		For(&firewallv1alpha1.EbpfEgressFirewall{}).
		Watches(&corev1.Node{}, handler.EnqueueRequestsFromMapFunc(r.nodeToEbpfEgressFirewall)).
		Watches(&ocpnetworkv1alpha1.DNSNameResolver{}, handler.EnqueueRequestsFromMapFunc(r.dnsNameResolverToEbpfEgressFirewall),
			builder.WithPredicates(predicate.Funcs{
				CreateFunc: func(ce event.CreateEvent) bool {
					dnsNameResolverObj, ok := ce.Object.(*ocpnetworkv1alpha1.DNSNameResolver)
					if !ok {
						return false
					}

					if dnsNameResolverObj.Namespace != r.Config.DNSNameResolverNamespace {
						return false
					}

					dnsDetails, exists := r.dnsNameObjMap[string(dnsNameResolverObj.Spec.Name)]
					if !exists {
						dnsDetails.ebpfEfObjNamespacedNames = sets.New[types.NamespacedName]()
					}
					dnsDetails.objName = dnsNameResolverObj.Name
					r.dnsNameObjMap[string(dnsNameResolverObj.Spec.Name)] = dnsDetails

					return true
				},
				UpdateFunc: func(ue event.UpdateEvent) bool {
					dnsNameResolverObj, ok := ue.ObjectNew.(*ocpnetworkv1alpha1.DNSNameResolver)
					if !ok {
						return false
					}

					if dnsNameResolverObj.Namespace != r.Config.DNSNameResolverNamespace {
						return false
					}

					dnsDetails, exists := r.dnsNameObjMap[string(dnsNameResolverObj.Spec.Name)]
					if !exists {
						dnsDetails.ebpfEfObjNamespacedNames = sets.New[types.NamespacedName]()
					}
					dnsDetails.objName = dnsNameResolverObj.Name
					r.dnsNameObjMap[string(dnsNameResolverObj.Spec.Name)] = dnsDetails

					return true
				},
				DeleteFunc: func(de event.DeleteEvent) bool {
					dnsNameResolverObj, ok := de.Object.(*ocpnetworkv1alpha1.DNSNameResolver)
					if !ok {
						return false
					}

					if dnsNameResolverObj.Namespace != r.Config.DNSNameResolverNamespace {
						return false
					}

					return true
				},
			})).
		Complete(r)
}

func (r *EbpfEgressFirewallReconciler) nodeToEbpfEgressFirewall(ctx context.Context, obj client.Object) []reconcile.Request {
	var reconcileRequests []reconcile.Request

	node, ok := obj.(*corev1.Node)
	if !ok {
		return reconcileRequests
	}

	nodeLabels := node.Labels

	if len(nodeLabels) == 0 {
		return reconcileRequests
	}

	ebpfEfList := &firewallv1alpha1.EbpfEgressFirewallList{}
	err := r.Cache.List(ctx, ebpfEfList, &client.ListOptions{})
	if err != nil {
		return []reconcile.Request{}
	}

	for _, ebpfEfObj := range ebpfEfList.Items {
		for _, allowRules := range ebpfEfObj.Spec.AllowRules {
			if allowRules.To.DestinationType == firewallv1alpha1.Node {
				nodeSelector, err := metav1.LabelSelectorAsSelector(allowRules.To.Node.NodeSelector)
				if err != nil {
					continue
				}

				if nodeSelector.Matches(labels.Set(nodeLabels)) {
					reconcileRequests = append(reconcileRequests, reconcile.Request{
						NamespacedName: types.NamespacedName{
							Name:      ebpfEfObj.Name,
							Namespace: ebpfEfObj.Namespace,
						},
					})
				}
			}
		}
		for _, denyRules := range ebpfEfObj.Spec.DenyRules {
			if denyRules.To.DestinationType == firewallv1alpha1.Node {
				nodeSelector, err := metav1.LabelSelectorAsSelector(denyRules.To.Node.NodeSelector)
				if err != nil {
					continue
				}

				if nodeSelector.Matches(labels.Set(nodeLabels)) {
					reconcileRequests = append(reconcileRequests, reconcile.Request{
						NamespacedName: types.NamespacedName{
							Name:      ebpfEfObj.Name,
							Namespace: ebpfEfObj.Namespace,
						},
					})
				}
			}
		}
	}

	return reconcileRequests
}

func (r *EbpfEgressFirewallReconciler) dnsNameResolverToEbpfEgressFirewall(ctx context.Context, obj client.Object) []reconcile.Request {
	var reconcileRequests []reconcile.Request

	dnsNameResolverObj, ok := obj.(*ocpnetworkv1alpha1.DNSNameResolver)
	if !ok {
		return reconcileRequests
	}

	if dnsNameResolverObj.Namespace != r.Config.DNSNameResolverNamespace {
		return reconcileRequests
	}

	objDetails, exists := r.dnsNameObjMap[string(dnsNameResolverObj.Spec.Name)]
	if !exists {
		return reconcileRequests
	}

	for ebpfEfNamespacedName := range objDetails.ebpfEfObjNamespacedNames {
		reconcileRequests = append(reconcileRequests, reconcile.Request{NamespacedName: ebpfEfNamespacedName})
	}

	return reconcileRequests
}

//+kubebuilder:rbac:groups=firewall.arkadeepsen.io,resources=ebpfegressfirewalls,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=firewall.arkadeepsen.io,resources=ebpfegressfirewalls/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=firewall.arkadeepsen.io,resources=ebpfegressfirewalls/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the EbpfEgressFirewall object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.14.1/pkg/reconcile
func (r *EbpfEgressFirewallReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)

	fwObj := &firewallv1alpha1.EbpfEgressFirewall{}
	err := r.Cache.Get(ctx, req.NamespacedName, fwObj)

	if err != nil {
		if errors.IsNotFound(err) {
			r.deleteEbpfEgressFirewallRules(req.NamespacedName)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, r.addEbpfEgressFirewallRules(ctx, fwObj)
}

func (r *EbpfEgressFirewallReconciler) deleteEbpfEgressFirewallRules(namespacedName types.NamespacedName) {
	if dnsNames, exists := r.ebpfEfDNSNamesMap[namespacedName]; exists {
		for dnsName := range dnsNames {
			if objDetails, found := r.dnsNameObjMap[dnsName]; found {
				delete(objDetails.ebpfEfObjNamespacedNames, namespacedName)
				if len(objDetails.ebpfEfObjNamespacedNames) == 0 {
					delete(r.dnsNameObjMap, dnsName)
				}
			}
		}
		delete(r.ebpfEfDNSNamesMap, namespacedName)
	}
}

func (r *EbpfEgressFirewallReconciler) addEbpfEgressFirewallRules(ctx context.Context, ebpfEf *firewallv1alpha1.EbpfEgressFirewall) error {
	var errs []error
	for _, allowRule := range ebpfEf.Spec.AllowRules {
		switch allowRule.To.DestinationType {
		case firewallv1alpha1.CIDR:
		case firewallv1alpha1.DNS:
			dnsName := allowRule.To.DNS.DNSName
			ebpfEfNamespacedName := types.NamespacedName{Name: ebpfEf.Name, Namespace: ebpfEf.Namespace}
			dnsNames, exists := r.ebpfEfDNSNamesMap[ebpfEfNamespacedName]
			if !exists {
				dnsNames = sets.New[string]()
			}
			dnsNames.Insert(dnsName)
			r.ebpfEfDNSNamesMap[ebpfEfNamespacedName] = dnsNames

			objDetails, found := r.dnsNameObjMap[dnsName]
			if !found {
				objDetails.ebpfEfObjNamespacedNames = sets.New[types.NamespacedName]()
			}
			objDetails.ebpfEfObjNamespacedNames.Insert(ebpfEfNamespacedName)
			r.dnsNameObjMap[dnsName] = objDetails

			if objDetails.objName != "" {
				dnsNameResolverNamespacedName := types.NamespacedName{Name: objDetails.objName, Namespace: r.Config.DNSNameResolverNamespace}
				dnsNameResolverObj := &ocpnetworkv1alpha1.DNSNameResolver{}
				err := r.Cache.Get(ctx, dnsNameResolverNamespacedName, dnsNameResolverObj)
				if err != nil {
					errs = append(errs, err)
					continue
				}
			}
		case firewallv1alpha1.Node:
			selector, err := metav1.LabelSelectorAsSelector(allowRule.To.Node.NodeSelector)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			nodeList := &corev1.NodeList{}
			err = r.Cache.List(ctx, nodeList, &client.ListOptions{
				LabelSelector: selector,
			})
			if err != nil {
				errs = append(errs, err)
				continue
			}
		default:

		}
	}

	for _, denyRule := range ebpfEf.Spec.DenyRules {
		switch denyRule.To.DestinationType {
		case firewallv1alpha1.CIDR:
		case firewallv1alpha1.Node:
			selector, err := metav1.LabelSelectorAsSelector(denyRule.To.Node.NodeSelector)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			nodeList := &corev1.NodeList{}
			err = r.Cache.List(ctx, nodeList, &client.ListOptions{
				LabelSelector: selector,
			})
			if err != nil {
				errs = append(errs, err)
				continue
			}
		default:

		}
	}

	return utilerrors.NewAggregate(errs)
}
