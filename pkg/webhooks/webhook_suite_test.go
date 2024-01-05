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
	"crypto/tls"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	corev1 "k8s.io/api/core/v1"

	//+kubebuilder:scaffold:imports

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	firewallv1alpha1 "github.com/arkadeepsen/ebpf-egress-firewall-operator/api/v1alpha1"
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

var cfg *rest.Config
var k8sClient client.Client
var testEnv *envtest.Environment
var ctx context.Context
var cancel context.CancelFunc

func TestAPIs(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecs(t, "Webhook Suite")
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	ctx, cancel = context.WithCancel(context.TODO())

	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: false,
		WebhookInstallOptions: envtest.WebhookInstallOptions{
			Paths: []string{filepath.Join("..", "..", "config", "webhook")},
		},
	}

	var err error
	// cfg is defined in this file globally.
	cfg, err = testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	scheme := runtime.NewScheme()
	err = firewallv1alpha1.AddToScheme(scheme)
	Expect(err).NotTo(HaveOccurred())

	err = corev1.AddToScheme(scheme)
	Expect(err).NotTo(HaveOccurred())

	err = admissionv1beta1.AddToScheme(scheme)
	Expect(err).NotTo(HaveOccurred())

	//+kubebuilder:scaffold:scheme

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())

	// start webhook server using Manager
	webhookInstallOptions := &testEnv.WebhookInstallOptions
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: scheme,
		WebhookServer: &webhook.DefaultServer{
			Options: webhook.Options{
				Host:    webhookInstallOptions.LocalServingHost,
				Port:    webhookInstallOptions.LocalServingPort,
				CertDir: webhookInstallOptions.LocalServingCertDir,
			},
		},
		LeaderElection: false,
		Metrics: server.Options{
			BindAddress: "0",
		},
	})
	Expect(err).NotTo(HaveOccurred())

	err = (&EbpfEgressFirewallWebhook{
		Cache: mgr.GetCache(),
	}).SetupWebhookWithManager(mgr)
	Expect(err).NotTo(HaveOccurred())

	//+kubebuilder:scaffold:webhook

	go func() {
		defer GinkgoRecover()
		err = mgr.Start(ctx)
		Expect(err).NotTo(HaveOccurred())
	}()

	// wait for the webhook server to get ready
	dialer := &net.Dialer{Timeout: time.Second}
	addrPort := fmt.Sprintf("%s:%d", webhookInstallOptions.LocalServingHost, webhookInstallOptions.LocalServingPort)
	Eventually(func() error {
		conn, err := tls.DialWithDialer(dialer, "tcp", addrPort, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return err
		}
		conn.Close()
		return nil
	}).Should(Succeed())

})

var _ = AfterSuite(func() {
	cancel()
	By("tearing down the test environment")
	err := testEnv.Stop()
	Expect(err).NotTo(HaveOccurred())
})

var _ = Context("test EbpfEgressFirewall validity", func() {
	It("should permit only a sigle EbpfEgressFirewall per namespace", func() {
		By("creating namespaces")
		namespace1 := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "foo",
			},
		}
		err := k8sClient.Create(context.Background(), namespace1)
		Expect(err).NotTo(HaveOccurred())
		defer k8sClient.Delete(context.Background(), namespace1)

		namespace2 := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "bar",
			},
		}
		err = k8sClient.Create(context.Background(), namespace2)
		Expect(err).NotTo(HaveOccurred())
		defer k8sClient.Delete(context.Background(), namespace2)

		By("creating the first EbpfEgressFirewall object successfully in foo")
		ebpfEfObj1 := &firewallv1alpha1.EbpfEgressFirewall{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "obj1",
				Namespace: namespace1.Name,
			},
		}
		err = k8sClient.Create(context.Background(), ebpfEfObj1)
		Expect(err).NotTo(HaveOccurred())

		By("creating the second EbpfEgressFirewall object successfully in bar")
		ebpfEfObj2 := &firewallv1alpha1.EbpfEgressFirewall{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "obj2",
				Namespace: namespace2.Name,
			},
		}
		err = k8sClient.Create(context.Background(), ebpfEfObj2)
		Expect(err).NotTo(HaveOccurred())

		By("trying to create the third EbpfEgressFirewall object unsuccessfully in foo")
		ebpfEfObj3 := &firewallv1alpha1.EbpfEgressFirewall{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "obj3",
				Namespace: namespace1.Name,
			},
		}
		err = k8sClient.Create(context.Background(), ebpfEfObj3)
		Expect(err).To(HaveOccurred())
	})

	It("correctly validates EbpfEgressFirewall spec for allow rules with CIDR as destination type", func() {
		By("creating a namespace")
		namespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "foo",
			},
		}
		err := k8sClient.Create(context.Background(), namespace)
		Expect(err).NotTo(HaveOccurred())
		defer k8sClient.Delete(context.Background(), namespace)

		By("creating an EbpfEgressFirewall object with CIDR as destination type in the allow rules")
		ebpfEfObj := &firewallv1alpha1.EbpfEgressFirewall{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "obj",
				Namespace: namespace.Name,
			},
			Spec: firewallv1alpha1.EbpfEgressFirewallSpec{
				AllowRules: []firewallv1alpha1.AllowRule{
					{
						To: firewallv1alpha1.AllowRuleDestination{
							DestinationType: firewallv1alpha1.CIDR,
							CIDR: &firewallv1alpha1.CIDRConfig{
								CIDRSelector: "1.1.1.0/24",
							},
						},
					},
				},
			},
		}
		err = k8sClient.Create(context.Background(), ebpfEfObj)
		Expect(err).NotTo(HaveOccurred())
	})

	It("correctly validates EbpfEgressFirewall spec for allow rules with CIDR as destination type but without CIDRConfig", func() {
		By("creating a namespace")
		namespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "foo",
			},
		}
		err := k8sClient.Create(context.Background(), namespace)
		Expect(err).NotTo(HaveOccurred())
		defer k8sClient.Delete(context.Background(), namespace)

		By("trying to create an EbpfEgressFirewall object with CIDR as destination type in the allow rules but without CIDRConfig")
		ebpfEfObj := &firewallv1alpha1.EbpfEgressFirewall{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "obj",
				Namespace: namespace.Name,
			},
			Spec: firewallv1alpha1.EbpfEgressFirewallSpec{
				AllowRules: []firewallv1alpha1.AllowRule{
					{
						To: firewallv1alpha1.AllowRuleDestination{
							DestinationType: firewallv1alpha1.CIDR,
						},
					},
				},
			},
		}
		err = k8sClient.Create(context.Background(), ebpfEfObj)
		Expect(err).To(HaveOccurred())
	})

	It("correctly validates EbpfEgressFirewall spec for allow rules with DNS as destination type", func() {
		By("creating a namespace")
		namespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "foo",
			},
		}
		err := k8sClient.Create(context.Background(), namespace)
		Expect(err).NotTo(HaveOccurred())
		defer k8sClient.Delete(context.Background(), namespace)

		By("creating an EbpfEgressFirewall object with DNS as destination type in the allow rules")
		ebpfEfObj := &firewallv1alpha1.EbpfEgressFirewall{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "obj",
				Namespace: namespace.Name,
			},
			Spec: firewallv1alpha1.EbpfEgressFirewallSpec{
				AllowRules: []firewallv1alpha1.AllowRule{
					{
						To: firewallv1alpha1.AllowRuleDestination{
							DestinationType: firewallv1alpha1.DNS,
							DNS: &firewallv1alpha1.DNSConfig{
								DNSName: "www.example.com",
							},
						},
					},
				},
			},
		}
		err = k8sClient.Create(context.Background(), ebpfEfObj)
		Expect(err).NotTo(HaveOccurred())

	})

	It("correctly validates EbpfEgressFirewall spec for allow rules with DNS as destination type but without DNSConfig", func() {
		By("creating a namespace")
		namespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "foo",
			},
		}
		err := k8sClient.Create(context.Background(), namespace)
		Expect(err).NotTo(HaveOccurred())
		defer k8sClient.Delete(context.Background(), namespace)

		By("trying to create an EbpfEgressFirewall object with DNS as destination type in the allow rules but without DNSConfig")
		ebpfEfObj := &firewallv1alpha1.EbpfEgressFirewall{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "obj",
				Namespace: namespace.Name,
			},
			Spec: firewallv1alpha1.EbpfEgressFirewallSpec{
				AllowRules: []firewallv1alpha1.AllowRule{
					{
						To: firewallv1alpha1.AllowRuleDestination{
							DestinationType: firewallv1alpha1.DNS,
						},
					},
				},
			},
		}
		err = k8sClient.Create(context.Background(), ebpfEfObj)
		Expect(err).To(HaveOccurred())

	})

	It("correctly validates EbpfEgressFirewall spec for allow rules with Node as destination type", func() {
		By("creating a namespace")
		namespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "foo",
			},
		}
		err := k8sClient.Create(context.Background(), namespace)
		Expect(err).NotTo(HaveOccurred())
		defer k8sClient.Delete(context.Background(), namespace)

		By("creating an EbpfEgressFirewall object with Node as destination type in the allow rules")
		ebpfEfObj := &firewallv1alpha1.EbpfEgressFirewall{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "obj",
				Namespace: namespace.Name,
			},
			Spec: firewallv1alpha1.EbpfEgressFirewallSpec{
				AllowRules: []firewallv1alpha1.AllowRule{
					{
						To: firewallv1alpha1.AllowRuleDestination{
							DestinationType: firewallv1alpha1.Node,
							Node: &firewallv1alpha1.NodeConfig{
								NodeSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"type": "allowed-node",
									},
								},
							},
						},
					},
				},
			},
		}
		err = k8sClient.Create(context.Background(), ebpfEfObj)
		Expect(err).NotTo(HaveOccurred())

	})

	It("correctly validates EbpfEgressFirewall spec for allow rules with Node as destination type but without NodeConfig", func() {
		By("creating a namespace")
		namespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "foo",
			},
		}
		err := k8sClient.Create(context.Background(), namespace)
		Expect(err).NotTo(HaveOccurred())
		defer k8sClient.Delete(context.Background(), namespace)

		By("trying to create an EbpfEgressFirewall object with Node as destination type in the allow rules but without NodeConfig")
		ebpfEfObj := &firewallv1alpha1.EbpfEgressFirewall{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "obj",
				Namespace: namespace.Name,
			},
			Spec: firewallv1alpha1.EbpfEgressFirewallSpec{
				AllowRules: []firewallv1alpha1.AllowRule{
					{
						To: firewallv1alpha1.AllowRuleDestination{
							DestinationType: firewallv1alpha1.Node,
						},
					},
				},
			},
		}
		err = k8sClient.Create(context.Background(), ebpfEfObj)
		Expect(err).To(HaveOccurred())

	})

	It("correctly validates EbpfEgressFirewall spec for deny rules with CIDR as destination type", func() {
		By("creating a namespace")
		namespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "foo",
			},
		}
		err := k8sClient.Create(context.Background(), namespace)
		Expect(err).NotTo(HaveOccurred())
		defer k8sClient.Delete(context.Background(), namespace)

		By("creating an EbpfEgressFirewall object with CIDR as destination type in the deny rules")
		ebpfEfObj := &firewallv1alpha1.EbpfEgressFirewall{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "obj",
				Namespace: namespace.Name,
			},
			Spec: firewallv1alpha1.EbpfEgressFirewallSpec{
				DenyRules: []firewallv1alpha1.DenyRule{
					{
						To: firewallv1alpha1.DenyRuleDestination{
							DestinationType: firewallv1alpha1.CIDR,
							CIDR: &firewallv1alpha1.CIDRConfig{
								CIDRSelector: "1.1.1.0/24",
							},
						},
					},
				},
			},
		}
		err = k8sClient.Create(context.Background(), ebpfEfObj)
		Expect(err).NotTo(HaveOccurred())
	})

	It("correctly validates EbpfEgressFirewall spec for deny rules with CIDR as destination type but without CIDRConfig", func() {
		By("creating a namespace")
		namespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "foo",
			},
		}
		err := k8sClient.Create(context.Background(), namespace)
		Expect(err).NotTo(HaveOccurred())
		defer k8sClient.Delete(context.Background(), namespace)

		By("trying to create an EbpfEgressFirewall object with CIDR as destination type in the deny rules but without CIDRConfig")
		ebpfEfObj := &firewallv1alpha1.EbpfEgressFirewall{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "obj",
				Namespace: namespace.Name,
			},
			Spec: firewallv1alpha1.EbpfEgressFirewallSpec{
				DenyRules: []firewallv1alpha1.DenyRule{
					{
						To: firewallv1alpha1.DenyRuleDestination{
							DestinationType: firewallv1alpha1.CIDR,
						},
					},
				},
			},
		}
		err = k8sClient.Create(context.Background(), ebpfEfObj)
		Expect(err).To(HaveOccurred())
	})

	It("correctly validates EbpfEgressFirewall spec for deny rules with Node as destination type", func() {
		By("creating a namespace")
		namespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "foo",
			},
		}
		err := k8sClient.Create(context.Background(), namespace)
		Expect(err).NotTo(HaveOccurred())
		defer k8sClient.Delete(context.Background(), namespace)

		By("creating an EbpfEgressFirewall object with Node as destination type in the deny rules")
		ebpfEfObj := &firewallv1alpha1.EbpfEgressFirewall{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "obj",
				Namespace: namespace.Name,
			},
			Spec: firewallv1alpha1.EbpfEgressFirewallSpec{
				DenyRules: []firewallv1alpha1.DenyRule{
					{
						To: firewallv1alpha1.DenyRuleDestination{
							DestinationType: firewallv1alpha1.Node,
							Node: &firewallv1alpha1.NodeConfig{
								NodeSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"type": "denied-node",
									},
								},
							},
						},
					},
				},
			},
		}
		err = k8sClient.Create(context.Background(), ebpfEfObj)
		Expect(err).NotTo(HaveOccurred())

	})

	It("correctly validates EbpfEgressFirewall spec for deny rules with Node as destination type but without NodeConfig", func() {
		By("creating a namespace")
		namespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "foo",
			},
		}
		err := k8sClient.Create(context.Background(), namespace)
		Expect(err).NotTo(HaveOccurred())
		defer k8sClient.Delete(context.Background(), namespace)

		By("trying to create an EbpfEgressFirewall object with Node as destination type in the deny rules but without NodeConfig")
		ebpfEfObj := &firewallv1alpha1.EbpfEgressFirewall{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "obj",
				Namespace: namespace.Name,
			},
			Spec: firewallv1alpha1.EbpfEgressFirewallSpec{
				DenyRules: []firewallv1alpha1.DenyRule{
					{
						To: firewallv1alpha1.DenyRuleDestination{
							DestinationType: firewallv1alpha1.Node,
						},
					},
				},
			},
		}
		err = k8sClient.Create(context.Background(), ebpfEfObj)
		Expect(err).To(HaveOccurred())

	})

	It("correctly validates EbpfEgressFirewall spec for allow rules with invalid destination type", func() {
		By("creating a namespace")
		namespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "foo",
			},
		}
		err := k8sClient.Create(context.Background(), namespace)
		Expect(err).NotTo(HaveOccurred())
		defer k8sClient.Delete(context.Background(), namespace)

		By("trying to create an EbpfEgressFirewall object with Invalid as destination type in the allow rules")
		ebpfEfObj := &firewallv1alpha1.EbpfEgressFirewall{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "obj",
				Namespace: namespace.Name,
			},
			Spec: firewallv1alpha1.EbpfEgressFirewallSpec{
				AllowRules: []firewallv1alpha1.AllowRule{
					{
						To: firewallv1alpha1.AllowRuleDestination{
							DestinationType: firewallv1alpha1.DestinationType("Invalid"),
						},
					},
				},
			},
		}
		err = k8sClient.Create(context.Background(), ebpfEfObj)
		Expect(err).To(HaveOccurred())

	})

	It("correctly validates EbpfEgressFirewall spec for deny rules with invalid destination type", func() {
		By("creating a namespace")
		namespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "foo",
			},
		}
		err := k8sClient.Create(context.Background(), namespace)
		Expect(err).NotTo(HaveOccurred())
		defer k8sClient.Delete(context.Background(), namespace)

		By("trying to create an EbpfEgressFirewall object with DNS as destination type in the deny rules")
		ebpfEfObj := &firewallv1alpha1.EbpfEgressFirewall{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "obj",
				Namespace: namespace.Name,
			},
			Spec: firewallv1alpha1.EbpfEgressFirewallSpec{
				DenyRules: []firewallv1alpha1.DenyRule{
					{
						To: firewallv1alpha1.DenyRuleDestination{
							DestinationType: firewallv1alpha1.DNS,
						},
					},
				},
			},
		}
		err = k8sClient.Create(context.Background(), ebpfEfObj)
		Expect(err).To(HaveOccurred())

	})

	It("correctly validates EbpfEgressFirewall spec for update of destination type from CIDR to DNS for allow rules", func() {
		By("creating a namespace")
		namespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "foo",
			},
		}
		err := k8sClient.Create(context.Background(), namespace)
		Expect(err).NotTo(HaveOccurred())
		defer k8sClient.Delete(context.Background(), namespace)

		By("creating an EbpfEgressFirewall object with CIDR as destination type in the allow rules")
		ebpfEfObj := &firewallv1alpha1.EbpfEgressFirewall{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "obj",
				Namespace: namespace.Name,
			},
			Spec: firewallv1alpha1.EbpfEgressFirewallSpec{
				AllowRules: []firewallv1alpha1.AllowRule{
					{
						To: firewallv1alpha1.AllowRuleDestination{
							DestinationType: firewallv1alpha1.CIDR,
							CIDR: &firewallv1alpha1.CIDRConfig{
								CIDRSelector: "1.1.1.0/24",
							},
						},
					},
				},
			},
		}
		err = k8sClient.Create(context.Background(), ebpfEfObj)
		Expect(err).NotTo(HaveOccurred())

		By("fetching the newly created EbpfEgressFirewall object")
		ebpfEfNamespacedName := types.NamespacedName{
			Name:      ebpfEfObj.Name,
			Namespace: ebpfEfObj.Namespace,
		}
		err = k8sClient.Get(context.Background(), ebpfEfNamespacedName, ebpfEfObj)
		Expect(err).NotTo(HaveOccurred())

		By("updating the destination type of the allow rules from CIDR to DNS in the EbpfEgressFirewall object")
		ebpfEfObj.Spec.AllowRules[0] = firewallv1alpha1.AllowRule{
			To: firewallv1alpha1.AllowRuleDestination{
				DestinationType: firewallv1alpha1.DNS,
				DNS: &firewallv1alpha1.DNSConfig{
					DNSName: "www.example.com",
				},
			},
		}
		err = k8sClient.Update(context.Background(), ebpfEfObj)
		Expect(err).NotTo(HaveOccurred())

	})

	It("correctly validates EbpfEgressFirewall spec for incorrect update of allow rules with destination type CIDR", func() {
		By("creating a namespace")
		namespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "foo",
			},
		}
		err := k8sClient.Create(context.Background(), namespace)
		Expect(err).NotTo(HaveOccurred())
		defer k8sClient.Delete(context.Background(), namespace)

		By("creating an EbpfEgressFirewall object with CIDR as destination type in the allow rules")
		ebpfEfObj := &firewallv1alpha1.EbpfEgressFirewall{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "obj",
				Namespace: namespace.Name,
			},
			Spec: firewallv1alpha1.EbpfEgressFirewallSpec{
				AllowRules: []firewallv1alpha1.AllowRule{
					{
						To: firewallv1alpha1.AllowRuleDestination{
							DestinationType: firewallv1alpha1.CIDR,
							CIDR: &firewallv1alpha1.CIDRConfig{
								CIDRSelector: "1.1.1.0/24",
							},
						},
					},
				},
			},
		}
		err = k8sClient.Create(context.Background(), ebpfEfObj)
		Expect(err).NotTo(HaveOccurred())

		By("fetching the newly created EbpfEgressFirewall object")
		ebpfEfNamespacedName := types.NamespacedName{
			Name:      ebpfEfObj.Name,
			Namespace: ebpfEfObj.Namespace,
		}
		err = k8sClient.Get(context.Background(), ebpfEfNamespacedName, ebpfEfObj)
		Expect(err).NotTo(HaveOccurred())

		By("trying to update the allow rules with destination type CIDR")
		ebpfEfObj.Spec.AllowRules[0] = firewallv1alpha1.AllowRule{
			To: firewallv1alpha1.AllowRuleDestination{
				DestinationType: firewallv1alpha1.CIDR,
			},
		}
		err = k8sClient.Update(context.Background(), ebpfEfObj)
		Expect(err).To(HaveOccurred())

	})

	It("correctly validates EbpfEgressFirewall spec for update of destination type from Node to CIDR for deny rules", func() {
		By("creating a namespace")
		namespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "foo",
			},
		}
		err := k8sClient.Create(context.Background(), namespace)
		Expect(err).NotTo(HaveOccurred())
		defer k8sClient.Delete(context.Background(), namespace)

		By("creating an EbpfEgressFirewall object with Node as destination type in the deny rules")
		ebpfEfObj := &firewallv1alpha1.EbpfEgressFirewall{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "obj",
				Namespace: namespace.Name,
			},
			Spec: firewallv1alpha1.EbpfEgressFirewallSpec{
				DenyRules: []firewallv1alpha1.DenyRule{
					{
						To: firewallv1alpha1.DenyRuleDestination{
							DestinationType: firewallv1alpha1.Node,
							Node: &firewallv1alpha1.NodeConfig{
								NodeSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"type": "denied-node",
									},
								},
							},
						},
					},
				},
			},
		}
		err = k8sClient.Create(context.Background(), ebpfEfObj)
		Expect(err).NotTo(HaveOccurred())

		By("fetching the newly created EbpfEgressFirewall object")
		ebpfEfNamespacedName := types.NamespacedName{
			Name:      ebpfEfObj.Name,
			Namespace: ebpfEfObj.Namespace,
		}
		err = k8sClient.Get(context.Background(), ebpfEfNamespacedName, ebpfEfObj)
		Expect(err).NotTo(HaveOccurred())

		By("updating the destination type of the deny rules from Node to CIDR in the EbpfEgressFirewall object")
		ebpfEfObj.Spec.DenyRules[0] = firewallv1alpha1.DenyRule{
			To: firewallv1alpha1.DenyRuleDestination{
				DestinationType: firewallv1alpha1.CIDR,
				CIDR: &firewallv1alpha1.CIDRConfig{
					CIDRSelector: "1.1.1.0/24",
				},
			},
		}
		err = k8sClient.Update(context.Background(), ebpfEfObj)
		Expect(err).NotTo(HaveOccurred())

	})

	It("correctly validates EbpfEgressFirewall spec for incorrect update of deny rules with destination type Node", func() {
		By("creating a namespace")
		namespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "foo",
			},
		}
		err := k8sClient.Create(context.Background(), namespace)
		Expect(err).NotTo(HaveOccurred())
		defer k8sClient.Delete(context.Background(), namespace)

		By("creating an EbpfEgressFirewall object with Node as destination type in the deny rules")
		ebpfEfObj := &firewallv1alpha1.EbpfEgressFirewall{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "obj",
				Namespace: namespace.Name,
			},
			Spec: firewallv1alpha1.EbpfEgressFirewallSpec{
				DenyRules: []firewallv1alpha1.DenyRule{
					{
						To: firewallv1alpha1.DenyRuleDestination{
							DestinationType: firewallv1alpha1.Node,
							Node: &firewallv1alpha1.NodeConfig{
								NodeSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"type": "denied-node",
									},
								},
							},
						},
					},
				},
			},
		}
		err = k8sClient.Create(context.Background(), ebpfEfObj)
		Expect(err).NotTo(HaveOccurred())

		By("fetching the newly created EbpfEgressFirewall object")
		ebpfEfNamespacedName := types.NamespacedName{
			Name:      ebpfEfObj.Name,
			Namespace: ebpfEfObj.Namespace,
		}
		err = k8sClient.Get(context.Background(), ebpfEfNamespacedName, ebpfEfObj)
		Expect(err).NotTo(HaveOccurred())

		By("trying to update the deny rules with destination type Node")
		ebpfEfObj.Spec.DenyRules[0] = firewallv1alpha1.DenyRule{
			To: firewallv1alpha1.DenyRuleDestination{
				DestinationType: firewallv1alpha1.Node,
			},
		}
		err = k8sClient.Update(context.Background(), ebpfEfObj)
		Expect(err).To(HaveOccurred())

	})
})
