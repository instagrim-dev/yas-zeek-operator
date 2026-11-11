package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1alpha1 "github.com/instagrim-dev/yas-zeek-operator/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/yaml"
)

func TestAPIServerSiteConfigAndUpdate(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("set KUBEBUILDER_ASSETS for API server tests")
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "config", "crd.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := yaml.YAMLToJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	crd := &extv1.CustomResourceDefinition{}
	if err = json.Unmarshal(data, crd); err != nil {
		t.Fatal(err)
	}
	env := &envtest.Environment{CRDs: []*extv1.CustomResourceDefinition{crd}}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Error(err)
		}
	})
	scheme := runtime.NewScheme()
	for _, register := range []func(*runtime.Scheme) error{v1alpha1.AddToScheme, corev1.AddToScheme, appsv1.AddToScheme} {
		if err = register(scheme); err != nil {
			t.Fatal(err)
		}
	}
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	sensor := &v1alpha1.KSensor{ObjectMeta: metav1.ObjectMeta{Name: "example", Namespace: "default"}, Spec: v1alpha1.KSensorSpec{TenantNamespace: "default", Engine: map[string]v1alpha1.EngineApp{"NSM": {Enabled: true, Image: "zeek:test", CpuLimit: "1", MemoryLimit: "1Gi", SiteConfig: "@load policy/test-a", Scripts: map[string]string{"custom": "event zeek_init() { print 1; }"}}}, Network: v1alpha1.NetworkConfig{Mesh: v1alpha1.MeshConfig{Image: "mesh:test", CpuLimit: "1", MemoryLimit: "1Gi"}}, Monitoring: v1alpha1.MonitoringConfig{Metrics: v1alpha1.MetricsConfig{Image: "metrics:test", CpuLimit: "1", MemoryLimit: "1Gi"}}}}
	if err := c.Create(ctx, sensor); err != nil {
		t.Fatal(err)
	}
	key := types.NamespacedName{Name: "example", Namespace: "default"}
	r := &ZeekReconciler{Client: c, Scheme: scheme}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatal(err)
	}
	set := &appsv1.StatefulSet{}
	setKey := types.NamespacedName{Name: "zeek-manager", Namespace: "default"}
	if err := c.Get(ctx, setKey, set); err != nil {
		t.Fatal(err)
	}
	old := set.Spec.Template.Annotations["zeek.yas.ohbmo.com/site-config-sha256"]
	if old == "" {
		t.Fatal("missing hash")
	}
	current := &v1alpha1.KSensor{}
	if err := c.Get(ctx, key, current); err != nil {
		t.Fatal(err)
	}
	engine := current.Spec.Engine["NSM"]
	engine.WorkerReplicas = 3
	engine.SiteConfig = "@load policy/test-b"
	engine.Scripts["custom"] = "event zeek_init() { print 2; }"
	current.Spec.Engine["NSM"] = engine
	if err := c.Update(ctx, current); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatal(err)
	}
	cm := &corev1.ConfigMap{}
	if err := c.Get(ctx, types.NamespacedName{Name: "nsm-local-zeek", Namespace: "default"}, cm); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cm.Data["local.zeek"], "@load policy/test-b") {
		t.Fatal("missing changed policy")
	}
	if err := c.Get(ctx, setKey, set); err != nil {
		t.Fatal(err)
	}
	if old == set.Spec.Template.Annotations["zeek.yas.ohbmo.com/site-config-sha256"] {
		t.Fatal("rollout hash did not change")
	}
	scripts := &corev1.ConfigMap{}
	if err := c.Get(ctx, types.NamespacedName{Name: "nsm-site-scripts", Namespace: "default"}, scripts); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(scripts.Data["custom.zeek"], "print 2") {
		t.Fatal("script update not applied")
	}
	found := false
	for _, mount := range set.Spec.Template.Spec.Containers[0].VolumeMounts {
		if mount.Name == "site-scripts" {
			found = true
		}
	}
	if !found {
		t.Fatal("managed scripts not mounted")
	}

	worker := &appsv1.StatefulSet{}
	if err := c.Get(ctx, types.NamespacedName{Name: "zeek-worker", Namespace: "default"}, worker); err != nil {
		t.Fatal(err)
	}
	if worker.Spec.Replicas == nil || *worker.Spec.Replicas != 3 {
		t.Fatal("wrong worker replica count")
	}
	for _, mount := range worker.Spec.Template.Spec.Containers[0].VolumeMounts {
		if mount.Name == "cluster-layout-zeek" {
			t.Fatal("must not override ZeekControl-generated layout")
		}
	}

	for i, name := range []string{"worker-001", "worker-002", "worker-003"} {
		svc := &corev1.Service{}
		if err := c.Get(ctx, types.NamespacedName{Name: name, Namespace: "default"}, svc); err != nil {
			t.Fatal(err)
		}
		expected := fmt.Sprintf("zeek-worker-%d", i)
		if svc.Spec.Selector["statefulset.kubernetes.io/pod-name"] != expected {
			t.Fatalf("service %s selects wrong pod", name)
		}
	}
	node := &corev1.ConfigMap{}
	if err := c.Get(ctx, types.NamespacedName{Name: "nsm-cluster-node-cfg", Namespace: "default"}, node); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(node.Data["node.cfg"], "host=worker-003.default.svc.cluster.local") {
		t.Fatal("missing third worker DNS")
	}
	before := set.Spec.Template.Annotations["zeek.yas.ohbmo.com/site-config-sha256"]
	if err := c.Get(ctx, key, current); err != nil {
		t.Fatal(err)
	}
	engine = current.Spec.Engine["NSM"]
	engine.WorkerReplicas = 1
	current.Spec.Engine["NSM"] = engine
	if err := c.Update(ctx, current); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, setKey, set); err != nil {
		t.Fatal(err)
	}
	if before == set.Spec.Template.Annotations["zeek.yas.ohbmo.com/site-config-sha256"] {
		t.Fatal("topology change did not roll manager")
	}
	if err := c.Get(ctx, types.NamespacedName{Name: "worker-003", Namespace: "default"}, &corev1.Service{}); !apierrors.IsNotFound(err) {
		t.Fatalf("stale worker service: %v", err)
	}

}
