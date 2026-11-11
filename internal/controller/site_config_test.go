package controller

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	zeekv1 "github.com/instagrim-dev/yas-zeek-operator/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestSiteConfigChangesReconcileAndRollPods(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	for _, register := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, zeekv1.AddToScheme} {
		if err := register(scheme); err != nil {
			t.Fatal(err)
		}
	}
	var engine zeekv1.EngineApp
	if err := json.Unmarshal([]byte(`{"Enabled":true,"Image":"zeek:test","CpuLimit":"1","MemoryLimit":"1Gi","SiteConfig":"@load policy/test-a"}`), &engine); err != nil {
		t.Fatal(err)
	}
	sensor := &zeekv1.KSensor{ObjectMeta: metav1.ObjectMeta{Name: "example", Namespace: "default", UID: types.UID("uid")}, Spec: zeekv1.KSensorSpec{TenantNamespace: "default", Engine: map[string]zeekv1.EngineApp{"NSM": engine}, Network: zeekv1.NetworkConfig{Mesh: zeekv1.MeshConfig{CpuLimit: "1", MemoryLimit: "1Gi"}}, Monitoring: zeekv1.MonitoringConfig{Metrics: zeekv1.MetricsConfig{CpuLimit: "1", MemoryLimit: "1Gi"}}}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(sensor).Build()
	r := &ZeekReconciler{Client: c, Scheme: scheme}
	request := ctrl.Request{NamespacedName: types.NamespacedName{Name: "example", Namespace: "default"}}
	if _, err := r.Reconcile(ctx, request); err != nil {
		t.Fatal(err)
	}
	config := &corev1.ConfigMap{}
	if err := c.Get(ctx, types.NamespacedName{Name: "nsm-local-zeek", Namespace: "default"}, config); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(config.Data["local.zeek"], "@load policy/test-a") {
		t.Fatal("custom site config missing")
	}
	set := &appsv1.StatefulSet{}
	key := types.NamespacedName{Name: "zeek-manager", Namespace: "default"}
	if err := c.Get(ctx, key, set); err != nil {
		t.Fatal(err)
	}
	old := set.Spec.Template.Annotations["zeek.yas.ohbmo.com/site-config-sha256"]
	if old == "" {
		t.Fatal("missing site configuration hash")
	}
	current := &zeekv1.KSensor{}
	if err := c.Get(ctx, request.NamespacedName, current); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"Enabled":true,"Image":"zeek:test","CpuLimit":"1","MemoryLimit":"1Gi","SiteConfig":"@load policy/test-b"}`), &engine); err != nil {
		t.Fatal(err)
	}
	current.Spec.Engine["NSM"] = engine
	if err := c.Update(ctx, current); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, request); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, types.NamespacedName{Name: "nsm-local-zeek", Namespace: "default"}, config); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(config.Data["local.zeek"], "@load policy/test-b") || strings.Contains(config.Data["local.zeek"], "@load policy/test-a") {
		t.Fatal("site config was not replaced")
	}
	if err := c.Get(ctx, key, set); err != nil {
		t.Fatal(err)
	}
	if old == set.Spec.Template.Annotations["zeek.yas.ohbmo.com/site-config-sha256"] {
		t.Fatal("site config change did not roll pods")
	}
}
