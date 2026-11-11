package controller

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	v1alpha1 "github.com/instagrim-dev/yas-zeek-operator/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestInlineScriptsAreMountedUpdatedAndRemoved(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	for _, reg := range []func(*runtime.Scheme) error{v1alpha1.AddToScheme, corev1.AddToScheme, appsv1.AddToScheme} {
		_ = reg(scheme)
	}
	var engine v1alpha1.EngineApp
	if err := json.Unmarshal([]byte(`{"Enabled":true,"Image":"zeek:test","CpuLimit":"1","MemoryLimit":"1Gi","Scripts":{"custom":"event zeek_init() { print 1; }"}}`), &engine); err != nil {
		t.Fatal(err)
	}
	sensor := &v1alpha1.KSensor{ObjectMeta: metav1.ObjectMeta{Name: "sensor", Namespace: "default", UID: types.UID("sensor-uid")}, Spec: v1alpha1.KSensorSpec{TenantNamespace: "default", Engine: map[string]v1alpha1.EngineApp{"NSM": engine}, Network: v1alpha1.NetworkConfig{Mesh: v1alpha1.MeshConfig{CpuLimit: "1", MemoryLimit: "1Gi"}}, Monitoring: v1alpha1.MonitoringConfig{Metrics: v1alpha1.MetricsConfig{CpuLimit: "1", MemoryLimit: "1Gi"}}}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(sensor).Build()
	r := &ZeekReconciler{Client: c, Scheme: scheme}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "sensor", Namespace: "default"}}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	cm := &corev1.ConfigMap{}
	key := types.NamespacedName{Name: "nsm-site-scripts", Namespace: "default"}
	if err := c.Get(ctx, key, cm); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cm.Data["custom.zeek"], "print 1") {
		t.Fatal("script content missing")
	}
	set := &appsv1.StatefulSet{}
	setKey := types.NamespacedName{Name: "zeek-manager", Namespace: "default"}
	if err := c.Get(ctx, setKey, set); err != nil {
		t.Fatal(err)
	}
	old := set.Spec.Template.Annotations["zeek.yas.ohbmo.com/site-config-sha256"]
	found := false
	for _, m := range set.Spec.Template.Spec.Containers[0].VolumeMounts {
		if m.Name == "site-scripts" && m.MountPath == "/zeek/share/zeek/site/managed" {
			found = true
		}
	}
	if !found {
		t.Fatal("script mount missing")
	}
	local := &corev1.ConfigMap{}
	if err := c.Get(ctx, types.NamespacedName{Name: "nsm-local-zeek", Namespace: "default"}, local); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(local.Data["local.zeek"], "@load ./managed/custom.zeek") {
		t.Fatal("script load directive missing")
	}
	cur := &v1alpha1.KSensor{}
	if err := c.Get(ctx, req.NamespacedName, cur); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"Enabled":true,"Image":"zeek:test","CpuLimit":"1","MemoryLimit":"1Gi","Scripts":{"custom":"event zeek_init() { print 2; }"}}`), &engine); err != nil {
		t.Fatal(err)
	}
	cur.Spec.Engine["NSM"] = engine
	if err := c.Update(ctx, cur); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, key, cm); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cm.Data["custom.zeek"], "print 2") {
		t.Fatal("script did not update")
	}
	if err := c.Get(ctx, setKey, set); err != nil {
		t.Fatal(err)
	}
	if old == set.Spec.Template.Annotations["zeek.yas.ohbmo.com/site-config-sha256"] {
		t.Fatal("script update did not roll workload")
	}
	if err := c.Get(ctx, req.NamespacedName, cur); err != nil {
		t.Fatal(err)
	}
	engine = v1alpha1.EngineApp{}
	if err := json.Unmarshal([]byte(`{"Enabled":true,"Image":"zeek:test","CpuLimit":"1","MemoryLimit":"1Gi","Scripts":{}}`), &engine); err != nil {
		t.Fatal(err)
	}
	cur.Spec.Engine["NSM"] = engine
	if err := c.Update(ctx, cur); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, key, cm); !apierrors.IsNotFound(err) {
		t.Fatalf("obsolete script config remains: %v", err)
	}
}

func TestInlineScriptRejectsUnsafeNamesBeforeCreatingWorkloads(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = v1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	sensor := &v1alpha1.KSensor{ObjectMeta: metav1.ObjectMeta{Name: "sensor", Namespace: "default"}, Spec: v1alpha1.KSensorSpec{TenantNamespace: "default", Engine: map[string]v1alpha1.EngineApp{"NSM": {Enabled: true, Scripts: map[string]string{"../bad": "x"}}}}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(sensor).Build()
	r := &ZeekReconciler{Client: c, Scheme: scheme}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "sensor", Namespace: "default"}}); err == nil {
		t.Fatal("unsafe script name accepted")
	}
	var sets appsv1.StatefulSetList
	if err := c.List(ctx, &sets); err != nil {
		t.Fatal(err)
	}
	if len(sets.Items) != 0 {
		t.Fatal("created workload for invalid script")
	}
}
