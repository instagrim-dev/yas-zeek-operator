package controller

import (
	"context"
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

func TestZeekReconcilesWithoutSuricata(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	for _, register := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, v1alpha1.AddToScheme} {
		if err := register(scheme); err != nil {
			t.Fatal(err)
		}
	}
	sensor := &v1alpha1.KSensor{ObjectMeta: metav1.ObjectMeta{Name: "example", Namespace: "default"}, Spec: v1alpha1.KSensorSpec{TenantNamespace: "default", Engine: map[string]v1alpha1.EngineApp{"NSM": {Enabled: true, Image: "zeek:test", CpuLimit: "1", MemoryLimit: "1Gi"}}, Network: v1alpha1.NetworkConfig{Mesh: v1alpha1.MeshConfig{CpuLimit: "1", MemoryLimit: "1Gi"}}, Monitoring: v1alpha1.MonitoringConfig{Metrics: v1alpha1.MetricsConfig{CpuLimit: "1", MemoryLimit: "1Gi"}}}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(sensor).Build()
	r := &ZeekReconciler{Client: c, Scheme: scheme}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "example", Namespace: "default"}}); err != nil {
		t.Fatal(err)
	}
	for _, node := range []string{"manager", "proxy", "logger", "worker"} {
		var ss appsv1.StatefulSet
		if err := c.Get(ctx, types.NamespacedName{Name: "zeek-" + node, Namespace: "default"}, &ss); err != nil {
			t.Fatalf("Zeek %s not created: %v", node, err)
		}
	}
	// A subsequent specification change must update the deployed engine image.
	var current v1alpha1.KSensor
	key := types.NamespacedName{Name: "example", Namespace: "default"}
	if err := c.Get(ctx, key, &current); err != nil {
		t.Fatal(err)
	}
	engine := current.Spec.Engine["NSM"]
	engine.Image = "zeek:updated"
	current.Spec.Engine["NSM"] = engine
	if err := c.Update(ctx, &current); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatal(err)
	}
	var manager appsv1.StatefulSet
	if err := c.Get(ctx, types.NamespacedName{Name: "zeek-manager", Namespace: "default"}, &manager); err != nil {
		t.Fatal(err)
	}
	if got := manager.Spec.Template.Spec.Containers[0].Image; got != "zeek:updated" {
		t.Fatalf("manager image = %q, want updated image", got)
	}
	var ids appsv1.Deployment
	if err := c.Get(ctx, types.NamespacedName{Name: "suricata", Namespace: "default"}, &ids); !apierrors.IsNotFound(err) {
		t.Fatalf("independent Zeek reconciliation unexpectedly found Suricata: %v", err)
	}
}

func TestZeekDisabledDoesNotCreateWorkloads(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = v1alpha1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	sensor := &v1alpha1.KSensor{ObjectMeta: metav1.ObjectMeta{Name: "example", Namespace: "default"}, Spec: v1alpha1.KSensorSpec{TenantNamespace: "default"}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(sensor).Build()
	r := &ZeekReconciler{Client: c, Scheme: scheme}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "example", Namespace: "default"}}); err != nil {
		t.Fatal(err)
	}
	var ss appsv1.StatefulSet
	if err := c.Get(ctx, types.NamespacedName{Name: "zeek-manager", Namespace: "default"}, &ss); !apierrors.IsNotFound(err) {
		t.Fatalf("disabled Zeek unexpectedly found workloads: %v", err)
	}
}

func TestZeekLegacyModeDoesNotCreateWorkloads(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = v1alpha1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	sensor := &v1alpha1.KSensor{ObjectMeta: metav1.ObjectMeta{Name: "example", Namespace: "default"}, Spec: v1alpha1.KSensorSpec{TenantNamespace: "default", Mode: "Legacy", Engine: map[string]v1alpha1.EngineApp{"NSM": {Enabled: true}}}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(sensor).Build()
	r := &ZeekReconciler{Client: c, Scheme: scheme}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "example", Namespace: "default"}}); err != nil {
		t.Fatal(err)
	}
	var ss appsv1.StatefulSet
	if err := c.Get(ctx, types.NamespacedName{Name: "zeek-manager", Namespace: "default"}, &ss); !apierrors.IsNotFound(err) {
		t.Fatalf("legacy mode unexpectedly found Zeek workloads: %v", err)
	}
}

func TestZeekDisableDeletesOnlyOwnedEngineObjects(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = v1alpha1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	sensor := &v1alpha1.KSensor{ObjectMeta: metav1.ObjectMeta{Name: "example", Namespace: "default", UID: types.UID("sensor-uid")}, Spec: v1alpha1.KSensorSpec{TenantNamespace: "default", Engine: map[string]v1alpha1.EngineApp{"NSM": {Enabled: true, Image: "zeek:test", CpuLimit: "1", MemoryLimit: "1Gi"}}, Network: v1alpha1.NetworkConfig{Mesh: v1alpha1.MeshConfig{CpuLimit: "1", MemoryLimit: "1Gi"}}, Monitoring: v1alpha1.MonitoringConfig{Metrics: v1alpha1.MetricsConfig{CpuLimit: "1", MemoryLimit: "1Gi"}}}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(sensor).Build()
	r := &ZeekReconciler{Client: c, Scheme: scheme}
	key := types.NamespacedName{Name: "example", Namespace: "default"}
	req := ctrl.Request{NamespacedName: key}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	var outsider corev1.ConfigMap
	if err := c.Get(ctx, types.NamespacedName{Name: "nsm-networks-cfg", Namespace: "default"}, &outsider); err != nil {
		t.Fatal(err)
	}
	outsider.OwnerReferences = []metav1.OwnerReference{{APIVersion: "v1", Kind: "Other", Name: "other", UID: types.UID("other")}}
	if err := c.Update(ctx, &outsider); err != nil {
		t.Fatal(err)
	}
	unrelated := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "unrelated", Namespace: "default", OwnerReferences: []metav1.OwnerReference{{UID: types.UID("sensor-uid")}}}}
	if err := c.Create(ctx, unrelated); err != nil {
		t.Fatal(err)
	}
	var latest v1alpha1.KSensor
	if err := c.Get(ctx, key, &latest); err != nil {
		t.Fatal(err)
	}
	zeek := latest.Spec.Engine["NSM"]
	zeek.Enabled = false
	latest.Spec.Engine["NSM"] = zeek
	if err := c.Update(ctx, &latest); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	var ss appsv1.StatefulSet
	if err := c.Get(ctx, types.NamespacedName{Name: "zeek-manager", Namespace: "default"}, &ss); !apierrors.IsNotFound(err) {
		t.Fatalf("owned Zeek workload remains: %v", err)
	}
	for _, node := range []string{"manager", "proxy", "logger", "worker"} {
		var workload appsv1.StatefulSet
		if err := c.Get(ctx, types.NamespacedName{Name: "zeek-" + node, Namespace: "default"}, &workload); !apierrors.IsNotFound(err) {
			t.Fatalf("Zeek workload %s remains: %v", node, err)
		}
		serviceName := node
		if node != "manager" {
			serviceName += "-001"
		}
		var service corev1.Service
		if err := c.Get(ctx, types.NamespacedName{Name: serviceName, Namespace: "default"}, &service); !apierrors.IsNotFound(err) {
			t.Fatalf("Zeek service %s remains: %v", serviceName, err)
		}
	}
	for _, name := range []string{"nsm-prometheus-server-config", "nsm-mesh-config", "nsm-cluster-node-cfg", "nsm-zeekctl-cfg", "nsm-local-zeek", "nsm-multi-cluster-layout-zeek"} {
		var config corev1.ConfigMap
		if err := c.Get(ctx, types.NamespacedName{Name: name, Namespace: "default"}, &config); !apierrors.IsNotFound(err) {
			t.Fatalf("owned config %s remains: %v", name, err)
		}
	}
	for _, name := range []string{"nsm-networks-cfg", "unrelated"} {
		var cm corev1.ConfigMap
		if err := c.Get(ctx, types.NamespacedName{Name: name, Namespace: "default"}, &cm); err != nil {
			t.Fatalf("unrelated %s removed: %v", name, err)
		}
	}
}

func TestZeekRejectsCrossNamespaceOwnership(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = v1alpha1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	sensor := &v1alpha1.KSensor{ObjectMeta: metav1.ObjectMeta{Name: "example", Namespace: "default"}, Spec: v1alpha1.KSensorSpec{TenantNamespace: "other", Engine: map[string]v1alpha1.EngineApp{"NSM": {Enabled: true}}}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(sensor).Build()
	r := &ZeekReconciler{Client: c, Scheme: scheme}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "example", Namespace: "default"}}); err == nil {
		t.Fatal("cross-namespace owner accepted")
	}
}
