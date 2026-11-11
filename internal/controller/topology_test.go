package controller

import (
	"context"
	"encoding/json"
	"github.com/go-logr/logr"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/instagrim-dev/yas-zeek-operator/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestWorkerTopologyReconcilesScaleAndDNS(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = v1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	sensor := &v1.KSensor{}
	if err := json.Unmarshal([]byte(`{"metadata":{"name":"example","namespace":"default","uid":"owner"},"spec":{"TenantNamespace":"default","Engine":{"NSM":{"Enabled":true,"WorkerReplicas":3,"Image":"zeek:test","CpuLimit":"1","MemoryLimit":"1Gi"}},"Network":{"Mesh":{"CpuLimit":"1","MemoryLimit":"1Gi"}},"Monitoring":{"Metrics":{"CpuLimit":"1","MemoryLimit":"1Gi"}}}}`), sensor); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(sensor).Build()
	r := &ZeekReconciler{Client: c, Scheme: scheme}
	key := types.NamespacedName{Name: "example", Namespace: "default"}
	req := ctrl.Request{NamespacedName: key}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	var worker appsv1.StatefulSet
	if err := c.Get(ctx, types.NamespacedName{Name: "zeek-worker", Namespace: "default"}, &worker); err != nil {
		t.Fatal(err)
	}
	if worker.Spec.Replicas == nil || *worker.Spec.Replicas != 3 {
		t.Fatalf("workers: %v", worker.Spec.Replicas)
	}
	for _, v := range []struct{ name, pod string }{{"worker-001", "zeek-worker-0"}, {"worker-002", "zeek-worker-1"}, {"worker-003", "zeek-worker-2"}} {
		var svc corev1.Service
		if err := c.Get(ctx, types.NamespacedName{Name: v.name, Namespace: "default"}, &svc); err != nil {
			t.Fatal(err)
		}
		if svc.Spec.Selector["statefulset.kubernetes.io/pod-name"] != v.pod {
			t.Fatal("incorrect selector", v.name)
		}
	}
	var cm corev1.ConfigMap
	if err := c.Get(ctx, types.NamespacedName{Name: "nsm-cluster-node-cfg", Namespace: "default"}, &cm); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"[worker-001]", "[worker-002]", "[worker-003]"} {
		if !strings.Contains(cm.Data["node.cfg"], host) {
			t.Fatalf("missing %s in node cfg", host)
		}
	}
	var current v1.KSensor
	if err := c.Get(ctx, key, &current); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(current)
	var object map[string]interface{}
	_ = json.Unmarshal(raw, &object)
	object["spec"].(map[string]interface{})["Engine"].(map[string]interface{})["NSM"].(map[string]interface{})["WorkerReplicas"] = float64(1)
	raw, _ = json.Marshal(object)
	if err := json.Unmarshal(raw, &current); err != nil {
		t.Fatal(err)
	}
	if err := c.Update(ctx, &current); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	var services corev1.ServiceList
	if err := c.List(ctx, &services); err != nil {
		t.Fatal(err)
	}
	for _, svc := range services.Items {
		if svc.Name == "worker-002" || svc.Name == "worker-003" {
			t.Fatalf("stale worker service %s", svc.Name)
		}
	}
}

func TestWorkerReplicasValidationAndOwnership(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = v1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	sensor := &v1.KSensor{ObjectMeta: metav1.ObjectMeta{Name: "example", Namespace: "default", UID: types.UID("owner")}, Spec: v1.KSensorSpec{TenantNamespace: "default", Engine: map[string]v1.EngineApp{"NSM": {Enabled: true, WorkerReplicas: -1}}}}
	foreign := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "worker-002", Namespace: "default"}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(sensor, foreign).Build()
	r := &ZeekReconciler{Client: c, Scheme: scheme}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "example", Namespace: "default"}}
	if _, err := r.Reconcile(ctx, req); err == nil {
		t.Fatal("negative worker count accepted")
	}
	// A disabled sensor may clean up only Services that it owns.
	sensor.Spec.Engine["NSM"] = v1.EngineApp{Enabled: false}
	if err := c.Update(ctx, sensor); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, types.NamespacedName{Name: "worker-002", Namespace: "default"}, &corev1.Service{}); err != nil {
		t.Fatalf("foreign service was removed: %v", err)
	}
}

func TestManagerInitializerUsesPortableShellComparison(t *testing.T) {
	sensor := v1.KSensor{ObjectMeta: metav1.ObjectMeta{Name: "sensor", Namespace: "default"}, Spec: v1.KSensorSpec{TenantNamespace: "default", Engine: map[string]v1.EngineApp{"NSM": {CpuLimit: "1", MemoryLimit: "1Gi"}}, Network: v1.NetworkConfig{Mesh: v1.MeshConfig{CpuLimit: "1", MemoryLimit: "1Gi"}}, Monitoring: v1.MonitoringConfig{Metrics: v1.MetricsConfig{CpuLimit: "1", MemoryLimit: "1Gi"}}}}
	r := &KSensorReconciler{Scheme: runtime.NewScheme()}
	_ = v1.AddToScheme(r.Scheme)
	_ = appsv1.AddToScheme(r.Scheme)
	set, err := r.DefineSsNsmCluster(context.Background(), logr.Discard(), sensor, "manager")
	if err != nil {
		t.Fatal(err)
	}
	cmd := strings.Join(set.Spec.Template.Spec.InitContainers[0].Command, " ")
	if !strings.Contains(cmd, `[ "$POD_NAME" = zeek-manager-0 ]`) {
		t.Fatal("manager initializer must use portable POSIX shell equality")
	}
}

// Optional live Zeek check: ZEEK_BINARY points to an installed Zeek executable.
func TestDefaultSitePolicyLoadsWithZeek(t *testing.T) {
	binary := os.Getenv("ZEEK_BINARY")
	if binary == "" {
		t.Skip("set ZEEK_BINARY to exercise a real Zeek executable")
	}
	sensor := v1.KSensor{Spec: v1.KSensorSpec{TenantNamespace: "default"}}
	file := filepath.Join(t.TempDir(), "local.zeek")
	if err := os.WriteFile(file, []byte(siteConfig(sensor)), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "-C", file, "-e", "event zeek_init(){ terminate(); }")
	cmd.Dir = t.TempDir()
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Zeek rejected site policy: %v\n%s", err, output)
	}
}

func TestWorkerSSHServerAcceptsMoreThanOneConnection(t *testing.T) {
	args := ZeekCtrArgs("worker")
	for _, arg := range args {
		if arg == "-d" {
			t.Fatal("sshd debug mode exits after one connection")
		}
	}
}

func TestZeekControlConfigDoesNotAssumeSharedSpool(t *testing.T) {
	config := nsmConfigs["nsm-zeekctl-cfg"]
	if strings.Contains(config, "HaveNFS=1") || !strings.Contains(config, "HaveNFS=0") {
		t.Fatal("pod-local spool must not be treated as shared NFS")
	}
}
