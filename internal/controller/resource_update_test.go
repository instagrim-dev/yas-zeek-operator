package controller

import (
	"context"
	"testing"

	"github.com/go-logr/logr"
	v1alpha1 "github.com/instagrim-dev/yas-zeek-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestCreateOrUpdateAppliesDesiredConfig(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	old := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "config", Namespace: "default"}, Data: map[string]string{"value": "old"}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(old).Build()
	r := &KSensorReconciler{Client: c, Scheme: scheme}
	desired := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "config", Namespace: "default"}, Data: map[string]string{"value": "new"}}
	if err := r.CreateOrUpdateCRD(ctx, logr.Discard(), v1alpha1.KSensor{}, desired, schema.GroupVersionKind{Version: "v1", Kind: "ConfigMap"}); err != nil {
		t.Fatal(err)
	}
	got := &corev1.ConfigMap{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(old), got); err != nil {
		t.Fatal(err)
	}
	if got.Data["value"] != "new" {
		t.Fatalf("desired value not applied: %q", got.Data["value"])
	}
}

func TestCreateOrUpdateLeavesUnchangedResourceAlone(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	existing := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "config", Namespace: "default"}, Data: map[string]string{"value": "same"}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existing).Build()
	before := &corev1.ConfigMap{}
	_ = c.Get(ctx, client.ObjectKeyFromObject(existing), before)
	r := &KSensorReconciler{Client: c, Scheme: scheme}
	desired := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "config", Namespace: "default"}, Data: map[string]string{"value": "same"}}
	if err := r.CreateOrUpdateCRD(ctx, logr.Discard(), v1alpha1.KSensor{}, desired, schema.GroupVersionKind{Version: "v1", Kind: "ConfigMap"}); err != nil {
		t.Fatal(err)
	}
	after := &corev1.ConfigMap{}
	_ = c.Get(ctx, client.ObjectKeyFromObject(existing), after)
	if after.ResourceVersion != before.ResourceVersion {
		t.Fatal("unchanged resource was updated")
	}
}

func TestCreateOrUpdateDoesNotTakeOtherControllersResource(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	owner := true
	other := metav1.OwnerReference{APIVersion: "zeek.yas.ohbmo.com/v1alpha1", Kind: "KSensor", Name: "other", UID: "other", Controller: &owner}
	existing := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "config", Namespace: "default", OwnerReferences: []metav1.OwnerReference{other}}, Data: map[string]string{"value": "old"}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existing).Build()
	r := &KSensorReconciler{Client: c, Scheme: scheme}
	newOwner := other
	newOwner.Name = "another"
	newOwner.UID = "another"
	desired := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "config", Namespace: "default", OwnerReferences: []metav1.OwnerReference{newOwner}}, Data: map[string]string{"value": "new"}}
	if err := r.CreateOrUpdateCRD(ctx, logr.Discard(), v1alpha1.KSensor{}, desired, schema.GroupVersionKind{Version: "v1", Kind: "ConfigMap"}); err == nil {
		t.Fatal("resource takeover should be rejected")
	}
}
