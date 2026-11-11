package controller

import (
	"context"
	"fmt"
	"github.com/go-logr/logr"
	v1alpha1 "github.com/instagrim-dev/yas-zeek-operator/api/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"reflect"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type KSensorReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

func ptrOf[T any](value T) *T {
	return &value
}

func labels(o v1alpha1.KSensor, component string) map[string]string {
	instance := component
	if o.Spec.Ingest.PacketCapture != "" {
		instance += "-" + o.Spec.Ingest.PacketCapture
	}
	return map[string]string{
		"app.kubernetes.io/name":      o.Name,
		"app.kubernetes.io/component": component,
		"app.kubernetes.io/instance":  instance,
		"app.kubernetes.io/part-of":   "ksensor",
	}
}

func GetUnstructuredObj(resObj runtime.Object) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.Object, _ = runtime.DefaultUnstructuredConverter.ToUnstructured(resObj)
	//u := unstructured.Unstructured{Object: innerObj}
	return u
}

func (r *KSensorReconciler) CreateOrUpdateCRD(ctx context.Context, logger logr.Logger, ksensorObj v1alpha1.KSensor, rObj runtime.Object, s schema.GroupVersionKind) error {
	uResObj := GetUnstructuredObj(rObj.DeepCopyObject())
	uResObj.SetGroupVersionKind(s)
	existing := &unstructured.Unstructured{}
	existing.SetGroupVersionKind(s)
	if err := r.Get(ctx, client.ObjectKeyFromObject(uResObj), existing); err != nil {
		if errors.IsNotFound(err) {
			return r.Create(ctx, uResObj)
		}
		return err
	}
	if owner := metav1.GetControllerOf(uResObj); owner != nil {
		if current := metav1.GetControllerOf(existing); current == nil || current.UID != owner.UID {
			return fmt.Errorf("refusing to take over %s %s/%s: it is not controlled by this KSensor", s.Kind, existing.GetNamespace(), existing.GetName())
		}
	}
	// Retain server-assigned fields while applying the newly rendered desired object.
	uResObj.SetResourceVersion(existing.GetResourceVersion())
	if s.Kind == "Service" {
		for _, field := range []string{"clusterIP", "clusterIPs", "ipFamilies", "ipFamilyPolicy", "healthCheckNodePort"} {
			if _, found, _ := unstructured.NestedFieldNoCopy(uResObj.Object, "spec", field); !found {
				if value, present, _ := unstructured.NestedFieldCopy(existing.Object, "spec", field); present {
					_ = unstructured.SetNestedField(uResObj.Object, value, "spec", field)
				}
			}
		}
	}
	if desiredObjectMatches(uResObj.Object, existing.Object) {
		return nil
	}
	return r.Update(ctx, uResObj)
}

// desiredObjectMatches ignores server-added defaults but compares explicitly rendered fields.
func desiredObjectMatches(desired, existing map[string]interface{}) bool {
	for k, v := range desired {
		if k == "status" {
			continue
		}
		current, ok := existing[k]
		if !ok {
			return false
		}
		if k == "data" || k == "binaryData" {
			if !reflect.DeepEqual(v, current) {
				return false
			}
			continue
		}
		if !desiredValueMatches(v, current) {
			return false
		}
	}
	return true
}
func desiredValueMatches(desired, existing interface{}) bool {
	switch d := desired.(type) {
	case map[string]interface{}:
		e, ok := existing.(map[string]interface{})
		if !ok {
			return false
		}
		for k, v := range d {
			if k == "resourceVersion" {
				continue
			}
			got, ok := e[k]
			if !ok || !desiredValueMatches(v, got) {
				return false
			}
		}
		return true
	case []interface{}:
		e, ok := existing.([]interface{})
		if !ok || len(d) != len(e) {
			return false
		}
		for i := range d {
			if !desiredValueMatches(d[i], e[i]) {
				return false
			}
		}
		return true
	default:
		return reflect.DeepEqual(desired, existing)
	}
}

var minReplicas int32 = 1
