package controller

import (
	"context"

	"github.com/go-logr/logr"
	v1alpha1 "github.com/instagrim-dev/yas-zeek-operator/api/v1alpha1"
	"github.com/instagrim-dev/yas-zeek-operator/internal/siteconfig"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (r *KSensorReconciler) reconcileSiteScripts(ctx context.Context, logger logr.Logger, sensor v1alpha1.KSensor) error {
	data, _, err := siteconfig.ScriptFiles(sensor.Spec.Engine["NSM"].Scripts)
	if err != nil {
		return err
	}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "nsm-site-scripts", Namespace: sensor.Namespace}, Data: data}
	if len(data) > 0 {
		if err := ctrl.SetControllerReference(&sensor, cm, r.Scheme); err != nil {
			return err
		}
		return r.CreateOrUpdateCRD(ctx, logger, sensor, cm, schema.GroupVersionKind{Version: "v1", Kind: "ConfigMap"})
	}
	if err := r.Get(ctx, client.ObjectKeyFromObject(cm), cm); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}
	if !metav1.IsControlledBy(cm, &sensor) {
		return nil
	}
	uid, version := cm.UID, cm.ResourceVersion
	if err := r.Delete(ctx, cm, client.Preconditions{UID: &uid, ResourceVersion: &version}); err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	return nil
}
