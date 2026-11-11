package controller

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/go-logr/logr"

	"context"

	v1alpha1 "github.com/instagrim-dev/yas-zeek-operator/api/v1alpha1"
	ctrl "sigs.k8s.io/controller-runtime"
)

func (r *KSensorReconciler) DefineCmSidecar(ctx context.Context, logger logr.Logger, ksensorObj v1alpha1.KSensor, componentName string, sidecarType string, sidecarConfData string, sidecarConfConfigKey string) (*corev1.ConfigMap, error) {
	// Sidecar CM
	sidecarConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      componentName + "-" + sidecarType,
			Namespace: ksensorObj.Spec.TenantNamespace,
		},
		Data: map[string]string{
			sidecarConfConfigKey: sidecarConfData,
		},
	}
	ctrl.SetControllerReference(&ksensorObj, sidecarConfigMap, r.Scheme)
	return sidecarConfigMap, nil
}
