/*
Copyright 2024.

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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// KSensorSpec defines the desired state of KSensor
type KSensorSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	Replicas        *int32               `json:"Replicas,omitempty"`
	TenantNamespace string               `json:"TenantNamespace"`
	Mode            string               `json:"Mode"`
	Ingest          IngestConfig         `json:"Ingest"`
	Transport       TransportConfig      `json:"Transport,optional"`
	Engine          map[string]EngineApp `json:"Engine,optional"`
	Network         NetworkConfig        `json:"Network"`
	Monitoring      MonitoringConfig     `json:"Monitoring"`
}

type IngestConfig struct {
	PacketCapture string `json:"PacketCapture"`
	Enabled       bool   `json:"Enabled,optional,omitempty"`
	Image         string `json:"Image"`
	CpuLimit      string `json:"CpuLimit"`
	MemoryLimit   string `json:"MemoryLimit"`
}

type TransportConfig struct {
	Upstream    string `json:"Upstream"`
	Downstream  string `json:"Downstream"`
	Type        string `json:"Type"`
	Image       string `json:"Image"`
	CpuLimit    string `json:"CpuLimit"`
	MemoryLimit string `json:"MemoryLimit"`
}

type MeshConfig struct {
	Name        string `json:"Name,optional,omitempty"`
	Image       string `json:"Image"`
	Enabled     bool   `json:"Enabled,optional,omitempty"`
	CpuLimit    string `json:"CpuLimit"`
	MemoryLimit string `json:"MemoryLimit"`
}

type EngineApp struct {
	Name          string            `json:"Name,optional,omitempty"`
	Image         string            `json:"Image"`
	Enabled       bool              `json:"Enabled,optional"`
	Mode          string            `json:"Mode,optional,omitempty"`
	CpuLimit      string            `json:"CpuLimit"`
	MemoryLimit   string            `json:"MemoryLimit"`
	Observability map[string]string `json:"Observability,optional,omitempty"`
}

type MetricsConfig struct {
	Name        string `json:"Name,optional,omitempty"`
	Image       string `json:"Image"`
	Enabled     bool   `json:"Enabled,optional,omitempty"`
	CpuLimit    string `json:"CpuLimit"`
	MemoryLimit string `json:"MemoryLimit"`
	Replicas    int32  `json:"Replicas"`
}

type NetworkConfig struct {
	Mesh MeshConfig `json:"Mesh"`
}

type MonitoringGrafanaAuthBasic struct {
	Enabled bool `json:"Enabled"`
}
type MonitoringGrafanaAuthAnonymous struct {
	Enabled bool   `json:"Enabled"`
	OrgRole string `json:"OrgRole,optional,omitempty"`
}
type MonitoringGrafanaAuth struct {
	Basic     MonitoringGrafanaAuthBasic     `json:"Basic"`
	Anonymous MonitoringGrafanaAuthAnonymous `json:"Anonymous,optional,omitempty"`
}

type MonitoringGrafanaServer struct {
	RootUrl  string `json:"RootUrl,optional,omitempty"`
	HttpPort int32  `json:"HttpPort,optional,omitempty"`
}

type MonitoringGrafana struct {
	Image    string                  `json:"Image"`
	Auth     MonitoringGrafanaAuth   `json:"Auth,optional,omitempty"`
	Server   MonitoringGrafanaServer `json:"Server,optional,omitempty"`
	Replicas int32                   `json:"Replicas"`
}
type MonitoringConfig struct {
	TenantNamespace string            `json:"TenantNamespace"`
	Metrics         MetricsConfig     `json:"Metrics"`
	Logs            EngineApp         `json:"Logs,optional,omitempty"`
	Grafana         MonitoringGrafana `json:"Grafana,optional,omitempty"`
	Thanos          map[string]string `json:"Thanos"`
}

// KSensorStatus defines the observed state of KSensor
type KSensorStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	Replicas int32  `json:"Replicas,omitempty"`
	Selector string `json:"Selector,omitempty"`
	// +optional
	Conditions []metav1.Condition `json:"Conditions,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:subresource:scale:specpath=.spec.replicas,statuspath=.status.replicas,selectorpath=.status.selector

// KSensor is the Schema for the ksensors API
type KSensor struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KSensorSpec   `json:"spec,omitempty"`
	Status KSensorStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// KSensorList contains a list of KSensor
type KSensorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KSensor `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KSensor{}, &KSensorList{})
}
