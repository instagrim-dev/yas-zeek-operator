/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the Specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/instagrim-dev/yas-zeek-operator/internal/siteconfig"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"strings"
	//"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"context"

	//"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	//"k8s.io/apimachinery/pkg/runtime"
	//"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/instagrim-dev/yas-zeek-operator/api/v1alpha1"
)

var (
	minReadySeconds int32 = 1
	nsmConfigs            = map[string]string{
		"nsm-prometheus-server-config": `
global:
  scrape_interval: 5s
  evaluation_interval: 5s
  external_labels:
    cluster: prometheus-ha
    # Each Prometheus has to have unique labels.
    replica: $(POD_NAME)
rule_files:
  - /etc/prometheus/rules/*rules.yaml
scrape_configs:
  - job_name: "envoy"
    metrics_path: "/stats/prometheus"
    static_configs:
      - targets:
        - "127.0.0.1:15000"
  - job_name: "websocat"
    static_configs:
      - targets:
        - "127.0.0.1:9067"
  - job_name: "zeek"
    scrape_interval: 1s
    static_configs:
      - targets:
        - "127.0.0.1:9911"

`,
		"nsm-mesh-config": `
admin:
  #access_log_path: /tmp/admin_access.log
  address:
    socket_address:
      address: 127.0.0.1
      port_value: 15000

  #profile_path: /tmp/envoy.prof

cluster_manager: {}

static_resources:
  listeners:
  - name: evy_egress_lst
    address:
      socket_address:
        address: 0.0.0.0
        port_value: 15001
    traffic_direction: OUTBOUND
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: egress_lst
          codec_type: AUTO
          max_request_headers_kb: 8192
          use_remote_address: true
          route_config:
            name: transport
            virtual_hosts:
            - name: transport_service
              domains:
              - "*"
              routes:
              - match:
                  prefix: "/"
                route:
                  cluster: cls_pcap_bucket
          http_filters:
          - name: sigv4-signing
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.aws_request_signing.v3.AwsRequestSigning
              service_name: s3
              host_rewrite: s3.amazonaws.com
              #region: "us-west-2,us-east-1,us-east-2"
              region: "us-east-1"
              use_unsigned_payload: true
              # signing_algorithm: AWS_SIGV4A
              match_excluded_headers:
              - prefix: x-envoy
              #- prefix: x-forwarded
              #- exact: x-amzn-trace-id
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
          access_log:
          - name: envoy.access_loggers.stdout
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog
              log_format:
                json_format:
                  "@timestamp": "%START_TIME%"
                  client.address: "%DOWNSTREAM_REMOTE_ADDRESS%"
                  client.local.address: "%DOWNSTREAM_LOCAL_ADDRESS%"
                  response_flags_hdr: "%RESPONSE_FLAGS%"
                  envoy.route.name: "%ROUTE_NAME%"
                  envoy.upstream.cluster: "%UPSTREAM_CLUSTER%"
                  host.hostname: "%HOSTNAME%"
                  http.request.body.bytes: "%BYTES_RECEIVED%"
                  http.request.duration: "%DURATION%"
                  http.request.headers.accept: "%REQ(ACCEPT)%"
                  http.request.headers.authority: "%REQ(:AUTHORITY)%"
                  http.request.headers.id: "%REQ(X-REQUEST-ID)%"
                  #http.request.headers.x_forwarded_for: "%REQ(X-FORWARDED-FOR)%"
                  #http.request.headers.x_forwarded_proto: "%REQ(X-FORWARDED-PROTO)%"
                  #http.request.method: "%REQ(:METHOD)%"
                  #http.response.body.bytes: "%BYTES_SENT%"
                  #http.response.header.bytes: "%RESPONSE_HEADERS_BYTES%"
                  http.upstream.header.bytes: "%UPSTREAM_HEADER_BYTES_SENT%"
                  http.request.header.bytes: "%REQUEST_HEADERS_BYTES%"
  clusters:
  - name: cls_manager
    connect_timeout: 1.25s
    type: STRICT_DNS
    #type: STATIC
    dns_lookup_family: V4_ONLY
    lb_policy: ROUND_ROBIN
    load_assignment:
      cluster_name: cls_ingest
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: manager
                port_value: 5667
  - name: cls_pcap_bucket
    type: STRICT_DNS
    # connect_timeout: 5.250s
    connect_timeout: 0.250s
    #transport_socket:
      #name: envoy.transport_sockets.tls
      #typed_config:
        #"@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
    transport_socket:
      name: envoy.transport_sockets.tap
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.transport_sockets.tap.v3.Tap
        common_config:
          static_config:
            match_config:
              any_match: true
            output_config:
              max_buffered_tx_bytes: 1000000
              max_buffered_rx_bytes: 1000000
              sinks:
              - file_per_tap:
                  path_prefix: /transport/http.pcap
        transport_socket:
          name: envoy.transport_sockets.tls
          typed_config:
            '@type': type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
    load_assignment:
      cluster_name: s3
      endpoints:
        - lb_endpoints:
            - endpoint:
                address:
                  socket_address:
                    address: s3.amazonaws.com
                    port_value: 443

`,
		"nsm-standalone-node-cfg": `
[zeek]
type=standalone
host=localhost
interface=eth0

`,
		"nsm-cluster-node-cfg": `
[manager]
type=manager
host=manager.yas

[logger-001]
type=logger
host=logger-001.yas.svc.cluster.local

[proxy-001]
type=proxy
host=proxy-001.yas.svc.cluster.local

[worker-001]
type=worker
host=worker-001.yas.svc.cluster.local
interface=eth0
lb_method=interfaces
lb_interfaces=eth0
lbProcs=2

`,
		"nsm-zeekctl-cfg": `
BrokerDBDir = ${SPOOL}/brokerstore
CfgDir = /zeek/etc
CrashExpireInterval = 0
HaveNFS=0
LogDir = /zeek/logs
LogExpireInterval = 0
LogRotationInterval = 0
MailConnectionSummary = 0
MailHostUpDown = 0
MailTo = root@localhost
MinDiskSpace = 0
SitePolicyScripts = local.zeek
SpoolDir = /zeek/logs/spool
StatsLogEnable = 1
StatsLogExpireInterval = 0
StatusCmdShowAll = 0
TmpDir = /tmp
TmpExecDir = /tmp
ZeekPort = 27760

`,
		"nsm-networks-cfg": `
127.0.0.1/8
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
172.20.0.1/16       Docker address space
172.20.0.2/16       Container local eth0

`,
		"nsm-local-zeek": `
redef digest_salt = "Please change this value. OK.";
@load frameworks/files/detect-MHR
@load frameworks/files/hash-all-files
@load frameworks/software/version-changes
@load frameworks/software/vulnerable
@load frameworks/telemetry/log
@load misc/capture-loss
@load misc/loaded-scripts
@load misc/stats
#@load policy/frameworks/notice/extend-email/hostnames
@load protocols/conn/known-hosts
@load protocols/conn/known-services
@load protocols/dns/detect-external-names
@load protocols/ftp/detect
@load protocols/ftp/software
@load protocols/http/software
@load protocols/smtp/software
@load protocols/ssh/detect-bruteforcing
@load protocols/ssh/geo-data
@load protocols/ssh/interesting-hostnames
@load protocols/ssh/software
@load protocols/ssl/known-certs
@load protocols/ssl/log-hostcerts-only
@load protocols/ssl/validate-certs
@load-sigs frameworks/signatures/detect-windows-shells

`,
		"nsm-single-cluster-layout-zeek": `
redef Cluster::manager_is_logger=F;
redef Cluster::nodes = {
  ["manager"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1,, $p=27760/tcp],
  ["logger-001"] = [$node_type=Cluster::LOGGER, $ip=127.0.0.1, $p=27761/tcp, $manager="manager"],
  ["proxy-001"] = [$node_type=Cluster::PROXY, $ip=127.0.0.1, $p=27762/tcp, $manager="manager"],
  ["worker-001"] = [$node_type=Cluster::WORKER, $ip=127.0.0.1, $manager="manager"],
};

`,
		"nsm-multi-cluster-layout-zeek": `
redef Cluster::manager_is_logger=F;
redef Cluster::nodes = {
  ["manager"] = [
    $node_type=Cluster::MANAGER, $ip=manager.yas, $p=27760/tcp,
  ],
  ["logger-001"] = [$node_type=Cluster::LOGGER, $ip=logger-001.yas.svc.cluster.local, $p=27760/tcp, $manager="manager",

  ],
  ["proxy-001"] = [$node_type=Cluster::PROXY, $ip=proxy-001.yas.svc.cluster.local, $p=27760/tcp, $manager="manager"

  ],
  ["worker-001"] = [$node_type=Cluster::WORKER, $ip=worker-001.yas.svc.cluster.local, $manager="manager"

  ],
};

`,
	}
)

func ZeekCtrCmds(nodeType string) []string {
	cli := []string{}

	if nodeType == "manager" {
		cli = []string{
			"/dumb-init-arm64",
			"--",
		}
	} else {
		cli = []string{
			"/tini",
			"-w",
			"-v",
			"-s",
			"--",
		}
	}
	return cli
}

func ZeekCtrArgs(nodeType string) []string {
	cli := []string{}
	if nodeType == "manager" {
		cli = []string{
			"bash",
			"-c",
			"set -ux -o pipefail; /usr/sbin/sshd; until /zeek/bin/zeekctl deploy; do sleep 10; done; while true; do /zeek/bin/zeekctl status; sleep 30; done",
		}
	} else {
		cli = []string{
			"/usr/sbin/sshd",
			"-D",
		}
	}
	return cli
}

func siteConfig(sensor v1alpha1.KSensor) string {
	base := strings.ReplaceAll(nsmConfigs["nsm-local-zeek"], ".yas.svc.", "."+sensor.Spec.TenantNamespace+".svc.")
	base = siteconfig.AppendPolicy(base, sensor.Spec.Engine["NSM"].SiteConfig)
	_, names, _ := siteconfig.ScriptFiles(sensor.Spec.Engine["NSM"].Scripts)
	for _, name := range names {
		base += "\n@load ./managed/" + name + "\n"
	}
	return base
}

// workerCount defaults omitted values to one to preserve existing installations.
func workerCount(sensor v1alpha1.KSensor) int32 {
	n := sensor.Spec.Engine["NSM"].WorkerReplicas
	if n == 0 {
		return 1
	}
	return n
}

// workerTopology constructs unique ZeekCtl identities and per-pod DNS services.
func workerTopology(sensor v1alpha1.KSensor) string {
	namespace := sensor.Spec.TenantNamespace
	nodes := strings.ReplaceAll(nsmConfigs["nsm-cluster-node-cfg"], ".yas.svc.", "."+namespace+".svc.")
	nodes = strings.ReplaceAll(nodes, "host=manager.yas", "host=manager."+namespace)
	nodes = nodes[:strings.Index(nodes, "[worker-001]")]
	for i := int32(1); i <= workerCount(sensor); i++ {
		name := fmt.Sprintf("worker-%03d", i)
		host := fmt.Sprintf("%s.%s.svc.cluster.local", name, namespace)
		nodes += fmt.Sprintf("[%s]\ntype=worker\nhost=%s\ninterface=eth0\n\n", name, host)
	}
	return nodes
}

func siteConfigHash(sensor v1alpha1.KSensor) string {
	scripts, _ := json.Marshal(sensor.Spec.Engine["NSM"].Scripts)
	nodes := workerTopology(sensor)
	return fmt.Sprintf("%x", sha256.Sum256(append([]byte(siteConfig(sensor)+nodes+nsmConfigs["nsm-zeekctl-cfg"]), scripts...)))
}

func (r *KSensorReconciler) DefineCmNsm(ctx context.Context, logger logr.Logger, ksensorObj v1alpha1.KSensor, appComponentName string, appComponentConf string, appConfConfigKey string) (*corev1.ConfigMap, error) {
	// Sidecar CM
	nsmConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      appComponentName + "-" + appComponentConf, // grafana-datasource
			Namespace: ksensorObj.Spec.TenantNamespace,
		},
		Data: map[string]string{
			appConfConfigKey: strings.ReplaceAll(nsmConfigs[appComponentName+"-"+appComponentConf], ".yas.svc.", "."+ksensorObj.Spec.TenantNamespace+".svc."),
		},
	}
	if appComponentName == "nsm" && appComponentConf == "cluster-node-cfg" {
		nsmConfigMap.Data[appConfConfigKey] = workerTopology(ksensorObj)
	}
	if appComponentName == "nsm" && appComponentConf == "local-zeek" {
		nsmConfigMap.Data[appConfConfigKey] = siteConfig(ksensorObj)
	}
	ctrl.SetControllerReference(&ksensorObj, nsmConfigMap, r.Scheme)
	return nsmConfigMap, nil

}

func (r *KSensorReconciler) DefineSvcNsmCluster(ctx context.Context, logger logr.Logger, ksensorObj v1alpha1.KSensor, nodeType string, ordinal int32) (*corev1.Service, error) {
	nodeInstanceNum := fmt.Sprintf("%03d", ordinal+1)
	nameSuffix := string("")

	if nodeType != "manager" {
		nameSuffix = "-" + nodeInstanceNum
	}
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      nodeType + nameSuffix,
			Namespace: ksensorObj.Spec.TenantNamespace,
			Annotations: map[string]string{
				"prometheus.io/scrape": "true",
				"prometheus.io/port":   "9090",
			},
		},
		Spec: corev1.ServiceSpec{
			//Type: corev1.ServiceTypeLoadBalancer,
			ClusterIP: "None",
			Ports: []corev1.ServicePort{
				{
					Name:       "ssh",
					Port:       22,
					TargetPort: intstr.FromInt(22),
					Protocol:   "TCP",
				},
				{
					Name:       "broker",
					Port:       9999,
					TargetPort: intstr.FromInt(9999),
					Protocol:   "TCP",
				},
				{
					Name:       "zeekc1",
					Port:       27760,
					TargetPort: intstr.FromInt(27760),
					Protocol:   "TCP",
				},
				{
					Name:       "zeekc2",
					Port:       27761,
					TargetPort: intstr.FromInt(27761),
					Protocol:   "TCP",
				},
				{
					Name:       "zeekc3",
					Port:       27762,
					TargetPort: intstr.FromInt(27762),
					Protocol:   "TCP",
				},
				{
					Name:       "zeekc4",
					Port:       27763,
					TargetPort: intstr.FromInt(27763),
					Protocol:   "TCP",
				},
				{
					Name:       "agent1",
					Port:       2149,
					TargetPort: intstr.FromInt(2149),
					Protocol:   "TCP",
				},
				{
					Name:       "agent2",
					Port:       2150,
					TargetPort: intstr.FromInt(2150),
					Protocol:   "TCP",
				},
				{
					Name:       "agent3",
					Port:       2151,
					TargetPort: intstr.FromInt(2151),
					Protocol:   "TCP",
				},
			},
			Selector: map[string]string{
				"statefulset.kubernetes.io/pod-name": fmt.Sprintf("zeek-%s-%d", nodeType, ordinal),
			},
		},
	}
	ctrl.SetControllerReference(&ksensorObj, svc, r.Scheme)
	return svc, nil
}
func (r *KSensorReconciler) DefineSsNsmCluster(ctx context.Context, logger logr.Logger, ksensorObj v1alpha1.KSensor, nodeType string) (*appsv1.StatefulSet, error) {
	logger.Info("Rendering App...", "Namespace", ksensorObj.Spec.TenantNamespace, "Deployment", ksensorObj.Spec.TenantNamespace)
	hostNetwork := false
	if nodeType == "worker" {
		hostNetwork = false
	}

	ss := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "zeek-" + nodeType,
			Namespace: ksensorObj.Spec.TenantNamespace,
			Annotations: map[string]string{
				"lbProcs":         "0",
				"zeekCpuAffinity": "false",
				"zeekEnvVars":     "",
				"zeekHost":        "$(ZEEK_CLUSTER_NODE_NAME)." + ksensorObj.Spec.TenantNamespace + ".svc.cluster.local",
				"zeekInterface":   "",
				"zeekName":        "$(ZEEK_CLUSTER_NODE_NAME)",
				"zeekPinCpus":     "0",
			},
			Labels: labels(ksensorObj, nodeType),
		},
		Spec: appsv1.StatefulSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: labels(ksensorObj, nodeType),
			},
			Replicas:        ptrOf(minReplicas),
			MinReadySeconds: minReadySeconds,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      labels(ksensorObj, nodeType),
					Annotations: map[string]string{"zeek.yas.ohbmo.com/site-config-sha256": siteConfigHash(ksensorObj)},
				},
				Spec: corev1.PodSpec{
					Tolerations: []corev1.Toleration{
						{
							Operator: "Exists",
							Effect:   "NoSchedule",
						},
					},
					HostNetwork: hostNetwork,
					//HostAliases: ZeekHostAlias(nodeType),
					InitContainers: []corev1.Container{
						{
							Name:            "init-envsubst",
							Image:           "akubrinsky/envsubst:latest",
							ImagePullPolicy: "IfNotPresent",
							Env: []corev1.EnvVar{
								corev1.EnvVar{
									Name: "POD_IP",
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{
											FieldPath: "status.podIP",
										},
									},
								},
								corev1.EnvVar{
									Name: "POD_NS",
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{
											FieldPath: "metadata.namespace",
										},
									},
								},
								corev1.EnvVar{
									Name: "POD_NAME",
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{
											FieldPath: "metadata.name",
										},
									},
								},
								corev1.EnvVar{
									Name: "HOST_IP",
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{
											FieldPath: "status.hostIP",
										},
									},
								},
							},
							Command: []string{
								"sh",
								"-c",
								"echo $POD_IP $POD_NAME $POD_NS $HOST_IP && if [ \"$POD_NAME\" = zeek-manager-0 ]; then export MANAGER=$POD_IP && envsubst < /init/node.cfg > /shared/node.cfg && cat /shared/node.cfg && cp /init/zeekctl.cfg /init/networks.cfg /shared/. && ls -l /shared; fi && echo net.ipv6.conf.all.disable_ipv6=1 | tee -a /etc/sysctl.conf && echo net.ipv6.conf.default.disable_ipv6=1 | tee -a /etc/sysctl.conf && echo net.ipv6.conf.lo.disable_ipv6=1 | tee -a /etc/sysctl.conf",
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "node-cfg",
									MountPath: "/init/node.cfg",
									SubPath:   "node.cfg",
								},
								{
									Name:      "networks-cfg",
									MountPath: "/init/networks.cfg",
									SubPath:   "networks.cfg",
								},
								{
									Name:      "zeekctl-cfg",
									MountPath: "/init/zeekctl.cfg",
									SubPath:   "zeekctl.cfg",
								},
								{
									Name:      "shared",
									MountPath: "/shared",
								},
							},
						},
					},
					Containers: []corev1.Container{
						{
							Name:            "zeek",
							Image:           ksensorObj.Spec.Engine["NSM"].Image,
							ImagePullPolicy: "IfNotPresent",
							WorkingDir:      "/zeek/logs",
							//Hostname:        nodeType,
							//Subdomain: "zeek",
							Env: []corev1.EnvVar{
								corev1.EnvVar{
									Name:  "TRANSPORT",
									Value: ksensorObj.Spec.Transport.Downstream,
								},
								corev1.EnvVar{
									Name:  "ZEEK_DNS_FAKE",
									Value: "on",
								},
								corev1.EnvVar{
									Name:  "ZEEK_LOG_SUFFIX",
									Value: "log",
								},
								corev1.EnvVar{
									Name:  "ZEEK_PLUGIN_ACTIVATE",
									Value: "",
								},
								corev1.EnvVar{
									Name:  "ZEEK_PLUGIN_PATH",
									Value: "/zeek/share/zeek/builtin-plugins",
								},
								corev1.EnvVar{
									Name:  "ZEEKPATH",
									Value: "/zeek/share/zeek:/zeek/share/zeek/builtin-plugins",
								},
								corev1.EnvVar{
									Name:  "ZEEK_PREFIXES",
									Value: "",
								},
								corev1.EnvVar{
									Name:  "ZEEK_SEED_FILE",
									Value: "",
								},
								corev1.EnvVar{
									Name:  "ZEEK_SEED_VALUES",
									Value: "",
								},
								corev1.EnvVar{
									Name:  "ENABLE_ZEEK_UNIT_TESTS",
									Value: "",
								},
								corev1.EnvVar{
									Name:  "ZEEK_DEBUG_LOG_STDERR",
									Value: "1",
								},
								corev1.EnvVar{
									Name:  "ZEEK_DISABLE_ZEEKYGEN",
									Value: "1",
								},
								corev1.EnvVar{
									Name:  "ZEEK_DEFAULT_LISTEN_ADDRESS",
									Value: "",
								},
								corev1.EnvVar{
									Name:  "TERM",
									Value: "xterm-256color",
								},
								corev1.EnvVar{
									Name: "POD_IP",
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{
											FieldPath: "status.podIP",
										},
									},
								},
							},
							Args:    ZeekCtrArgs(nodeType),
							Command: ZeekCtrCmds(nodeType),
							Ports: []corev1.ContainerPort{
								{
									Name:          "metrics",
									ContainerPort: 9911,
								},
								{
									Name:          "broker",
									ContainerPort: 9999,
								},
								{
									Name:          "zeekc1",
									ContainerPort: 27760,
								},
								{
									Name:          "zeekc2",
									ContainerPort: 27761,
								},
								{
									Name:          "zeekc3",
									ContainerPort: 27762,
								},
								{
									Name:          "zeekc4",
									ContainerPort: 27763,
								},
								{
									Name:          "agent1",
									ContainerPort: 2149,
								},
								{
									Name:          "agent2",
									ContainerPort: 2150,
								},
								{
									Name:          "agent3",
									ContainerPort: 2151,
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "local-zeek",
									MountPath: "/zeek/share/zeek/site/local.zeek",
									SubPath:   "local.zeek",
								},
								{
									Name:      "custom",
									MountPath: "/zeek/share/zeek/site/custom",
								},
								{
									Name:      "extracted-files",
									MountPath: "/zeek/extracted_files",
								},
								{
									Name:      "spool",
									MountPath: "/zeek/logs/spool",
								},
								{
									Name:      "intel",
									MountPath: "/zeek/intel",
								},
								{
									Name:      "logs",
									MountPath: "/zeek/logs",
								},
								{
									Name:      "cluster-ssh",
									MountPath: "/zeek/.ssh/",
								},
								{
									Name:      "shared",
									MountPath: "/zeek/etc",
								},
							},
							// LivenessProbe: &corev1.Probe{
							// 	ProbeHandler: corev1.ProbeHandler{
							// 		TCPSocket: &corev1.TCPSocketAction{
							// 			Port: intstr.FromInt(9911),
							// 		},
							// 	},
							// 	InitialDelaySeconds: 3,
							// 	PeriodSeconds:       5,
							// },
							Resources: corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									"cpu":    resource.MustParse(ksensorObj.Spec.Engine["NSM"].CpuLimit),
									"memory": resource.MustParse(ksensorObj.Spec.Engine["NSM"].MemoryLimit),
								},
								// Requests: corev1.ResourceList{
								//  "cpu":    resource.MustParse(cpuReq),
								//  "memory": resource.MustParse(memReq),
								// },
							},
							SecurityContext: &corev1.SecurityContext{
								//RunAsNonRoot:  &[]bool{true}[0],
								//RunAsUser: &[]int64{1000}[0],
								Capabilities: &corev1.Capabilities{
									Add: []corev1.Capability{
										"NET_ADMIN",
										"NET_RAW",
										"SYS_NICE",
										"CAP_SYS_ADMIN",
									},
								},
							},
						},
						// {
						//  Name:            "transport",
						//  Image:           ksensorObj.Spec.Transport.Image,
						//  ImagePullPolicy: "IfNotPresent",
						//  Env: []corev1.EnvVar{
						//    corev1.EnvVar{
						//      Name:  "TRANSPORT",
						//      Value: ksensorObj.Spec.Transport.Downstream,
						//    },
						//  },
						//  Args: []string{
						//    "/websocat",
						//    "--prometheus=127.0.0.1:9067",
						//    "--binary",
						//    "-vv",
						//    "ws://ingest.yas.svc.cluster.local:5667/",
						//    "reuse:appendfile:$(TRANSPORT)",
						//  },
						//  Command: []string{
						//    "/tini",
						//    "-w",
						//    "-v",
						//    "-s",
						//    "--",
						//  },
						//  Ports: []corev1.ContainerPort{
						//    {
						//      Name:          "ws",
						//      ContainerPort: 5667,
						//    },
						//    {
						//      Name:          "metrics",
						//      ContainerPort: 9067,
						//    },
						//  },
						//  VolumeMounts: []corev1.VolumeMount{
						//    {
						//      Name:      "transport",
						//      MountPath: "/transport/",
						//    },
						//  },
						//  Resources: corev1.ResourceRequirements{
						//    Limits: corev1.ResourceList{
						//      "cpu":    resource.MustParse(ksensorObj.Spec.Transport.CpuLimit),
						//      "memory": resource.MustParse(ksensorObj.Spec.Transport.MemoryLimit),
						//    },
						//  },
						// },
						{
							Name:            "mesh",
							Image:           ksensorObj.Spec.Network.Mesh.Image,
							ImagePullPolicy: "IfNotPresent",
							Args: []string{
								"/app/envoy",
								"-c",
								"/etc/envoy/envoy.yml",
							},
							Command: []string{
								"/tini",
								"-w",
								"-v",
								"-s",
								"--",
							},
							Ports: []corev1.ContainerPort{
								{
									Name:          "admin",
									ContainerPort: 15000,
								},
								{
									Name:          "egress",
									ContainerPort: 15001,
								},
								{
									Name:          "ingress",
									ContainerPort: 15003,
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "envoy-config",
									MountPath: "/etc/envoy",
								},
								{
									Name:      "transport",
									MountPath: "/transport/",
								},
							},
							Resources: corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									"cpu":    resource.MustParse(ksensorObj.Spec.Network.Mesh.CpuLimit),
									"memory": resource.MustParse(ksensorObj.Spec.Network.Mesh.MemoryLimit),
								},
							},
						},
						{
							Name:            "prometheus",
							Image:           ksensorObj.Spec.Monitoring.Metrics.Image,
							ImagePullPolicy: "IfNotPresent",
							Args: []string{
								"--config.file=/etc/prometheus/prometheus.yaml",
								"--storage.tsdb.path=/prometheus/",
								"--web.enable-lifecycle",
								"--storage.tsdb.no-lockfile",
								"--storage.tsdb.min-block-duration=2h",
								"--storage.tsdb.max-block-duration=2h",
							},
							Ports: []corev1.ContainerPort{
								{
									Name:          "prometheus",
									ContainerPort: 9090,
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "prometheus-storage",
									MountPath: "/prometheus/",
								},
								{
									Name:      "prometheus-server-config",
									MountPath: "/etc/prometheus/",
								},
								{
									Name:      "prometheus-rules",
									MountPath: "/etc/prometheus/rules",
								},
							},
							Resources: corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									"cpu":    resource.MustParse(ksensorObj.Spec.Monitoring.Metrics.CpuLimit),
									"memory": resource.MustParse(ksensorObj.Spec.Monitoring.Metrics.MemoryLimit),
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "envoy-config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "nsm-mesh-config",
									},
									Items: []corev1.KeyToPath{
										{
											Key:  "envoy.yml",
											Path: "envoy.yml",
										},
									},
								},
							},
						},
						{
							Name: "prometheus-server-config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "nsm-prometheus-server-config",
									},
									Items: []corev1.KeyToPath{
										{
											Key:  "prometheus.yaml.tmpl",
											Path: "prometheus.yaml",
										},
									},
								},
							},
						},
						{
							Name: "zeekctl-cfg",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "nsm-zeekctl-cfg",
									},
									Items: []corev1.KeyToPath{
										{
											Key:  "zeekctl.cfg",
											Path: "zeekctl.cfg",
										},
									},
								},
							},
						},
						{
							Name: "node-cfg",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "nsm-cluster-node-cfg",
									},
									Items: []corev1.KeyToPath{
										{
											Key:  "node.cfg",
											Path: "node.cfg",
										},
									},
								},
							},
						},
						{
							Name: "networks-cfg",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "nsm-networks-cfg",
									},
									Items: []corev1.KeyToPath{
										{
											Key:  "networks.cfg",
											Path: "networks.cfg",
										},
									},
								},
							},
						},
						{
							Name: "local-zeek",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "nsm-local-zeek",
									},
									Items: []corev1.KeyToPath{
										{
											Key:  "local.zeek",
											Path: "local.zeek",
										},
									},
								},
							},
						},
						{
							Name: "cluster-ssh",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: "nsm-zeek-cluster-ssh",
									Items: []corev1.KeyToPath{
										{
											Key:  "prv",
											Path: "cluster",
										},
										{
											Key:  "pub",
											Path: "cluster.pub",
										},
									},
								},
							},
						},
						{
							Name: "transport",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{
									Medium: "Memory",
								},
							},
						},
						{
							Name: "shared",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{
									Medium: "Memory",
								},
							},
						},
						{
							Name: "intel",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{
									Medium: "Memory",
								},
							},
						},
						{
							Name: "logs",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{
									Medium: "Memory",
								},
							},
						},
						{
							Name: "spool",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{
									Medium: "Memory",
								},
							},
						},
						{
							Name: "custom",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{
									Medium: "Memory",
								},
							},
						},
						{
							Name: "extracted-files",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{
									Medium: "Memory",
								},
							},
						},
						{
							Name: "prometheus-storage",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{
									Medium: "Memory",
								},
							},
						},
						{
							Name: "prometheus-rules",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{
									Medium: "Memory",
								},
							},
						},
					},
				},
			},
		},
	}
	if len(ksensorObj.Spec.Engine["NSM"].Scripts) > 0 {
		ss.Spec.Template.Spec.Volumes = append(ss.Spec.Template.Spec.Volumes, corev1.Volume{Name: "site-scripts", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "nsm-site-scripts"}}}})
		ss.Spec.Template.Spec.Containers[0].VolumeMounts = append(ss.Spec.Template.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "site-scripts", MountPath: "/zeek/share/zeek/site/managed", ReadOnly: true})
	}
	if nodeType == "worker" {
		ss.Spec.Replicas = ptrOf(workerCount(ksensorObj))
	}
	ctrl.SetControllerReference(&ksensorObj, ss, r.Scheme)
	return ss, nil
}
func (r *KSensorReconciler) CreateComponentAppNsmCluster(ctx context.Context, logger logr.Logger, ksensorObj v1alpha1.KSensor) error {

	if err := r.reconcileSiteScripts(ctx, logger, ksensorObj); err != nil {
		return err
	}

	metricsCM, err := r.DefineCmSidecar(ctx, logger, ksensorObj, "nsm", "prometheus-server-config", nsmConfigs["nsm-prometheus-server-config"], "prometheus.yaml.tmpl")
	if err != nil {
		logger.Error(err, "prom CM failed")
		return err
	}

	meshCM, err := r.DefineCmSidecar(ctx, logger, ksensorObj, "nsm", "mesh-config", nsmConfigs["nsm-mesh-config"], "envoy.yml")
	if err != nil {
		logger.Error(err, "evy CM failed")
		return err
	}

	zeekNodeConfCm, err := r.DefineCmNsm(ctx, logger, ksensorObj, "nsm", "cluster-node-cfg", "node.cfg")
	if err != nil {
		logger.Error(err, "zeek zeekNodeConfCm failed")
		return err
	}
	zeekCtlConfCm, err := r.DefineCmNsm(ctx, logger, ksensorObj, "nsm", "zeekctl-cfg", "zeekctl.cfg")
	if err != nil {
		logger.Error(err, "zeek zeekCtlConfCm failed")
		return err
	}
	zeekNetworksConfCm, err := r.DefineCmNsm(ctx, logger, ksensorObj, "nsm", "networks-cfg", "networks.cfg")
	if err != nil {
		logger.Error(err, "zeek zeekNetworksConfCm failed")
		return err
	}
	zeekLocalConfCm, err := r.DefineCmNsm(ctx, logger, ksensorObj, "nsm", "local-zeek", "local.zeek")
	if err != nil {
		logger.Error(err, "zeek zeekLocalConfCm failed")
		return err
	}
	// The deployment references the pre-provisioned nsm-zeek-cluster-ssh Secret.

	// ConfigMaps
	if err = r.CreateOrUpdateCRD(ctx, logger, ksensorObj, metricsCM, schema.GroupVersionKind{
		Kind:    "ConfigMap",
		Version: "v1",
	}); err != nil {
		logger.Error(err, "Failed metrics CM")
		return err
	}
	if err = r.CreateOrUpdateCRD(ctx, logger, ksensorObj, meshCM, schema.GroupVersionKind{
		Kind:    "ConfigMap",
		Version: "v1",
	}); err != nil {
		logger.Error(err, "Failed mesh CM")
		return err
	}

	if err = r.CreateOrUpdateCRD(ctx, logger, ksensorObj, zeekNodeConfCm, schema.GroupVersionKind{
		Kind:    "ConfigMap",
		Version: "v1",
	}); err != nil {
		logger.Error(err, "Failed node-cfg CM")
		return err
	}
	if err = r.CreateOrUpdateCRD(ctx, logger, ksensorObj, zeekCtlConfCm, schema.GroupVersionKind{
		Kind:    "ConfigMap",
		Version: "v1",
	}); err != nil {
		logger.Error(err, "Failed zeekctl-cfg CM")
		return err
	}
	if err = r.CreateOrUpdateCRD(ctx, logger, ksensorObj, zeekNetworksConfCm, schema.GroupVersionKind{
		Kind:    "ConfigMap",
		Version: "v1",
	}); err != nil {
		logger.Error(err, "Failed networks-cfg CM")
		return err
	}
	if err = r.CreateOrUpdateCRD(ctx, logger, ksensorObj, zeekLocalConfCm, schema.GroupVersionKind{
		Kind:    "ConfigMap",
		Version: "v1",
	}); err != nil {
		logger.Error(err, "Failed local-zeek CM")
		return err
	}

	// if err = r.CreateOrUpdateCRD(ctx, logger, ksensorObj, zeekApp, schema.GroupVersionKind{
	//  Kind:    "Deployment",
	//  Group:   "apps",
	//  Version: "v1",
	// }); err != nil {
	//  logger.Error(err, "Failed App Deploy")
	//  return err
	// }

	for _, nodeType := range []string{"manager", "proxy", "logger", "worker"} {
		nodeSs, err := r.DefineSsNsmCluster(ctx, logger, ksensorObj, nodeType)
		if err != nil {
			return err
		}
		if err = r.CreateOrUpdateCRD(ctx, logger, ksensorObj, nodeSs, schema.GroupVersionKind{Kind: "StatefulSet", Group: "apps", Version: "v1"}); err != nil {
			return err
		}
		count := int32(1)
		if nodeType == "worker" {
			count = workerCount(ksensorObj)
		}
		for i := int32(0); i < count; i++ {
			svc, err := r.DefineSvcNsmCluster(ctx, logger, ksensorObj, nodeType, i)
			if err != nil {
				return err
			}
			if err = r.CreateOrUpdateCRD(ctx, logger, ksensorObj, svc, schema.GroupVersionKind{Kind: "Service", Version: "v1"}); err != nil {
				return err
			}
		}
	}
	if err := r.deleteWorkerServices(ctx, &ksensorObj, workerCount(ksensorObj)); err != nil {
		return err
	}
	return nil
}
