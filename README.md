# YAS Zeek Operator

A standalone Kubernetes controller extracted from YAS that reconciles a Zeek cluster topology. It watches a `KSensor` custom resource in `zeek.yas.ohbmo.com/v1alpha1` and creates manager, proxy, logger, and worker StatefulSets, Services and ConfigMaps. It does not install Suricata, packet capture, or an ingest controller.

This is an early operator: the controller and API behavior have fake-client tests, but no live packet-processing or production deployment is claimed. Workload templates retain assumptions from the original prototype, including SSH/ZeekControl, Envoy, a Prometheus sidecar, image-specific commands, and capture transport. They require compatible images and cluster-specific configuration; `zeek/zeek` alone is not established to satisfy them. The Zeek manager and workers will not run until those dependencies are provided. Audit the rendered configuration for your environment before using real traffic.

## Install and configure

Requirements: Kubernetes access, Go 1.21+ for development, a container image builder, and compatible cluster/sidecar images. No published operator image is currently provided.

1. Build and load or push an operator image: `docker build -t <your-registry>/yas-zeek-operator:<tag> .`.
2. Replace `yas-zeek-operator:dev` in `config/operator.yaml` with the accessible image, then install `kubectl apply -k config`.
3. Edit `examples/zeek.yaml` to provide compatible engine and sidecar images and the capture/transport settings. The `example.invalid` images are placeholders. Apply it with `kubectl apply -f examples/zeek.yaml`.
4. Create a Kubernetes Secret named `nsm-zeek-cluster-ssh` in the sensor namespace with `prv` and `pub` keys containing a compatible cluster SSH keypair. The operator neither creates nor deletes this secret.

The `KSensor` and `spec.TenantNamespace` must share a namespace. Resource names are fixed, so use one sensor per namespace. Set `spec.Engine.NSM.Enabled` to `false` to remove only Zeek resources controlled by that sensor. The custom resource uses a distinct API group from the historical YAS KSensor API; existing objects are not automatically migrated.

`kubectl get ksensors.zeek.yas.ohbmo.com -A` lists configured sensors. Observe generated StatefulSets with `kubectl get statefulsets -n yas`. A generated StatefulSet is not proof that Zeek has started or processed traffic.

## Development

Run `go test ./...`, `go build -o bin/manager ./cmd`, and `kubectl kustomize config`. Tests exercise reconciler behavior using Kubernetes fake clients; they do not start a cluster or check network data. The repository uses new Git history and carries selected Zeek-specific YAS API and controller source, including their Apache-2.0 notices; no historical repository or old keys are included.

## License

Source files inherited from the earlier YAS operator carry Apache-2.0 boilerplate. See [LICENSE](LICENSE).
