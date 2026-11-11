# YAS Zeek Operator

A standalone Kubernetes controller extracted from YAS that reconciles a Zeek cluster topology. It watches a `KSensor` custom resource in `zeek.yas.ohbmo.com/v1alpha1` and creates manager, proxy, logger, and worker StatefulSets, Services and ConfigMaps. It does not install Suricata, packet capture, or an ingest controller.

This is an early operator; a disposable cluster test observed live Zeek processes and connection records, but production deployment is not established. Workload templates retain assumptions from the original prototype, including SSH/ZeekControl, Envoy, a Prometheus sidecar, image-specific commands, and capture transport. The Zeek cluster image must include `/zeek/bin/zeekctl`, an SSH client and server, `rsync`, `/tini`, and `/dumb-init-arm64`; the init image must provide `envsubst`. ZeekControl must be able to authenticate and verify SSH hosts on every node. The workloads require compatible images and cluster-specific configuration; `zeek/zeek` alone is not established to satisfy them. The Zeek manager and workers will not run until those dependencies are provided. Audit the rendered configuration for your environment before using real traffic.

## Install and configure

Requirements: Kubernetes access, Go 1.21+ for development, a container image builder, and compatible cluster/sidecar images. No published operator image is currently provided.

1. Build and load or push an operator image: `docker build -t <your-registry>/yas-zeek-operator:<tag> .`.
2. Replace `yas-zeek-operator:dev` in `config/operator.yaml` with the accessible image, then install `kubectl apply -k config`.
3. Edit `examples/zeek.yaml` to provide compatible engine and sidecar images and the capture/transport settings. The `example.invalid` images are placeholders. Apply it with `kubectl apply -f examples/zeek.yaml`.
4. Create a Kubernetes Secret named `nsm-zeek-cluster-ssh` in the sensor namespace with `prv` and `pub` keys containing a compatible cluster SSH keypair. The operator neither creates nor deletes this secret.

Configure `spec.Engine.NSM.WorkerReplicas` to set the worker count (1–999; omitted or zero defaults to one). The operator assigns ZeekControl identities and headless Services `worker-001`, `worker-002`, and so on, each selecting its matching StatefulSet pod. A topology change rolls the manager and workers, and scale-down removes only stale Services owned by that KSensor. ZeekControl generates `cluster-layout.zeek` from `node.cfg`; startup retries a failed `zeekctl deploy`. Capture transport and flow distribution must be provided by the installation: creating workers does not distribute traffic. A three-worker Zeek 9 cluster was observed running in a disposable test environment using an SSH-enabled adapter and stub sidecars; see [live verification](docs/live-verification.md). This does not establish production readiness or flow-aware distribution.

The `KSensor` and `spec.TenantNamespace` must share a namespace. Resource names are fixed, so use one sensor per namespace. Set `spec.Engine.NSM.Enabled` to `false` to remove only Zeek resources controlled by that sensor. The custom resource uses a distinct API group from the historical YAS KSensor API; existing objects are not automatically migrated.

Optional `spec.Engine.NSM.SiteConfig` appends Zeek policy to the generated `local.zeek`. `spec.Engine.NSM.Scripts` maps script names to inline Zeek source. The operator writes those scripts to an owned ConfigMap, mounts them read-only, and appends the corresponding `@load` directives. Script names use letters, digits, underscores or hyphens, without an extension. Changes to either policy or scripts roll the Zeek StatefulSets so the mounted policy is refreshed; removing a script removes its managed ConfigMap entry. These facilities adapt the earlier p6m Zeek operator's site configuration and inline-script handling.

```yaml
spec:
  Engine:
    NSM:
      SiteConfig: 'redef LogAscii::use_json = T;'
      Scripts:
        startup: |
          event zeek_init() { print "managed script loaded"; }
```

Provide complete Zeek source compatible with the chosen image and keep credentials out of these fields. Configuration reconciliation is tested against the Kubernetes API server; loading scripts in a live Zeek cluster has not been demonstrated.

`kubectl get ksensors.zeek.yas.ohbmo.com -A` lists configured sensors. Observe generated StatefulSets with `kubectl get statefulsets -n yas`. A generated StatefulSet is not proof that Zeek has started or processed traffic.

## Development

Run `go test ./...`, `go build -o bin/manager ./cmd`, and `kubectl kustomize config`. Most tests use Kubernetes fake clients. An additional test runs against an API server when `KUBEBUILDER_ASSETS` points to envtest binaries; it checks site-policy reconciliation, not packet processing or workload readiness. The repository uses new Git history and carries selected Zeek-specific YAS API and controller source, including their Apache-2.0 notices; no historical repository or old keys are included.

## License

Source files inherited from the earlier YAS operator carry Apache-2.0 boilerplate. See [LICENSE](LICENSE).
