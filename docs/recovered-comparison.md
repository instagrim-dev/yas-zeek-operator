# Historical operator comparison

The recovered p6m Zeek operator at `fc517c9869e937962693d9639b73228fac8f15c8` includes a `ZeekCluster` API with configurable topology, site configuration, scripts, plugins, observability and backup. Its tests and runtime behavior have not been reproduced here. It uses separate p6m platform libraries and a different Kubernetes API from this project.

This project retains its existing `KSensor` API and fixed manager, worker, logger and proxy topology. Its `SiteConfig` facility adapts the earlier generator's user-provided site configuration behavior; the adaptation preserves the historical file's Apache-2.0 attribution. It appends policy to `local.zeek`, reconciles the ConfigMap and rolls the workload templates on changes. It also adapts the historical inline-script ConfigMap pattern: scripts are validated, mounted read-only, loaded from the site policy and trigger a rollout when changed. It does not implement external script sources, plugins, backup, or the historical API.

Historical worker scaling cannot be safely transplanted by raising the current StatefulSet replica count: the current configuration identifies only `worker-001` and the Service selects one pod. A scalable cluster needs a verified per-worker identity, DNS, configuration and packet-distribution design. No multi-worker readiness or traffic claims are made here.
