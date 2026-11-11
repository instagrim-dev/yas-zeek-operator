# Contributing

Please open an issue describing the intended behavior before a substantial change. For a pull request, explain the change and its verification, run `go test ./...` and `go build -o /tmp/yas-zeek-manager ./cmd`, and check that `kubectl kustomize config` renders. Do not commit packet captures, credentials, cluster keys, proprietary images, or internal configuration. Include tests for controller behavior, and distinguish fake-client checks from tests using a Kubernetes cluster and actual traffic.
