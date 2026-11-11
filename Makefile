.PHONY: test build manifests

test:
	go test ./...
build:
	go build -o bin/manager ./cmd
manifests:
	kubectl kustomize config
