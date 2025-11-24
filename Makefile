build:
	CGO_ENABLED=0 go build -o ./bin/signer ./cmd/signer

run: build
	./bin/signer --unix-domain-socket ./k8s-external-signer.sock

IMAGE_NAME ?= k8s-external-signer
IMAGE_TAG ?= $(shell git rev-parse --short HEAD)
IMAGE_REGISTRY ?= ghcr.io/zarvd
IMAGE ?= $(IMAGE_REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)
image:
	docker build \
		--platform linux/amd64 \
		--tag $(IMAGE) \
		--file docker/release.Dockerfile .
