.PHONY: test build release-snapshot release clean create-test-certificates

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X github.com/marco-introini/certinfo/cmd.version=$(VERSION) -X github.com/marco-introini/certinfo/cmd.commit=$(COMMIT) -X github.com/marco-introini/certinfo/cmd.date=$(DATE)

test:
	go test -parallel=4 ./cmd/... ./pkg/... -v

test-cover:
	go test ./... -cover

build:
	go build -ldflags "$(LDFLAGS)" -o certinfo .

release-snapshot:
	goreleaser release --snapshot --skip=publish

release:
	./scripts/release.sh

create-test-certificates:
	rm -fr ./test_certs/*
	./generate_certs.sh
	./generate_pqc_certs.sh
	
clean:
	rm -rf dist/
	rm certinfo