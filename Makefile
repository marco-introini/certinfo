.PHONY: test build install release-snapshot release

test:
	go test -parallel=4 ./cmd/... ./pkg/... -v

test-cover:
	go test ./... -cover

build:
	go build -o certinfo ./main.go

release-snapshot:
	goreleaser release --snapshot --skip=publish

release:
	goreleaser release
