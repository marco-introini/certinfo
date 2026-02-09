.PHONY: test build release-snapshot release clean

test:
	go test -parallel=4 ./cmd/... ./pkg/... -v

test-cover:
	go test ./... -cover

build:
	go build -o certinfo ./main.go

release-snapshot:
	goreleaser release --snapshot --skip=publish

clean:
	rm -rf dist/
	rm certinfo