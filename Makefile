.PHONY: test build install

test:
	go test -parallel=4 ./cmd/... ./pkg/... -v

test-cover:
	go test ./... -cover

build:
	go build -o certinfo ./main.go

install:
	go install ./main.go
