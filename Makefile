.PHONY: test build release-snapshot release clean create-test-certificates

test:
	go test -parallel=4 ./cmd/... ./pkg/... -v

test-cover:
	go test ./... -cover

build:
	go build -o certinfo ./main.go

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