.PHONY: all build test clean fmt lint

all: build

build:
	go build -o auto-approve ./cmd/auto-approve

test:
	go test -v ./...

clean:
	rm -f auto-approve
	go clean

fmt:
	go fmt ./...

lint:
	go vet ./...
	golangci-lint run

install:
	go install ./cmd/auto-approve

# Run examples (dry-run)
run-pr-example:
	./auto-approve --pr golang/go#12345 --dry-run

run-project-example:
	./auto-approve --project golang/go --dry-run

run-org-example:
	./auto-approve --org golang --dry-run