GO ?= go

.PHONY: all vet test race bin clean

all: vet test bin

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

bin:
	$(GO) build -o bin/agentbox ./cmd/agentbox

clean:
	rm -rf bin
