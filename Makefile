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
	mkdir -p bin
	$(GO) build -o bin/agentbox ./cmd/agentbox
	$(GO) build -o bin/agentboxd ./cmd/agentboxd

clean:
	rm -rf bin
