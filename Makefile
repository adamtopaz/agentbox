GO ?= go
SUDO ?= sudo

.PHONY: all vet test race bin setup clean

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

setup: bin
	$(SUDO) ./bin/agentbox setup

clean:
	rm -rf bin
