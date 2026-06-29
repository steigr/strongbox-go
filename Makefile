.PHONY: all
all: build

.PHONY: build
build:
	mkdir -p bin
	go build -o bin/strongbox -ldflags "-w -s" ./cmd/strongbox