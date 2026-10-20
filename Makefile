.PHONY: test race build run demo fmt vet

test:
	go test ./...

race:
	go test -race ./...

build:
	mkdir -p bin
	go build -o bin/crg-server ./cmd/server
	go build -o bin/crg-simulate ./cmd/simulate

run:
	go run ./cmd/server

demo:
	go run ./cmd/simulate

fmt:
	gofmt -w ./cmd ./internal

vet:
	go vet ./...
