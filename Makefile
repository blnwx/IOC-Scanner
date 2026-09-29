GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)

frontend/node_modules/.package-lock.json: frontend/package.json frontend/package-lock.json
	npm --prefix frontend ci

lint: frontend/node_modules/.package-lock.json
	npm --prefix frontend run lint

web: lint
	npm --prefix frontend run build

build: web
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o iocscanner ./src

build-linux-amd64:
	$(MAKE) build GOOS=linux GOARCH=amd64

test: web
	npm --prefix frontend test
	go test ./...

run: build
	./iocscanner

.PHONY: web lint build build-linux-amd64 test run
