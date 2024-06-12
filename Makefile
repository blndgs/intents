GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test

BINARY_NAME=model

all: test build
build:
	$(GOBUILD) ./...
test:
	$(GOTEST) -v ./...
clean:
	rm -f $(BINARY_NAME)