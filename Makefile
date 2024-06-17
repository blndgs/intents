GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test

BINARY_NAME=model

all: test build
build:
	$(GOBUILD) ./...
test:
	$(GOTEST) -v ./...
testv:
	$(GOTEST) ./...
clean:
	rm -f $(BINARY_NAME)