all: test build
build:
	go build ./...
test:
	go test ./...
testv:
	go test -v ./...
cover:
	go test -coverprofile=coverage.out
# view coverage in browser
vcover:
	go tool cover -html=coverage.out -o coverage.html
# view function summary coverage in terminal
fcover:
	go tool cover -func=coverage.out
vet:
	go vet ./...
lint:	
	golangci-lint run ./...
clean:
	rm converage.out
	rm coverage.html