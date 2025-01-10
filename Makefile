.PHONY: thrift
thrift:
	thrift -r -gen go:package_prefix=github.com/sclgo/impala-go/internal/generated/ interfaces/ImpalaService.thrift
	rm -rf ./internal/generated/
	mv gen-go ./internal/generated/

.PHONY: cli
cli: usql

usql:
	go run github.com/sclgo/usqlgen@v0.1.1 -v build --import github.com/sclgo/impala-go

.PHONY: test-cli
test-cli: usql
	./usql -c "\drivers" | grep impala

test:
	mkdir -p coverage/covdata
	# Use the new binary format to ensure integration tests and cross-package calls are counted towards coverage
	# https://go.dev/blog/integration-test-coverage
	go test -race -cover -v -vet=all `exec go list ./... | grep -v "./internal/generated"` -args -test.gocoverdir="${PWD}/coverage/covdata"
	go tool covdata percent -i=./coverage/covdata
	# Convert to old text format for coveralls upload
	go tool covdata textfmt -i=./coverage/covdata -o ./coverage/covprofile
	go tool cover -html=./coverage/covprofile -o ./coverage/coverage.html
