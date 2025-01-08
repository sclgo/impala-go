.PHONY: thrift
thrift:
	thrift -r -gen go:package_prefix=github.com/sclgo/impala-go/internal/services/ interfaces/ImpalaService.thrift
	rm -rf ./internal/services
	mv gen-go ./internal/services

.PHONY: cli
cli: usql

usql:
	go run github.com/sclgo/usqlgen@v0.1.1 -v build --import github.com/sclgo/impala-go

.PHONY: test-cli
test-cli: usql
	./usql -c "\drivers" | grep impala

