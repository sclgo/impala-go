.PHONY: thrift
thrift:
	thrift -r -gen go:package_prefix=github.com/sclgo/impala-go/internal/generated/ interfaces/ImpalaService.thrift
	rm -rf ./internal/generated/
	mv gen-go ./internal/generated/

.PHONY: cli
cli: usql

usql:
	go run github.com/sclgo/usqlgen@v0.1.1 -v build --import github.com/sclgo/impala-go

short-test:
	go test -short -v ./...

.PHONY: test-cli
test-cli: usql
	./usql -c "\drivers" | grep impala

PKGS=$(shell go list ./... | grep -v "./internal/generated")
PKGS_LST=$(shell echo ${PKGS} | tr ' ' ',')
test:
	mkdir -p coverage/covdata
# Use the new binary format to ensure integration tests and cross-package calls are counted towards coverage
# https://go.dev/blog/integration-test-coverage
# -coverpkg can't be ./... because that will include generated code in the stats
# -p 1 disable parallel testing in favor of streaming log output - https://github.com/golang/go/issues/24929#issuecomment-384484654
	go test -race -cover -covermode atomic -coverpkg "${PKGS_LST}" -v -vet=all -timeout 15m -p 1\
		${PKGS} \
		-args -test.gocoverdir="${PWD}/coverage/covdata" \
		| ts -s
# NB: ts command requires moreutils package; awk trick from https://stackoverflow.com/a/25764579 doesn't stream output
	go tool covdata percent -i=./coverage/covdata
	# Convert to old text format for coveralls upload
	go tool covdata textfmt -i=./coverage/covdata -o ./coverage/covprofile
	go tool cover -html=./coverage/covprofile -o ./coverage/coverage.html

checks: check_changes check_deps check_tidy

check_changes:
# make sure .next.version contains the intended next version
# if the following fails, update either the next version or undo any unintended api changes
	go run golang.org/x/exp/cmd/gorelease@latest -version $(shell cat .next.version)

check_deps:
# checks for possibly leaked dependencies like in 
# https://www.dolthub.com/blog/2022-11-07-pruning-test-dependencies-from-golang-binaries/
	go build ./examples/enumerateDB.go	
	strings enumerateDB | grep -m 1 github.com/sclgo/impala-go # sanity
	! (strings enumerateDB | grep testify)
	! (strings enumerateDB | grep docker)

check_tidy:
	go mod tidy
	# Verify that `go mod tidy` didn't introduce any changes. Run go mod tidy before pushing.
	git diff --exit-code --stat go.mod go.sum
