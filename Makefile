.PHONY: generate realclean cover viewcover test lint check_diffs imports tidy

generate: 
	@go generate
	@$(MAKE) generate-jwa generate-jwe generate-jwk generate-jws generate-jwt

generate-%:
	@echo "> Generating for $(patsubst generate-%,%,$@)"
	@go generate $(shell pwd -P)/$(patsubst generate-%,%,$@)

realclean:
	rm coverage.out

test:
	cd examples && go test -v -race && cd .. && go test -v -race ./...

cover:
	$(MAKE) cover-stdlib

cover-stdlib:
	cd examples && go test -v -race && cd .. && go test -v -race -coverpkg=./... -coverprofile=coverage.out.tmp ./...
	@# This is NOT cheating. tools to generate code don't need to be
	@# included in the final result. Also, we currently don't do
	@# any active development on the jwx command
	@cat coverage.out.tmp | grep -v "internal/cmd" | grep -v "cmd/jwx/jwx.go" > coverage.out
	@rm coverage.out.tmp

cover-goccy:
	cd examples && go test -v -tags jwx_goccy -race && cd .. && go test -v -tags jwx_goccy -race -coverpkg=./... -coverprofile=coverage.out.tmp ./...
	@# This is NOT cheating. tools to generate code don't need to be
	@# included in the final result
	@cat coverage.out.tmp | grep -v "internal/cmd" > coverage.out
	@rm coverage.out.tmp

smoke:
	$(MAKE) smoke-stdlib

smoke-stdlib:
	cd examples && go test -race && cd .. && go test -race -short ./...

smoke-goccy:
	cd examples && go test -tags jwx_goccy -race && cd .. && go test -tags jwx_goccy -race -short ./...

viewcover:
	go tool cover -html=coverage.out

lint:
	golangci-lint run ./...

check_diffs:
	./scripts/check-diff.sh

imports:
	goimports -w ./

tidy:
	go mod tidy
	cd examples && go mod tidy && cd ..
	cd bench && go mod tidy && cd ..
