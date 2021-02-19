.PHONY: generate realclean cover viewcover test lint check_diffs imports tidy
generate: 
	@go generate
	@$(MAKE) generate-jwa generate-jwe generate-jwk generate-jws generate-jwt

generate-%:
	@echo "> Generating for $(patsubst generate-%,%,$@)"
	@go generate $(shell pwd -P)/$(patsubst generate-%,%,$@)

realclean:
	rm coverage.out

_test:
	go test -race $(TESTOPTS)

test:
	$(MAKE) -C examples _test
	$(MAKE) -C bench _test
	$(MAKE) _test TESOPTS=./...

cover:
	$(MAKE) cover-stdlib

cover-stdlib:
	$(MAKE) -f $(PWD)/Makefile -C examples _test
	$(MAKE) -f $(PWD)/Makefile -C bench _test
	$(MAKE) -f $(PWD)/Makefile -C cmd/jwx _test
	$(MAKE) _test TESTOPTS="-coverpkg=./... -coverprofile=coverage.out.tmp ./..."
	@# This is NOT cheating. tools to generate code don't need to be
	@# included in the final result. Also, we currently don't do
	@# any active development on the jwx command
	@cat coverage.out.tmp | grep -v "internal/jose" | grep -v "internal/jwxtest" | grep -v "internal/cmd" | grep -v "cmd/jwx/jwx.go" > coverage.out
	@rm coverage.out.tmp

cover-goccy:
	$(MAKE) -f $(PWD)/Makefile -C examples _test TESTOPTS="-tags jwx_goccy"
	$(MAKE) -f $(PWD)/Makefile -C cmd/jwx _test TESTOPTS="-tags jwx_goccy"
	$(MAKE) _test TESTOPTS="-tags jwx_goccy -coverpkg=./... -coverprofile=coverage.out.tmp ./..."
	@# This is NOT cheating. tools to generate code don't need to be
	@# included in the final result
	@cat coverage.out.tmp | grep -v "internal/jose" | grep -v "internal/jwxtest" | grep -v "internal/cmd" | grep -v "cmd/jwx/jwx.go" > coverage.out
	@rm coverage.out.tmp

smoke:
	$(MAKE) smoke-stdlib

smoke-stdlib:
	$(MAKE) -f $(PWD)/Makefile -C examples _test
	$(MAKE) -f $(PWD)/Makefile -C bench _test
	$(MAKE) -f $(PWD)/Makefile -C cmd/jwx _test
	$(MAKE) _test TESTOPTS="-short ./..."

smoke-goccy:
	$(MAKE) -f $(PWD)/Makefile -C examples _test TESTOPTS="-tags jwx_goccy"
	$(MAKE) -f $(PWD)/Makefile -C bench _test TESTOPTS="-tags jwx_goccy"
	$(MAKE) -f $(PWD)/Makefile -C cmd/jwx _test TESTOPTS="-tags jwx_goccy"
	$(MAKE) _test TESOPTS="-short -tags jwx_goccy ./..."

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
