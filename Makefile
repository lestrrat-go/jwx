.PHONY: generate realclean cover viewcover test lint check_diffs imports tidy jwx fuzz fuzz-jwt fuzz-jws fuzz-jwe fuzz-jwk companion-test

export GOEXPERIMENT := jsonv2

generate:
	@go generate
	@$(MAKE) generate-jwa generate-jwe generate-jwk generate-jws generate-jwt
	@./scripts/gofmt.sh

generate-%:
	@go generate $(shell pwd -P)/$(patsubst generate-%,%,$@)

realclean:
	rm coverage.out

test-cmd:
	env TESTOPTS="$(TESTOPTS)" ./scripts/test.sh

test:
	$(MAKE) test-cmd TESTOPTS=

cover-cmd:
	env MODE=cover ./scripts/test.sh

cover:
	$(MAKE) cover-cmd TESTOPTS=

smoke-cmd:
	env MODE=short ./scripts/test.sh

smoke:
	$(MAKE) smoke-cmd TESTOPTS=

viewcover:
	go tool cover -html=coverage.out

lint:
	golangci-lint run ./...

check_diffs:
	./scripts/check-diff.sh

imports:
	goimports -w ./

tidy:
	./scripts/tidy.sh

FUZZTIME ?= 30s

fuzz: fuzz-jwt fuzz-jws fuzz-jwe fuzz-jwk

fuzz-jwt:
	go test ./jwt/ -run "^$$" -fuzz FuzzParse -fuzztime $(FUZZTIME)
	go test ./jwt/ -run "^$$" -fuzz FuzzSignAndParse -fuzztime $(FUZZTIME)

fuzz-jws:
	go test ./jws/ -run "^$$" -fuzz FuzzParse -fuzztime $(FUZZTIME)
	go test ./jws/ -run "^$$" -fuzz FuzzSignAndVerify -fuzztime $(FUZZTIME)

fuzz-jwe:
	go test ./jwe/ -run "^$$" -fuzz FuzzParse -fuzztime $(FUZZTIME)
	go test ./jwe/ -run "^$$" -fuzz FuzzEncryptAndDecrypt -fuzztime $(FUZZTIME)

fuzz-jwk:
	go test ./jwk/ -run "^$$" -fuzz "^FuzzParseKey$$" -fuzztime $(FUZZTIME)
	go test ./jwk/ -run "^$$" -fuzz "^FuzzParse$$" -fuzztime $(FUZZTIME)
	go test ./jwk/ -run "^$$" -fuzz FuzzParseKeyRoundtrip -fuzztime $(FUZZTIME)

companion-test:
	./scripts/test-companion.sh $(or $(MODULES),all)

jwx:
	@./scripts/install-jwx.sh
