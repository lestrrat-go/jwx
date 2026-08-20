.PHONY: generate realclean cover viewcover test lint check_diffs imports tidy jwx fuzz fuzz-jwt fuzz-jws fuzz-jwe fuzz-jwk companion-test print-goexperiment

# encoding/json/v2 sits behind GOEXPERIMENT=jsonv2 on Go 1.26 and is part of
# the standard library from Go 1.27 on. Probe the toolchain rather than
# hardcoding a version, and do not name the experiment when the toolchain
# already ships it for real: that forces the standard library to be rebuilt
# under a non-default configuration.
#
# Both branches rewrite GOEXPERIMENT instead of only setting it, because the
# caller may have exported it. On Go 1.27 an inherited jsonv2 would otherwise
# survive and trigger the very rebuild this probe exists to avoid. Experiments
# other than jsonv2 are always preserved, and the result is idempotent, so a
# recursive $(MAKE) that inherits it lands on the same value. GOEXPERIMENT is
# cleared for the probe itself so that recursion re-probes the toolchain
# honestly instead of reading back what this file exported.
GOEXPERIMENT_COMMA := ,
GOEXPERIMENT_EMPTY :=
GOEXPERIMENT_SPACE := $(GOEXPERIMENT_EMPTY) $(GOEXPERIMENT_EMPTY)
GOEXPERIMENT_OTHERS := $(strip $(filter-out jsonv2,$(subst $(GOEXPERIMENT_COMMA),$(GOEXPERIMENT_SPACE),$(GOEXPERIMENT))))
GOEXPERIMENT_REST := $(subst $(GOEXPERIMENT_SPACE),$(GOEXPERIMENT_COMMA),$(GOEXPERIMENT_OTHERS))

ifneq ($(shell GOEXPERIMENT= go list encoding/json/v2 >/dev/null 2>&1 || echo needed),)
export GOEXPERIMENT := $(if $(GOEXPERIMENT_REST),$(GOEXPERIMENT_REST)$(GOEXPERIMENT_COMMA))jsonv2
else
export GOEXPERIMENT := $(GOEXPERIMENT_REST)
endif

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

# Reports the GOEXPERIMENT this Makefile settled on for the current toolchain.
# CI uses it to assert that the Go 1.27 job does not name the jsonv2 experiment.
print-goexperiment:
	@echo "$(GOEXPERIMENT)"

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
