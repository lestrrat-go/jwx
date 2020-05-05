.PHONY: generate realclean cover viewcover test lint check_diffs imports

generate: 
	@$(MAKE) generate-jwa generate-jwk generate-jws generate-jwt

generate-%:
	@cd $(patsubst generate-%,%,$@); go generate 

realclean:
	rm coverage.out

test:
	go test -v -race ./...

cover:
	go test -v -tags debug0 -race -coverpkg=./... -coverprofile=coverage.out.tmp ./...
	@# This is NOT cheating. tools to generate code don't need to be
	@# included in the final result
	@cat coverage.out.tmp | grep -v "internal/cmd" | grep -v "internal/codegen" > coverage.out
	@rm coverage.out.tmp

viewcover:
	go tool cover -html=coverage.out

lint:
	golangci-lint run ./...

check_diffs:
	./scripts/check-diff.sh

imports:
	goimports -w ./

