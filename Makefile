.PHONY: generate realclean cover viewcover test lint check_diffs imports

generate: 
	go get ./...
	@$(MAKE) generate-jwa generate-jwk generate-jws generate-jwt

generate-%:
	@cd $(patsubst generate-%,%,$@); go generate 

realclean:
	rm coverage.out

cover:
	go test -v -coverpkg=./... -coverprofile=coverage.out ./...

viewcover:
	go tool cover -html=coverage.out

test:
	go test -v ./...

lint:
	golangci-lint run ./...

check_diffs:
	./scripts/check-diff.sh

imports:
	goimports -w ./

