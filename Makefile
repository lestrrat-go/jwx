.PHONY: generate realclean cover viewcover

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

imports:
	goimports -w ./
