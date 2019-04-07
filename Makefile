.PHONY: generate realclean cover viewcover

generate: 
	@$(MAKE) generate-jwa generate-jwk generate-jws generate-jwt

generate-%:
	@cd $(patsubst generate-%,%,$@); go generate 

realclean:
	rm cover.out

cover:
	go test -cover -coverprofile=cover.out -v ./...

viewcover:
	go tool cover -html=cover.out