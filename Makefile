.PHONY: generate

generate: 
	@$(MAKE) generate-jwa generate-jwk generate-jws generate-jwt

generate-%:
	@cd $(patsubst generate-%,%,$@); go generate 