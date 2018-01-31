.PHONY: generate

generate: 
	@$(MAKE) generate-jwa generate-jws generate-jwt

generate-%:
	@cd $(patsubst generate-%,%,$@); go generate 