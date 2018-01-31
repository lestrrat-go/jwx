.PHONY: generate

generate: 
	@$(MAKE) generate-jwa generate-jwt

generate-%:
	@cd $(patsubst generate-%,%,$@); go generate 