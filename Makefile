.PHONY: generate

generate: generate-jwt

generate-jwt:
	@cd jwt; go generate 