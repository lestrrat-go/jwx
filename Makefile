.PHONY: generate

generate: generate-jwt

generate-jwt:
	@pushd jwt;go generate && popd