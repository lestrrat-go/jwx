#!/bin/bash

set -e

# cmd/jwx requires special treatment.
# it should always depend on the latest version

if [[ -z "$GITHUB_SHA" ]]; then
	GITHUB_SHA=$(git log -n 1 --format=%H)
fi
pushd cmd/jwx
go get -u github.com/lestrrat-go/jwx/v2@"$GITHUB_SHA"
popd

for dir in $(find . -name 'go.mod' | perl -pe 's{/go.mod$}{}'); do
	pushd "$dir"
	go mod tidy
	popd
done
