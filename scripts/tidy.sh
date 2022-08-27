#!/bin/bash

set -e

# cmd/jwx requires special treatment.
# it should always depend on the latest version

sha1=$(git log -n 1 --format=%H)
pushd cmd/jwx
go get -u github.com/lestrrat-go/jwx/v2@"$sha1"
popd

for dir in $(find . -name 'go.mod' | perl -pe 's{/go.mod$}{}'); do
	pushd "$dir"
	go mod tidy
	popd
done
