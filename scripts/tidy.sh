#!/bin/bash

for dir in $(find . -name 'go.mod' | perl -pe 's{/go.mod$}{}'); do
	pushd "$dir"
	go mod tidy
	popd
done
