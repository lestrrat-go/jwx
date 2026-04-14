#!/bin/bash

set -e

TAG="$1"
if [[ -z "$TAG" ]]; then
	echo "tag name must be provided"
	exit 1
fi

# Make sure Changes file contains an entry for this release
if ! relentry=$(grep -m1 "$TAG" Changes); then
	echo "$TAG does not exist in Changes file"
	exit 1
fi

reldate=${relentry#$TAG - }
reldate=${reldate//['$\t\n\r']}
parseddate=$(date --date="$reldate" "+%d %b %Y")

if [[ "$reldate" != "$parseddate" ]]; then
	echo "$TAG does not seem to exist in Changes file (wrong entry format?)";
	exit 1;
fi

# Update dependency in sibling modules
for dir in ./cmd/jwx; do
	echo "👉 $dir"
	pushd $dir > /dev/null

	go get github.com/lestrrat-go/jwx/v4@"$TAG"
	go mod tidy

	popd > /dev/null
done
