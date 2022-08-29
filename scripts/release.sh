#!/bin/bash

set -e

TAG="$1"
if [[ -z "$TAG" ]]; then
	echo "tag name must be provided"
fi

# Make sure Changes file contains an entry for this release
relentry=$(grep "$TAG" Changes)
if [[ "$?" -ne 0 ]]; then
	echo "$TAG does not exist in Changes file";
	exit 1;
fi

reldate=${relentry#$TAG - }
parseddate=$(date --date="$reldate" "+%d %b %Y")

if [[ "$reldate" != "$parseddate" ]]; then
	echo "$TAG does not seem to exist in Changes file (wrong entry format?)";
	exit 1;
fi

# Update dependency in ./cmd/jwx ./examples
for dir in ./cmd/jwx ./examples ./bench/performance; do
	echo "👉 $dir"
	pushd $dir > /dev/null

	go mod edit -require=github.com/lestrrat-go/jwx/v2@"$TAG"
	go mod tidy

	popd > /dev/null
done

# set up tag
git tag "$TAG"

echo "tag $TAG has been created. Make sure to commit/push/push --tags afterwards"
