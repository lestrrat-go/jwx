#!/bin/bash

# Script to perform code generation. This exists to overcome
# the fact that go:generate doesn't really allow you to change directories

# This file is expected to be executed from jwk directory

set -e

echo "👉 Generating JWK files..."
DIR=../tools/cmd/genjwk
pushd "$DIR" > /dev/null
GOWORK=off go build -o .genjwk main.go
popd > /dev/null

EXE="${DIR}/.genjwk"
"$EXE" -objects="$DIR/objects.yml"
echo "✔ done!"

rm "$EXE"
