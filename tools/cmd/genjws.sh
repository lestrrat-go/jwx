#!/bin/bash

# Script to perform code generation. This exists to overcome
# the fact that go:generate doesn't really allow you to change directories

# This file is expected to be executed from jws directory

set -e

echo "👉 Generating JWS files..."
DIR=../tools/cmd/genjws
pushd "$DIR" > /dev/null
GOWORK=off go build -o .genjws main.go
popd > /dev/null

EXE="${DIR}/.genjws"
"$EXE" -objects="$DIR/objects.yml"
echo "✔ done!"

rm "$EXE"
