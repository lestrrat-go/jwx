#!/bin/bash

# Script to perform code generation. This exists to overcome
# the fact that go:generate doesn't really allow you to change directories

# This file is expected to be executed from jwa directory

set -e

echo "👉 Generating JWA files..."
DIR=../tools/cmd/genjwa

pushd "$DIR" > /dev/null
GOWORK=off go build -o .genjwa main.go
popd > /dev/null

EXE="${DIR}/.genjwa"
"$EXE" "$DIR/objects.yml"
echo "✔ done!"

rm "$EXE"
