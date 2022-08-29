#!/bin/bash

# Script to perform code generation. This exists to overcome
# the fact that go:generate doesn't really allow you to change directories

# This file is expected to be executed from jwe directory

set -e

echo "👉 Generating JWE files..."
DIR=../tools/cmd/genjwe
pushd "$DIR" > /dev/null
GOWORK=off go build -o .genjwe main.go
popd > /dev/null

EXE="${DIR}/.genjwe"
"$EXE" -objects="$DIR/objects.yml"
echo "✔ done!"

rm "$EXE"
