#!/bin/bash

# Script to perform code generation. This exists to overcome
# the fact that go:generate doesn't really allow you to change directories

# This file is expected to be executed from jwt directory

set -e

echo "👉 Generating JWT files..."
DIR=../tools/cmd/genjwt
pushd "$DIR" > /dev/null
GOWORK=off go build -o .genjwt main.go
popd > /dev/null

EXE="${DIR}/.genjwt"
"$EXE" -objects="$DIR/objects.yml"
echo "✔ done!"

rm "$EXE"
