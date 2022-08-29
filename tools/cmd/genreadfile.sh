#!/bin/bash

# Script to perform code generation. This exists to overcome
# the fact that go:generate doesn't really allow you to change directories

set -e

echo "👉 Generating ReadFile() for each package..."
export GOWORK=off
DIR="tools/cmd/genreadfile"
pushd "$DIR" > /dev/null
go build -o .genreadfile main.go
popd > /dev/null

EXE="$DIR/.genreadfile"
"$EXE"
echo "✔ done!"

rm "$EXE"
