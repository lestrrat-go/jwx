#!/bin/bash

# Script to perform code generation. This exists to overcome
# the fact that go:generate doesn't really allow you to change directories

# This script is expected to be executed from the root directory of jwx

set -e

echo "👉 Generating options..."

DIR=tools/cmd/genoptions
pushd "$DIR" > /dev/null
GOWORK=off go build -o .genoptions main.go
popd > /dev/null

EXE="$DIR/.genoptions"

for dir in jwe jwk jws jwt; do
  echo "  ⌛ Processing $dir/options.yaml"
  "$EXE" -objects="$dir/options.yaml"
done
echo "✔ done!"

rm "$EXE"
