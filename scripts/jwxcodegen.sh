#!/bin/bash
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"
EXE="$DIR/.jwxcodegen"

# Build fresh each invocation to avoid running stale binaries
pushd "$ROOT/internal/jwxcodegen/cmd/jwxcodegen" > /dev/null
GOWORK=off go build -o "$EXE" .
popd > /dev/null

"$EXE" "$@"
rm -f "$EXE"
