#!/bin/bash
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"
EXE="$DIR/.jwxcodegen"

# Build once, reuse
if [ ! -f "$EXE" ]; then
    pushd "$ROOT/internal/jwxcodegen/cmd/jwxcodegen" > /dev/null
    GOWORK=off go build -o "$EXE" .
    popd > /dev/null
fi

"$EXE" "$@"
