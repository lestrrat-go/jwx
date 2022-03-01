#!/bin/bash

# Script to perform code generation. This exists to overcome
# the fact that go:generate doesn't really allow you to change directories

# This script is expected to be executed from the root directory of jwx

set -e

pushd internal/cmd/genoptions
go build -o genoptions main.go
popd

./internal/cmd/genoptions/genoptions -objects=jwe/options.yaml
./internal/cmd/genoptions/genoptions -objects=jws/options.yaml

rm internal/cmd/genoptions/genoptions
