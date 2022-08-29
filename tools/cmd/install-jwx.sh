#!/bin/bash

set -e

# find where to install. GOBIN or GOPATH/bin

install_dir="$(go env GOBIN)"
if [[ -z "$install_dir" ]]; then
	install_dir=$(go env GOPATH)/bin
fi

# make sure the directory exists

mkdir -p "$install_dir"

pushd cmd/jwx > /dev/null

go build -o "$install_dir/jwx" .

popd > /dev/null

echo "Installed jwx in $install_dir/jwx"
