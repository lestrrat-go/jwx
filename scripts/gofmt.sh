#!/bin/bash

go fmt ./...

# Clean up cached jwxcodegen binary
rm -f "$(dirname "$0")/.jwxcodegen"
