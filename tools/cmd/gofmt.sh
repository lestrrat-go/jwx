#!/bin/bash

find . -name '*.go' | xargs gofmt -w -s
