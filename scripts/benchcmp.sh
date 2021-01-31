#!/bin/bash

# ./benchcmp.sh branch1 branch2 [count]

function curbranch {
	git rev-parse --abbrev-ref HEAD 2>/dev/null
}

function curcommit {
	git log -n 1 --format=%H | cut -c 1-9
}

count=$3
if [[ -z "$count" ]]; then
	count=5
fi

if [[ ! "$count" != ^[1-9][0-9]*$ ]]; then
	echo "third argument must be a positive integer"
	exit 1
fi

set -e

tmpdir=$(mktemp -d 2>/dev/null || mktemp -d -t 'jwxbench')

origbranch=$(git rev-parse --abbrev-ref HEAD)
outputfiles=()
commits=()

echo "# Going to run ${count} iterations of benchmarks against $1 and $2 branches"
for branch in $1 $2
do
  cbranch=$(curbranch)
	if [[ "$branch" != "$cbranch" ]]; then
		git switch $branch
	fi

	echo "# Running benchmark against $branch..."
	output="${tmpdir}/${branch/\//-}.bench.txt"
	outputfiles+=($output)
	commits+=($(curcommit))

	pushd bench
	set -x
	go test -count=$count -bench . -benchmem | tee "$output"
	set +x
	popd
done

cbranch=$(curbranch)
if [[ "$cbranch" != "$origbranch" ]]; then
	git switch "$origbranch"
fi

echo "Benchmark comparison for:"
echo "  $1 (${commits[0]})"
echo "  $2 (${commits[1]})"
echo ""
benchstat "${outputfiles[0]}" "${outputfiles[1]}"
