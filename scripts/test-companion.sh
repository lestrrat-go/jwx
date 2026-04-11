#!/bin/bash

set -euo pipefail

export GOEXPERIMENT=jsonv2

JWX_ROOT=$(cd "$(dirname "$0")/.."; pwd -P)
COMPANIONS_YAML="$JWX_ROOT/companions.yaml"

if [ ! -f "$JWX_ROOT/go.mod" ]; then
	echo "ERROR: cannot find go.mod in $JWX_ROOT"
	exit 1
fi

if [ ! -f "$COMPANIONS_YAML" ]; then
	echo "ERROR: cannot find companions.yaml in $JWX_ROOT"
	exit 1
fi

# Parse companions.yaml: emit "name repo branch runtests" per testable module.
# Modules with runtests: false are excluded.
parse_modules() {
	python3 -c "
import yaml, sys
with open(sys.argv[1]) as f:
    data = yaml.safe_load(f)
for m in data.get('modules', []):
    if m.get('runtests', True) is False:
        continue
    print(m['name'], m['repo'], m.get('branch', 'main'))
" "$COMPANIONS_YAML"
}

# Resolve which modules to test
if [ $# -eq 0 ]; then
	filter="all"
else
	filter="$1"
fi

WORKDIR="$JWX_ROOT/.companions"
mkdir -p "$WORKDIR"

failures=0
results=()

while read -r name repo branch; do
	if [ "$filter" != "all" ]; then
		# Check if this module is in the filter list
		match=false
		IFS=', ' read -ra selected <<< "$filter"
		for s in "${selected[@]}"; do
			if [ "$s" = "$name" ]; then
				match=true
				break
			fi
		done
		if [ "$match" = false ]; then
			continue
		fi
	fi

	echo ""
	echo "===== Testing companion module: $name ====="
	echo ""

	moddir="$WORKDIR/$name"

	if [ -d "$moddir/.git" ]; then
		actual_url=$(git -C "$moddir" remote get-url origin 2>/dev/null || true)
		if [ "$actual_url" != "$repo" ]; then
			echo "Remote URL mismatch: expected $repo, got $actual_url"
			echo "Removing and re-cloning..."
			rm -rf "$moddir"
		else
			echo "Reusing existing checkout, pulling latest..."
			git -C "$moddir" fetch --depth=1 origin "$branch"
			git -C "$moddir" reset --hard FETCH_HEAD
		fi
	fi

	if [ ! -d "$moddir/.git" ]; then
		if ! git clone --depth=1 --branch "$branch" "$repo" "$moddir"; then
			echo "FAIL: could not clone $name"
			failures=$((failures + 1))
			results+=("FAIL $name (clone failed)")
			continue
		fi
	fi

	pushd "$moddir" > /dev/null

	# Use go.work to redirect jwx/v4 to the local checkout.
	# This avoids modifying go.mod, which would show up in git diff
	# and risk accidental commits.
	cat > go.work <<GOWORK
go $(go env GOVERSION | sed 's/^go//')

use (
	.
	$JWX_ROOT
)
GOWORK

	if go test -race ./...; then
		results+=("PASS $name")
	else
		failures=$((failures + 1))
		results+=("FAIL $name")
	fi

	popd > /dev/null
done < <(parse_modules)

echo ""
echo "===== Companion Test Summary ====="
for r in "${results[@]}"; do
	echo "  $r"
done
echo "=================================="

if [ "$failures" -ne 0 ]; then
	echo "$failures module(s) failed"
	exit 1
fi

echo "All companion modules passed"
