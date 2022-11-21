#!/bin/bash

ROOT=$(cd $(dirname $0)/..; pwd -P)
DST="$ROOT/coverage.out"
if [[ -e "$DST" ]]; then
	rm "$DST"
fi

testopts=($TESTOPTS)

tmpfile=coverage.out.tmp
case "$MODE" in
	"cover")
		testopts+=("-coverpkg=./...")
		testopts+=("-coverprofile=$tmpfile")
		;;
	"short")
		testopts+=("-short")
		;;
esac

echo "mode: atomic" > "$DST"
for dir in . ./examples ./bench/performance ./cmd/jwx; do
	pushd "$dir" > /dev/null
	go test -race -json ${testopts[@]} ./... | tparse
	if [[ -e "$tmpfile" ]]; then
		cat "$tmpfile" | tail -n +2 | grep -v "internal/jose" | grep -v "internal/jwxtest" | grep -v "internal/cmd" >> "$DST"
		rm "$tmpfile"
	fi
	popd > /dev/null
done
