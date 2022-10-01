#!/bin/sh

DIR=$(cd $(dirname $0)/..; pwd -P)

sketch -d $DIR/jwt \
	--dev-mode --dev-path=$DIR/../sketch \
	--exclude='^object\.method\.decodeExtraField$' \
	--tmpl-dir=$DIR/tools/jwt/tmpl \
	--verbose \
        $DIR/tools/jwt
