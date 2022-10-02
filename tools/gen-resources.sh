#!/bin/sh

DIR=$(cd $(dirname $0)/..; pwd -P)

sketch -d $DIR/jwt \
	--dev-mode --dev-path=$DIR/../sketch \
	--exclude='^object\.method\.decodeExtraField$' \
	--exclude-schema='^OpenID$' \
	--tmpl-dir=$DIR/tools/jwt/tmpl \
	--verbose \
        $DIR/tools/jwt

sketch -d $DIR/jwt/openid \
	--dev-mode --dev-path=$DIR/../sketch \
	--exclude='^object\.method\.decodeExtraField$' \
	--exclude-schema='^JWT$' \
	--tmpl-dir=$DIR/tools/jwt/tmpl \
	--verbose \
        $DIR/tools/jwt

