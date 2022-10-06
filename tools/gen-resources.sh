#!/bin/sh

DIR=$(cd $(dirname $0)/..; pwd -P)
set -e

sketch -d $DIR/jwt \
	--exclude-symbol='^object\.method\.decodeExtraField$' \
	--exclude-schema='^OpenID$' \
	--tmpl-dir=$DIR/tools/jwt/tmpl \
	--verbose \
	$DIR/tools/jwt

sketch -d $DIR/jwt/openid \
	--exclude-symbol='^object\.method\.decodeExtraField$' \
	--exclude-schema='^JWT$' \
	--tmpl-dir=$DIR/tools/jwt/tmpl \
	--verbose \
	$DIR/tools/jwt

sketch -d $DIR/jwk \
	--exclude-symbol='^builder\..+' \
	--exclude-symbol='^object\.method\.decodeExtraField$' \
	--tmpl-dir=$DIR/tools/jwk/tmpl \
	--verbose \
	$DIR/tools/jwk

sketch -d $DIR/jws \
	--dev-mode --dev-path=$DIR/../sketch \
	--exclude-symbol='^builder\..+' \
	--exclude-symbol='^object\.method\.decodeExtraField$' \
	--tmpl-dir=$DIR/tools/jws/tmpl \
	--verbose \
	$DIR/tools/jws

sketch -d $DIR/jwe \
	--dev-mode --dev-path=$DIR/../sketch \
	--exclude-symbol='^builder\..+' \
	--exclude-symbol='^object\.method\.decodeExtraField$' \
	--tmpl-dir=$DIR/tools/jwe/tmpl \
	--verbose \
	$DIR/tools/jwe

