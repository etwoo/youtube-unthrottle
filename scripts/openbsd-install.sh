#!/usr/bin/env sh

set -euo pipefail

# Install project dependencies via OS package manager
pkg_add cmake git ada curl jansson pcre2 protobuf-c quickjs

# Workaround lack of quickjs pkgconfig metadata
QJS_IN=./vendor/quickjs.pc.in
QJS_PKGCONFIG=/usr/local/lib/pkgconfig/quickjs.pc
QJS_PREFIX=/usr/local
QJS_VERSION="$(pkg_info -Iq quickjs | cut -d- -f2-)"
m4 -D QUICKJS_PREFIX="$QJS_PREFIX" -D QUICKJS_VERSION="$QJS_VERSION" "$QJS_IN" \
	> "$QJS_PKGCONFIG"
