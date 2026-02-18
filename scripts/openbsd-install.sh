#!/usr/bin/env sh

set -euo pipefail

# Install project dependencies via OS package manager
pkg_add cmake git ada curl jansson pcre2 protobuf-c quickjs

# Workaround lack of quickjs pkgconfig metadata
QIN=./vendor/quickjs.pc.in
QPC=/usr/local/lib/pkgconfig/quickjs.pc
QPREFIX=/usr/local
QVERSION="$(pkg_info -Iq quickjs | cut -d- -f2-)"
m4 -D QUICKJS_PREFIX="$QPREFIX" -D QUICKJS_VERSION="$QVERSION" "$QIN" > "$QPC"
