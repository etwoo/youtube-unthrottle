#!/usr/bin/env sh

set -euo pipefail

# Install project dependencies via OS package manager
pkg_add cmake git ada curl pcre2 protobuf-c quickjs

# Workaround lack of quickjs pkgconfig metadata
QIN=./vendor/quickjs.pc.in
QP=/usr/local
QL="$QP/lib"
QV="$(pkg_info -Iq quickjs | cut -d- -f2-)"
QOUT="$QL/pkgconfig/quickjs.pc"

m4 -D QUICKJS_PREFIX="$QP" -D QUICKJS_LIBDIR="$QL" -D QUICKJS_VERSION="$QV" \
	"$QIN" > "$QOUT"
