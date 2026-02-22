#!/usr/bin/env sh

set -euo pipefail

# Install packages via Homebrew, quieting reinstall warnings if necessary
brew install --quiet cmake pkgconf ada-url curl pcre2 protobuf-c quickjs

# Workaround lack of quickjs pkgconfig metadata
QIN=./vendor/quickjs.pc.in
QP="$(brew --prefix quickjs | xargs realpath)"
QL="$QP/lib"
QV="$(brew list --versions quickjs | cut -d' ' -f2)"
QOUT="$(brew --prefix)/lib/pkgconfig/quickjs.pc"

m4 -D QUICKJS_PREFIX="$QP" -D QUICKJS_LIBDIR="$QL" -D QUICKJS_VERSION="$QV" \
	"$QIN" > "$QOUT"

if [ "$(uname)" == Linux ] ; then
	brew install --quiet libseccomp
fi
