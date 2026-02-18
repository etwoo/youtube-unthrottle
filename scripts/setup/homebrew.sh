#!/usr/bin/env sh

set -euo pipefail

# Install packages via Homebrew, quieting reinstall warnings if necessary
brew install --quiet cmake pkgconf ada-url curl jansson pcre2 protobuf-c quickjs

# Workaround lack of quickjs pkgconfig metadata
QIN=./vendor/quickjs.pc.in
QPC="$(brew --prefix)/lib/pkgconfig/quickjs.pc"
QPREFIX="$(brew --prefix quickjs | xargs realpath)"
QVERSION="$(brew list --versions quickjs | cut -d' ' -f2)"
m4 -D QUICKJS_PREFIX="$QPREFIX" -D QUICKJS_VERSION="$QVERSION" "$QIN" > "$QPC"

if [ "$(uname)" == Linux ] ; then
	brew install --quiet libseccomp
fi
