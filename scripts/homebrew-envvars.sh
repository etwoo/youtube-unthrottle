#!/usr/bin/env bash

set -euxo pipefail

BREW_PREFIX="$1"
CC_HINT="$2"

echo "CFLAGS=-I$BREW_PREFIX/include"
echo "LDFLAGS=-L$BREW_PREFIX/lib"
echo "LD_LIBRARY_PATH=$BREW_PREFIX/lib"

# For reference on this idiom for checking if a glob matched, see:
#   https://unix.stackexchange.com/a/298302
shopt -s nullglob
for match in "$BREW_PREFIX/bin/$CC_HINT"-[0-9]* ; do
	echo "CC=$match"
	exit 0
done
for match in "$(brew --prefix llvm)/bin/$CC_HINT"-[0-9]* ; do
	echo "CC=$match"
	exit 0
done

echo "No CC found" >&2
exit 1
