#!/usr/bin/env bash

set -euxo pipefail

BREW_PREFIX="$1"
BREW_CACHE="$2"
CC_PKG="$3"

if [ -f "$BREW_CACHE" ] ; then
	# On cache hit, restore cached Homebrew packages
	tar xkPf "$BREW_CACHE"
else
	# On cache miss, compute Homebrew content before package install
	find "$BREW_PREFIX" ! -type d | sort > homebrew-before.txt
fi

# Workaround https://github.com/actions/runner-images/issues/9966
if [ "$(uname)" == Darwin ] ; then
	sudo rm /usr/local/bin/{idle3,pip3,pydoc3,python3}*
fi

brew install --quiet "$CC_PKG"
bash "$(dirname "$0")/../setup/homebrew.sh"

if [ "$(uname)" == Linux ] ; then
	# Ubuntu: change default shell from dash to bash
	sudo mv /bin/sh{,bak}
	sudo ln -s /bin/{bash,sh}
fi

# On cache miss, compare Homebrew content before and after package install
# and then store the resulting diff as a new tarball.
if [ -f homebrew-before.txt ] ; then
	comm -13 homebrew-before.txt <(find "$BREW_PREFIX" ! -type d | sort) \
		| tar cPf "$BREW_CACHE" --zstd --files-from -
fi
