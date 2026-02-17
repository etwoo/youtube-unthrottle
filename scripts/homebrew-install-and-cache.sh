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

# Install packages via Homebrew, quieting reinstall warnings if necessary
brew install --quiet "$CC_PKG" cmake pkgconf curl jansson pcre2 protobuf-c quickjs

# Workaround lack of quickjs pkgconfig metadata
QUICKJS_PC="$(brew --prefix)/lib/pkgconfig/quickjs.pc"
QUICKJS_PREFIX="$(brew --prefix quickjs | xargs realpath)"
QUICKJS_VERSION="$(brew list --versions quickjs | cut -w -f2)"
m4 ./vendor/quickjs.pc.in                     \
	-D QUICKJS_PREFIX="$QUICKJS_PREFIX"   \
	-D QUICKJS_VERSION="$QUICKJS_VERSION" \
	> "$QUICKJS_PC"

if [ "$(uname)" == Darwin ] ; then
	brew install --quiet ada-url
elif [ "$(uname)" == Linux ] ; then
	# Workaround lack of ada-url bottle (Homebrew binary package) on Linux
	# https://github.com/Homebrew/homebrew-core/pull/233020
	curl -Lo ada.tgz https://github.com/ada-url/ada/archive/refs/tags/v3.3.0.tar.gz
	tar zxf ada.tgz
	cmake -S ada-3.3.0 -B ada-build --install-prefix "$(brew --prefix)" -DBUILD_SHARED_LIBS=ON
	cmake --build ada-build
	cmake --install ada-build
	rm -rf ada.tgz ada-3.3.0 ada-build
	# Install Linux-specific packages
	brew install --quiet libseccomp
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
