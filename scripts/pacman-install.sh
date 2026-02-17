#!/usr/bin/env bash

set -euxo pipefail

# Install project dependencies via Arch Linux package manager
pacman	--noconfirm --needed -Sy \
	--assume-installed guile \
	--assume-installed perl  \
	base-devel               \
	cmake                    \
	clang                    \
	git                      \
	pkgconf                  \
	ada                      \
	curl                     \
	jansson                  \
	libseccomp               \
	pcre2                    \
	protobuf-c               \
	glibc
# Note: update glibc in case nightly CI container image (host OS)
# uses newer glibc version than fortnightly VM image (guest OS)

# Workaround lack of quickjs package for Arch Linux
git clone --depth 1 https://aur.archlinux.org/quickjs.git
cd quickjs
chmod 777 .
runuser -u nobody -- makepkg -s
pacman --noconfirm -U -- *.pkg.tar.*
cd -

# Workaround lack of quickjs pkgconfig metadata
QJS_IN=./vendor/quickjs.pc.in
QJS_PKGCONFIG=/usr/lib/pkgconfig/quickjs.pc
QJS_PREFIX=/usr
QJS_VERSION="$(pacman -Qi quickjs | grep ^Ver | tr -s ' ' | cut -d' ' -f3)"
m4 -D QUICKJS_PREFIX="$QJS_PREFIX" -D QUICKJS_VERSION="$QJS_VERSION" "$QJS_IN" \
	> "$QJS_PKGCONFIG"
