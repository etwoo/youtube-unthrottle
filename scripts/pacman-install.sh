#!/usr/bin/env bash
set -euxo pipefail

# Install project dependencies via Arch Linux package manager
pacman	-Sy --needed --noconfirm --noprogressbar \
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

if [ "$#" -ge 1 ] && [ "$1" == '--skip-quickjs' ]; then
	echo "Skipping QuickJS install ..."
	exit 0
fi

# Disable LTO before building libquickjs.a, to allow programs that link
# statically against libquickjs.a the freedom to use a different compiler.
sed -i 's@^LTOFLAGS="-flto=auto"@LTOFLAGS="-fno-lto"@' /etc/makepkg.conf

# Workaround lack of quickjs package for Arch Linux
pushd /tmp
runuser -u nobody -- git clone --depth 1 https://aur.archlinux.org/quickjs.git
cd quickjs
sed -i '18i sed -i '\''s@\(PROGS=.*\)run-test.*@\1@g;s@PROGS+=.*examples.*@@g'\'' "${_pv}/Makefile"' PKGBUILD
MAKEFLAGS="-j$(nproc)" runuser -u nobody -- makepkg -s
pacman -U --noconfirm -- *.pkg.tar.*
popd

# Workaround lack of quickjs pkgconfig metadata
QIN=./vendor/quickjs.pc.in
QPC=/usr/lib/pkgconfig/quickjs.pc
QPREFIX=/usr
QVERSION="$(pacman -Qi quickjs | grep ^Ver | tr -s ' ' | cut -d' ' -f3)"
m4 -D QUICKJS_PREFIX="$QPREFIX" -D QUICKJS_VERSION="$QVERSION" "$QIN" > "$QPC"
