#!/usr/bin/env bash

set -euxo pipefail

packages=(
	'clang'
	'cmake'
	'gcc'
	'git'
	'libada-url-dev'
	'libc6-dev'
	'libcurl4-openssl-dev'
	'libjansson-dev'
	'libpcre2-dev'
	'libprotobuf-c-dev'
	'libseccomp-dev'
	'libquickjs'
	'make'
	'm4'
	'protobuf-c-compiler'
	'protobuf-compiler'
)

# Install project dependencies via OS package manager
apt update -qq && apt install -y "${packages[@]}"

# Workaround lack of quickjs pkgconfig metadata
QIN=./vendor/quickjs.pc.in
QPC=/usr/lib/pkgconfig/quickjs.pc
QPREFIX=/usr
QVERSION="$(apt show libquickjs | grep ^Version | cut -d' ' -f2)"
m4 -D QUICKJS_PREFIX="$QPREFIX" -D QUICKJS_VERSION="$QVERSION" "$QIN" > "$QPC"
