#!/usr/bin/env bash

set -euxo pipefail

packages=(
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
apt update -qq && apt install -qqy "${packages[@]}"

# Workaround lack of quickjs pkgconfig metadata
QIN=./vendor/quickjs.pc.in
QP=/usr
QL="$QP/lib/x86_64-linux-gnu"
QV="$(apt show libquickjs | grep ^Version | cut -d' ' -f2)"
QOUT="$QL/pkgconfig/quickjs.pc"

m4 -D QUICKJS_PREFIX="$QP" -D QUICKJS_LIBDIR="$QL" -D QUICKJS_VERSION="$QV" \
	"$QIN" > "$QOUT"
