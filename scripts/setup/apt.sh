#!/usr/bin/env bash

set -euxo pipefail

packages=(
	'build-essential'
	'clang'
	'clang-format'
	'clang-tidy'
	'cmake'
	'git'
	'libada-url-dev'
	'libcurl4-openssl-dev'
	'libpcre2-dev'
	'libprotobuf-c-dev'
	'libseccomp-dev'
	'libquickjs'
	'm4'
	'protobuf-c-compiler'
	'protobuf-compiler'
)

apt-get update -qq
# Install LD_PRELOAD utility to disable fsync() and speed up dpkg batches
apt-get install -qqy eatmydata
# Install project dependencies via OS package manager
eatmydata apt-get install -qqy "${packages[@]}" > /dev/null

# Workaround lack of quickjs pkgconfig metadata
QIN=./vendor/quickjs.pc.in
QP=/usr
QL="$QP/lib/x86_64-linux-gnu"
QV="$(apt-cache show libquickjs | grep ^Version | cut -d' ' -f2)"
QOUT="$QL/pkgconfig/quickjs.pc"

m4 -D QUICKJS_PREFIX="$QP" -D QUICKJS_LIBDIR="$QL" -D QUICKJS_VERSION="$QV" \
	"$QIN" > "$QOUT"

# Change default shell from dash to bash
mv /bin/sh{,.bak}
ln -s /bin/{bash,sh}
