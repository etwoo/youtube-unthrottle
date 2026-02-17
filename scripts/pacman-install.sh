#!/usr/bin/env bash

set -euxo pipefail

# Install project dependencies via Arch Linux package manager
pacman	--noprogressbar          \
	--noconfirm              \
	--needed                 \
	-Sy                      \
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

# Install AUR helper
git clone --depth 1 https://aur.archlinux.org/yay-bin.git
cd yay-bin
makepkg -si
cd -

# Workaround lack of quickjs package for Arch Linux
yay -S quickjs
