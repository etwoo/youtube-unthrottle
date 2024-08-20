#!/usr/bin/env bash

set -euxo pipefail

COVERAGE_PROFILE_DIR="$1"
COBERTURA_OUTPUT="$2"
BIN='./build/youtube-unthrottle'
PROFILE_DATA='coverage.profdata'
LCOV_FMT='coverage.lcov'
LCOV_TO_COBERTURA=$(find ./build -name lcov_cobertura.py)

find ./build -path "*/$COVERAGE_PROFILE_DIR/*" | \
	xargs llvm-profdata merge -sparse -o "$PROFILE_DATA"
llvm-cov export -instr-profile="$PROFILE_DATA" "$BIN" -format=lcov > "$LCOV_FMT"
python "$LCOV_TO_COBERTURA" "$LCOV_FMT" -o "$COBERTURA_OUTPUT"
