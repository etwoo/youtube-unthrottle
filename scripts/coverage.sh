#!/usr/bin/env bash

set -euxo pipefail

# TODO: use ctest instead, to avoid having to hardcode every test?
# TODO: change open_coverage_fd() to choose a unique filename per test; maybe treat COVERAGE_PROFILE like a directory, and generate a random/unique filename to create within that directory? then teach this script to process all the files within the COVERAGE_PROFILE directory
COVERAGE_PROFILE=seccomp.profraw ./build/tests/sandbox/sandbox-seccomp -v

BIN='./build/youtube-unthrottle'
PROFILE_DATA='sandbox.profdata'
LCOV_FMT='sandbox.lcov'
LCOV_TO_COBERTURA=$(find ./build -name lcov_cobertura.py)

llvm-profdata merge -sparse -o "$PROFILE_DATA" ./*.profraw
llvm-cov export -instr-profile="$PROFILE_DATA" "$BIN" -format=lcov > "$LCOV_FMT"
python "$LCOV_TO_COBERTURA" "$LCOV_FMT" -o sandbox.xml
