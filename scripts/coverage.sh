#!/usr/bin/env bash

set -euxo pipefail

# TODO: use ctest instead, to avoid having to hardcode every test?
# TODO: change open_coverage_fd() to choose a unique filename per test; maybe treat COVERAGE_PROFILE like a directory, and generate a random/unique filename to create within that directory? then teach this script to process all the files within the COVERAGE_PROFILE directory
COVERAGE_PROFILE=seccomp.profraw ./build/tests/sandbox/sandbox-seccomp -v

llvm-profdata merge -sparse -o sandbox.profdata *.profraw

llvm-cov export -instr-profile=sandbox.profdata ./build/youtube-unthrottle -format=lcov > sandbox.lcov

LCOV_COBERTURA_PY=$(find ./build -name lcov_cobertura.py)
python "$LCOV_COBERTURA_PY" sandbox.lcov -o sandbox.xml
