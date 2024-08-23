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

#
# Generate a coverage report that includes a single-value line coverage
# percentage, which GitLab can then display in the merge request widget.
#
# https://docs.gitlab.com/ee/ci/testing/code_coverage.html#view-code-coverage-results-in-the-merge-request
#
llvm-cov report -show-region-summary=0 -show-branch-summary=0 \
	-instr-profile="$PROFILE_DATA" "$BIN" \
	-ignore-filename-regex 'main.c|src/coverage.c'

#
# Convert profdata -> lcov -> cobertura. GitLab the latter to drive the test
# coverage visualization feature in the file diff view of MRs.
#
# https://docs.gitlab.com/ee/ci/testing/test_coverage_visualization/index.html
#
llvm-cov export -instr-profile="$PROFILE_DATA" "$BIN" -format=lcov > "$LCOV_FMT"
python "$LCOV_TO_COBERTURA" "$LCOV_FMT" -o "$COBERTURA_OUTPUT"
