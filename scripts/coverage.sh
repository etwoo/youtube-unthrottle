#!/usr/bin/env bash

set -euxo pipefail

COVERAGE_PROFILE=seccomp.profraw ./build/tests/sandbox/sandbox-seccomp -v

llvm-profdata merge -sparse -o sandbox.profdata seccomp.profraw

llvm-cov export -ignore-filename-regex=build/ -instr-profile=sandbox.profdata \
	-object ./build/tests/sandbox/sandbox-landlock \
	-object ./build/tests/sandbox/sandbox-seccomp \
	-format=lcov > sandbox.lcov

curl -o lcov_cobertura.py 'https://raw.githubusercontent.com/eriwen/lcov-to-cobertura-xml/master/lcov_cobertura/lcov_cobertura.py'
python ./lcov_cobertura.py sandbox.lcov -o sandbox.xml
