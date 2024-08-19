#!/usr/bin/env bash

set -euxo pipefail

cd ./build/tests/sandbox/

COVERAGE_PROFILE=landlock.profraw ./sandbox-landlock -v
COVERAGE_PROFILE=seccomp.profraw ./sandbox-seccomp -v

llvm-profdata merge -sparse -o sandbox.profdata \
	landlock.profraw seccomp.profraw

llvm-cov export -ignore-filename-regex=build/ -instr-profile=sandbox.profdata \
	-object ./sandbox-landlock -object ./sandbox-seccomp \
	-format=lcov > sandbox.lcov

curl -o lcov_cobertura.py 'https://raw.githubusercontent.com/eriwen/lcov-to-cobertura-xml/master/lcov_cobertura/lcov_cobertura.py'
python ./lcov_cobertura.py sandbox.lcov -o sandbox.xml
