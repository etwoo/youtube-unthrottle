#!/usr/bin/env bash

set -euo pipefail

CHECK_PROSE_OUTPUT="$1"

VALE_INI=".vale.ini"
STYLES_PATH=$(grep StylesPath "$VALE_INI" | cut -f2 -d= | tr -d ' ')
VOCABULARY_NAME=$(grep Vocab "$VALE_INI" | cut -f2 -d= | tr -d ' ')
VOCABULARY_PATH="$STYLES_PATH/config/vocabularies/$VOCABULARY_NAME/accept.txt"

mkdir -p "$(dirname "$VOCABULARY_PATH")"
cp ./scripts/check-prose-accept.txt "$VOCABULARY_PATH"

find . -type f -regextype egrep -regex '.*\.(c|cmake|exp|h|md|sh|txt|yml)'     \
	-and ! -path './build/*'                                               \
	-and ! -name 'get_cpm.cmake'                                           \
	-print0 | xargs -0 vale --output="$CHECK_PROSE_OUTPUT"
