#!/usr/bin/env sh

set -euo pipefail

STATUS=0

echo 'Checking for non-const global variables ...'
if find . -type f -regextype egrep -regex '.*\.(h|c)' -and ! -path './build/*' \
	| ctags -L- --output-format=json --sort=yes --c-kinds=v --extras=-F \
	| jq -rM .pattern \
	| sed 's@^/\^@@g' \
	| sed 's@\$/$@@g' \
	| grep -v '^const' ; then
	echo 'ERROR: non-const global variables potentially make this code not thread-safe; please refactor this code to avoid mutable global state'
	STATUS=1
fi

echo 'Checking for non-const local variables with static duration ...'
if find . -type f -regextype egrep -regex '.*\.(h|c)' -and ! -path './build/*' \
	| ctags -L- --output-format=json --sort=yes --c-kinds=l \
	| jq -rM .pattern \
	| sed 's@^/\^@@g' \
	| sed 's@\$/$@@g' \
	| grep -P '\t+static' ; then
	echo 'ERROR: non-const variables with static duration make this code non-reentrant and likely not thread-safe; please refactor this code to avoid mutable global state'
	STATUS=1
fi

exit $STATUS
