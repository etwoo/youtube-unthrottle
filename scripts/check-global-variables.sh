#!/usr/bin/env sh

set -euo pipefail

function find_c_code
{
	find . -regextype egrep -regex '.*\.(h|c)' -and ! -path './build/*' \
		| ctags -L- --output-format=json "$@" \
		| jq -rM '.pattern | ltrimstr("/^") | rtrimstr("$/")'
}

STATUS=0

echo 'Checking for non-const global variables ...'
if find_c_code --c-kinds=v --extras=-F | grep -v '^const' ; then
	cat << EOF
ERROR: non-const global variables potentially make this code not thread-safe

EOF
	STATUS=1
fi

echo 'Checking for non-const local variables with static duration ...'
if find_c_code --c-kinds=l | grep -P '\t+static' ; then
	cat << EOF
ERROR: non-const variables with static duration make this code non-reentrant

EOF
	STATUS=1
fi

if [ $STATUS -ne 0 ]; then
	echo 'Please refactor this code to avoid mutable global state!'

fi

echo "Exiting with status $STATUS"
exit $STATUS
