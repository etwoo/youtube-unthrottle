#!/usr/bin/env sh

set -euo pipefail

CMD="$1"
shift

function t
{
	local -r pattern="$1"
	shift

	echo -n "Expecting \"$pattern\" from \`$(basename "$CMD") $*\` ... "
	local -r output=$($CMD "$@" 2>&1)

	if echo "$output" | grep -qE "$pattern" ; then
		echo "PASS"
	else
		echo -e "FAIL on output:\n$output"
		exit 1
	fi
}

t "Missing URL"

t "Missing --proof-of-origin" foo.test
t "Missing --proof-of-origin" foo.test --proof-of-origin ""
t "requires an argument" foo.test --proof-of-origin

t "Missing --visitor-data" foo.test --proof-of-origin p
t "Missing --visitor-data" foo.test --proof-of-origin p --visitor-data ""
t "requires an argument" foo.test --proof-of-origin p --visitor-data

t "Invalid --quality" foo.test --proof-of-origin p --visitor-data v --quality +
t "requires an argument" foo.test --proof-of-origin p --visitor-data v --quality

t "un(recognized|known)" --foobar
t "un(recognized|known)" foo.test --proof-of-origin p --visitor-data v --foobar
t "un(recognized|known)" --help --foobar
t "un(recognized|known)" --sandbox --foobar
