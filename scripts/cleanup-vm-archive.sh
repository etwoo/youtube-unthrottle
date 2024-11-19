#!/usr/bin/env sh

set -euo pipefail

DST_DIRECTORY="$1"

if [ ! -d "$DST_DIRECTORY" ] ; then
	echo "Decompressed dir does not exist: $DST_DIRECTORY; no-op success"
	exit 0
fi

echo "Before cleanup:"
find "$DST_DIRECTORY"

#
# Delete files in $DST_DIRECTORY that are marked as coming from cache, while
# taking care not to perturb any other files created by another process
# generating new, updated artifacts (i.e. cache miss -> cache repopulate).
#
find "$DST_DIRECTORY" -type f -name '*.please_delete' | while read -r cur ; do
	echo "Cleanup: $cur"
	echo "Cleanup: ${cur%.*}"
	rm -- "$cur" "${cur%.*}"
done
rmdir --ignore-fail-on-non-empty "$DST_DIRECTORY"

echo "After cleanup:"
if [ -d "$DST_DIRECTORY" ] ; then
	find "$DST_DIRECTORY"
fi
