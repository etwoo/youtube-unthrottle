#!/usr/bin/env sh

set -euo pipefail

OUTPUT_FILE="$1"
shift

cat << EOF > "$OUTPUT_FILE"
/* Generated by $0 */
#include "coverage.h"
#include "greatest.h"
GREATEST_MAIN_DEFS();
EOF

for filename ; do # iterate over remaining positional parameters
	entrypoint=$(basename "$filename" .c)
	cat <<- EOF
	$(sed -n 's@^SUITE(\(.*\))@SUITE_EXTERN(\1);@p' "$filename")
	int ${entrypoint}(int argc, char **argv);
	int ${entrypoint}(int argc, char **argv)
	{
	    int fd __attribute__((cleanup(coverage_cleanup))) = coverage_open();
	    GREATEST_MAIN_BEGIN();
	$(sed -n 's@^SUITE(\(.*\))@    RUN_SUITE(\1);@p' "$filename")
	    GREATEST_MAIN_END();
	}
	EOF
done >> "$OUTPUT_FILE"
