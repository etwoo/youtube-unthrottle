#ifndef REGEX_H
#define REGEX_H

#include "result.h"
#include "sys/compiler_features.h"
#include "sys/string_view.h"

/*
 * Find <pattern_in> within <subject_in>.
 *
 * Note: <pattern_in> must contain exactly one capture group.
 *
 * Return value:
 *
 * If <pattern_in> matches, return OK and update <capture>.
 *
 * If <pattern_in> evaluates successfully but does not match, return OK and
 * reinitialize <capture>, i.e. zero-out the <capture> struct.
 *
 * If evaluating <pattern_in> and <subject_in> fails, leading to an
 * indeterminate state, return a non-OK result_t.
 */
result_t re_capture(const char *pattern_in,
                    const struct string_view *subject_in,
                    struct string_view *capture) WARN_UNUSED;

#endif
