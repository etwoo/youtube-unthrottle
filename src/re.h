#ifndef REGEX_H
#define REGEX_H

#include "compiler_features.h"

#include <stdbool.h>
#include <stddef.h> /* for size_t */

bool re_capture(const char *pattern_in,
                const char *subject_in,
                size_t sz,
                const char **capture_p,
                size_t *capture_sz) WARN_UNUSED;

#endif
