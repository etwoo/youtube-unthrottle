#ifndef REGEX_H
#define REGEX_H

#include "compiler_features.h"
#include "string_view.h"

#include <stdbool.h>

bool re_capture(const char *pattern_in,
                const struct string_view *subject_in,
                struct string_view *capture) WARN_UNUSED;

#endif
