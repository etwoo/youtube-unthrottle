#ifndef REGEX_H
#define REGEX_H

#include <stdbool.h>
#include <stddef.h> /* for size_t */

bool re_capture(const char *pattern_in,
                const char *subject_in,
                size_t sz,
                const char **capture_p,
                size_t *capture_sz);

bool re_capturef(const char *subject_in,
                 size_t sz,
                 const char **capture_p,
                 size_t *capture_sz,
                 const char *my_format,
                 ...) __attribute__((format(printf, 5, 6)));

bool
re_pattern_escape(const char *in, size_t in_sz, char *out, size_t out_capacity);

#endif
