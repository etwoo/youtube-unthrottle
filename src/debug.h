#ifndef DEBUG_H
#define DEBUG_H

#include <errno.h>
#include <string.h> /* for strerror() */

#define debug(pattern, ...)                                                    \
	debug_at_line(__FILE__, __LINE__, pattern, ##__VA_ARGS__)

void
debug_at_line(const char *fname, unsigned int lineno, const char *pattern, ...)
	__attribute__((format(printf, 3, 4)));

#define warn(pattern, ...)                                                     \
	warn_at_line(__FILE__, __LINE__, pattern, ##__VA_ARGS__)

#define pwarn(msg, ...) warn("%s: %s", msg, strerror(errno))

void
warn_at_line(const char *fname, unsigned int lineno, const char *pattern, ...)
	__attribute__((format(printf, 3, 4)));

#endif
