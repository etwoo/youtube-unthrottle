#ifndef DEBUG_H
#define DEBUG_H

#include <errno.h>
#include <error.h>
#include <string.h> /* for strerror() */

#define debug(pattern, ...)                                                    \
	debug_at_line(__FILE_NAME__, __LINE__, pattern, ##__VA_ARGS__)

void
debug_at_line(const char *fname, unsigned int lineno, const char *pattern, ...)
	__attribute__((format(printf, 3, 4)));

#define warn(pattern, ...)                                                     \
	warn_at_line(__FILE_NAME__, __LINE__, pattern, ##__VA_ARGS__)

#define warn_if(cond, pattern, ...)                                            \
	do {                                                                   \
		if (!(cond)) {                                                 \
			break;                                                 \
		}                                                              \
		warn(pattern ": %s", ##__VA_ARGS__, strerror(errno));          \
	} while (0);

#define pwarn(msg) warn("%s: %s", msg, strerror(errno))

void
warn_at_line(const char *fname, unsigned int lineno, const char *pattern, ...)
	__attribute__((format(printf, 3, 4)));

#define error_if(cond, pattern, ...)                                           \
	do {                                                                   \
		if (!(cond)) {                                                 \
			break;                                                 \
		}                                                              \
		error_at_line(1,                                               \
		              errno,                                           \
		              __FILE_NAME__,                                   \
		              __LINE__,                                        \
		              "ERROR: " pattern,                               \
		              ##__VA_ARGS__);                                  \
	} while (0);

#endif
