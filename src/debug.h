#ifndef DEBUG_H
#define DEBUG_H

#include <errno.h>
#include <string.h> /* for strerror() */

/*
 * Log a message at DEBUG level via printf-style format string, along with the
 * callsite's filename and line number.
 */
#define debug(pattern, ...)                                                    \
	debug_at_line(__FILE_NAME__, __LINE__, pattern, ##__VA_ARGS__)

void
debug_at_line(const char *fname, unsigned int lineno, const char *pattern, ...)
	__attribute__((format(printf, 3, 4)));

/*
 * Log a message at INFO level, if <cond> evaluates to true.
 *
 * Use this macro for error conditions that, while helpful to log for
 * diagnostic purposes, need not cause a change in control flow (e.g. early
 * return, break out of loop, jump to function cleanup). This macro applies
 * particularly well to error-handling codepaths that cause little harm if
 * ignored, like errors close()-ing a file descriptor or munmap()-ing a buffer
 * shortly before process exit (which cleans up these resources automatically).
 *
 * info_if() has an advantage over the open-coded alternative, in that the
 * former does not create the appearance of missing line coverage, while the
 * latter does. The two approaches do not truly differ, e.g. condition/decision
 * coverage looks similar in either case, but the superficial difference in
 * line coverage can act as a clue for humans reading coverage reports, in that
 * info_if() signals that a given line has enough test coverage even if we only
 * exercise <cond> == false, while an open-coded version with missing line
 * coverage looks more like a candidate for coverage of <cond> == true.
 */
#define info_if(cond, pattern, ...)                                            \
	while (cond) {                                                         \
		info(pattern, ##__VA_ARGS__);                                  \
		break;                                                         \
	}
/*
 * Like info_if(), with "%m" (aka strerror) appended to <pattern>.
 */
#define info_m_if(cond, pattern, ...)                                          \
	info_if(cond, pattern ": %s", ##__VA_ARGS__, strerror(errno))
/*
 * Log a message at INFO level via printf-style format string, along with the
 * callsite's filename and line number.
 */
#define info(pattern, ...)                                                     \
	info_at_line(__FILE_NAME__, __LINE__, pattern, ##__VA_ARGS__)

void
info_at_line(const char *fname, unsigned int lineno, const char *pattern, ...)
	__attribute__((format(printf, 3, 4)));

#endif
