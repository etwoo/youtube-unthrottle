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
 * Log a message at INFO level, if <cond> is true.
 *
 * This macro is useful for error conditions that, while useful to log for
 * diagnostic purposes, need not cause a change in control flow (e.g. early
 * return, break out of loop, jump to function cleanup). This macro is
 * particularly suitable for error-handling codepaths that are relatively
 * harmless to ignore, like errors close()-ing a file descriptor or
 * munmap()-ing a buffer shortly before process exit (which cleans up these
 * resources automatically).
 *
 * One benefit of info_if() over the open-coded equivalent is that the former
 * does not create the appearance of missing line coverage, unlike the latter.
 * Branch coverage (aka condition/decision coverage) looks similar in either
 * case, and in truth, there is no real difference in code coverage. However,
 * the surface-level difference in line coverage can act as an annotation to
 * people reading code coverage reports, in that info_if() signals that a given
 * line is sufficiently covered even if only (cond == false) is covered, while
 * an open-coded equivalent with missing line coverage looks more obviously
 * like a candidate for test coverage that exercises (cond == true).
 */
#define info_if(cond, pattern, ...)                                            \
	while (cond) {                                                         \
		info(pattern, ##__VA_ARGS__);                                  \
		break;                                                         \
	}
/*
 * Like info_if(), with "%m" equivalent appended to <pattern>.
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
