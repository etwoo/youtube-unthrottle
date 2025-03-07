#ifndef SEATBELT_OS_API_H
#define SEATBELT_OS_API_H

/*
 * Include this header file to work around deprecation warnings and missing
 * declarations in the macOS platform headers, aka /usr/local/include/sandbox.h
 *
 * Although these platform APIs lack official documentation, important software
 * projects like Chrome and Firefox rely on them, making these APIs unlikely to
 * disappear despite their deprecation status.
 */

#include <stdint.h>

int sandbox_init_with_parameters(const char *,
                                 uint64_t,
                                 const char **const,
                                 char **);

void sandbox_free_error(char *);

char *sandbox_extension_issue_generic(const char *, uint32_t);
int64_t sandbox_extension_consume(const char *);
int sandbox_extension_release(int64_t);

#endif
