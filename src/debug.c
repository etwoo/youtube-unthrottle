#include "debug.h"

#include <stdarg.h>
#include <stdio.h>

static __attribute__((format(printf, 4, 0))) void
vlog(const char *level,
     const char *fname,
     unsigned int lineno,
     const char *pattern,
     va_list ap)
{
	fprintf(stderr, "%-*s %s:%u: ", 5, level, fname, lineno);
	/* magic number 5: longest logging level == 5 chars */
	vfprintf(stderr, pattern, ap);
	fputc('\n', stderr);

#if 0
	/* padded/aligned version: */
	fprintf(stderr, "%*s:%-*u: ", 13, fname, 3, lineno);
	/* magic number 13: longest source code filename == 13 chars */
	/* magic number 3: longest source file has 3-digit line count */
#endif
}

void
debug_at_line(const char *fname, unsigned int lineno, const char *pattern, ...)
{
#ifdef WITH_DEBUG_OUTPUT
	va_list ap;
	va_start(ap, pattern);
	vlog("DEBUG", fname, lineno, pattern, ap);
	va_end(ap);
#else
	(void)fname;
	(void)lineno;
	(void)pattern;
#endif
}

void
info_at_line(const char *fname, unsigned int lineno, const char *pattern, ...)
{
	va_list ap;
	va_start(ap, pattern);
	vlog("INFO", fname, lineno, pattern, ap);
	va_end(ap);
}
