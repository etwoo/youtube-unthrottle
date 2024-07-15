#include "debug.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>

static void
vlog(const char *level,
     const char *fname,
     unsigned int lineno,
     const char *pattern,
     va_list ap)
{
	fprintf(stderr, "%-*s %s:%u: ", 5, level, fname, lineno);
	/* magic number 5: longest logging level is 5 chars */
	vfprintf(stderr, pattern, ap);
	fputc('\n', stderr);

	/* padded/aligned version: */
	/* fprintf(stderr, "%*s:%-*u: ", 13, fname, 3, lineno); */
	/* magic number 13: longest source code filename is 13 chars */
	/* magic number 3: longest source file has 3-digit line count */
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
	(void)fname;   /* unused */
	(void)lineno;  /* unused */
	(void)pattern; /* unused */
#endif
}

void
warn_at_line(const char *fname, unsigned int lineno, const char *pattern, ...)
{
	va_list ap;
	va_start(ap, pattern);
	vlog("WARN", fname, lineno, pattern, ap);
	va_end(ap);
}
