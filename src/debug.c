#include "debug.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>

static void
vlog(const char *fname, unsigned int lineno, const char *pattern, va_list ap)
{
	fprintf(stderr, "%s:%u: ", fname, lineno);
	vfprintf(stderr, pattern, ap);
	fputc('\n', stderr);

	/* padded/aligned version: */
	/* fprintf(stderr, "%*s:%-*u: ", 13, fname, 3, lineno); */
	/* magic number 13: longest source code filename is 13 chars */
	/* magic number 3: longest source file has 3-digit line count */
}

static bool DEBUG_ENABLED = true;

void
debug_at_line(const char *fname, unsigned int lineno, const char *pattern, ...)
{
	if (!DEBUG_ENABLED) {
		return;
	}

	va_list ap;
	va_start(ap, pattern);
	vlog(fname, lineno, pattern, ap);
	va_end(ap);
}

void
warn_at_line(const char *fname, unsigned int lineno, const char *pattern, ...)
{
	va_list ap;
	va_start(ap, pattern);
	vlog(fname, lineno, pattern, ap);
	va_end(ap);
}
