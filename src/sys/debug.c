#include "sys/debug.h"

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
}

void
debug_at_line(const char *fname, unsigned int lineno, const char *pattern, ...)
{
#ifdef WITH_DEBUG_LOG
	va_list ap; // NOLINT(cppcoreguidelines-init-variables)
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
	va_list ap; // NOLINT(cppcoreguidelines-init-variables)
	va_start(ap, pattern);
	vlog("INFO", fname, lineno, pattern, ap);
	va_end(ap);
}
