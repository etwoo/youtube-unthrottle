#include "sandbox.h"

#if defined(__linux__)
#include "sandbox/linux/landlock.h"
#include "sandbox/linux/seccomp.h"
#elif defined(__APPLE__)
#include "sandbox/darwin/seatbelt.h"
#endif
#include "sandbox/verify.h"
#include "sys/array.h"
#include "sys/debug.h"

#if defined(__OpenBSD__)
#include <err.h> /* for err() */
#endif
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h> /* for EX_OSERR */
#include <unistd.h>

struct sandbox_context {
#if defined(__APPLE__)
	struct seatbelt_context seatbelt;
#else
	/*
	 * In C (unlike in C++), empty structs lead to undefined behavior.
	 *
	 * gcc specifically supports empty structs as a GNU extension:
	 *
	 *   https://gcc.gnu.org/onlinedocs/gcc/Empty-Structures.html
	 *
	 * ... and clang seems to match gcc in this regard. Still, leaving this
	 * struct empty produces a compiler warning under -Wpedantic.
	 *
	 * Out of caution, we declare an unused struct member explicitly. In
	 * the future, please remove `ensure_struct_non_empty` on any platforms
	 * that gain genuine struct members, like `struct seatbelt_context`.
	 */
	char ensure_struct_non_empty MAYBE_UNUSED;
#endif
};

struct sandbox_context *
sandbox_init(void)
{
	struct sandbox_context *p = malloc(sizeof(*p));
	if (p) {
		memset(p, 0, sizeof(*p));
	}
	return p;
}

void
sandbox_free(struct sandbox_context *context)
{
	free(context);
}

void
sandbox_cleanup(struct sandbox_context **pp)
{
	sandbox_free(*pp);
}

static const char *const ALLOWED_PATHS[] = {
	/* for temporary files */
	P_tmpdir,
#if defined(__OpenBSD__)
	/* for outbound HTTPS */
	"/etc/ssl/cert.pem",
#elif defined(__linux__)
	/* for outbound HTTPS */
	"/etc/resolv.conf",
	"/etc/ssl/certs/ca-certificates.crt",
#elif defined(__APPLE__)
	/* for other potential locations of temporary files */
	"/tmp",
	"/private/var/tmp",
	"/private/tmp",
	/* for outbound HTTPS */
	"/etc/ssl/cert.pem",
	"/private/etc/ssl/cert.pem",
#endif
};

static WARN_UNUSED result_t
sandbox_with(
#if defined(__OpenBSD__)
	const char *promises
#else
#if defined(__APPLE__)
	struct sandbox_context *context,
#endif
	unsigned flags
#endif
)
{
	const size_t sz = ARRAY_SIZE(ALLOWED_PATHS);
#if defined(__OpenBSD__)
	for (size_t i = 0; i < sz; ++i) {
		if (unveil(ALLOWED_PATHS[i], "r") < 0) {
			err(EX_OSERR, "Error in unveil()");
		}
	}
	if (pledge(promises, NULL) < 0) {
		err(EX_OSERR, "Error in pledge()");
	}
#elif defined(__linux__)
	check(landlock_apply(ALLOWED_PATHS, sz, 443));
	check(seccomp_apply(flags));
#elif defined(__APPLE__)
	check(seatbelt_init(&context->seatbelt));
	check(seatbelt_revoke(&context->seatbelt, ~flags));
#endif
	check(sandbox_verify(ALLOWED_PATHS, sz, sz, true));
	return RESULT_OK;
}

result_t
sandbox_only_io_inet_tmpfile(struct sandbox_context *context MAYBE_UNUSED)
{
	result_t tmp = sandbox_with(
#if defined(__OpenBSD__)
		"dns inet rpath stdio tmppath unveil"
#elif defined(__linux__)
		SECCOMP_STDIO | SECCOMP_INET | SECCOMP_SANDBOX | SECCOMP_TMPFILE
#elif defined(__APPLE__)
		context,
		SEATBELT_INET | SEATBELT_TMPFILE | SEATBELT_RPATH
#endif
	);
	check(tmp);

	debug("%s() succeeded", __func__);
	return RESULT_OK;
}

result_t
sandbox_only_io_inet_rpath(struct sandbox_context *context MAYBE_UNUSED)
{
	result_t tmp = sandbox_with(
#if defined(__OpenBSD__)
		"dns inet rpath stdio unveil"
#elif defined(__linux__)
		SECCOMP_STDIO | SECCOMP_INET | SECCOMP_SANDBOX | SECCOMP_RPATH
#elif defined(__APPLE__)
		context,
		SEATBELT_INET | SEATBELT_RPATH
#endif
	);
	check(tmp);

	debug("%s() succeeded", __func__);
	return RESULT_OK;
}

result_t
sandbox_only_io(struct sandbox_context *context MAYBE_UNUSED)
{
#if defined(__OpenBSD__)
	if (unveil(NULL, NULL) < 0) {
		err(EX_OSERR, "Error in final unveil()");
	}
	if (pledge("stdio", NULL) < 0) {
		err(EX_OSERR, "Error in pledge()");
	}
#elif defined(__linux__)
	check(landlock_apply(NULL, 0, 0));
	check(seccomp_apply(SECCOMP_STDIO));
#elif defined(__APPLE__)
	check(seatbelt_init(&context->seatbelt));
	check(seatbelt_revoke(&context->seatbelt, 0xFFFFFFFF));
#endif

#if defined(__OpenBSD__)
	/* skip -- sandbox_verify() would abort() due to pledge() restriction */
#else
	const size_t sz = ARRAY_SIZE(ALLOWED_PATHS);
	check(sandbox_verify(ALLOWED_PATHS, 0, sz, false));
#endif

	debug("%s() succeeded", __func__);
	return RESULT_OK;
}
