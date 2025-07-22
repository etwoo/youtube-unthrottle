#include "sandbox.h"

#if defined(__linux__)
#include "sandbox/linux/landlock.h"
#include "sandbox/linux/seccomp.h"
#elif defined(__APPLE__)
#include "sandbox/darwin/seatbelt.h"
#endif
#include "sys/array.h"
#include "sys/compiler_features.h"
#include "sys/debug.h"

#include <arpa/inet.h>
#include <assert.h>
#if defined(__OpenBSD__)
#include <err.h> /* for err() */
#endif
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h> /* for exit() */
#include <sys/socket.h>
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

sandbox_handle_t
sandbox_init(void)
{
	struct sandbox_context *p = malloc(sizeof(*p));
	if (p) {
		memset(p, 0, sizeof(*p));
	}
	return p;
}

void
sandbox_cleanup(struct sandbox_context *context)
{
	free(context);
}

static const char NEVER_ALLOWED_CANARY[] = "/etc/passwd";

static void
sandbox_verify(const char *const *paths,
               size_t paths_allowed,
               size_t paths_total,
               bool connect_allowed)
{
	int rc = -1;

#if defined(__linux__)
	pid_t target = getpid();
	assert(target > 0);

	/*
	 * Use kill() as a dead man's switch for the sandbox.
	 *
	 * Either seccomp correctly blocks kill(), allowing verification to
	 * proceed, or kill() incorrectly runs, stopping this process before
	 * any unexpected actions can occur.
	 */
	rc = kill(target, SIGKILL);
	assert(rc < 0);
	assert(errno == EACCES);
	debug("sandbox verify: blocked kill()");
#endif

	size_t i = 0;

	/* sanity-check sandbox: explicit path allowlist */
	for (i = 0; i < paths_allowed; ++i) {
		int allowed = open(paths[i], 0);
		assert(allowed >= 0);
		close(allowed);
		debug("sandbox verify: allowed %s", paths[i]);
	}

	/* sanity-check sandbox: implicit path blocklist */
	for (i = paths_allowed; i < paths_total; ++i) {
		int fd = open(paths[i], 0);
		assert(fd < 0);
		assert(errno == EACCES || errno == ENOENT || errno == EPERM);
		debug("sandbox verify: blocked %s", paths[i]);
	}

	{
		int fd = open(NEVER_ALLOWED_CANARY, 0);
		assert(fd < 0);
		assert(errno == EACCES || errno == ENOENT || errno == EPERM);
		debug("sandbox verify: blocked %s", NEVER_ALLOWED_CANARY);
	}

	/* sanity-check sandbox: network connect() */

	int sfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (connect_allowed) {
		assert(sfd >= 0);
	}
#if !defined(__APPLE__)
	else {
		/*
		 * On most platforms, sandboxing blocks socket() entirely.
		 */
		assert(sfd < 0);
		debug("sandbox verify: blocked connect()");
		return;
	}
#endif

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(443);
	inet_pton(AF_INET, "23.192.228.68", &sa.sin_addr); /* example.com */

	rc = connect(sfd, (struct sockaddr *)&sa, sizeof(sa));
	if (connect_allowed) {
		assert(rc == 0);
	}
#if defined(__APPLE__)
	else {
		/*
		 * On macOS, sandboxing allows socket(), then blocks connect().
		 */
		assert(rc != 0);
	}
#endif

	rc = close(sfd);
	assert(rc == 0);
	debug("sandbox verify: %s connect()",
	      connect_allowed ? "allowed" : "blocked");
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
	"/private/tmp",
	"/private/var/tmp",
	"/tmp",
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
	sandbox_verify(ALLOWED_PATHS, sz, sz, true);
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
	sandbox_verify(ALLOWED_PATHS, 0, ARRAY_SIZE(ALLOWED_PATHS), false);
#endif

	debug("%s() succeeded", __func__);
	return RESULT_OK;
}
