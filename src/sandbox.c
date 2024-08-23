#include "sandbox.h"

#include "array.h"
#include "debug.h"
#include "landlock.h"
#include "seccomp.h"

#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h> /* for exit() */
#include <sys/socket.h>
#include <sysexits.h> /* for EX_OSERR */
#include <unistd.h>

static const char NEVER_ALLOWED_CANARY[] = "/etc/passwd";

static void
sandbox_verify(const char **paths,
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
	 * proceed, or kill() is incorrectly allowed, stopping this process
	 * before any unexpected actions can occur.
	 */
	rc = kill(target, SIGKILL);
	assert(rc < 0);
	assert(errno == EACCES);
	debug("sandbox verify: blocked kill()");
#endif

	size_t i;

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
		assert(errno == EACCES || errno == ENOENT);
		debug("sandbox verify: blocked %s", paths[i]);
	}

	{
		int fd = open(NEVER_ALLOWED_CANARY, 0);
		assert(fd < 0);
		assert(errno == EACCES || errno == ENOENT);
		debug("sandbox verify: blocked %s", NEVER_ALLOWED_CANARY);
	}

	/* sanity-check sandbox: network connect() */

	int sfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (!connect_allowed) {
		assert(sfd < 0);
		goto done;
	}
	assert(connect_allowed);
	assert(sfd >= 0);

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(443);
	inet_pton(AF_INET, "93.184.215.14", &sa.sin_addr); /* example.com */

	rc = connect(sfd, (struct sockaddr *)&sa, sizeof(sa));
	assert(rc == 0);

	rc = close(sfd);
	assert(rc == 0);

done:
	debug("sandbox verify: %s connect()",
	      connect_allowed ? "allowed" : "blocked");
}

static const char *ALLOWED_PATHS[] = {
	/* for temporary files */
	P_tmpdir,
#if defined(__linux__)
	/* for outbound HTTPS */
	"/etc/resolv.conf",
	"/etc/ssl/certs/ca-certificates.crt",
#elif defined(__OpenBSD__)
	/* for outbound HTTPS */
	"/etc/ssl/cert.pem",
#endif
};

static void
sandbox_restrict_filesystem(void)
{
	const size_t sz = ARRAY_SIZE(ALLOWED_PATHS);
#if defined(__linux__)
	landlock_apply(ALLOWED_PATHS, sz, 443);
#elif defined(__OpenBSD__)
	for (size_t i = 0; i < sz; ++i) {
		if (unveil(ALLOWED_PATHS[i], "r") < 0) {
			err(EX_OSERR, "Error in unveil()");
		}
	}
#endif
}

#define SECCOMP_IO_INET_COMMON_FLAGS                                           \
	(SECCOMP_STDIO | SECCOMP_INET | SECCOMP_SANDBOX)

void
sandbox_only_io_inet_tmpfile(void)
{
	sandbox_restrict_filesystem();
#if defined(__linux__)
	seccomp_apply(SECCOMP_IO_INET_COMMON_FLAGS | SECCOMP_TMPFILE);
#elif defined(__OpenBSD__)
	if (pledge("dns inet rpath stdio tmppath unveil", NULL) < 0) {
		err(EX_OSERR, "Error in pledge()");
	}
#endif
	const size_t sz = ARRAY_SIZE(ALLOWED_PATHS);
	sandbox_verify(ALLOWED_PATHS, sz, sz, true);
	debug("%s() succeeded", __FUNCTION__);
}

void
sandbox_only_io_inet_rpath(void)
{
	sandbox_restrict_filesystem();
#if defined(__linux__)
	seccomp_apply(SECCOMP_IO_INET_COMMON_FLAGS | SECCOMP_RPATH);
#elif defined(__OpenBSD__)
	if (pledge("dns inet rpath stdio unveil", NULL) < 0) {
		err(EX_OSERR, "Error in pledge()");
	}
#endif
	const size_t sz = ARRAY_SIZE(ALLOWED_PATHS);
	sandbox_verify(ALLOWED_PATHS, sz, sz, true);
	debug("%s() succeeded", __FUNCTION__);
}

void
sandbox_only_io(void)
{
#if defined(__linux__)
	landlock_apply(ALLOWED_PATHS, 1, 0);
	seccomp_apply(SECCOMP_STDIO);
#elif defined(__OpenBSD__)
	if (unveil(NULL, NULL) < 0) {
		err(EX_OSERR, "Error in final unveil()");
	}
	if (pledge("stdio", NULL) < 0) {
		err(EX_OSERR, "Error in pledge()");
	}
#endif
	/* sandbox_verify() would abort() at this point */
	debug("%s() succeeded", __FUNCTION__);
}
