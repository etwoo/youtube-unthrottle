#include "sandbox.h"

#include "array.h"
#include "debug.h"
#include "landlock.h"
#include "seccomp.h"

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

static const char NEVER_ALLOWED_CANARY[] = "/etc/passwd";

static WARN_UNUSED int
check_socket(void)
{
	return socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
}

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
	 * proceed, or kill() incorrectly runs, stopping this process before
	 * any unexpected actions can occur.
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

	if (!connect_allowed) {
		int sfd = check_socket();
		assert(sfd < 0);
		debug("sandbox verify: blocked connect()");
		return;
	}

	assert(connect_allowed);
	int sfd = check_socket();
	assert(sfd >= 0);

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(443);
	inet_pton(AF_INET, "23.192.228.68", &sa.sin_addr); /* example.com */

	rc = connect(sfd, (struct sockaddr *)&sa, sizeof(sa));
	assert(rc == 0);

	rc = close(sfd);
	assert(rc == 0);
	debug("sandbox verify: allowed connect()");
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

static WARN_UNUSED result_t
sandbox_with(unsigned flags, const char *promises)
{
	const size_t sz = ARRAY_SIZE(ALLOWED_PATHS);
#if defined(__linux__)
	(void)promises; /* unused */
	check(landlock_apply(ALLOWED_PATHS, sz, 443));
	check(seccomp_apply(SECCOMP_STDIO | SECCOMP_INET | SECCOMP_SANDBOX |
	                    flags));
#elif defined(__OpenBSD__)
	(void)flags; /* unused */
	for (size_t i = 0; i < sz; ++i) {
		if (unveil(ALLOWED_PATHS[i], "r") < 0) {
			err(EX_OSERR, "Error in unveil()");
		}
	}
	if (pledge(promises, NULL) < 0) {
		err(EX_OSERR, "Error in pledge()");
	}
#endif
	sandbox_verify(ALLOWED_PATHS, sz, sz, true);
	return RESULT_OK;
}

result_t
sandbox_only_io_inet_tmpfile(void)
{
	const char *promises = "dns inet rpath stdio tmppath unveil";
	check(sandbox_with(SECCOMP_TMPFILE, promises));
	debug("%s() succeeded", __func__);
	return RESULT_OK;
}

result_t
sandbox_only_io_inet_rpath(void)
{
	const char *promises = "dns inet rpath stdio unveil";
	check(sandbox_with(SECCOMP_RPATH, promises));
	debug("%s() succeeded", __func__);
	return RESULT_OK;
}

result_t
sandbox_only_io(void)
{
#if defined(__linux__)
	check(landlock_apply(NULL, 0, 0));
	check(seccomp_apply(SECCOMP_STDIO));
	sandbox_verify(ALLOWED_PATHS, 0, ARRAY_SIZE(ALLOWED_PATHS), false);
#elif defined(__OpenBSD__)
	if (unveil(NULL, NULL) < 0) {
		err(EX_OSERR, "Error in final unveil()");
	}
	if (pledge("stdio", NULL) < 0) {
		err(EX_OSERR, "Error in pledge()");
	}
	/* sandbox_verify() would abort() here due to pledge() restrictions */
#endif
	debug("%s() succeeded", __func__);
	return RESULT_OK;
}
