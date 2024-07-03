#include "sandbox.h"

#include "array.h"
#include "debug.h"
#include "landlock.h"

#include <assert.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

static const char NEVER_ALLOWED_CANARY[] = "/etc/passwd";

static void
sandbox_verify(const char **paths,
               size_t paths_allowed,
               size_t paths_total,
               bool connect_allowed)
{
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

	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	struct addrinfo *ai = NULL;
	int rc = getaddrinfo("example.com", "443", &hints, &ai);
	assert(rc == 0);

	int sfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	assert(sfd >= 0);

	const bool connected = !connect(sfd, ai->ai_addr, ai->ai_addrlen);
	assert(connected == connect_allowed);
	if (!connect_allowed) {
		assert(errno == EACCES);
	}
	debug("sandbox verify: %s connect()",
	      connect_allowed ? "allowed" : "blocked");

	freeaddrinfo(ai);
	close(sfd);
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

void
sandbox_only_io_inet(void)
{
	const size_t sz = ARRAY_SIZE(ALLOWED_PATHS);
#if defined(__linux__)
	landlock_apply(ALLOWED_PATHS, sz, 443);
#elif defined(__OpenBSD__)
	for (size_t i = 0; i < sz; ++i) {
		if (unveil(ALLOWED_PATHS[i], "r") < 0) {
			pwarn("Error in unveil()");
		}
	}
	if (unveil(NULL, NULL) < 0) {
		pwarn("Error in final unveil()");
	}
	if (pledge("dns inet rpath stdio tmppath", NULL) < 0) {
		pwarn("Error in pledge()");
	}
#endif
	sandbox_verify(ALLOWED_PATHS, sz, sz, true);
}

void
sandbox_only_io(void)
{
#if defined(__linux__)
	landlock_apply(ALLOWED_PATHS, 1, 0);
	sandbox_verify(ALLOWED_PATHS, 1, ARRAY_SIZE(ALLOWED_PATHS), false);
#elif defined(__OpenBSD__)
	if (pledge("stdio", NULL) < 0) {
		pwarn("Error in pledge()");
	}
	/* sandbox_verify() would abort() at this point */
#endif
}
