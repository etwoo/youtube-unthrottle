#include "sandbox/verify.h"

#include "sys/debug.h"

#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

#pragma GCC diagnostic push
#if defined(__GNUC__) && !defined(__clang__)
/*
 * gcc-15's -Wanalyzer-fd-leak check does not seem to understand how
 * __attribute__((cleanup)) closes the test socket in sandbox_verify()
 * on certain error paths, like when verify(sfd < 0) fails and triggers
 * an early return.
 *
 * The analyzer in particular does not seem to see that (sfd >= 0) in
 * the body of sandbox_verify() guarantees that (*file_or_socket >= 0)
 * in descriptor_cleanup().
 *
 * If `gcc -fanalyzer` handles this scenario differently in the future,
 * we can remove the #pragma directives surrounding sandbox_verify() and
 * its helper functions.
 */
#pragma GCC diagnostic ignored "-Wanalyzer-fd-leak"
#endif

static void
descriptor_cleanup(const int *file_or_socket)
{
	info_m_if(*file_or_socket >= 0 && close(*file_or_socket) < 0,
	          "Ignoring error close()-ing test descriptor");
}

#define auto_descriptor int __attribute__((cleanup(descriptor_cleanup)))

static WARN_UNUSED int
open_file(int *fd, const char *path)
{
	*fd = open(path, 0);
	return *fd;
}

static WARN_UNUSED int
open_socket(int *sfd)
{
	*sfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	return *sfd;
}

#define verify(cond)                                                           \
	do {                                                                   \
		if (cond) {                                                    \
			debug("sandbox check passed: " #cond);                 \
		} else {                                                       \
			info("sandbox check failed: " #cond);                  \
			return make_result(ERR_SANDBOX_VERIFY, #cond);         \
		}                                                              \
	} while (0)

static const char NEVER_ALLOWED_CANARY[] = "/etc/passwd";

result_t
sandbox_verify(const char *const *paths,
               size_t paths_allowed,
               size_t paths_total,
               bool network_allowed)
{
#if defined(__linux__)
	/*
	 * Use kill() as a dead man's switch for the sandbox.
	 *
	 * Either seccomp correctly blocks kill(), allowing verification to
	 * proceed, or kill() incorrectly runs, stopping this process before
	 * any unexpected actions can occur.
	 */
	verify(kill(getpid(), SIGKILL) < 0);
	verify(errno == EACCES);
	debug("%s(): blocked kill()", __func__);
#endif

	/* sanity-check sandbox: explicit path allowlist */
	for (size_t i = 0; i < paths_allowed; ++i) {
		auto_descriptor fd = -1;
		verify(open_file(&fd, paths[i]) >= 0);
		debug("%s(): allowed %s", __func__, paths[i]);
	}

	/* sanity-check sandbox: implicit path blocklist */
	for (size_t i = paths_allowed; i < paths_total; ++i) {
		auto_descriptor fd = -1;
		verify(open_file(&fd, paths[i]) < 0);
		verify(errno == EACCES || errno == ENOENT || errno == EPERM);
		debug("%s(): blocked %s", __func__, paths[i]);
	}

	{
		auto_descriptor fd = -1;
		verify(open_file(&fd, NEVER_ALLOWED_CANARY) < 0);
		verify(errno == EACCES || errno == ENOENT || errno == EPERM);
		debug("%s(): blocked %s", __func__, NEVER_ALLOWED_CANARY);
	}

	/* sanity-check sandbox: network connect() */

	auto_descriptor sfd = -1;
#if !defined(__APPLE__)
	if (!network_allowed) {
		/*
		 * On most platforms, sandboxing blocks socket() entirely.
		 */
		verify(open_socket(&sfd) < 0);
		debug("%s(): blocked socket()", __func__);
		return RESULT_OK;
	}
#endif
	verify(open_socket(&sfd) >= 0);

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(443);
	inet_pton(AF_INET, "23.192.228.68", &sa.sin_addr); /* example.com */

#if defined(__APPLE__)
	if (!network_allowed) {
		/*
		 * On macOS, sandboxing allows socket(), then blocks connect().
		 */
		verify(connect(sfd, (struct sockaddr *)&sa, sizeof(sa)) != 0);
		debug("%s(): blocked connect()", __func__);
		return RESULT_OK;
	}
#endif
	verify(connect(sfd, (struct sockaddr *)&sa, sizeof(sa)) == 0);
	debug("%s(): allowed socket() and connect()", __func__);

	assert(network_allowed && "Mistakes in OS-specific #if macros above?");
	return RESULT_OK;
}

#undef auto_descriptor
#undef verify

#pragma GCC diagnostic pop /* restore -Wanalyzer-fd-leak */
