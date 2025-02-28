#include "sandbox.h"

#include "array.h"
#include "debug.h"
#include "landlock.h"
#include "seccomp.h"

#include <arpa/inet.h>
#include <assert.h>
#if defined(__OpenBSD__) || defined(__APPLE__)
#include <err.h> /* for err() */
#endif
#include <fcntl.h>
#include <netdb.h>
#if defined(__APPLE__)
#include <sandbox.h>
#endif
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

	int sfd = check_socket();
	if (connect_allowed) {
		assert(sfd >= 0);
	}
#if !defined(__APPLE__)
	else {
		assert(sfd < 0);
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
		assert(rc != 0);
	}
#endif

	rc = close(sfd);
	assert(rc == 0);
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
#elif defined(__APPLE__)
	/* check other potential locations for temporary files */
	"/private/tmp",
	"/private/var/tmp",
	"/tmp",
#endif
};

#if defined(__APPLE__)

/*
 * Some helpful macOS sandbox (aka Seatbelt) references:
 *
 * https://newosxbook.com/files/HITSB.pdf
 * https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/
 * http://www.semantiscope.com/research/BHDC2011/BHDC2011-Paper.pdf
 * https://bdash.net.nz/posts/sandboxing-on-macos/
 * https://searchfox.org/mozilla-central/source/security/sandbox/mac/
 * https://github.com/chromium/chromium/tree/main/sandbox/mac
 * https://github.com/chromium/chromium/tree/main/sandbox/policy/mac
 * https://github.com/steven-michaud/SandboxMirror/blob/master/app-sandbox.md
 * https://github.com/kristapsdz/oconfigure/blob/master/test-sandbox_init.c
 * https://github.com/opa334/opainject/blob/main/sandbox.h
 */
static const char MACOS_SEATBELT_POLICY[] =
	"(version 1)\n"
	"\n"
	"(deny default)\n"
	/* not already covered by (deny default) */
	"(deny process-info*)\n"
	"(deny nvram*)\n"
	"(deny iokit-get-properties)\n"
	"(deny file-map-executable)\n"
	"\n"
	"(allow file-read*\n"
	"  (require-all\n"
	"    (require-any\n"
	"      (subpath \"/private/tmp\")\n"
	"      (subpath \"/private/var/tmp\")\n"
	"      (literal \"/tmp\")\n"
	"      (literal \"/var\")\n"
	"      (literal \"/var/tmp\"))\n"
	"    (extension \"com.apple.app-sandbox.read\")))\n"
	"\n"
	"(allow file-read* file-write*\n"
	"  (require-all\n"
	"    (require-any\n"
	"      (subpath \"/private/tmp\")\n"
	"      (subpath \"/private/var/tmp\")\n"
	"      (literal \"/tmp\")\n"
	"      (literal \"/var\")\n"
	"      (literal \"/var/tmp\"))\n"
	"    (extension \"com.apple.app-sandbox.write\")))\n"
	"\n"
	"(allow network-outbound\n"
	"  (require-all\n"
	"    (require-any\n"
	"      (control-name \"com.apple.netsrc\")\n"
	"      (literal \"/private/var/run/mDNSResponder\")\n"
	"      (remote tcp))\n"
	"    (extension \"com.apple.security.network.client\")))\n";

char *sandbox_extension_issue_generic(const char *eclass, uint32_t flags);
int64_t sandbox_extension_consume(const char *extension_token);
int sandbox_extension_release(int64_t extension_handle);
int sandbox_init(const char *profile, uint64_t flags, char **errorbuf);
void sandbox_free_error(char *errorbuf);

const unsigned MACOS_SEATBELT_TMPFILE = 0x01;
const unsigned MACOS_SEATBELT_RPATH = 0x02;
const unsigned MACOS_SEATBELT_INET = 0x04;

#define sandbox_extend(x) sandbox_extension_issue_generic(x, 0)

#endif

static int64_t X_TMPFILE = -1;
static int64_t X_RPATH = -1;
static int64_t X_INET = -1;

static WARN_UNUSED result_t
sandbox_with(
#if defined(__linux__) || defined(__APPLE__)
	unsigned flags
#elif defined(__OpenBSD__)
	const char *promises
#endif
	)
{
	const size_t sz = ARRAY_SIZE(ALLOWED_PATHS);
#if defined(__linux__)
	check(landlock_apply(ALLOWED_PATHS, sz, 443));
	check(seccomp_apply(SECCOMP_STDIO | SECCOMP_INET | SECCOMP_SANDBOX |
	                    flags));
#elif defined(__OpenBSD__)
	for (size_t i = 0; i < sz; ++i) {
		if (unveil(ALLOWED_PATHS[i], "r") < 0) {
			err(EX_OSERR, "Error in unveil()");
		}
	}
	if (pledge(promises, NULL) < 0) {
		err(EX_OSERR, "Error in pledge()");
	}
#elif defined(__APPLE__)
	char *token_tmpfile = NULL;
	if (0 != (flags & MACOS_SEATBELT_TMPFILE) && X_TMPFILE < 0) {
		token_tmpfile = sandbox_extend("com.apple.app-sandbox.write");
		if (token_tmpfile == NULL) {
			err(EX_OSERR, "Error in Seatbelt extension create tmpfile");
		}
	} else if (0 == (flags & MACOS_SEATBELT_TMPFILE) && X_TMPFILE >= 0) {
		if (sandbox_extension_release(X_TMPFILE) < 0) {
			err(EX_OSERR, "Error in Seatbelt extension release tmpfile");
		}
		X_TMPFILE = -1;
		debug("Seatbelt tmpfile extension release succeeded");
	}
	// TODO: dedup copy-pasta below
	char *token_rpath = NULL;
	if (0 != (flags & (MACOS_SEATBELT_RPATH|MACOS_SEATBELT_TMPFILE)) && X_RPATH < 0) {
		token_rpath = sandbox_extend("com.apple.app-sandbox.read");
		if (token_rpath == NULL) {
			err(EX_OSERR, "Error in Seatbelt extension create rpath");
		}
	} else if (0 == (flags & MACOS_SEATBELT_RPATH) && X_RPATH >= 0) {
		if (sandbox_extension_release(X_RPATH) < 0) {
			err(EX_OSERR, "Error in Seatbelt extension release rpath");
		}
		debug("Seatbelt rpath extension release succeeded");
		X_RPATH = -1;
	}
	// TODO: dedup copy-pasta below
	char *token_inet = NULL;
	if (0 != (flags & MACOS_SEATBELT_INET) && X_INET < 0) {
		token_inet = sandbox_extend("com.apple.security.network.client");
		if (token_inet == NULL) {
			err(EX_OSERR, "Error in Seatbelt extension create inet");
		}
	} else if (0 == (flags & MACOS_SEATBELT_INET) && X_INET >= 0) {
		if (sandbox_extension_release(X_INET) < 0) {
			err(EX_OSERR, "Error in Seatbelt extension release inet");
		}
		debug("Seatbelt inet extension release succeeded");
		X_INET = -1;
	}

	static bool seatbelt_init = false; // TODO: convert to context variable passed into sandbox functions, to avoid mutable global state
	if (seatbelt_init == false) {
		char *ep = NULL;
		if (sandbox_init(MACOS_SEATBELT_POLICY, 0, &ep) < 0) {
			err(EX_OSERR, "Error in Seatbelt init");
			sandbox_free_error(ep);
		}
		debug("Seatbelt init succeeded");
		if (token_tmpfile) {
			X_TMPFILE = sandbox_extension_consume(token_tmpfile);
			if (X_TMPFILE < 0) {
				err(EX_OSERR, "Error in Seatbelt consume tmpfile");
			}
			debug("Seatbelt tmpfile extension consume succeeded");
		}
		// TODO: dedup copy-pasta below
		if (token_rpath) {
			X_RPATH = sandbox_extension_consume(token_rpath);
			if (X_RPATH < 0) {
				err(EX_OSERR, "Error in Seatbelt consume rpath");
			}
			debug("Seatbelt rpath extension consume succeeded");
		}
		// TODO: dedup copy-pasta below
		if (token_inet) {
			X_INET = sandbox_extension_consume(token_inet);
			if (X_INET < 0) {
				err(EX_OSERR, "Error in Seatbelt consume inet");
			}
			debug("Seatbelt inet extension consume succeeded");
		}
		seatbelt_init = true;
	}
#endif
	// TODO: consolidate with sandbox_verify() invocation in sandbox_only_io(), avoid verifying sandbox twice when calling sandbox_only_io()
	sandbox_verify(ALLOWED_PATHS, (flags != 0) ? sz : 0, sz, flags != 0);
	return RESULT_OK;
}

result_t
sandbox_only_io_inet_tmpfile(void)
{
	result_t tmp = sandbox_with(
#if defined(__linux__)
			   SECCOMP_TMPFILE
#elif defined(__OpenBSD__)
			   "dns inet rpath stdio tmppath unveil"
#elif defined(__APPLE__)
			   MACOS_SEATBELT_INET|MACOS_SEATBELT_TMPFILE
#endif
	);
	check(tmp);

	debug("%s() succeeded", __func__);
	return RESULT_OK;
}

result_t
sandbox_only_io_inet_rpath(void)
{
	result_t tmp = sandbox_with(
#if defined(__linux__)
			   SECCOMP_RPATH
#elif defined(__OpenBSD__)
			   "dns inet rpath stdio unveil"
#elif defined(__APPLE__)
			   MACOS_SEATBELT_INET|MACOS_SEATBELT_RPATH
#endif
	);
	check(tmp);

	debug("%s() succeeded", __func__);
	return RESULT_OK;
}

result_t
sandbox_only_io(void)
{
#if defined(__linux__)
	check(landlock_apply(NULL, 0, 0));
	check(seccomp_apply(SECCOMP_STDIO));
#elif defined(__OpenBSD__)
	if (unveil(NULL, NULL) < 0) {
		err(EX_OSERR, "Error in final unveil()");
	}
	if (pledge("stdio", NULL) < 0) {
		err(EX_OSERR, "Error in pledge()");
	}
#elif defined(__APPLE__)
	check(sandbox_with(0));
#endif

#if defined(__OpenBSD__)
	/* skip -- sandbox_verify() would abort() due to pledge() restriction */
#else
	sandbox_verify(ALLOWED_PATHS, 0, ARRAY_SIZE(ALLOWED_PATHS), false);
#endif

	debug("%s() succeeded", __func__);
	return RESULT_OK;
}
