#include "sandbox.h"

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif
#define __SANE_USERSPACE_TYPES__

/*
 * Some helpful Landlock references:
 *
 *   https://lwn.net/Articles/859908/
 *   https://docs.kernel.org/userspace-api/landlock.html
 *
 * There is BSD-licensed sample code in the Linux kernel repo, as well:
 *
 *   samples/landlock/sandboxer.c
 */
#include <fcntl.h>
#include <linux/landlock.h>
#include <linux/prctl.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#undef _GNU_SOURCE /* revert for any other includes */

#include "debug.h"

#ifndef landlock_create_ruleset
static inline int
landlock_create_ruleset(const struct landlock_ruleset_attr *const attr,
                        const size_t size,
                        const __u32 flags)
{
	return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
#endif

#ifndef landlock_add_rule
static inline int
landlock_add_rule(const int ruleset_fd,
                  const enum landlock_rule_type rule_type,
                  const void *const rule_attr,
                  const __u32 flags)
{
	return syscall(__NR_landlock_add_rule,
	               ruleset_fd,
	               rule_type,
	               rule_attr,
	               flags);
}
#endif

#ifndef landlock_restrict_self
static inline int
landlock_restrict_self(const int ruleset_fd, const __u32 flags)
{
	return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}
#endif

// TODO: update README.md with sandboxing as one of the learning topics
void
enter_chroot(void)
{
}
/* TODO on OpenBSD: unveil("/tmp", "rw"); unveil(NULL, NULL); */

static const char *ALLOWED[] = {
	/* for temporary files */
	P_tmpdir,
	/* for DNS and SSL/TLS */
	"/etc/resolv.conf",
	"/etc/ssl/certs/ca-certificates.crt",
};

/* TODO: consider failing closed instead of open, abort() on failure? */
void
require_only_io_inet(void)
{
	int fd = -1; /* guarantee fd is invalid by default */
	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
		.handled_access_net = LANDLOCK_ACCESS_NET_CONNECT_TCP,
	};
	struct landlock_path_beneath_attr pb = {
		.allowed_access = ruleset_attr.handled_access_fs,
		.parent_fd = -1, /* guarantee fd is invalid by default */
	};
	struct landlock_net_port_attr np = {
		.allowed_access = ruleset_attr.handled_access_net,
		.port = 443, /* for DNS */
	};

	fd = landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
	if (fd < 0) {
		pwarn("Error in landlock_create_ruleset()");
		goto cleanup;
	}

	for (size_t i = 0; i < ARRAY_SIZE(ALLOWED); ++i) {
		const char *p = ALLOWED[i];

		pb.parent_fd = open(p, O_PATH);
		if (pb.parent_fd < 0) {
			warn("Error opening %s for landlock restriction", p);
			goto cleanup;
		}

		if (landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &pb, 0)) {
			pwarn("Error in LANDLOCK_RULE_PATH_BENEATH");
			goto cleanup;
		}

		if (close(pb.parent_fd) < 0) {
			pwarn("Error while close()-ing Landlock paths fd");
			pb.parent_fd = -1; /* avoid double-close() on cleanup */
			goto cleanup;
		}

		pb.parent_fd = -1;
	}

	if (landlock_add_rule(fd, LANDLOCK_RULE_NET_PORT, &np, 0)) {
		pwarn("Error in LANDLOCK_RULE_NET_PORT");
		goto cleanup;
	}

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		pwarn("Error in prctl(PR_SET_NO_NEW_PRIVS, ...)");
		goto cleanup;
	}

	if (landlock_restrict_self(fd, 0)) {
		pwarn("Error in landlock_restrict_self()");
		goto cleanup;
	}

	debug("require_only_io_inet() succeeded");

cleanup:
	if (pb.parent_fd >= 0 && close(pb.parent_fd) < 0) {
		pwarn("Ignoring error while close()-ing Landlock paths fd");
	}
	if (fd >= 0 && close(fd) < 0) {
		pwarn("Ignoring error while close()-ing Landlock ruleset fd");
	}
}
/* TODO on openbsd: pledge("inet rpath stdio tmppath") */

void
require_only_io(void)
{
	/* TODO: try empty ruleset, see if read/write fails as expected */
}
/* TODO on OpenBSD: pledge("stdio") */
