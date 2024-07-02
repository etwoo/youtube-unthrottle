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
#include <linux/landlock.h>
#include <sys/syscall.h>
#include <unistd.h>

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

#undef _GNU_SOURCE /* revert for any other includes */

#include "debug.h"
#include "landlock.h"

#include <fcntl.h>
#include <linux/prctl.h>
#include <sys/prctl.h>

static void
ruleset_add_rule_paths(int fd, const char **paths, size_t sz)
{
	struct landlock_path_beneath_attr pb = {
		.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE,
		.parent_fd = -1, /* guarantee fd is invalid by default */
	};

	for (size_t i = 0; i < sz; ++i) {
		const char *p = paths[i];

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

cleanup:
	if (pb.parent_fd >= 0 && close(pb.parent_fd) < 0) {
		pwarn("Ignoring error while close()-ing Landlock paths fd");
	}
}

static void
ruleset_add_rule_port(int fd, int port)
{
	struct landlock_net_port_attr np = {
		.allowed_access = LANDLOCK_ACCESS_NET_CONNECT_TCP,
		.port = port,
	};

	if (landlock_add_rule(fd, LANDLOCK_RULE_NET_PORT, &np, 0)) {
		pwarn("Error in LANDLOCK_RULE_NET_PORT");
		goto cleanup;
	}

cleanup:
	/* no particular cleanup to do (yet) */
}

void
landlock_apply(const char **paths, int sz, const int *port)
{
	int fd = -1;
	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
		.handled_access_net = LANDLOCK_ACCESS_NET_CONNECT_TCP,
	};

	fd = landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
	if (fd < 0) {
		pwarn("Error in landlock_create_ruleset()");
		goto cleanup;
	}

	if (paths) {
		ruleset_add_rule_paths(fd, paths, sz);
	}

	if (port) {
		ruleset_add_rule_port(fd, *port);
	}

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		pwarn("Error in prctl(PR_SET_NO_NEW_PRIVS, ...)");
		goto cleanup;
	}

	if (landlock_restrict_self(fd, 0)) {
		pwarn("Error in landlock_restrict_self()");
		goto cleanup;
	}

	debug("ruleset_apply() succeeded");

cleanup:
	if (fd >= 0 && close(fd) < 0) {
		pwarn("Ignoring error while close()-ing Landlock ruleset fd");
	}
}
