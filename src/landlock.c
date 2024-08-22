#ifndef _GNU_SOURCE
#define _GNU_SOURCE
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
		error_if(pb.parent_fd < 0,
		         "Cannot open %s for landlock restriction",
			 p);

		error_if(landlock_add_rule(fd,
		                           LANDLOCK_RULE_PATH_BENEATH,
		                           &pb,
		                           0),
			 "Cannot add rule with LANDLOCK_RULE_PATH_BENEATH");

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
	error_if(landlock_add_rule(fd, LANDLOCK_RULE_NET_PORT, &np, 0),
		 "Cannot add rule with LANDLOCK_RULE_NET_PORT");
}

void
landlock_apply(const char **paths, int sz, int port)
{
	struct landlock_ruleset_attr ra = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
		.handled_access_net = LANDLOCK_ACCESS_NET_CONNECT_TCP,
	};

	int fd = landlock_create_ruleset(&ra, sizeof(ra), 0);
	error_if(fd < 0, "Cannot landlock_create_ruleset()");

	if (paths) {
		ruleset_add_rule_paths(fd, paths, sz);
	}

	if (port > 0) {
		ruleset_add_rule_port(fd, port);
	}

	error_if(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0),
	         "Cannot prctl(PR_SET_NO_NEW_PRIVS, ...)");

	error_if(landlock_restrict_self(fd, 0),
	         "Cannot landlock_restrict_self()");

	debug("landlock_apply() succeeded");

	if (fd >= 0 && close(fd) < 0) {
		pwarn("Ignoring error while close()-ing Landlock ruleset fd");
	}
}
