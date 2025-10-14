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
 * The Linux kernel repository contains BSD-licensed sample code, as well:
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
	return (int)syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
#endif

#ifndef landlock_add_rule
static inline int
landlock_add_rule(const int ruleset_fd,
                  const enum landlock_rule_type rule_type,
                  const void *const rule_attr,
                  const __u32 flags)
{
	return (int)syscall(__NR_landlock_add_rule,
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
	return (int)syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}
#endif

#undef _GNU_SOURCE /* revert for any other includes */

#include "sandbox/linux/landlock.h"
#include "sys/debug.h"

#include <fcntl.h>
#include <linux/prctl.h>
#include <stdbool.h>
#include <sys/prctl.h>

static WARN_UNUSED result_t
ruleset_add_one(int fd, const char *path, struct landlock_path_beneath_attr *pb)
{
	int rc = 0;

	pb->parent_fd = open(path, O_PATH);
	const bool opened = (pb->parent_fd >= 0);
	check_if(!opened, ERR_SANDBOX_LANDLOCK_OPEN_O_PATH, errno, path);

	rc = landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, pb, 0);
	check_if(rc < 0, ERR_SANDBOX_LANDLOCK_ADD_RULE_PATH, errno, path);

	rc = close(pb->parent_fd);
	info_m_if(rc < 0, "Ignoring error close()-ing Landlock paths fd");
	pb->parent_fd = -1;

	return RESULT_OK;
}

static WARN_UNUSED result_t
ruleset_add_rule_paths(int fd, const char *const *paths, size_t sz)
{
	struct landlock_path_beneath_attr pb = {
		.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE,
		.parent_fd = -1, /* guarantee invalid <fd> by default */
	};

	for (size_t i = 0; i < sz; ++i) {
		check(ruleset_add_one(fd, paths[i], &pb));
	}

	return RESULT_OK;
}

static WARN_UNUSED result_t
ruleset_add_rule_port(int fd, int port)
{
	struct landlock_net_port_attr np = {
		.allowed_access = LANDLOCK_ACCESS_NET_CONNECT_TCP,
		.port = port,
	};
	const int rc = landlock_add_rule(fd, LANDLOCK_RULE_NET_PORT, &np, 0);
	check_if(rc < 0, ERR_SANDBOX_LANDLOCK_ADD_RULE_PORT, errno);
	return RESULT_OK;
}

result_t
landlock_apply(const char *const *paths, int sz, int port)
{
	int rc = 0;

	struct landlock_ruleset_attr ra = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
		.handled_access_net = LANDLOCK_ACCESS_NET_CONNECT_TCP,
	};
	int fd = landlock_create_ruleset(&ra, sizeof(ra), 0);
	check_if(fd < 0, ERR_SANDBOX_LANDLOCK_CREATE_RULESET, errno);

	if (paths) {
		check(ruleset_add_rule_paths(fd, paths, sz));
	}

	if (port > 0) {
		check(ruleset_add_rule_port(fd, port));
	}

	rc = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	check_if(rc < 0, ERR_SANDBOX_LANDLOCK_SET_NO_NEW_PRIVS, errno);

	rc = landlock_restrict_self(fd, 0);
	check_if(rc < 0, ERR_SANDBOX_LANDLOCK_RESTRICT_SELF, errno);

	debug("landlock_apply() succeeded");

	rc = close(fd);
	info_m_if(rc < 0, "Ignoring error close()-ing Landlock ruleset fd");

	return RESULT_OK;
}
