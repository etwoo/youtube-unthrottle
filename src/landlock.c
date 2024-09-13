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

static result_t
ruleset_add_one(int fd, const char *path, struct landlock_path_beneath_attr *pb)
{
	int rc = -1;

	pb->parent_fd = open(path, O_PATH);
	if (pb->parent_fd < 0) {
		result_t err = {
			.err = ERR_SANDBOX_LANDLOCK_OPEN_O_PATH,
			.num = errno,
		};
		result_strcpy(&err, path);
		return err;
	}

	rc = landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, pb, 0);
	if (rc < 0) {
		result_t err = {
			.err = ERR_SANDBOX_LANDLOCK_ADD_RULE_PATH,
			.num = errno,
		};
		result_strcpy(&err, path);
		return err;
	}

	rc = close(pb->parent_fd);
	info_m_if(rc < 0, "Ignoring error close()-ing Landlock paths fd");
	pb->parent_fd = -1;

	return RESULT_OK;
}

static result_t
ruleset_add_rule_paths(int fd, const char **paths, size_t sz)
{
	struct landlock_path_beneath_attr pb = {
		.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE,
		.parent_fd = -1, /* guarantee fd is invalid by default */
	};

	for (size_t i = 0; i < sz; ++i) {
		check(ruleset_add_one(fd, paths[i], &pb));
	}

	return RESULT_OK;
}

static result_t
ruleset_add_rule_port(int fd, int port)
{
	struct landlock_net_port_attr np = {
		.allowed_access = LANDLOCK_ACCESS_NET_CONNECT_TCP,
		.port = port,
	};
	const int rc = landlock_add_rule(fd, LANDLOCK_RULE_NET_PORT, &np, 0);
	check_if_cond_with_errno(rc < 0, ERR_SANDBOX_LANDLOCK_ADD_RULE_PORT);
	return RESULT_OK;
}

result_t
landlock_apply(const char **paths, int sz, int port)
{
	int rc = -1;

	struct landlock_ruleset_attr ra = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
		.handled_access_net = LANDLOCK_ACCESS_NET_CONNECT_TCP,
	};
	int fd = landlock_create_ruleset(&ra, sizeof(ra), 0);
	check_if_cond_with_errno(fd < 0, ERR_SANDBOX_LANDLOCK_CREATE_RULESET);

	if (paths) {
		check(ruleset_add_rule_paths(fd, paths, sz));
	}

	if (port > 0) {
		check(ruleset_add_rule_port(fd, port));
	}

	rc = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	check_if_cond_with_errno(rc < 0, ERR_SANDBOX_LANDLOCK_SET_NO_NEW_PRIVS);

	rc = landlock_restrict_self(fd, 0);
	check_if_cond_with_errno(rc < 0, ERR_SANDBOX_LANDLOCK_RESTRICT_SELF);

	debug("landlock_apply() succeeded");

	rc = close(fd);
	info_m_if(rc < 0, "Ignoring error close()-ing Landlock ruleset fd");

	return RESULT_OK;
}
