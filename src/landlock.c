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
#include "result_type.h"

#include <fcntl.h>
#include <linux/prctl.h>
#include <stdio.h>  /* for asprintf() */
#include <stdlib.h> /* for free() */
#include <sys/prctl.h>

/*
 * Set up codegen macros for module-specific result_t.
 */
#define GET_PATH(x) x->path ? x->path : "[Cannot allocate path]"
#define PATH(fmt) ASPRINTF(fmt ": %s", GET_PATH(p), strerror(p->num))

#define ERROR_TABLE(X)                                                         \
	X(OK, LITERAL("Success in " __FILE_NAME__))                            \
	X(ERR_CREATE_RULESET, PERR("Error in landlock_create_ruleset()"))      \
	X(ERR_OPEN_O_PATH, PATH("Error in open O_PATH for %s (Landlock)"))     \
	X(ERR_ADD_RULE_PATH, PATH("Error in landlock_add_rule() for %s"))      \
	X(ERR_ADD_RULE_PORT, PERR("Error in landlock_add_rule() for port"))    \
	X(ERR_SET_NO_NEW_PRIVS, PERR("Error in prctl(PR_SET_NO_NEW_PRIVS)"))   \
	X(ERR_RESTRICT_SELF, PERR("Error in landlock_restrict_self()"))

#define ERROR_EXAMPLE_ARGS 0, strdup("/foo/bar")

/*
 * Extend `struct result_base` to create a module-specific result_t.
 */
struct result_ll {
	struct result_base base;
	enum { ERROR_TABLE(INTO_ENUM) } err;
	int num;
	char *path;
};

static void
result_ll_cleanup_members(struct result_ll *p __attribute__((unused)))
{
}

DEFINE_RESULT(result_ll,
              MEMBER(int, err),
              MEMBER(int, num),
              MEMBER(char *, path))

static result_t WARN_UNUSED
make_result(int err, int my_errno)
{
	return make_result_ll(err, my_errno, NULL);
}

static WARN_UNUSED result_t
ruleset_add_one(int fd, const char *path, struct landlock_path_beneath_attr *pb)
{
	int rc = -1;

	pb->parent_fd = open(path, O_PATH);
	if (pb->parent_fd < 0) {
		return make_result_ll(ERR_OPEN_O_PATH, errno, strdup(path));
	}

	rc = landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, pb, 0);
	if (rc < 0) {
		return make_result_ll(ERR_ADD_RULE_PATH, errno, strdup(path));
	}

	rc = close(pb->parent_fd);
	info_m_if(rc < 0, "Ignoring error close()-ing Landlock paths fd");
	pb->parent_fd = -1;

	return RESULT_OK;
}

static WARN_UNUSED result_t
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

static WARN_UNUSED result_t
ruleset_add_rule_port(int fd, int port)
{
	struct landlock_net_port_attr np = {
		.allowed_access = LANDLOCK_ACCESS_NET_CONNECT_TCP,
		.port = port,
	};
	const int rc = landlock_add_rule(fd, LANDLOCK_RULE_NET_PORT, &np, 0);
	check_if(rc < 0, ERR_ADD_RULE_PORT, errno);
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
	check_if(fd < 0, ERR_CREATE_RULESET, errno);

	if (paths) {
		check(ruleset_add_rule_paths(fd, paths, sz));
	}

	if (port > 0) {
		check(ruleset_add_rule_port(fd, port));
	}

	rc = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	check_if(rc < 0, ERR_SET_NO_NEW_PRIVS, errno);

	rc = landlock_restrict_self(fd, 0);
	check_if(rc < 0, ERR_RESTRICT_SELF, errno);

	debug("landlock_apply() succeeded");

	rc = close(fd);
	info_m_if(rc < 0, "Ignoring error close()-ing Landlock ruleset fd");

	return RESULT_OK;
}

#undef ERROR_EXAMPLE_ARGS
#undef ERROR_TABLE
#undef PATH
#undef GET_PATH
