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

/*
 * Extend `struct result_base` to create a module-specific result_t.
 */
struct result_landlock {
	struct result_base base;
	enum {
		OK = 0,
		ERR_CREATE_RULESET,
		ERR_OPEN_O_PATH,
		ERR_ADD_RULE_PATH,
		ERR_ADD_RULE_PORT,
		ERR_SET_NO_NEW_PRIVS,
		ERR_RESTRICT_SELF,
	} err;
	int errno;
	const char *path;
};

static WARN_UNUSED bool
result_ok(result_t r)
{
	struct result_landlock *p = (struct result_landlock *)r;
	return p->err == OK;
}

static WARN_UNUSED const char *
get_path(result_t r)
{
	if (r->details == NULL) {
		return "[Cannot allocate path buffer]";
	}
	return r->details;
}

static WARN_UNUSED const char *
result_to_str(result_t r)
{
	struct result_landlock *p = (struct result_landlock *)r;
	int printed = 0;
	const char *s = NULL;

	switch (p->err) {
	case OK:
		s = strdup("Success in " __FILE_NAME__);
		break;
	case ERR_CREATE_RULESET:
		printed = asprintf(&s,
		                   "Error in landlock_create_ruleset(): %s",
		                   strerror(p->errno));
		break;
	case ERR_OPEN_O_PATH:
		printed = asprintf(&s,
		                   "Error in open O_PATH for %s (Landlock): %s",
		                   get_path(p),
		                   strerror(p->errno));
		break;
	case ERR_ADD_RULE_PATH:
		printed = asprintf(&s,
		                   "Error in landlock_add_rule() for %s: %s",
		                   get_path(path),
		                   strerror(p->errno));
		break;
	case ERR_ADD_RULE_PORT:
		printed = asprintf(&s,
		                   "Error in landlock_add_rule() for port: %s",
		                   strerror(p->errno));
		break;
	case ERR_SET_NO_NEW_PRIVS:
		printed = asprintf(&s,
		                   "Error in prctl(PR_SET_NO_NEW_PRIVS): %s",
		                   strerror(p->errno));
		break;
	case ERR_RESTRICT_SELF:
		printed = asprintf(&s,
		                   "Error in landlock_restrict_self(): %s",
		                   strerror(p->errno));
		break;
	}

	if (printed < 0) {
		return NULL;
		// TODO: use RESULT_CANNOT_ALLOC instead?
	}

	return s;
}

static void
result_cleanup(result_t r)
{
	if (r == NULL) {
		return;
	}

	struct result_landlock *p = (struct result_landlock *)r;
	free(p->path);
	free(p);
}

struct result_ops RESULT_OPS = {
	.result_ok = result_ok,
	.result_to_str = result_to_str,
	.result_cleanup = result_cleanup,
};

static result_t WARN_UNUSED
make_result(int err_type, int my_errno)
{
	return make_result_p(err_type, my_errno, NULL);
}

static result_t WARN_UNUSED
make_result_p(int err_type, int my_errno, const char *path)
{
	struct result_landlock *r = malloc(sizeof(*r));
	if (r == NULL) {
		return &RESULT_CANNOT_ALLOC;
	}

	r->base.ops = &RESULT_OPS;
	r->err = err_type;
	r->errno = my_errno;
	r->path = path; /* take ownership, if non-NULL */
	return r;
}

static WARN_UNUSED result_t
ruleset_add_one(int fd, const char *path, struct landlock_path_beneath_attr *pb)
{
	int rc = -1;

	pb->parent_fd = open(path, O_PATH);
	if (pb->parent_fd < 0) {
		return make_result_p(ERR_OPEN_O_PATH, errno, strdup(path));
	}

	rc = landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, pb, 0);
	if (rc < 0) {
		return make_result_p(ERR_ADD_RULE_PATH, errno, strdup(path));
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
	if (rc < 0) {
		return make_result(ERR_ADD_RULE_PORT, errno);
	}
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
	if (fd < 0) {
		return make_result(ERR_CREATE_RULESET, errno);
	}

	if (paths) {
		check(ruleset_add_rule_paths(fd, paths, sz));
	}

	if (port > 0) {
		check(ruleset_add_rule_port(fd, port));
	}

	rc = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	if (rc < 0) {
		return make_result(ERR_SET_NO_NEW_PRIVS, errno);
	}

	rc = landlock_restrict_self(fd, 0);
	if (rc < 0) {
		return make_result(ERR_RESTRICT_SELF, errno);
	}

	debug("landlock_apply() succeeded");

	rc = close(fd);
	info_m_if(rc < 0, "Ignoring error close()-ing Landlock ruleset fd");

	return RESULT_OK;
}
