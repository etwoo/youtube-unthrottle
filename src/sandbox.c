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
#include <linux/landlock.h>
#include <linux/prctl.h>
#include <stddef.h>
#include <sys/syscall.h>
#include <unistd.h>

#undef _GNU_SOURCE /* revert for any other includes */

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

void
require_only_io_inet(void)
{
}
/* TODO on openbsd: pledge("inet rpath stdio tmppath") */

void
require_only_io(void)
{
}
/* TODO on OpenBSD: pledge("stdio") */
