#include "seccomp.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* for O_TMPFILE in open() */
#endif
#include <fcntl.h>
#undef _GNU_SOURCE /* revert for any other includes */

#include "array.h"
#include "debug.h"

#include <assert.h>
#include <linux/magic.h> /* for OVERLAYFS_SUPER_MAGIC */
#include <linux/prctl.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/statfs.h>

/*
 * Some helpful libseccomp references:
 *
 *   https://lwn.net/Articles/494252/
 *   https://man.archlinux.org/man/seccomp_rule_add.3.en
 *
 * Note: the EXAMPLES section of the seccomp_rule_add manpage (linked above)
 * contains sample code for libseccomp usage.
 */
#include <seccomp.h>

/*
 * Benign Linux syscalls loosely corresponding to OpenBSD pledge("stdio")
 *
 * Reference: Cosmopolitan Libc's pledge-linux.c implementation
 *
 * See also: https://justine.lol/pledge/
 */
static const char *SYSCALLS_STDIO[] = {
	"sigreturn",
	"restart_syscall",
	"sched_yield",
	"sched_getaffinity",
	"clock_getres",
	"clock_gettime",
	"clock_nanosleep",
	"close_range",
	"close",
	"write",
	"writev",
	"pwrite64",
	"pwritev",
	"pwritev2",
	"read",
	"readv",
	"pread64",
	"preadv",
	"preadv2",
	"dup",
	"dup2",
	"dup3",
	"fchdir",
	"fcntl", /* see restrictions in seccomp_allow_fcntl() */
	"fstat",
	"newfstatat", /* for open() with O_PATH, used with landlock APIs */
	"fsync",
	"sysinfo",
	"fdatasync",
	"ftruncate",
	"getrandom",
	"getgroups",
	"getpgid",
	"getpgrp",
	"getpid",
	"gettid",
	"getuid",
	"getgid",
	"getsid",
	"getppid",
	"geteuid",
	"getegid",
	"getrlimit",
	"getresgid",
	"getresuid",
	"getitimer",
	"setitimer",
	"timerfd_create",
	"timerfd_settime",
	"timerfd_gettime",
	"copy_file_range",
	"gettimeofday",
	"sendfile",
	"vmsplice",
	"splice",
	"lseek",
	"tee",
	"brk",
	"msync",
	"mmap", /* see restrictions in seccomp_allow_mmap() */
	"mlock",
	"mremap",
	"munmap",
	"mincore",
	"madvise",
	"fadvise64",
	"mprotect", /* see restrictions in seccomp_allow_mprotect() */
	"arch_prctl",
	"migrate_pages",
	"sync_file_range",
	"set_tid_address",
	"membarrier",
	"nanosleep",
	"pipe",
	"pipe2",
	"poll",
	"ppoll",
	"select",
	"pselect6",
	"epoll_create",
	"epoll_create1",
	"epoll_ctl",
	"epoll_wait",
	"epoll_pwait",
	"epoll_pwait2",
	"alarm",
	"pause",
	"shutdown",
	"eventfd",
	"eventfd2",
	"signalfd",
	"signalfd4",
	"sigaction",
	"sigaltstack",
	"sigprocmask",
	"sigsuspend",
	"sigpending",
	"rt_sigaction",
	"rt_sigprocmask",
	"rt_sigsuspend",
	"rt_sigpending",
	"rt_sigtimedwait",
	"socketpair",
	"getrusage",
	"times",
	"umask",
	"wait4",
	"uname",
	"prctl", /* see restrictions in seccomp_allow_prctl() */
	"futex",
	"set_robust_list",
	"get_robust_list",
	"sched_getaffinity",
	"sched_setaffinity",
};

/*
 * Linux syscalls loosely corresponding to OpenBSD pledge("inet")
 */
static const char *SYSCALLS_INET[] = {
	"socket",
	"bind",
	"connect",
	"ioctl",
	"getsockopt",
	"setsockopt",
	"getpeername",
	"getsockname",
	"sendto",
	"recvfrom",
	"sendmmsg",
	"sendmsg",
	"recvmsg",
};

/*
 * Linux syscalls corresponding to the ability to modify the sandbox itself, a
 * conceptual superset of OpenBSD pledge("unveil")
 */
static const char *SYSCALLS_SANDBOX_MODIFY[] = {
	"landlock_create_ruleset",
	"landlock_add_rule",
	"landlock_restrict_self",
	"seccomp",
};

/*
 * Linux syscalls that we always allow, no matter what the caller specifies.
 */
static const char *SYSCALLS_SANDBOX_BASIS[] = {
	"exit_group",
	"exit",
	"rseq",
};

static void
warn_seccomp_rule_add(const char *sc, int rc)
{
	warn("Error adding seccomp rule for syscall=%s: %s", sc, strerror(-rc));
}

/*
 * Add each syscall rule separately, producing an OR relationship (union).
 */
static int
seccomp_allow_cmp_union(scmp_filter_ctx ctx,
                        int num,
                        const struct scmp_arg_cmp *op,
                        size_t sz)
{
	for (size_t i = 0; i < sz; ++i) {
		int rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, num, 1, op[i]);
		if (rc < 0) {
			return rc;
		}
	}
	return 0;
}

/*
 * Quiet clang warnings about a member being left uninitialized in the
 * scmp_arg_cmp struct (-Wmissing-field-initializers). In cases where
 * the scmp_compare op only takes one argument, like SCMP_CMP_EQ, it is
 * intentional for the libseccomp macros not to initialize datum_b, as
 * this member represents an optional second argument.
 */
#define SCMP_ARG_UNUSED 0

static int
seccomp_allow_fcntl(scmp_filter_ctx ctx, int num)
{
	const struct scmp_arg_cmp op[] = {
		SCMP_A1(SCMP_CMP_EQ, F_DUPFD, SCMP_ARG_UNUSED),
		SCMP_A1(SCMP_CMP_EQ, F_DUPFD_CLOEXEC, SCMP_ARG_UNUSED),
		SCMP_A1(SCMP_CMP_EQ, F_GETFD, SCMP_ARG_UNUSED),
		SCMP_A1(SCMP_CMP_EQ, F_SETFD, SCMP_ARG_UNUSED),
		SCMP_A1(SCMP_CMP_EQ, F_GETFL, SCMP_ARG_UNUSED),
		SCMP_A1(SCMP_CMP_EQ, F_SETFL, SCMP_ARG_UNUSED),
	};
	return seccomp_allow_cmp_union(ctx, num, op, ARRAY_SIZE(op));
}

static int
seccomp_allow_mprotect(scmp_filter_ctx ctx, int num)
{
	const struct scmp_arg_cmp op[] = {
		SCMP_A2(SCMP_CMP_MASKED_EQ, ~(PROT_READ | PROT_WRITE), 0),
	};
	return seccomp_allow_cmp_union(ctx, num, op, ARRAY_SIZE(op));
}

static int
seccomp_allow_mmap(scmp_filter_ctx ctx, int num)
{
	/*
	 * Add syscall rules for <prot> and <flags> args to mmap()
	 * simultaneously, producing an AND relationship (intersection).
	 */
	const int allowed_flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_DENYWRITE |
	                          MAP_FIXED | MAP_NORESERVE | MAP_STACK;
	const struct scmp_arg_cmp arr[] = {
		SCMP_A2(SCMP_CMP_MASKED_EQ, ~(PROT_READ | PROT_WRITE), 0),
		SCMP_A3(SCMP_CMP_MASKED_EQ, ~allowed_flags, 0),
	};
	return seccomp_rule_add_array(ctx, SCMP_ACT_ALLOW, num, 2, arr);
}

static int
seccomp_allow_prctl(scmp_filter_ctx ctx, int num)
{
	const struct scmp_arg_cmp op[] = {
		SCMP_A0(SCMP_CMP_EQ, PR_SET_NAME, SCMP_ARG_UNUSED),
		SCMP_A0(SCMP_CMP_EQ, PR_GET_NAME, SCMP_ARG_UNUSED),
		SCMP_A0(SCMP_CMP_EQ, PR_GET_SECCOMP, SCMP_ARG_UNUSED),
		SCMP_A0(SCMP_CMP_EQ, PR_SET_SECCOMP, SCMP_ARG_UNUSED),
		SCMP_A0(SCMP_CMP_EQ, PR_SET_NO_NEW_PRIVS, SCMP_ARG_UNUSED),
		SCMP_A0(SCMP_CMP_EQ, PR_CAPBSET_READ, SCMP_ARG_UNUSED),
		SCMP_A0(SCMP_CMP_EQ, PR_CAPBSET_DROP, SCMP_ARG_UNUSED),
	};
	return seccomp_allow_cmp_union(ctx, num, op, ARRAY_SIZE(op));
}

static bool
seccomp_allow(scmp_filter_ctx ctx, const char **syscalls, size_t sz)
{
	for (size_t i = 0; i < sz; ++i) {
		const int num = seccomp_syscall_resolve_name(syscalls[i]);
		if (num == __NR_SCMP_ERROR) {
			warn("Cannot resolve syscall number for syscall=%s",
			     syscalls[i]);
			return false;
		}
		int rc = -1;
		if (0 == strcmp(syscalls[i], "fcntl")) {
			rc = seccomp_allow_fcntl(ctx, num);
		} else if (0 == strcmp(syscalls[i], "mmap")) {
			rc = seccomp_allow_mmap(ctx, num);
		} else if (0 == strcmp(syscalls[i], "mprotect")) {
			rc = seccomp_allow_mprotect(ctx, num);
		} else if (0 == strcmp(syscalls[i], "prctl")) {
			rc = seccomp_allow_prctl(ctx, num);
		} else {
			assert(0 != strcmp(syscalls[i], "openat"));
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, num, 0);
		}
		if (rc < 0) {
			warn_seccomp_rule_add(syscalls[i], rc);
			return false;
		}
	}
	return true;
}

static bool
seccomp_allow_tmpfile(scmp_filter_ctx ctx,
                      const char **syscalls __attribute__((unused)),
                      size_t sz __attribute__((unused)))
{
	const int num = SCMP_SYS(openat);

	struct statfs fs;
	memset(&fs, 0, sizeof(fs));
	if (statfs(P_tmpdir, &fs) < 0) {
		pwarn("Error in statfs()");
	} else if (fs.f_type == OVERLAYFS_SUPER_MAGIC) {
		warn("%s is overlayfs, which does not support O_TMPFILE; "
		     "now allowing openat() unconditionally and relying on "
		     "Landlock to restrict access to the filesystem!",
		     P_tmpdir);
		int rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, num, 0);
		if (rc < 0) {
			warn_seccomp_rule_add("openat", rc);
			return false;
		}
		return true;
	}

	/*
	 * Require openat() callers to be doing either landlock-related O_PATH
	 * calls or tmpfile-creation O_TMPFILE|O_EXCL calls.
	 */
	const int allowed_flags = O_PATH | O_TMPFILE | O_EXCL | O_RDWR;
	const struct scmp_arg_cmp op[] = {
		SCMP_A2(SCMP_CMP_MASKED_EQ, ~allowed_flags, 0),
	};
	int rc = seccomp_allow_cmp_union(ctx, num, op, ARRAY_SIZE(op));
	if (rc < 0) {
		warn_seccomp_rule_add("openat", rc);
		return false;
	}
	return true;
}

static bool
seccomp_allow_rpath(scmp_filter_ctx ctx,
                    const char **syscalls __attribute__((unused)),
                    size_t sz __attribute__((unused)))
{
	const int num = SCMP_SYS(openat);
	/*
	 * Require openat() callers to be doing either landlock-related O_PATH
	 * calls or O_RDONLY operations (i.e. all-zero flags).
	 */
	assert(O_RDONLY == 0);
	const int allowed_flags = O_PATH | O_RDONLY;
	const struct scmp_arg_cmp op[] = {
		SCMP_A2(SCMP_CMP_MASKED_EQ, ~allowed_flags, 0),
	};
	int rc = seccomp_allow_cmp_union(ctx, num, op, ARRAY_SIZE(op));
	if (rc < 0) {
		warn_seccomp_rule_add("openat", rc);
		return false;
	}
	return true;
}

const unsigned SECCOMP_STDIO = 0x01;
const unsigned SECCOMP_INET = 0x02;
const unsigned SECCOMP_SANDBOX = 0x04;
const unsigned SECCOMP_TMPFILE = 0x08;
const unsigned SECCOMP_RPATH = 0x10;

static struct seccomp_apply_handler {
	unsigned flag;
	bool (*handle)(scmp_filter_ctx, const char **, size_t);
	const char **syscalls;
	size_t sz;
} SECCOMP_APPLY_HANDLERS[] = {
	{
		SECCOMP_STDIO,
		seccomp_allow,
		SYSCALLS_STDIO,
		ARRAY_SIZE(SYSCALLS_STDIO),
	},
	{
		SECCOMP_INET,
		seccomp_allow,
		SYSCALLS_INET,
		ARRAY_SIZE(SYSCALLS_INET),
	},
	{
		SECCOMP_SANDBOX,
		seccomp_allow,
		SYSCALLS_SANDBOX_MODIFY,
		ARRAY_SIZE(SYSCALLS_SANDBOX_MODIFY),
	},
	{
		SECCOMP_TMPFILE,
		seccomp_allow_tmpfile,
		NULL,
		0,
	},
	{
		SECCOMP_RPATH,
		seccomp_allow_rpath,
		NULL,
		0,
	},
};

static bool
seccomp_apply_common(scmp_filter_ctx ctx, unsigned flags)
{
	if (!seccomp_allow(ctx,
	                   SYSCALLS_SANDBOX_BASIS,
	                   ARRAY_SIZE(SYSCALLS_SANDBOX_BASIS))) {
		return false;
	}

	for (size_t i = 0; i < ARRAY_SIZE(SECCOMP_APPLY_HANDLERS); ++i) {
		struct seccomp_apply_handler *h = SECCOMP_APPLY_HANDLERS + i;

		const bool match = (0 != (flags & h->flag));
		if (!match) {
			continue;
		}

		const bool result = h->handle(ctx, h->syscalls, h->sz);
		if (!result) {
			return false;
		}
	}

	return true;
}

void
seccomp_apply(unsigned flags)
{
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ERRNO(EACCES));
	if (ctx == NULL) {
		pwarn("Error in seccomp_init()");
		goto cleanup;
	}

	if (!seccomp_apply_common(ctx, flags)) {
		goto cleanup;
	}

	if (seccomp_load(ctx) < 0) {
		pwarn("Error in seccomp_load()");
		goto cleanup;
	}

	debug("seccomp_apply() succeeded");

cleanup:
	seccomp_release(ctx);
}
