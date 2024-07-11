#include "seccomp.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* for O_TMPFILE in open() */
#endif
#include <fcntl.h>
#undef _GNU_SOURCE /* revert for any other includes */

#include "array.h"
#include "debug.h"

#include <assert.h>
#include <linux/prctl.h>
#include <sched.h>
#include <stdbool.h>
#include <sys/mman.h>

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
	"exit_group",
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
 * Linux syscalls corresponding to the ability to create new threads
 */
static const char *SYSCALLS_THREAD[] = {
	"clone", /* block clone3() and allow clone() with CLONE_THREAD */
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
	"exit",
	"rseq",
};

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

static int
seccomp_allow_clone_block_clone3(scmp_filter_ctx ctx, int num)
{
	/*
	 * Trick glibc into thinking that clone3() syscall is unavailable,
	 * causing a fallback to old-school clone().
	 *
	 * Reference: https://github.com/AkihiroSuda/clone3-workaround
	 */
	int rc = seccomp_rule_add(ctx,
	                          SCMP_ACT_ERRNO(ENOSYS),
	                          SCMP_SYS(clone3),
	                          0);
	if (rc < 0) {
		pwarn("Error hiding clone3 syscall");
		return rc;
	}

	/*
	 * Require clone() callers to be creating a thread (not a process).
	 */
	const int required = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_THREAD;
	const struct scmp_arg_cmp op[] = {
		SCMP_A1(SCMP_CMP_MASKED_EQ, required, required),
	};
	return seccomp_allow_cmp_union(ctx, num, op, ARRAY_SIZE(op));
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
		const char *cur = syscalls[i];
		if (0 == strcmp(cur, "clone")) {
			rc = seccomp_allow_clone_block_clone3(ctx, num);
		} else if (0 == strcmp(cur, "fcntl")) {
			rc = seccomp_allow_fcntl(ctx, num);
		} else if (0 == strcmp(cur, "mmap")) {
			rc = seccomp_allow_mmap(ctx, num);
		} else if (0 == strcmp(cur, "mprotect")) {
			rc = seccomp_allow_mprotect(ctx, num);
		} else if (0 == strcmp(cur, "prctl")) {
			rc = seccomp_allow_prctl(ctx, num);
		} else {
			assert(0 != strcmp(cur, "openat"));
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, num, 0);
		}
		if (rc < 0) {
			warn("Error in seccomp_rule_add() for syscall=%s: %s",
			     cur,
			     strerror(-rc));
			return false;
		}
	}
	return true;
}

static int
seccomp_allow_tmpfile(scmp_filter_ctx ctx)
{
	const int num = SCMP_SYS(openat);
	/*
	 * Require openat() callers to provide O_TMPFILE or O_RDONLY.
	 */
	const struct scmp_arg_cmp op[] = {
		SCMP_A1(SCMP_CMP_MASKED_EQ, O_TMPFILE, O_TMPFILE),
		SCMP_A1(SCMP_CMP_MASKED_EQ, O_RDONLY, O_RDONLY),
	};
	return seccomp_allow_cmp_union(ctx, num, op, ARRAY_SIZE(op));
}

static int
seccomp_allow_rpath(scmp_filter_ctx ctx)
{
	const int num = SCMP_SYS(openat);
	/*
	 * Require openat() callers to provide O_RDONLY.
	 */
	const struct scmp_arg_cmp op[] = {
		SCMP_A1(SCMP_CMP_MASKED_EQ, O_RDONLY, O_RDONLY),
	};
	return seccomp_allow_cmp_union(ctx, num, op, ARRAY_SIZE(op));
}

#define ALLOW(ctx, x) seccomp_allow(ctx, x, ARRAY_SIZE(x))

const unsigned SECCOMP_STDIO = 0x01;
const unsigned SECCOMP_INET = 0x02;
const unsigned SECCOMP_SANDBOX = 0x04;
const unsigned SECCOMP_TMPFILE = 0x08;
const unsigned SECCOMP_RPATH = 0x10;
const unsigned SECCOMP_THREAD = 0x20;

static bool
seccomp_apply_common(scmp_filter_ctx ctx, unsigned flags)
{
	if (!ALLOW(ctx, SYSCALLS_SANDBOX_BASIS)) {
		return false;
	}

	if (((flags & SECCOMP_SANDBOX) != 0) &&
	    !ALLOW(ctx, SYSCALLS_SANDBOX_MODIFY)) {
		return false;
	}

	if (((flags & SECCOMP_STDIO) != 0) && !ALLOW(ctx, SYSCALLS_STDIO)) {
		return false;
	}

	if (((flags & SECCOMP_INET) != 0) && !ALLOW(ctx, SYSCALLS_INET)) {
		return false;
	}

	if (((flags & SECCOMP_TMPFILE) != 0) &&
	    (seccomp_allow_tmpfile(ctx) != 0)) {
		return false;
	}

	if (((flags & SECCOMP_RPATH) != 0) && (seccomp_allow_rpath(ctx) != 0)) {
		return false;
	}

	if (((flags & SECCOMP_THREAD) != 0) && !ALLOW(ctx, SYSCALLS_THREAD)) {
		return false;
	}

	return true;
}

#undef ALLOW

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
