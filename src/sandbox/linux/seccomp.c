#include "sandbox/linux/seccomp.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* for O_TMPFILE */
#endif
#include <fcntl.h>
#undef _GNU_SOURCE /* revert for any other includes */

#include "sys/array.h"
#include "sys/debug.h"

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
static const char *const SYSCALLS_STDIO[] = {
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
static const char *const SYSCALLS_INET[] = {
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
 * Linux syscalls corresponding to the ability to alter the sandbox itself, a
 * conceptual superset of OpenBSD pledge("unveil")
 */
static const char *const SYSCALLS_SANDBOX_MODIFY[] = {
	"landlock_create_ruleset",
	"landlock_add_rule",
	"landlock_restrict_self",
	"seccomp",
};

/*
 * Linux syscalls that we always allow, no matter what the caller specifies.
 */
static const char *const BASE[] = {
	"clone3",
	"exit_group",
	"exit",
	"rseq",
};

/*
 * Convert a numeric return value from seccomp_rule_add* into a result_t.
 */
static WARN_UNUSED result_t
to_result(int added, const char *syscall)
{
	return (added == 0 ? RESULT_OK
	                   : make_result(ERR_SANDBOX_SECCOMP_RULE_ADD,
	                                 -1 * added,
	                                 syscall));
}

/*
 * Accumulate two result_t's into one, preferring values that represent errors
 * over values representing success.
 */
static WARN_UNUSED result_t
accumulate(result_t prev, result_t cur)
{
	const bool new_winner = (cur.err > prev.err);
	{
		/*
		 * Log any errors that will not propagate to the caller. This
		 * can happen if, for example, two or more syscall names fail
		 * to resolve to syscall numbers; in this case, only one of the
		 * two resolution failures will propagate to the caller.
		 */
		auto_result_str str = (!new_winner && cur.err != OK)
		                              ? result_to_str(cur)
		                              : NULL;
		info_if(str, "Issue adding seccomp rule: %s", str);
	}

	result_cleanup(new_winner ? &prev : &cur);
	return new_winner ? cur : prev;
}

/*
 * Add each syscall rule separately, producing an OR relationship (union).
 */
static WARN_UNUSED result_t
seccomp_allow_cmp_union(scmp_filter_ctx ctx,
                        const char *sname,
                        int snum,
                        const struct scmp_arg_cmp *op,
                        size_t sz)
{
	result_t err = RESULT_OK;
	for (size_t i = 0; i < sz; ++i) {
		const int added =
			seccomp_rule_add(ctx, SCMP_ACT_ALLOW, snum, 1, op[i]);
		err = accumulate(err, to_result(added, sname));
	}
	return err;
}

/*
 * Quiet clang warnings about a member left uninitialized in the <scmp_arg_cmp>
 * struct (-Wmissing-field-initializers).
 *
 * In cases where <scmp_compare> only takes one argument, like SCMP_CMP_EQ,
 * libseccomp macros intentionally leave <datum_b> uninitialized, as this
 * member represents an optional second argument.
 */
#define SCMP_ARG_UNUSED 0

static WARN_UNUSED result_t
seccomp_allow_fcntl(scmp_filter_ctx ctx, const char *sname, int snum)
{
	const struct scmp_arg_cmp op[] = {
		SCMP_A1(SCMP_CMP_EQ, F_DUPFD, SCMP_ARG_UNUSED),
		SCMP_A1(SCMP_CMP_EQ, F_DUPFD_CLOEXEC, SCMP_ARG_UNUSED),
		SCMP_A1(SCMP_CMP_EQ, F_GETFD, SCMP_ARG_UNUSED),
		SCMP_A1(SCMP_CMP_EQ, F_SETFD, SCMP_ARG_UNUSED),
		SCMP_A1(SCMP_CMP_EQ, F_GETFL, SCMP_ARG_UNUSED),
		SCMP_A1(SCMP_CMP_EQ, F_SETFL, SCMP_ARG_UNUSED),
	};
	return seccomp_allow_cmp_union(ctx, sname, snum, op, ARRAY_SIZE(op));
}

static WARN_UNUSED result_t
seccomp_allow_mprotect(scmp_filter_ctx ctx, const char *sname, int snum)
{
	const int allowed_prot = PROT_READ | PROT_WRITE;
	const struct scmp_arg_cmp op[] = {
		SCMP_A2(SCMP_CMP_MASKED_EQ, ~(uint64_t)allowed_prot, 0),
	};
	return seccomp_allow_cmp_union(ctx, sname, snum, op, ARRAY_SIZE(op));
}

static WARN_UNUSED result_t
seccomp_allow_mmap(scmp_filter_ctx ctx, const char *sname, int snum)
{
	/*
	 * Add syscall rules for <prot> and <flags> arguments to mmap()
	 * simultaneously, producing an AND relationship (intersection).
	 */
	const int allowed_prot = PROT_READ | PROT_WRITE;
	const int allowed_flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_DENYWRITE |
	                          MAP_FIXED | MAP_NORESERVE | MAP_STACK;
	const struct scmp_arg_cmp arr[] = {
		SCMP_A2(SCMP_CMP_MASKED_EQ, ~(uint64_t)allowed_prot, 0),
		SCMP_A3(SCMP_CMP_MASKED_EQ, ~(uint64_t)allowed_flags, 0),
	};
	int added = seccomp_rule_add_array(ctx, SCMP_ACT_ALLOW, snum, 2, arr);
	return to_result(added, sname);
}

static WARN_UNUSED result_t
seccomp_allow_prctl(scmp_filter_ctx ctx, const char *sname, int snum)
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
	return seccomp_allow_cmp_union(ctx, sname, snum, op, ARRAY_SIZE(op));
}

static WARN_UNUSED result_t
seccomp_allow_one(scmp_filter_ctx ctx, const char *syscall)
{
	const int num = seccomp_syscall_resolve_name(syscall);
	const bool num_is_err = (num == __NR_SCMP_ERROR);
	check_if(num_is_err, ERR_SANDBOX_SECCOMP_RESOLVE_SYSCALL, syscall);

	result_t r = RESULT_OK;
	if (0 == strcmp(syscall, "fcntl")) {
		r = seccomp_allow_fcntl(ctx, syscall, num);
	} else if (0 == strcmp(syscall, "mmap")) {
		r = seccomp_allow_mmap(ctx, syscall, num);
	} else if (0 == strcmp(syscall, "mprotect")) {
		r = seccomp_allow_mprotect(ctx, syscall, num);
	} else if (0 == strcmp(syscall, "prctl")) {
		r = seccomp_allow_prctl(ctx, syscall, num);
	} else {
		assert(0 != strcmp(syscall, "openat"));
		const int added = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, num, 0);
		r = to_result(added, syscall);
	}
	return r;
}

static WARN_UNUSED result_t
seccomp_allow(scmp_filter_ctx ctx, const char *const *syscalls, size_t sz)
{
	result_t err = RESULT_OK;
	for (size_t i = 0; i < sz; ++i) {
		err = accumulate(err, seccomp_allow_one(ctx, syscalls[i]));
	}
	return err;
}

static WARN_UNUSED result_t
seccomp_allow_tmpfile(scmp_filter_ctx ctx,
                      const char *const *syscalls,
                      size_t sz)
{
	assert(syscalls == NULL);
	assert(sz == 0);
	const int num = SCMP_SYS(openat);

	struct statfs fs = {0};
	assert(statfs(P_tmpdir, &fs) == 0 &&
	       fs.f_type != OVERLAYFS_SUPER_MAGIC &&
	       "no support for O_TMPFILE on overlayfs; cannot restrict openat");

	/*
	 * Restrict openat() callers to landlock-related O_PATH calls and
	 * tmpfile-creation O_TMPFILE|O_EXCL calls.
	 */
	const int allowed_flags =
		O_CLOEXEC | O_PATH | O_TMPFILE | O_EXCL | O_RDWR;
	const struct scmp_arg_cmp op[] = {
		SCMP_A2(SCMP_CMP_MASKED_EQ, ~(uint64_t)allowed_flags, 0),
	};
	return seccomp_allow_cmp_union(ctx, "openat", num, op, ARRAY_SIZE(op));
}

static WARN_UNUSED result_t
seccomp_allow_rpath(scmp_filter_ctx ctx, const char *const *syscalls, size_t sz)
{
	assert(syscalls == NULL);
	assert(sz == 0);
	const int num = SCMP_SYS(openat);
	/*
	 * Restrict openat() callers to landlock-related O_PATH calls and
	 * O_RDONLY operations (i.e. all-zero flags).
	 */
	static_assert(!O_RDONLY, "O_RDONLY is unexpectedly non-zero");
	const int allowed_flags = O_CLOEXEC | O_PATH | O_RDONLY;
	const struct scmp_arg_cmp op[] = {
		SCMP_A2(SCMP_CMP_MASKED_EQ, ~(uint64_t)allowed_flags, 0),
	};
	return seccomp_allow_cmp_union(ctx, "openat", num, op, ARRAY_SIZE(op));
}

const unsigned SECCOMP_STDIO = 0x01;
const unsigned SECCOMP_INET = 0x02;
const unsigned SECCOMP_SANDBOX = 0x04;
const unsigned SECCOMP_TMPFILE = 0x08;
const unsigned SECCOMP_RPATH = 0x10;

struct seccomp_apply_handler {
	unsigned flag;
	result_t (*handle)(scmp_filter_ctx, const char *const *, size_t);
	const char *const *syscalls;
	size_t sz;
};

static const struct seccomp_apply_handler SECCOMP_APPLY_HANDLERS[] = {
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

static WARN_UNUSED result_t
seccomp_apply_common(scmp_filter_ctx ctx, unsigned flags)
{
	result_t err = RESULT_OK;
	err = accumulate(err, seccomp_allow(ctx, BASE, ARRAY_SIZE(BASE)));

	for (size_t i = 0; i < ARRAY_SIZE(SECCOMP_APPLY_HANDLERS); ++i) {
		const struct seccomp_apply_handler *h =
			SECCOMP_APPLY_HANDLERS + i;

		const bool match = (0 != (flags & h->flag));
		if (!match) {
			continue;
		}

		err = accumulate(err, h->handle(ctx, h->syscalls, h->sz));
	}

	return err;
}

static void
seccomp_cleanup(scmp_filter_ctx *ctx)
{
	if (*ctx) {
		seccomp_release(*ctx);
	}
}

result_t
seccomp_apply(unsigned flags)
{
	scmp_filter_ctx ctx __attribute__((cleanup(seccomp_cleanup))) =
		seccomp_init(SCMP_ACT_ERRNO(EACCES));
	check_if(ctx == NULL, ERR_SANDBOX_SECCOMP_INIT, errno);

	auto_result err = seccomp_apply_common(ctx, flags);
	auto_result_str str = (err.err == OK ? NULL : result_to_str(err));
	info_if(err.err, "Non-fatal issue adding seccomp rules: %s", str);

	const int rc = seccomp_load(ctx);
	check_if(rc < 0, ERR_SANDBOX_SECCOMP_LOAD, errno);

	debug("seccomp_apply() %s", err.err ? "had issues" : "succeeded");
	return RESULT_OK;
}

#undef SCMP_ARG_UNUSED
