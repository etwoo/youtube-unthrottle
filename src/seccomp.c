#if defined(__linux__)

#include "array.h"
#include "debug.h"
#include "seccomp.h"

#include <seccomp.h>
#include <stdbool.h>

const unsigned SECCOMP_STDIO = 0x1;
const unsigned SECCOMP_INET =  0x2;

/*
 * Benign Linux syscalls loosely corresponding to OpenBSD pledge("stdio")
 *
 * Reference: Cosmopolitan Libc's pledge-linux.c implementation
 */
static const char* SYSCALLS_STDIO[] = {
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
	/*
	 * TODO The second argument of fcntl() must be one of:
	 *
	 *   - F_DUPFD (0)
	 *   - F_DUPFD_CLOEXEC (1030)
	 *   - F_GETFD (1)
	 *   - F_SETFD (2)
	 *   - F_GETFL (3)
	 *   - F_SETFL (4)
	 */
	"fcntl",
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
	/*
	 * TODO The prot parameter of mmap() may only have:
	 *
	 *   - PROT_NONE  (0)
	 *   - PROT_READ  (1)
	 *   - PROT_WRITE (2)
	 *
	 * The flags parameter must not have:
	 *
	 *   - MAP_LOCKED   (0x02000)
	 *   - MAP_NONBLOCK (0x10000)
	 *   - MAP_HUGETLB  (0x40000)
	 */
	"mmap",
	"mlock",
	"mremap",
	"munmap",
	"mincore",
	"madvise",
	"fadvise64",
	/*
	 * TODO The prot parameter of mprotect() may only have:
	 *
	 *   - PROT_NONE  (0)
	 *   - PROT_READ  (1)
	 *   - PROT_WRITE (2)
	 */
	"mprotect",
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
	// "recvfrom",
	// "sendto | ADDRLESS",
	// "ioctl | RESTRICT",
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
	// "kill | SELF",
	// "tkill",
	// "tgkill | SELF",
	"socketpair",
	"getrusage",
	"times",
	"umask",
	"wait4",
	"uname",
	/*
	 * TODO The first parameter of prctl() can be any of
	 *
	 *   - PR_SET_NAME         (15)
	 *   - PR_GET_NAME         (16)
	 *   - PR_GET_SECCOMP      (21)
	 *   - PR_SET_SECCOMP      (22)
	 *   - PR_SET_NO_NEW_PRIVS (38)
	 *   - PR_CAPBSET_READ     (23)
	 *   - PR_CAPBSET_DROP     (24)
	 */
	"prctl",
	// "clone | THREAD",
	"futex",
	"set_robust_list",
	"get_robust_list",
	// "prlimit | STDIO",
	"sched_getaffinity",
	"sched_setaffinity",
};

/*
 * Linux syscalls loosely corresponding to OpenBSD pledge("inet")
 */
static const char* SYSCALLS_INET[] = {
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
 * Linux syscalls corresponding to Cosmopolitan's kPledgeStart, kPledgeUnveil
 */
static const char* SYSCALLS_SANDBOX_SETUP[] = {
	"exit",
	"rseq",
	"openat", /* for open() with O_TMPFILE */
	"clone3",
	"landlock_create_ruleset",
	"landlock_add_rule",
	"landlock_restrict_self",
	"seccomp",
};

static bool
seccomp_allow(scmp_filter_ctx ctx, const char **syscalls, size_t sz)
{
	for (size_t i = 0; i < sz; ++i) {
		int num = seccomp_syscall_resolve_name(syscalls[i]);
		if (num == __NR_SCMP_ERROR) {
			warn("Cannot resolve syscall number for syscall=%s",
			     syscalls[i]);
			return false;
		}
		int rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, num, 0);
		if (rc < 0) {
			warn("Error in seccomp_rule_add() for syscall=%s: %s",
			     syscalls[i], strerror(-rc));
			return false;
		}
	}
	return true;
}

static bool
seccomp_allow_stdio(scmp_filter_ctx ctx)
{
	return seccomp_allow(ctx, SYSCALLS_STDIO, ARRAY_SIZE(SYSCALLS_STDIO));
}

static bool
seccomp_allow_inet(scmp_filter_ctx ctx)
{
	return seccomp_allow(ctx, SYSCALLS_INET, ARRAY_SIZE(SYSCALLS_INET));
}

static bool
seccomp_allow_sandbox_start(scmp_filter_ctx ctx)
{
	return seccomp_allow(ctx,
	                     SYSCALLS_SANDBOX_SETUP,
	                     ARRAY_SIZE(SYSCALLS_SANDBOX_SETUP));
}

static bool
seccomp_apply_common(scmp_filter_ctx ctx, unsigned flags)
{
	const bool allow_stdio = ((flags & SECCOMP_STDIO) != 0);
	const bool allow_inet = ((flags & SECCOMP_INET) != 0);

	if (!seccomp_allow_sandbox_start(ctx)) {
		return false;
	}

	if (allow_stdio && !seccomp_allow_stdio(ctx)) {
		return false;
	}

	if (allow_inet && !seccomp_allow_inet(ctx)) {
		return false;
	}

	return true;
}

void
seccomp_apply(unsigned flags)
{
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL_PROCESS);
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

cleanup:
	seccomp_release(ctx);
}

#endif /* defined(__linux__) */
