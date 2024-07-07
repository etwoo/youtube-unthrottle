#if defined(__linux__)

#include "array.h"
#include "debug.h"
#include "seccomp.h"

#include <seccomp.h>
#include <stdbool.h>

const unsigned SECCOMP_IO_OPEN = 0x1;
const unsigned SECCOMP_IO_RW   = 0x2;
const unsigned SECCOMP_IO_INET = 0x4;

static const char* ALLOWED_SYSCALLS[] = {
	/*
	 * syscalls required after_inet()
	 */
	"mmap", /* TODO: maybe only required by duktape after_inet(), can be dropped if duktape separated out? */
	// TODO: after allowing mmap, prevent PROT_EXEC, i.e. only allow PROT_READ and/or PROT_WRITE, like: seccomp_rule_add(..., SCMP_SYS(mmap), ... SCMP_A2(SCMP_CMP_MASKED_NEQ, PROT_EXEC, ...))
	"munmap", /* TODO: maybe only required by duktape after_inet(), can be dropped if duktape separated out? */
	"write",
	"close",
	"fstat",
	"futex",
#if 0
	"openat", /* for open() with O_TMPFILE */
	"newfstatat", /* for open() with O_PATH, used with landlock APIs */
	"read",
#endif
#if 0
	/* after_inet(), these syscalls are only used by sandbox_verify(), which correctly causes crash, similar to pledge("stdio") */
	"socket",
	"setsockopt",
	"ioctl",
	"connect",
	"poll",
	"sendto",
	"recvfrom",
#endif
	"exit_group",
#if 0
	"getpeername",
	"landlock_create_ruleset",
	"landlock_add_rule",
	"landlock_restrict_self",
	"prctl",
	"seccomp",
#endif
#if 0
	/*
	 * additional syscalls required for curl and duktape
	 */
	"pipe2",
	"fcntl",
	"rt_sigaction",
	"rt_sigprocmask",
	"mprotect",
	"clone3",
	"rseq",
	"set_robust_list",
	"sendmmsg",
	"sendmsg",
	"recvmsg",
	"madvise",
	"bind",
	"getsockname",
	"getsockopt",
	"brk",
	"getpid",
	"getrandom",
#endif
#if 0
	// TODO: additional syscalls required for ASan/LSan StopTheWorld() during process teardown, where LSan walks threads looking for problems? needing to allow LSan to be able for fork() a child that can ptrace() the parent seems like maybe it's too powerful, basically makes the seccomp sandbox useless? maybe have to choose between a meaningful sandbox vs LSan diagnostics at runtime :(
	// TODO: ASan/LSan hangs on exit, even with these syscalls allowed
	"gettid",
	"getpid",
	"clone",
	"ptrace",
	"sched_yield",
#endif
};

static bool
seccomp_apply_common(scmp_filter_ctx ctx)
{
	for (size_t i = 0; i < ARRAY_SIZE(ALLOWED_SYSCALLS); ++i) {
		int num = seccomp_syscall_resolve_name(ALLOWED_SYSCALLS[i]);
		if (num == __NR_SCMP_ERROR) {
			warn("Cannot resolve syscall number for syscall=%s",
			     ALLOWED_SYSCALLS[i]);
			return false;
		}
		int rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, num, 0);
		if (rc < 0) {
			warn("Error in seccomp_rule_add() for syscall=%s: %s",
			     ALLOWED_SYSCALLS[i], strerror(-rc));
			return false;
		}
	}

	return true;
}

void
seccomp_apply(unsigned flags)
{
	(void)flags; // unused, TODO: use this

	int rc = -1;

	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
	if (ctx == NULL) {
		pwarn("Error in seccomp_init()");
		goto cleanup;
	}

	rc = seccomp_apply_common(ctx);
	if (rc < 0) {
		goto cleanup;
	}

	rc = seccomp_load(ctx);
	if (rc < 0) {
		pwarn("Error in seccomp_load()");
		goto cleanup;
	}

cleanup:
	seccomp_release(ctx);
}

#endif /* defined(__linux__) */
