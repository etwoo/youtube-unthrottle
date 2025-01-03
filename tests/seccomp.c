#include "seccomp.h"

#include "greatest.h"
#include "tmpfile.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/seccomp.h> /* for SECCOMP_* constants */
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

TEST
getpid_allowed(void)
{
	ASSERT_LT(0, getpid());
	PASS();
}

TEST
mmap_exec_allowed(void)
{
	void *p = mmap(NULL, 4, PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	ASSERT_NEQ(MAP_FAILED, p);
	int rc = munmap(p, 4);
	ASSERT_EQ(0, rc);
	PASS();
}

TEST
socket_allowed(void)
{
	int sfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	ASSERT_LTE(0, sfd);
	int rc = close(sfd);
	ASSERT_EQ(0, rc);
	PASS();
}

TEST
open_rdonly_allowed(void)
{
	int fd = open(__FILE__, O_RDONLY);
	ASSERT_LTE(0, fd);
	int rc = close(fd);
	ASSERT_EQ(0, rc);
	PASS();
}

TEST
open_tmpfile_allowed(void)
{
	int tmp = -1;
	result_t err = tmpfd(&tmp);
	ASSERT_EQ(OK, err.err);
	ASSERT_LTE(0, tmp);
	int rc = close(tmp);
	ASSERT_EQ(0, rc);
	PASS();
}

TEST
seccomp_change_allowed(void)
{
	uint32_t action = SECCOMP_RET_KILL_PROCESS;
	int rc = syscall(__NR_seccomp, SECCOMP_GET_ACTION_AVAIL, 0, &action);
	ASSERT_EQ(0, rc);
	PASS();
}

SUITE(before_seccomp)
{
	RUN_TEST(getpid_allowed);
	RUN_TEST(mmap_exec_allowed);
	RUN_TEST(socket_allowed);
	RUN_TEST(open_rdonly_allowed);
	RUN_TEST(open_tmpfile_allowed);
	RUN_TEST(seccomp_change_allowed);
}

TEST
mmap_exec_blocked(void)
{
	void *p = mmap(NULL, 4, PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	ASSERT_EQ(MAP_FAILED, p);
	PASS();
}

TEST
mmap_read_allowed(void)
{
	void *p = mmap(NULL, 4, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	ASSERT_NEQ(MAP_FAILED, p);
	int rc = munmap(p, 4);
	ASSERT_EQ(0, rc);
	PASS();
}

TEST
setup_seccomp_apply(int flags)
{
	result_t err = seccomp_apply(flags);
	ASSERT_EQ(OK, err.err);
	PASS();
}

SUITE(seccomp_io_inet_tmpfile)
{
	const int flags = SECCOMP_SANDBOX | SECCOMP_STDIO | SECCOMP_INET |
	                  SECCOMP_TMPFILE;
	RUN_TESTp(setup_seccomp_apply, flags);
	RUN_TEST(getpid_allowed);
	RUN_TEST(mmap_exec_blocked);
	RUN_TEST(mmap_read_allowed);
	RUN_TEST(socket_allowed);
	RUN_TEST(open_rdonly_allowed);
	RUN_TEST(open_tmpfile_allowed);
	RUN_TEST(seccomp_change_allowed);
}

TEST
open_tmpfile_blocked(void)
{
	int tmp = -1;
	result_t err = tmpfd(&tmp);
	ASSERT_EQ(ERR_TMPFILE, err.err);
	ASSERT_GT(0, tmp);
	ASSERT_EQ(EACCES, errno);
	PASS();
}

SUITE(seccomp_io_inet_rpath)
{
	const int flags =
		SECCOMP_SANDBOX | SECCOMP_STDIO | SECCOMP_INET | SECCOMP_RPATH;
	RUN_TESTp(setup_seccomp_apply, flags);
	RUN_TEST(getpid_allowed);
	RUN_TEST(mmap_exec_blocked);
	RUN_TEST(mmap_read_allowed);
	RUN_TEST(socket_allowed);
	RUN_TEST(open_rdonly_allowed);
	RUN_TEST(open_tmpfile_blocked);
	RUN_TEST(seccomp_change_allowed);
}

TEST
open_rdonly_blocked(void)
{
	int fd = open(__FILE__, O_RDONLY);
	ASSERT_GT(0, fd);
	ASSERT_EQ(EACCES, errno);
	PASS();
}

SUITE(seccomp_io_inet)
{
	const int flags = SECCOMP_SANDBOX | SECCOMP_STDIO | SECCOMP_INET;
	RUN_TESTp(setup_seccomp_apply, flags);
	RUN_TEST(getpid_allowed);
	RUN_TEST(mmap_exec_blocked);
	RUN_TEST(mmap_read_allowed);
	RUN_TEST(socket_allowed);
	RUN_TEST(open_rdonly_blocked);
	RUN_TEST(open_tmpfile_blocked);
	RUN_TEST(seccomp_change_allowed);
}

TEST
socket_blocked(void)
{
	int sfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sfd >= 0) {
		/*
		 * Make sure not to leak a file descriptor, even if socket()
		 * unexpectedly succeeds.
		 * */
		close(sfd);
	}
	ASSERT_GT(0, sfd);
	ASSERT_EQ(EACCES, errno);
	PASS();
}

SUITE(seccomp_io)
{
	const int flags = SECCOMP_SANDBOX | SECCOMP_STDIO;
	RUN_TESTp(setup_seccomp_apply, flags);
	RUN_TEST(getpid_allowed);
	RUN_TEST(mmap_exec_blocked);
	RUN_TEST(mmap_read_allowed);
	RUN_TEST(socket_blocked);
	RUN_TEST(open_rdonly_blocked);
	RUN_TEST(open_tmpfile_blocked);
	RUN_TEST(seccomp_change_allowed);
}

TEST
seccomp_change_blocked(void)
{
	uint32_t action = SECCOMP_RET_KILL_PROCESS;
	int rc = syscall(__NR_seccomp, SECCOMP_GET_ACTION_AVAIL, 0, &action);
	ASSERT_NEQ(0, rc);
	ASSERT_EQ(EACCES, errno);
	PASS();
}

SUITE(seccomp_io_sealed_sandbox)
{
	const int flags = SECCOMP_STDIO;
	RUN_TESTp(setup_seccomp_apply, flags);
	RUN_TEST(getpid_allowed);
	RUN_TEST(mmap_exec_blocked);
	RUN_TEST(mmap_read_allowed);
	RUN_TEST(socket_blocked);
	RUN_TEST(open_rdonly_blocked);
	RUN_TEST(open_tmpfile_blocked);
	RUN_TEST(seccomp_change_blocked);
}

/*
 * Note: it seems we cannot currently test seccomp_apply(0) in a single-process
 * context, as restricting the sandbox to this degree prevents the test rig
 * from proceeding, e.g. prevents greatest.h macros from printing test results
 * to stdout.
 *
 * We might need a multiprocess or multithreaded system to exercise this
 * scenario, such that seccomp_apply() can restrict a child process without
 * restricting the test rig itself.
 */
