#include "seccomp.h"

#include "coverage.h"
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
	ASSERT_GT(getpid(), 0);
	PASS();
}

TEST
mmap_exec_allowed(void)
{
	void *p = mmap(NULL, 4, PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	ASSERT_NEQ(p, MAP_FAILED);
	int rc = munmap(p, 4);
	ASSERT_EQ(rc, 0);
	PASS();
}

TEST
socket_allowed(void)
{
	int sfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	ASSERT_GTE(sfd, 0);
	int rc = close(sfd);
	ASSERT_EQ(rc, 0);
	PASS();
}

TEST
open_rdonly_allowed(void)
{
	int fd = open(__FILE__, O_RDONLY);
	ASSERT_GTE(fd, 0);
	int rc = close(fd);
	ASSERT_EQ(rc, 0);
	PASS();
}

TEST
open_tmpfile_allowed(void)
{
	int tmp = tmpfd();
	ASSERT_GTE(tmp, 0);
	int rc = close(tmp);
	ASSERT_EQ(rc, 0);
	PASS();
}

TEST
seccomp_change_allowed(void)
{
	uint32_t action = SECCOMP_RET_KILL_PROCESS;
	int rc = syscall(__NR_seccomp, SECCOMP_GET_ACTION_AVAIL, 0, &action);
	ASSERT_EQ(rc, 0);
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
	ASSERT_EQ(p, MAP_FAILED);
	PASS();
}

TEST
mmap_read_allowed(void)
{
	void *p = mmap(NULL, 4, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	ASSERT_NEQ(p, MAP_FAILED);
	int rc = munmap(p, 4);
	ASSERT_EQ(rc, 0);
	PASS();
}

SUITE(seccomp_io_inet_tmpfile)
{
	seccomp_apply(SECCOMP_SANDBOX | SECCOMP_STDIO | SECCOMP_INET |
	              SECCOMP_TMPFILE);

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
	int tmp = tmpfd();
	ASSERT_LT(tmp, 0);
	ASSERT_EQ(errno, EACCES);
	PASS();
}

SUITE(seccomp_io_inet_rpath)
{
	seccomp_apply(SECCOMP_SANDBOX | SECCOMP_STDIO | SECCOMP_INET |
	              SECCOMP_RPATH);

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
	ASSERT_LT(fd, 0);
	ASSERT_EQ(errno, EACCES);
	PASS();
}

SUITE(seccomp_io_inet)
{
	seccomp_apply(SECCOMP_SANDBOX | SECCOMP_STDIO | SECCOMP_INET);

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
	ASSERT_LT(sfd, 0);
	ASSERT_EQ(errno, EACCES);
	PASS();
}

SUITE(seccomp_io)
{
	seccomp_apply(SECCOMP_SANDBOX | SECCOMP_STDIO);

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
	ASSERT_NEQ(rc, 0);
	ASSERT_EQ(errno, EACCES);
	PASS();
}

SUITE(seccomp_io_sealed_sandbox)
{
	seccomp_apply(SECCOMP_STDIO);

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
 * context, as restricting the sandbox to this degree prevents the unit test
 * rig from proceeding, e.g. prevents greatest.h macros from being able to
 * print test results to stdout. We might need a multiprocess or multithreaded
 * unit test rig to exercise this scenario, such that seccomp_apply() can be
 * applied to a child process without restricting the unit test rig itself.
 */

GREATEST_MAIN_DEFS();

int
main(int argc, char **argv)
{
	int fd __attribute__((cleanup(coverage_cleanup))) = coverage_open();

	GREATEST_MAIN_BEGIN();

	RUN_SUITE(before_seccomp);
	RUN_SUITE(seccomp_io_inet_tmpfile);
	RUN_SUITE(seccomp_io_inet_rpath);
	RUN_SUITE(seccomp_io_inet);
	RUN_SUITE(seccomp_io);
	RUN_SUITE(seccomp_io_sealed_sandbox);

	GREATEST_MAIN_END();
}
