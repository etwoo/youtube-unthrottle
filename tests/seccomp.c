#include "sandbox/linux/seccomp.h"

#include "greatest.h"
#include "sys/tmpfile.h"
#include "test_macros.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/seccomp.h> /* for SECCOMP_* constants */
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

static enum greatest_test_res
check_getpid(void)
{
	ASSERT_LT(0, getpid());
	PASS();
}

static enum greatest_test_res
check_mmap_exec(bool allowed)
{
	void *p = mmap(NULL, 4, PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (allowed) {
		ASSERT_NEQ(MAP_FAILED, p);
		int rc = munmap(p, 4);
		ASSERT_EQ(0, rc);
	} else {
		ASSERT_EQ(MAP_FAILED, p);
	}
	PASS();
}

static enum greatest_test_res
check_socket(bool allowed)
{
	int sfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (allowed) {
		ASSERT_VALID_DESCRIPTOR(sfd);
		ASSERT_EQ(0, close(sfd));
	} else {
		ASSERT_INVALID_DESCRIPTOR(sfd);
		ASSERT_EQ(EACCES, errno);
	}
	PASS();
}

static enum greatest_test_res
check_open_rdonly(bool allowed)
{
	int fd = open(__FILE__, O_RDONLY);
	if (allowed) {
		ASSERT_VALID_DESCRIPTOR(fd);
		ASSERT_EQ(0, close(fd));
	} else {
		ASSERT_INVALID_DESCRIPTOR(fd);
		ASSERT_EQ(EACCES, errno);
	}
	PASS();
}

static enum greatest_test_res
check_open_tmpfile(bool allowed)
{
	int tmp = -1;
	auto_result err = tmpfd(&tmp);
	if (allowed) {
		ASSERT_EQ(OK, err.err);
		ASSERT_VALID_DESCRIPTOR(tmp);
		ASSERT_EQ(0, close(tmp));
	} else {
		ASSERT_EQ(ERR_TMPFILE, err.err);
		ASSERT_INVALID_DESCRIPTOR(tmp);
		ASSERT_EQ(EACCES, errno);
	}
	PASS();
}

static enum greatest_test_res
check_seccomp_change(bool allowed)
{
	uint32_t action = SECCOMP_RET_KILL_PROCESS;
	long rc = syscall(__NR_seccomp, SECCOMP_GET_ACTION_AVAIL, 0, &action);
	if (allowed) {
		ASSERT_EQ(0, rc);
	} else {
		ASSERT_NEQ(0, rc);
		ASSERT_EQ(EACCES, errno);
	}
	PASS();
}

TEST
seccomp_none(void)
{
	CHECK_CALL(check_getpid());
	CHECK_CALL(check_mmap_exec(true));
	CHECK_CALL(check_socket(true));
	CHECK_CALL(check_open_rdonly(true));
	CHECK_CALL(check_open_tmpfile(true));
	CHECK_CALL(check_seccomp_change(true));
	PASS();
}

static enum greatest_test_res
check_mmap_read(void)
{
	void *p = mmap(NULL, 4, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	ASSERT_NEQ(MAP_FAILED, p);
	int rc = munmap(p, 4);
	ASSERT_EQ(0, rc);
	PASS();
}

TEST
seccomp_io_inet_tmpfile(void)
{
	const unsigned flags = SECCOMP_SANDBOX | SECCOMP_STDIO | SECCOMP_INET |
	                       SECCOMP_TMPFILE;
	auto_result err = seccomp_apply(flags);
	ASSERT_EQ(OK, err.err);

	CHECK_CALL(check_getpid());
	CHECK_CALL(check_mmap_exec(false));
	CHECK_CALL(check_mmap_read());
	CHECK_CALL(check_socket(true));
	CHECK_CALL(check_open_rdonly(true));
	CHECK_CALL(check_open_tmpfile(true));
	CHECK_CALL(check_seccomp_change(true));
	PASS();
}

TEST
seccomp_io_inet_rpath(void)
{
	const unsigned flags =
		SECCOMP_SANDBOX | SECCOMP_STDIO | SECCOMP_INET | SECCOMP_RPATH;
	auto_result err = seccomp_apply(flags);
	ASSERT_EQ(OK, err.err);

	CHECK_CALL(check_getpid());
	CHECK_CALL(check_mmap_exec(false));
	CHECK_CALL(check_mmap_read());
	CHECK_CALL(check_socket(true));
	CHECK_CALL(check_open_rdonly(true));
	CHECK_CALL(check_open_tmpfile(false));
	CHECK_CALL(check_seccomp_change(true));
	PASS();
}

TEST
seccomp_io_inet(void)
{
	const unsigned flags = SECCOMP_SANDBOX | SECCOMP_STDIO | SECCOMP_INET;
	auto_result err = seccomp_apply(flags);
	ASSERT_EQ(OK, err.err);

	CHECK_CALL(check_getpid());
	CHECK_CALL(check_mmap_exec(false));
	CHECK_CALL(check_mmap_read());
	CHECK_CALL(check_socket(true));
	CHECK_CALL(check_open_rdonly(false));
	CHECK_CALL(check_open_tmpfile(false));
	CHECK_CALL(check_seccomp_change(true));
	PASS();
}

TEST
seccomp_io(void)
{
	const unsigned flags = SECCOMP_SANDBOX | SECCOMP_STDIO;
	auto_result err = seccomp_apply(flags);
	ASSERT_EQ(OK, err.err);

	CHECK_CALL(check_getpid());
	CHECK_CALL(check_mmap_exec(false));
	CHECK_CALL(check_mmap_read());
	CHECK_CALL(check_socket(false));
	CHECK_CALL(check_open_rdonly(false));
	CHECK_CALL(check_open_tmpfile(false));
	CHECK_CALL(check_seccomp_change(true));
	PASS();
}

TEST
seccomp_io_sealed_sandbox(void)
{
	const unsigned flags = SECCOMP_STDIO;
	auto_result err = seccomp_apply(flags);
	ASSERT_EQ(OK, err.err);

	CHECK_CALL(check_getpid());
	CHECK_CALL(check_mmap_exec(false));
	CHECK_CALL(check_mmap_read());
	CHECK_CALL(check_socket(false));
	CHECK_CALL(check_open_rdonly(false));
	CHECK_CALL(check_open_tmpfile(false));
	CHECK_CALL(check_seccomp_change(false));
	PASS();
}

SUITE(seccomp_variants)
{
	RUN_TEST(seccomp_none);
	RUN_TEST(seccomp_io_inet_tmpfile);
	RUN_TEST(seccomp_io_inet_rpath);
	RUN_TEST(seccomp_io_inet);
	RUN_TEST(seccomp_io);
	RUN_TEST(seccomp_io_sealed_sandbox);
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
