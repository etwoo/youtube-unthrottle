#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* for O_TMPFILE in open() */
#endif
#include <fcntl.h>
#undef _GNU_SOURCE /* revert for any other includes */

#include "greatest.h"
#include "seccomp.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

TEST before_seccomp(void) {
	pid_t my_pid = getpid();
	ASSERT_GT(my_pid, 0);

	/* mmap should be totally unrestricted */
	void *p = mmap(NULL, 4, PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	ASSERT_NEQ(p, MAP_FAILED);
	int rc = munmap(p, 4);
	ASSERT_EQ(rc, 0);

	int sfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	ASSERT_GTE(sfd, 0);
	rc = close(sfd);
	ASSERT_EQ(rc, 0);

	int fd = open(__FILE__, O_RDONLY);
	ASSERT_GTE(fd, 0);
	rc = close(fd);
	ASSERT_EQ(rc, 0);

	int tmpfd = open(P_tmpdir, O_TMPFILE | O_EXCL | O_RDWR, 0);
	ASSERT_GTE(tmpfd, 0);
	rc = close(tmpfd);
	ASSERT_EQ(rc, 0);

	PASS();
}

TEST seccomp_io_inet_tmpfile(void) {
	seccomp_apply(SECCOMP_SANDBOX | SECCOMP_STDIO | SECCOMP_INET |
	              SECCOMP_TMPFILE);

	pid_t my_pid = getpid();
	ASSERT_GT(my_pid, 0);

	/* mmap should no longer allow PROT_EXEC */
	void *p = mmap(NULL, 4, PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	ASSERT_EQ(p, MAP_FAILED);
	ASSERT_EQ(errno, EACCES);
	/* mmap should still allow PROT_READ */
	p = mmap(NULL, 4, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	ASSERT_NEQ(p, MAP_FAILED);
	int rc = munmap(p, 4);
	ASSERT_EQ(rc, 0);

	int sfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	ASSERT_GTE(sfd, 0);
	rc = close(sfd);
	ASSERT_EQ(rc, 0);

	int fd = open(__FILE__, O_RDONLY);
	ASSERT_GTE(fd, 0);
	rc = close(fd);
	ASSERT_EQ(rc, 0);

	int tmpfd = open(P_tmpdir, O_TMPFILE | O_EXCL | O_RDWR, 0);
	ASSERT_GTE(tmpfd, 0);
	rc = close(tmpfd);
	ASSERT_EQ(rc, 0);

	PASS();
}

TEST seccomp_io_inet_rpath(void) {
	seccomp_apply(SECCOMP_SANDBOX | SECCOMP_STDIO | SECCOMP_INET |
	              SECCOMP_RPATH);

	pid_t my_pid = getpid();
	ASSERT_GT(my_pid, 0);

	/* mmap should no longer allow PROT_EXEC */
	void *p = mmap(NULL, 4, PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	ASSERT_EQ(p, MAP_FAILED);
	ASSERT_EQ(errno, EACCES);
	/* mmap should still allow PROT_READ */
	p = mmap(NULL, 4, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	ASSERT_NEQ(p, MAP_FAILED);
	int rc = munmap(p, 4);
	ASSERT_EQ(rc, 0);

	int sfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	ASSERT_GTE(sfd, 0);
	rc = close(sfd);
	ASSERT_EQ(rc, 0);

	int fd = open(__FILE__, O_RDONLY);
	ASSERT_GTE(fd, 0);
	rc = close(fd);
	ASSERT_EQ(rc, 0);

	/* open should no longer allow O_TMPFILE */
	int tmpfd = open(P_tmpdir, O_TMPFILE | O_EXCL | O_RDWR, 0);
	ASSERT_LT(tmpfd, 0);
	ASSERT_EQ(errno, EACCES);

	PASS();
}

TEST seccomp_io_inet(void) {
	seccomp_apply(SECCOMP_SANDBOX | SECCOMP_STDIO | SECCOMP_INET);

	pid_t my_pid = getpid();
	ASSERT_GT(my_pid, 0);

	/* mmap should no longer allow PROT_EXEC */
	void *p = mmap(NULL, 4, PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	ASSERT_EQ(p, MAP_FAILED);
	ASSERT_EQ(errno, EACCES);
	/* mmap should still allow PROT_READ */
	p = mmap(NULL, 4, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	ASSERT_NEQ(p, MAP_FAILED);
	int rc = munmap(p, 4);
	ASSERT_EQ(rc, 0);

	int sfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	ASSERT_GTE(sfd, 0);
	rc = close(sfd);
	ASSERT_EQ(rc, 0);

	/* open should no longer allow O_RDONLY */
	int fd = open(__FILE__, O_RDONLY);
	ASSERT_LT(fd, 0);
	ASSERT_EQ(errno, EACCES);

	/* open should no longer allow O_TMPFILE */
	int tmpfd = open(P_tmpdir, O_TMPFILE | O_EXCL | O_RDWR, 0);
	ASSERT_LT(tmpfd, 0);
	ASSERT_EQ(errno, EACCES);

	PASS();
}

TEST seccomp_io(void) {
	seccomp_apply(SECCOMP_SANDBOX | SECCOMP_STDIO);

	pid_t my_pid = getpid();
	ASSERT_GT(my_pid, 0);

	/* mmap should no longer allow PROT_EXEC */
	void *p = mmap(NULL, 4, PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	ASSERT_EQ(p, MAP_FAILED);
	ASSERT_EQ(errno, EACCES);
	/* mmap should still allow PROT_READ */
	p = mmap(NULL, 4, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	ASSERT_NEQ(p, MAP_FAILED);
	int rc = munmap(p, 4);
	ASSERT_EQ(rc, 0);

	/* socket should no longer be allowed */
	int sfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	ASSERT_LT(sfd, 0);
	ASSERT_EQ(errno, EACCES);

	/* open should no longer allow O_RDONLY */
	int fd = open(__FILE__, O_RDONLY);
	ASSERT_LT(fd, 0);
	ASSERT_EQ(errno, EACCES);

	/* open should no longer allow O_TMPFILE */
	int tmpfd = open(P_tmpdir, O_TMPFILE | O_EXCL | O_RDWR, 0);
	ASSERT_LT(tmpfd, 0);
	ASSERT_EQ(errno, EACCES);

	PASS();
}

/*
 * Note: it seems we cannot currently test seccomp_apply(SECCOMP_SANDBOX) in
 * this single-process unit test rig, as restricting the sandbox to this degree
 * prevents the unit test rig from proceeding, e.g. prevents greatest.h macros
 * from being able to print test results to stdout. We'd probably need a
 * multiprocess or multithreaded unit test rig, to allow seccomp_apply() to
 * restrict a child process without restricting the unit test rig itself.
 */

SUITE(seccomp) {
	RUN_TEST(before_seccomp);
	RUN_TEST(seccomp_io_inet_tmpfile);
	RUN_TEST(seccomp_io_inet_rpath);
	RUN_TEST(seccomp_io_inet);
	RUN_TEST(seccomp_io);
}

GREATEST_MAIN_DEFS();

int
main(int argc, char **argv)
{
	GREATEST_MAIN_BEGIN();

	RUN_SUITE(seccomp);

	GREATEST_MAIN_END();
}
