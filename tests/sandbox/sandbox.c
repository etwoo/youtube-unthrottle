#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* for O_TMPFILE in open() */
#endif
#include <fcntl.h>
#undef _GNU_SOURCE /* revert for any other includes */

#include "array.h"
#include "greatest.h"
#include "landlock.h"
#include "seccomp.h"

#include <arpa/inet.h> /* for inet_addr() */
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h> /* for P_tmpdir */
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

TEST before_landlock_filesystem(void) {
	int fd = open(__FILE__, O_RDONLY);
	ASSERT_GTE(fd, 0);
	int rc = close(fd);
	ASSERT_EQ(rc, 0);

	int tmpfd = open(P_tmpdir, O_TMPFILE | O_EXCL | O_RDWR, 0);
	ASSERT_GTE(tmpfd, 0);
	rc = close(tmpfd);
	ASSERT_EQ(rc, 0);

	PASS();
}

TEST before_landlock_network(void) {
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	int sfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	ASSERT_GTE(sfd, 0);

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(443);
	sa.sin_addr.s_addr = inet_addr("example.com");

	int rc = connect(sfd, &sa, sizeof(sa));
	ASSERT_EQ(rc, 0);

	rc = close(sfd);
	ASSERT_EQ(rc, 0);

	PASS();
}

SUITE(before_landlock) {
	RUN_TEST(before_landlock_filesystem);
	RUN_TEST(before_landlock_network);
}

TEST setup_partial_landlock(void) {
	const char *paths[] = {
		P_tmpdir,
	};
	landlock_apply(paths, 1, 443);
	PASS();
}

TEST partial_landlock_filesystem(void) {
	int fd = open(__FILE__, O_RDONLY);
	ASSERT_LT(fd, 0);

	int tmpfd = open(P_tmpdir, O_TMPFILE | O_EXCL | O_RDWR, 0);
	ASSERT_GTE(tmpfd, 0);
	int rc = close(tmpfd);
	ASSERT_EQ(rc, 0);

	PASS();
}

SUITE(partial_landlock) {
	RUN_TEST(setup_partial_landlock);
	RUN_TEST(partial_landlock_filesystem);
	RUN_TEST(before_landlock_network); /* reuse before_* network check */
}

TEST setup_full_landlock(void) {
	landlock_apply(NULL, 0, 0);
	PASS();
}

TEST after_landlock_filesystem(void) {
	int fd = open(__FILE__, O_RDONLY);
	ASSERT_LT(fd, 0);

	int tmpfd = open(P_tmpdir, O_TMPFILE | O_EXCL | O_RDWR, 0);
	ASSERT_LT(tmpfd, 0);

	PASS();
}

TEST after_landlock_network(void) {
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	int sfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	ASSERT_GTE(sfd, 0);

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(443);
	sa.sin_addr.s_addr = inet_addr("example.com");

	int rc = connect(sfd, &sa, sizeof(sa));
	ASSERT_EQ(rc, -1);
	ASSERT_EQ(errno, EACCES);

	rc = close(sfd);
	ASSERT_EQ(rc, 0);

	PASS();
}

SUITE(full_landlock) {
	RUN_TEST(setup_full_landlock);
	RUN_TEST(after_landlock_filesystem);
	RUN_TEST(after_landlock_network);
}

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
	printf("WTF tmpfd %d\n", tmpfd);
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

TEST full_seccomp(void) {
	seccomp_apply(SECCOMP_SANDBOX);

	/* even getpid should be blocked now */
	pid_t my_pid = getpid();
	ASSERT_LT(my_pid, 0);
	ASSERT_EQ(errno, EACCES);

	/* mmap should no longer allow PROT_EXEC */
	void *p = mmap(NULL, 4, PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	ASSERT_EQ(p, MAP_FAILED);
	ASSERT_EQ(errno, EACCES);
	/* mmap should no longer allow PROT_READ */
	p = mmap(NULL, 4, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	ASSERT_EQ(p, MAP_FAILED);
	ASSERT_EQ(errno, EACCES);

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

SUITE(seccomp) {
	RUN_TEST(before_seccomp);
	RUN_TEST(seccomp_io_inet_tmpfile);
	RUN_TEST(seccomp_io_inet_rpath);
	RUN_TEST(seccomp_io_inet);
	RUN_TEST(seccomp_io);
	RUN_TEST(full_seccomp);
}

GREATEST_MAIN_DEFS();

int
main(int argc, char **argv)
{
	GREATEST_MAIN_BEGIN();

	/*
	 * Note: these tests are similar to `youtube-unthrottle --try-sandbox`
	 */
	RUN_SUITE(before_landlock);
	RUN_SUITE(partial_landlock);
	RUN_SUITE(full_landlock);
	RUN_SUITE(seccomp);

	GREATEST_MAIN_END();
}
