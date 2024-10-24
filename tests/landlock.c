#include "landlock.h"

#include "greatest.h"
#include "tmpfile.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

TEST
before_landlock_filesystem(void)
{
	int fd = open(__FILE__, O_RDONLY);
	ASSERT_GTE(fd, 0);
	int rc = close(fd);
	ASSERT_EQ(rc, 0);

	int tmp = -1;
	result_t err = tmpfd(&tmp);
	ASSERT_EQ(err.err, OK);
	ASSERT_GTE(tmp, 0);
	rc = close(tmp);
	ASSERT_EQ(rc, 0);

	PASS();
}

TEST
before_landlock_network(void)
{
	int sfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	ASSERT_GTE(sfd, 0);

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(443);
	inet_pton(AF_INET, "93.184.215.14", &sa.sin_addr); /* example.com */

	const int connected = connect(sfd, (struct sockaddr *)&sa, sizeof(sa));
	const int closed = close(sfd);
	ASSERT_EQ(connected, 0);
	ASSERT_EQ(closed, 0);

	PASS();
}

SUITE(before_landlock)
{
	RUN_TEST(before_landlock_filesystem);
	RUN_TEST(before_landlock_network);
}

TEST
setup_partial_landlock(void)
{
	const char *paths[] = {
		P_tmpdir,
	};
	result_t err = landlock_apply(paths, 1, 443);
	ASSERT_EQ(err.err, OK);
	PASS();
}

TEST
partial_landlock_filesystem(void)
{
	int fd = open(__FILE__, O_RDONLY);
	ASSERT_LT(fd, 0);

	int tmp = -1;
	result_t err = tmpfd(&tmp);
	ASSERT_EQ(err.err, OK);
	ASSERT_GTE(tmp, 0);
	int rc = close(tmp);
	ASSERT_EQ(rc, 0);

	PASS();
}

SUITE(partial_landlock)
{
	RUN_TEST(setup_partial_landlock);
	RUN_TEST(partial_landlock_filesystem);
	RUN_TEST(before_landlock_network); /* reuse before_* network check */
}

TEST
setup_full_landlock(void)
{
	result_t err = landlock_apply(NULL, 0, 0);
	ASSERT_EQ(err.err, OK);
	PASS();
}

TEST
after_landlock_filesystem(void)
{
	int fd = open(__FILE__, O_RDONLY);
	ASSERT_LT(fd, 0);

	int tmp = -1;
	result_t err = tmpfd(&tmp);
	ASSERT_EQ(err.err, ERR_TMPFILE);
	ASSERT_LT(tmp, 0);

	PASS();
}

TEST
after_landlock_network(void)
{
	int sfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	ASSERT_GTE(sfd, 0);

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(443);
	inet_pton(AF_INET, "93.184.215.14", &sa.sin_addr); /* example.com */

	const int connected = connect(sfd, (struct sockaddr *)&sa, sizeof(sa));
	const int connected_errno = errno;
	const int closed = close(sfd);
	ASSERT_EQ(connected, -1);
	ASSERT_EQ(connected_errno, EACCES);
	ASSERT_EQ(closed, 0);

	PASS();
}

SUITE(full_landlock)
{
	RUN_TEST(setup_full_landlock);
	RUN_TEST(after_landlock_filesystem);
	RUN_TEST(after_landlock_network);
}
