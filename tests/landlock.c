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
	ASSERT_LTE(0, fd);
	int rc = close(fd);
	ASSERT_EQ(0, rc);

	int tmp = -1;
	result_t err = tmpfd(&tmp);
	ASSERT_EQ(OK, err.err);
	ASSERT_LTE(0, tmp);
	rc = close(tmp);
	ASSERT_EQ(0, rc);

	PASS();
}

TEST
before_landlock_network(void)
{
	int sfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	ASSERT_LTE(0, sfd);

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(443);
	inet_pton(AF_INET, "93.184.215.14", &sa.sin_addr); /* example.com */

	const int connected = connect(sfd, (struct sockaddr *)&sa, sizeof(sa));
	const int closed = close(sfd);
	ASSERT_EQ(0, connected);
	ASSERT_EQ(0, closed);

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
	ASSERT_EQ(OK, err.err);
	PASS();
}

TEST
partial_landlock_filesystem(void)
{
	int fd = open(__FILE__, O_RDONLY);
	ASSERT_GT(0, fd);

	int tmp = -1;
	result_t err = tmpfd(&tmp);
	ASSERT_EQ(OK, err.err);
	ASSERT_LTE(0, tmp);
	int rc = close(tmp);
	ASSERT_EQ(0, rc);

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
	ASSERT_EQ(OK, err.err);
	PASS();
}

TEST
after_landlock_filesystem(void)
{
	int fd = open(__FILE__, O_RDONLY);
	ASSERT_GT(0, fd);

	int tmp = -1;
	result_t err = tmpfd(&tmp);
	ASSERT_EQ(ERR_TMPFILE, err.err);
	ASSERT_GT(0, tmp);

	PASS();
}

TEST
after_landlock_network(void)
{
	int sfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	ASSERT_LTE(0, sfd);

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(443);
	inet_pton(AF_INET, "93.184.215.14", &sa.sin_addr); /* example.com */

	const int connected = connect(sfd, (struct sockaddr *)&sa, sizeof(sa));
	const int connected_errno = errno;
	const int closed = close(sfd);
	ASSERT_EQ(-1, connected);
	ASSERT_EQ(EACCES, connected_errno);
	ASSERT_EQ(0, closed);

	PASS();
}

SUITE(full_landlock)
{
	RUN_TEST(setup_full_landlock);
	RUN_TEST(after_landlock_filesystem);
	RUN_TEST(after_landlock_network);
}
