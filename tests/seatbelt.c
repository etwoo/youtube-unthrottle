#include "seatbelt.h"

#include "greatest.h"
#include "tmpfile.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <unistd.h>

typedef enum {
	ALLOW_ALL,
	ALLOW_TMPFILE_CREATE,
	ALLOW_TMPFILE_READ,
	ALLOW_NONE,
} check_seatbelt_filesystem_level;

static enum greatest_test_res
check_seatbelt_filesystem(check_seatbelt_filesystem_level level)
{
	int fd = open(__FILE__, O_RDONLY);
	if (level <= ALLOW_ALL) {
		ASSERT_LTE(0, fd);
		int rc = close(fd);
		ASSERT_EQ(0, rc);
	} else {
		ASSERT_GT(0, fd);
	}

	int tmp = -1;
	auto_result err = tmpfd(&tmp);
	if (level <= ALLOW_TMPFILE_CREATE) {
		ASSERT_EQ(OK, err.err);
		ASSERT_LTE(0, tmp);
		int rc = close(tmp);
		ASSERT_EQ(0, rc);
	} else {
		ASSERT_EQ(ERR_TMPFILE, err.err);
		ASSERT_GT(0, tmp);
	}

	fd = open(P_tmpdir, 0);
	if (level <= ALLOW_TMPFILE_READ) {
		ASSERT_LTE(0, fd);
		int rc = close(fd);
		ASSERT_EQ(0, rc);
	} else {
		ASSERT_GT(0, fd);
	}

	PASS();
}

static enum greatest_test_res
check_seatbelt_network(bool allowed)
{
	int sfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	ASSERT_LTE(0, sfd);

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(443);
	inet_pton(AF_INET, "23.192.228.68", &sa.sin_addr); /* example.com */

	const int connected = connect(sfd, (struct sockaddr *)&sa, sizeof(sa));
	const int connected_errno = errno;
	const int closed = close(sfd);
	if (allowed) {
		ASSERT_EQ(0, connected);
	} else {
		ASSERT_EQ(-1, connected);
		ASSERT_EQ(EPERM, connected_errno);
	}
	ASSERT_EQ(0, closed);

	PASS();
}

TEST
seatbelt_none(void)
{
	CHECK_CALL(check_seatbelt_filesystem(ALLOW_ALL));
	CHECK_CALL(check_seatbelt_network(true));
	PASS();
}

static struct seatbelt_context TEST_CONTEXT = {0};

TEST
seatbelt_filesystem_allows_tmpfile_create(void)
{
	auto_result err = seatbelt_init(&TEST_CONTEXT);
	ASSERT_EQ(OK, err.err);

	CHECK_CALL(check_seatbelt_filesystem(ALLOW_TMPFILE_CREATE));
	CHECK_CALL(check_seatbelt_network(true));
	PASS();
}

TEST
seatbelt_filesystem_allows_tmpfile_read(void)
{
	auto_result err = seatbelt_revoke(&TEST_CONTEXT, SEATBELT_TMPFILE);
	ASSERT_EQ(OK, err.err);

	CHECK_CALL(check_seatbelt_filesystem(ALLOW_TMPFILE_READ));
	CHECK_CALL(check_seatbelt_network(true));
	PASS();
}

TEST
seatbelt_filesystem_blocks_tmpfile(void)
{
	auto_result err = seatbelt_revoke(&TEST_CONTEXT, SEATBELT_RPATH);
	ASSERT_EQ(OK, err.err);

	CHECK_CALL(check_seatbelt_filesystem(ALLOW_NONE));
	CHECK_CALL(check_seatbelt_network(true));
	PASS();
}

TEST
seatbelt_filesystem_blocks_tmpfile_blocks_network(void)
{
	auto_result err = seatbelt_revoke(&TEST_CONTEXT, SEATBELT_INET);
	ASSERT_EQ(OK, err.err);

	CHECK_CALL(check_seatbelt_filesystem(ALLOW_NONE));
	CHECK_CALL(check_seatbelt_network(false));
	PASS();
}

SUITE(seatbelt_variants)
{
	RUN_TEST(seatbelt_none);
	RUN_TEST(seatbelt_filesystem_allows_tmpfile_create);
	RUN_TEST(seatbelt_filesystem_allows_tmpfile_read);
	RUN_TEST(seatbelt_filesystem_blocks_tmpfile);
	RUN_TEST(seatbelt_filesystem_blocks_tmpfile_blocks_network);
}
