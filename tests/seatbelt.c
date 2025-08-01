#include "sandbox/darwin/seatbelt.h"

#include "greatest.h"
#include "sys/tmpfile.h"
#include "test_network.h"

#include <fcntl.h>  /* for open() */
#include <unistd.h> /* for close() */

typedef enum {
	ALLOW_ALL,
	ALLOW_TMPFILE_CREATE,
	ALLOW_TMPFILE_READ,
	ALLOW_NONE,
} check_seatbelt_filesystem_level;

static WARN_UNUSED enum greatest_test_res
check_seatbelt_filesystem(check_seatbelt_filesystem_level level)
{
	int fd = open(__FILE__, O_RDONLY);
	if (level <= ALLOW_ALL) {
		ASSERT_LTE(0, fd);
		int rc = close(fd);
		ASSERT_EQ(0, rc);
	} else {
		if (fd >= 0) {
			/*
			 * Make sure not to leak a file descriptor, even if
			 * open() unexpectedly succeeds.
			 */
			close(fd);
		}
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
		if (tmp >= 0) {
			/*
			 * Make sure not to leak a file descriptor, even if
			 * tmpfd() unexpectedly succeeds.
			 */
			close(tmp);
		}
		ASSERT_EQ(ERR_TMPFILE, err.err);
		ASSERT_GT(0, tmp);
	}

	fd = open(P_tmpdir, 0);
	if (level <= ALLOW_TMPFILE_READ) {
		ASSERT_LTE(0, fd);
		int rc = close(fd);
		ASSERT_EQ(0, rc);
	} else {
		if (fd >= 0) {
			/*
			 * Make sure not to leak a file descriptor, even if
			 * open() unexpectedly succeeds.
			 */
			close(fd);
		}
		ASSERT_GT(0, fd);
	}

	PASS();
}

TEST
seatbelt_none(void)
{
	CHECK_CALL(check_seatbelt_filesystem(ALLOW_ALL));
	CHECK_CALL(check_network(true));
	PASS();
}

TEST
seatbelt_filesystem_allows_tmpfile_create(struct seatbelt_context *c)
{
	auto_result err = seatbelt_init(c);
	ASSERT_EQ(OK, err.err);

	CHECK_CALL(check_seatbelt_filesystem(ALLOW_TMPFILE_CREATE));
	CHECK_CALL(check_network(true));
	PASS();
}

TEST
seatbelt_filesystem_allows_tmpfile_read(struct seatbelt_context *c)
{
	auto_result err = seatbelt_revoke(c, SEATBELT_TMPFILE);
	ASSERT_EQ(OK, err.err);

	CHECK_CALL(check_seatbelt_filesystem(ALLOW_TMPFILE_READ));
	CHECK_CALL(check_network(true));
	PASS();
}

TEST
seatbelt_filesystem_blocks_tmpfile(struct seatbelt_context *c)
{
	auto_result err = seatbelt_revoke(c, SEATBELT_RPATH);
	ASSERT_EQ(OK, err.err);

	CHECK_CALL(check_seatbelt_filesystem(ALLOW_NONE));
	CHECK_CALL(check_network(true));
	PASS();
}

TEST
seatbelt_filesystem_blocks_tmpfile_blocks_network(struct seatbelt_context *c)
{
	auto_result err = seatbelt_revoke(c, SEATBELT_INET);
	ASSERT_EQ(OK, err.err);

	CHECK_CALL(check_seatbelt_filesystem(ALLOW_NONE));
	CHECK_CALL(check_network(false));
	PASS();
}

SUITE(seatbelt_variants)
{
	struct seatbelt_context context = {0};
	RUN_TEST(seatbelt_none);
	RUN_TESTp(seatbelt_filesystem_allows_tmpfile_create, &context);
	RUN_TESTp(seatbelt_filesystem_allows_tmpfile_read, &context);
	RUN_TESTp(seatbelt_filesystem_blocks_tmpfile, &context);
	RUN_TESTp(seatbelt_filesystem_blocks_tmpfile_blocks_network, &context);
}
