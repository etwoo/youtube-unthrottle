#include "sandbox/linux/landlock.h"

#include "greatest.h"
#include "sys/tmpfile.h"
#include "test_network.h"

#include <fcntl.h>  /* for open() */
#include <unistd.h> /* for close() */

typedef enum {
	ALLOW_ALL,
	ALLOW_TMPFILE,
	ALLOW_NONE,
} check_landlock_filesystem_level;

static WARN_UNUSED enum greatest_test_res
check_landlock_filesystem(check_landlock_filesystem_level level)
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
	if (level <= ALLOW_TMPFILE) {
		ASSERT_EQ(OK, err.err);
		ASSERT_LTE(0, tmp);
		int rc = close(tmp);
		ASSERT_EQ(0, rc);
	} else {
		ASSERT_EQ(ERR_TMPFILE, err.err);
		ASSERT_GT(0, tmp);
	}

	PASS();
}

TEST
landlock_none(void)
{
	CHECK_CALL(check_landlock_filesystem(ALLOW_ALL));
	CHECK_CALL(check_network(true));
	PASS();
}

TEST
landlock_filesystem_except_tmpfile(void)
{
	const char *paths[] = {
		P_tmpdir,
	};
	auto_result err = landlock_apply(paths, 1, 443);
	ASSERT_EQ(OK, err.err);

	CHECK_CALL(check_landlock_filesystem(ALLOW_TMPFILE));
	CHECK_CALL(check_network(true));
	PASS();
}

TEST
landlock_filesystem_full(void)
{
	auto_result err = landlock_apply(NULL, 0, 443);
	ASSERT_EQ(OK, err.err);

	CHECK_CALL(check_landlock_filesystem(ALLOW_NONE));
	CHECK_CALL(check_network(true));
	PASS();
}

TEST
landlock_filesystem_network(void)
{
	auto_result err = landlock_apply(NULL, 0, 0);
	ASSERT_EQ(OK, err.err);

	CHECK_CALL(check_landlock_filesystem(ALLOW_NONE));
	CHECK_CALL(check_network(false));
	PASS();
}

SUITE(landlock_variants)
{
	RUN_TEST(landlock_none);
	RUN_TEST(landlock_filesystem_except_tmpfile);
	RUN_TEST(landlock_filesystem_full);
	RUN_TEST(landlock_filesystem_network);
}
