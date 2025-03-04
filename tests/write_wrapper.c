#include "greatest.h"
#include "sys/write.h"

#include <errno.h>

TEST
write_positive(void)
{
	const int fd = fileno(stdout);
	ASSERT_EQ(1, fd);
	const char *str = "Testing write_with_retry(): Hello, World!\n";
	ssize_t written = write_with_retry(fd, str, strlen(str));
	ASSERT_LT(0, written);
	ASSERT_EQ(strlen(str), (size_t)written);
	PASS();
}

TEST
write_negative(void)
{
	const int invalid_fd = -1;
	const char *str = "Testing write_with_retry(): expecting EBADF\n";
	ssize_t written = write_with_retry(invalid_fd, str, strlen(str));
	ASSERT_EQ(-1, written);
	ASSERT_EQ(EBADF, errno);
	PASS();
}

SUITE(write_simple)
{
	RUN_TEST(write_positive);
	RUN_TEST(write_negative);
}
