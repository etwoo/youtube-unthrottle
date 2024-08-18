#include "landlock.h"

#include "debug.h"
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

	int tmp = tmpfd();
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
	landlock_apply(paths, 1, 443);
	PASS();
}

TEST
partial_landlock_filesystem(void)
{
	int fd = open(__FILE__, O_RDONLY);
	ASSERT_LT(fd, 0);

	int tmp = tmpfd();
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
	landlock_apply(NULL, 0, 0);
	PASS();
}

TEST
after_landlock_filesystem(void)
{
	int fd = open(__FILE__, O_RDONLY);
	ASSERT_LT(fd, 0);

	int tmp = tmpfd();
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

	int rc = connect(sfd, (struct sockaddr *)&sa, sizeof(sa));
	ASSERT_EQ(rc, -1);
	ASSERT_EQ(errno, EACCES);

	rc = close(sfd);
	ASSERT_EQ(rc, 0);

	PASS();
}

SUITE(full_landlock)
{
	RUN_TEST(setup_full_landlock);
	RUN_TEST(after_landlock_filesystem);
	RUN_TEST(after_landlock_network);
}

GREATEST_MAIN_DEFS();

#ifdef WITH_COVERAGE

uint64_t __llvm_profile_get_size_for_buffer(void);
int __llvm_profile_write_buffer(char *buffer);

static int
open_coverage_fd(void)
{
	int fd = -1;

	char *profile = getenv("LLVM_PROFILE_FILE");
	if (profile == NULL) {
		pwarn("LLVM_PROFILE_FILE is not set");
		goto error;
	}

	fd = open(profile, O_CREAT | O_EXCL | O_WRONLY, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		pwarn("Error opening LLVM_PROFILE_FILE");
		goto error;
	}

error:
	return fd;
}

static void
write_coverage_and_close_fd(int fd)
{
	void *buf = NULL;

	uint64_t sz = __llvm_profile_get_size_for_buffer();
	if (sz == 0) {
		pwarn("Got invalid size zero for coverage buffer");
		goto error;
	}

	buf = malloc(sz);
	if (buf == NULL) {
		pwarn("Error in malloc() for coverage data");
		goto error;
	}

	if (__llvm_profile_write_buffer(buf) < 0) {
		pwarn("Error writing coverage data to in-memory buffer");
		goto error;
	}

	for (size_t remaining_bytes = sz; remaining_bytes > 0;) {
		const ssize_t written = write(fd, buf, remaining_bytes);
		if (written < 0) {
			pwarn("Error writing to LLVM_PROFILE_FILE");
			break;
		}
		remaining_bytes -= written;
	}

error:
	free(buf);
	if (fd >= 0 && close(fd) < 0) {
		pwarn("Ignoring error while close()-ing coverage fd");
	}
}

#endif

int
main(int argc, char **argv)
{
	GREATEST_MAIN_BEGIN();

#ifdef WITH_COVERAGE
	/*
	 * Open coverage file before Landlock starts blocking access.
	 */
	int coverage_fd = open_coverage_fd();
#endif

	RUN_SUITE(before_landlock);
	RUN_SUITE(partial_landlock);
	RUN_SUITE(full_landlock);

#ifdef WITH_COVERAGE
	write_coverage_and_close_fd(coverage_fd);
#endif

	GREATEST_MAIN_END();
}
