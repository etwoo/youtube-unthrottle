#include "coverage.h"

#ifndef WITH_COVERAGE

int
coverage_open(void)
{
	return -1;
}

void
coverage_write_and_close(int fd MAYBE_UNUSED)
{
}

#else

#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* for O_PATH */ // NOLINT(bugprone-reserved-identifier)
#endif
#include <fcntl.h>
#undef _GNU_SOURCE /* revert for any other includes */

#include "sys/array.h"
#include "sys/debug.h"
#include "sys/write.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

#define perror_if(cond, msg)                                                   \
	do {                                                                   \
		if (cond) {                                                    \
			perror(msg);                                           \
		}                                                              \
	} while (0)

// NOLINTBEGIN(bugprone-reserved-identifier)
int __llvm_profile_runtime(void);
uint64_t __llvm_profile_get_size_for_buffer(void);
int __llvm_profile_write_buffer(char *);
// NOLINTEND(bugprone-reserved-identifier)

int
__llvm_profile_runtime(void)
{
	return 0;
}

int
coverage_open(void)
{
	char *profile = getenv("COVERAGE_PROFILE_DIR");
	if (profile == NULL) {
		debug("COVERAGE_PROFILE_DIR is not set");
		return -1;
	}

	bool rc = mkdir(profile, S_IRWXU) == 0 || errno == EEXIST;
	perror_if(rc == false, "Cannot create coverage profile directory");

	int dirfd = open(profile, O_DIRECTORY | O_PATH);
	perror_if(dirfd < 0, "Cannot open coverage profile directory fd");

	char random_bytes[4];
	ssize_t got_bytes = getrandom(random_bytes, sizeof(random_bytes), 0);
	perror_if(got_bytes < 0, "Cannot obtain random bytes");

	char p[(2 * sizeof(random_bytes)) + 1];
	memset(p, '\0', sizeof(p));

	for (size_t i = 0; i < ARRAY_SIZE(random_bytes); ++i) {
		sprintf(p + (i * 2), "%02hhX", random_bytes[i]);
	}

	int fd = -1;
	fd = openat(dirfd, p, O_CREAT | O_EXCL | O_WRONLY, S_IRUSR | S_IWUSR);
	perror_if(fd < 0, "Cannot open coverage profile file");

	debug("Opened coverage file with dir=%s, filename=%s", profile, p);
	return fd;
}

void
coverage_write_and_close(int fd)
{
	if (fd < 0) {
		debug("No coverage fd set");
		return;
	}

	uint64_t sz = __llvm_profile_get_size_for_buffer();
	perror_if(sz == 0, "Got invalid size zero for coverage buffer");

	void *buf = malloc(sz);
	perror_if(buf == NULL, "Cannot malloc() buffer for coverage data");

	int copied = __llvm_profile_write_buffer(buf);
	perror_if(copied < 0, "Cannot copy coverage data to in-memory buffer");

	const ssize_t written = write_with_retry(fd, buf, sz);
	perror_if(written < 0, "Cannot write to coverage fd");

	debug("Wrote %zd bytes to coverage fd=%d", written, fd);

	free(buf);
	info_m_if(close(fd) < 0, "Ignoring error close()-ing coverage fd");
}

#undef perror_if

#endif

void
coverage_cleanup(const int *fd)
{
	coverage_write_and_close(*fd);
}
