#include "coverage.h"

#ifndef WITH_COVERAGE

int
coverage_open(void)
{
	return -1;
}

void
coverage_write_and_close(int fd __attribute__((unused)))
{
}

#else

#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* for O_PATH in open() */
#endif
#include <fcntl.h>
#undef _GNU_SOURCE /* revert for any other includes */

#include "array.h"
#include "debug.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

int __llvm_profile_runtime(void);

int
__llvm_profile_runtime(void)
{
	return 0;
}

uint64_t __llvm_profile_get_size_for_buffer(void);
int __llvm_profile_write_buffer(char *buffer);

int
coverage_open(void)
{
	char *profile = getenv("COVERAGE_PROFILE_DIR");
	if (profile == NULL) {
		warn_then_return_negative_1("COVERAGE_PROFILE_DIR is not set");
	}

	bool rc = mkdir(profile, S_IRWXU) == 0 || errno == EEXIST;
	error_if(rc == false, "Cannot create coverage profile directory");

	int dirfd = open(profile, O_DIRECTORY | O_PATH);
	error_if(dirfd < 0, "Cannot open coverage profile directory fd");

	char random_bytes[4];
	ssize_t got_bytes = getrandom(random_bytes, sizeof(random_bytes), 0);
	error_if(got_bytes < 0, "Cannot obtain random bytes");

	char p[(2 * sizeof(random_bytes)) + 1];
	memset(p, '\0', sizeof(p));

	for (size_t i = 0; i < ARRAY_SIZE(random_bytes); ++i) {
		sprintf(p + (i * 2), "%02hhX", random_bytes[i]);
	}

	int fd = -1;
	fd = openat(dirfd, p, O_CREAT | O_EXCL | O_WRONLY, S_IRUSR | S_IWUSR);
	error_if(fd < 0, "Cannot open coverage profile file");

	debug("Opened coverage file with dir=%s, filename=%s", profile, p);
	return fd;
}

void
coverage_write_and_close(int fd)
{
	if (fd < 0) {
		warn_then_return("Invalid coverage fd: %d", fd);
	}

	uint64_t sz = __llvm_profile_get_size_for_buffer();
	error_if(sz == 0, "Got invalid size zero for coverage buffer");

	void *buf = malloc(sz);
	error_if(buf == NULL, "Cannot malloc() buffer for coverage data");

	int copied = __llvm_profile_write_buffer(buf);
	error_if(copied < 0, "Cannot copy coverage data to in-memory buffer");

	void *to_write = buf;
	for (size_t remaining_bytes = sz; remaining_bytes > 0;) {
		const ssize_t written = write(fd, to_write, remaining_bytes);
		error_if(written < 0, "Cannot write to coverage profile file");
		to_write += written;
		remaining_bytes -= written;
	}

	debug("Wrote %zd bytes to coverage fd=%d", sz, fd);

	free(buf);
	info_if(close(fd) < 0, "Ignoring error close()-ing coverage fd");
}

#endif

void
coverage_cleanup(int *fd)
{
	coverage_write_and_close(*fd);
}
