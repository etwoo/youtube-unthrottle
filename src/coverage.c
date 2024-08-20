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

#include <sys/random.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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
	int fd = -1;

	char *profile = getenv("COVERAGE_PROFILE_DIR");
	if (profile == NULL) {
		warn("COVERAGE_PROFILE_DIR is not set");
		goto error;
	}

	if (mkdir(profile, S_IRWXU) < 0 && errno != EEXIST) {
		pwarn("Error creating coverage profile directory");
		goto error;
	}

	int dirfd = open(profile, O_DIRECTORY | O_PATH);
	if (dirfd < 0) {
		pwarn("Error opening coverage profile directory fd");
		goto error;
	}

	char random_bytes[4];
	if (getrandom(random_bytes, sizeof(random_bytes), 0) < 0) {
		pwarn("Error obtaining random bytes");
		goto error;
	}

	char name[(2 * sizeof(random_bytes)) + 1];
	memset(name, '\0', sizeof(name));

	for (size_t i = 0; i < ARRAY_SIZE(random_bytes); ++i) {
		sprintf(name + (i * 2), "%02hhX", random_bytes[i]);
	}

	fd = openat(dirfd, name, O_CREAT|O_EXCL|O_WRONLY, S_IRUSR|S_IWUSR);
	if (fd < 0) {
		pwarn("Error opening coverage profile file");
		goto error;
	}

	debug("Opened coverage file with dir=%s, filename=%s", profile, name);
error:
	return fd;
}

void
coverage_write_and_close(int fd)
{
	void *buf = NULL;

	if (fd < 0) {
		warn("Invalid coverage fd: %d", fd);
		goto error;
	}

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
			pwarn("Error writing to coverage profile file");
			goto error;
		}
		remaining_bytes -= written;
	}

	debug("Wrote %zd bytes to coverage fd=%d", sz, fd);

error:
	free(buf);
	if (fd >= 0 && close(fd) < 0) {
		pwarn("Ignoring error while close()-ing coverage fd");
	}
}

#endif
