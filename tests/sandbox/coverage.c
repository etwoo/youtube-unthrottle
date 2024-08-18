#include "coverage.h"

#ifndef WITH_COVERAGE

int
open_coverage_fd(void)
{
	return -1;
}

void
write_coverage_and_close_fd(int fd __attribute__((unused)))
{
}

#else

#include "debug.h"

#include <fcntl.h>
#include <stdint.h>
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
open_coverage_fd(void)
{
	int fd = -1;

	char *profile = getenv("COVERAGE_PROFILE");
	if (profile == NULL) {
		pwarn("COVERAGE_PROFILE is not set");
		goto error;
	}

	fd = open(profile, O_CREAT | O_EXCL | O_WRONLY, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		pwarn("Error opening COVERAGE_PROFILE");
		goto error;
	}

error:
	return fd;
}

void
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
			pwarn("Error writing to COVERAGE_PROFILE");
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
