#include "write.h"

#include <assert.h>
#include <limits.h>

ssize_t
write_with_retry(int fd, const char *buf, size_t nbyte)
{
	const size_t expected = nbyte;

	while (nbyte > 0) {
		const ssize_t written = write(fd, buf, nbyte);
		if (written < 0) {
			return written;
		}
		buf += written;
		nbyte -= written;
	}

	assert(expected <= SSIZE_MAX);
	return (ssize_t)expected;
}
