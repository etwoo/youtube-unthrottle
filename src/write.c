#include "write.h"

ssize_t
write_with_retry(int fd, const char *buf, size_t nbyte)
{
	const ssize_t expected = nbyte;

	while (nbyte > 0) {
		const ssize_t written = write(fd, buf, nbyte);
		if (written < 0) {
			return written;
		}
		buf += written;
		nbyte -= written;
	}

	return expected;
}
