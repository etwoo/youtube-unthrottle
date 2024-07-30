#include "tmpfile.h"

#include "debug.h"

#include <assert.h>
#include <fcntl.h>
#include <stdio.h> /* for P_tmpdir */
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

int
tmpfd(void)
{
	int fd = -1;

	/*
	 * strace suggests that tmpfile() already uses O_TMPFILE when
	 * possible, at least under glibc. As a result, there's no need
	 * to call open() with O_TMPFILE|O_EXCL ourselves.
	 */
	FILE *fs = tmpfile();
	if (fs == NULL) {
		pwarn("Error in tmpfile()");
		goto cleanup;
	}

	/*
	 * dup the underlying file descriptor behind the tmpfile stream, and
	 * then close the original stream. I believe (though I'm not totally
	 * sure) that this is necessary to avoid leaking the FILE* itself.
	 */

	int inner_fd = fileno(fs);
	if (inner_fd < 0) {
		pwarn("Error in fileno()");
		goto cleanup;
	}

	fd = dup(inner_fd);
	if (fd < 0) {
		pwarn("Error in dup()");
		goto cleanup;
	}

	debug("Got tmpfile with fd=%d", fd);

cleanup:
	if (fs != NULL && fclose(fs) != 0) {
		pwarn("Ignoring error while fclose()-ing tmpfile stream");
	}
	return fd;
}

bool
tmpmap(int fd, void **addr, unsigned int *sz)
{
	struct stat st = {
		.st_size = 0,
	};
	if (fstat(fd, &st) < 0) {
		pwarn("Error fetching size of tmpfile via fstat()");
		return false;
	}
	*sz = st.st_size;

	*addr = mmap(NULL, *sz, PROT_READ, MAP_PRIVATE, fd, 0);
	if (*addr == MAP_FAILED) {
		pwarn("Error mmap()-ing tmpfile");
		return false;
	}

	/*
	 * mmap() can technically return NULL on some platforms, but our
	 * callers use NULL as a default/sentinel value to indicate failure.
	 * Just bail out under this condition. If we ever want to deal with
	 * this, we'll need to export MAP_FAILED and break encapsulation of
	 * the tmpfile.c module a bit.
	 */
	assert(*addr != NULL);

	return true;
}

void
tmpunmap(void *addr, unsigned int sz)
{
	if (addr == MAP_FAILED || addr == NULL) {
		return;
	}

	if (munmap(addr, sz) < 0) {
		pwarn("Ignoring error while munmap()-ing tmpfile");
	}
}
