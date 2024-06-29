#ifndef _GNU_SOURCE
#  define _GNU_SOURCE /* for O_TMPFILE in open() */
#endif
#include <fcntl.h>
#undef _GNU_SOURCE /* revert for any other includes */

#include "debug.h"
#include "tmpfile.h"

#include <assert.h>
#include <sys/mman.h>
#include <sys/stat.h>

static const char TMPDIR[] = "/tmp";

int
tmpfd(void)
{
	int fd = open(TMPDIR, O_TMPFILE | O_EXCL | O_RDWR, 0);
	if (fd < 0) {
		pwarn("Error creating tmpfile via open() with O_TMPFILE");
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
