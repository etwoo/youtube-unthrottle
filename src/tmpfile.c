#include "tmpfile.h"

#include "debug.h"

#include <assert.h>
#include <fcntl.h>
#include <stdio.h> /* for P_tmpdir */
#include <sys/mman.h>
#include <sys/stat.h>

int
tmpfd(void)
{
	/*
	 * Disable spurious -fanalyzer warning under GCC:
	 *
	 *     warning: leak of "fs" [CWE-401] [-Wanalyzer-malloc-leak]
	 *
	 * GCC seems to think we should fclose(fs) before returning the fd
	 * produced by fileno(fs), but this would actually result in the fd
	 * being invalidated as well.
	 *
	 * Put another way, if we fclose(fs) before returning fd, the latter
	 * will produce an EBADF when we attempt to close(fd).
	 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wanalyzer-malloc-leak"

	int fd = -1;
	{
		/*
		 * strace suggests that tmpfile() already uses O_TMPFILE when
		 * possible, at least under glibc. As a result, there's no need
		 * to call open() with O_TMPFILE|O_EXCL ourselves.
		 */
		FILE *fs = tmpfile();
		if (fs == NULL) {
			pwarn("Error in tmpfile()");
		} else {
			fd = fileno(fs);
			if (fd < 0) {
				pwarn("Error in fileno()");
				fclose(fs);
			}
		}
	}

	if (fd >= 0) {
		debug("Got tmpfile with fd=%d", fd);
	}
	return fd;

#pragma GCC diagnostic pop
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
