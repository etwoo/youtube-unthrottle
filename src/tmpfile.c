#include "tmpfile.h"

#include "debug.h"

#include <assert.h>
#include <fcntl.h>
#include <stdio.h> /* for P_tmpdir */
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static void
checked_fclose(FILE **fs)
{
	info_m_if(*fs && fclose(*fs), "Ignoring error fclose()-ing stream");
}

int
tmpfd(void)
{
	/*
	 * strace suggests that tmpfile() already uses O_TMPFILE when
	 * possible, at least under glibc. As a result, there's no need
	 * to call open() with O_TMPFILE|O_EXCL ourselves.
	 */
	FILE *fs __attribute__((cleanup(checked_fclose))) = tmpfile();
	if (fs == NULL) {
		warn_m_then_return(-1, "Error in tmpfile()");
	}

	/*
	 * dup the underlying file descriptor behind the tmpfile stream, and
	 * then close the original stream. I believe (though I'm not totally
	 * sure) that this is necessary to avoid leaking the FILE* itself.
	 */

	int inner_fd = fileno(fs);
	if (inner_fd < 0) {
		warn_m_then_return(-1, "Error in fileno()");
	}

	int fd = dup(inner_fd);
	if (fd < 0) {
		warn_m_then_return(-1, "Error in dup()");
	}

	debug("Got tmpfile with fd=%d", fd);
	return fd;
}

bool
tmpmap(int fd, void **addr, unsigned int *sz)
{
	struct stat st = {
		.st_size = 0,
	};
	if (fstat(fd, &st) < 0) {
		warn_m_then_return(false, "Error fstat()-ing tmpfile");
	}
	*sz = st.st_size;

	*addr = mmap(NULL, *sz, PROT_READ, MAP_PRIVATE, fd, 0);
	if (*addr == MAP_FAILED) {
		warn_m_then_return(false, "Error mmap()-ing tmpfile");
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

	const int rc = munmap(addr, sz);
	info_m_if(rc < 0, "Ignoring error munmap()-ing tmpfile");
}
