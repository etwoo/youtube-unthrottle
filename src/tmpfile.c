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

result_t
tmpfd(int *fd)
{
	/*
	 * strace suggests that tmpfile() already uses O_TMPFILE when
	 * possible, at least under glibc. As a result, there's no need
	 * to call open() with O_TMPFILE|O_EXCL ourselves.
	 */
	FILE *fs __attribute__((cleanup(checked_fclose))) = tmpfile();
	check_if_cond_with_errno(fs == NULL, ERR_TMPFILE);

	/*
	 * dup the underlying file descriptor behind the tmpfile stream, and
	 * then close the original stream. I believe (though I'm not totally
	 * sure) that this is necessary to avoid leaking the FILE* itself.
	 */

	int inner_fd = fileno(fs);
	check_if_cond_with_errno(inner_fd < 0, ERR_TMPFILE_FILENO);

	int dup_fd = dup(inner_fd);
	check_if_cond_with_errno(dup_fd < 0, ERR_TMPFILE_DUP);

	*fd = dup_fd;
	debug("Got tmpfile with fd=%d", *fd);
	return RESULT_OK;
}

result_t
tmpmap(int fd, void **addr, unsigned int *sz)
{
	struct stat st = {
		.st_size = 0,
	};
	check_if_cond_with_errno(fstat(fd, &st) < 0, ERR_TMPFILE_FSTAT);
	*sz = st.st_size;

	*addr = mmap(NULL, *sz, PROT_READ, MAP_PRIVATE, fd, 0);
	check_if_cond_with_errno(*addr == MAP_FAILED, ERR_TMPFILE_MMAP);

	/*
	 * mmap() can technically return NULL on some platforms, but our
	 * callers use NULL as a default/sentinel value to indicate failure.
	 * Just bail out under this condition. If we ever want to deal with
	 * this, we'll need to export MAP_FAILED and break encapsulation of
	 * the tmpfile.c module a bit.
	 */
	assert(*addr != NULL);

	return RESULT_OK;
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
