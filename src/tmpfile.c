#include "tmpfile.h"

#include "debug.h"

#include <assert.h>
#include <fcntl.h>
#include <stdio.h> /* for <P_tmpdir> */
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
	 * strace output suggests that tmpfile() already uses O_TMPFILE when
	 * possible, at least under glibc. As a result, we need not call open()
	 * with O_TMPFILE|O_EXCL ourselves.
	 */
	FILE *fs __attribute__((cleanup(checked_fclose))) = tmpfile();
	check_if(fs == NULL, ERR_TMPFILE, errno);

	/*
	 * dup the underlying file descriptor behind the tmpfile stream, and
	 * then close the original stream. I believe fclose()-ing the original
	 * stream in this way avoids leaking the FILE* itself.
	 */

	int inner_fd = fileno(fs); // NOLINT(clang-analyzer-unix.Stream)
	check_if(inner_fd < 0, ERR_TMPFILE_FILENO, errno);

	int dup_fd = dup(inner_fd);
	check_if(dup_fd < 0, ERR_TMPFILE_DUP, errno);

	*fd = dup_fd;
	debug("Got tmpfile with fd=%d", *fd);
	return RESULT_OK;
}

result_t
tmpmap(int fd, struct string_view *addr)
{
	struct stat st = {
		.st_size = 0,
	};
	check_if(fstat(fd, &st) < 0, ERR_TMPFILE_FSTAT, errno);
	addr->sz = st.st_size;

	addr->data = mmap(NULL, addr->sz, PROT_READ, MAP_PRIVATE, fd, 0);
	check_if(addr->data == MAP_FAILED, ERR_TMPFILE_MMAP, errno);

	/*
	 * mmap() can technically return NULL on some platforms, but our
	 * callers use NULL as a default/sentinel value to signal failure.
	 * Just bail out under this condition. If we ever want to deal with
	 * this, we'll need to export MAP_FAILED and break encapsulation of
	 * the tmpfile.c module a bit.
	 */
	assert(addr->data != NULL);

	return RESULT_OK;
}

void
tmpunmap(struct string_view *addr)
{
	if (addr->data == MAP_FAILED || addr->data == NULL) {
		return;
	}

	const int rc = munmap((void *)addr->data, addr->sz);
	info_m_if(rc < 0, "Ignoring error munmap()-ing tmpfile");
}
