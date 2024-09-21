#include "tmpfile.h"

#include "debug.h"
#include "result_type.h"

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>  /* for P_tmpdir */
#include <stdlib.h> /* for free() */
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * Set up codegen macros for module-specific result_t.
 */
#define ERROR_TABLE(X)                                                         \
	X(OK, LITERAL("Success in " __FILE_NAME__))                            \
	X(ERR_TMPFILE, PERR("Error in tmpfile()"))                             \
	X(ERR_TMPFILE_FILENO, PERR("Error fileno()-ing tmpfile"))              \
	X(ERR_TMPFILE_DUP, PERR("Error dup()-ing tmpfile"))                    \
	X(ERR_TMPFILE_FSTAT, PERR("Error fstat()-ing tmpfile"))                \
	X(ERR_TMPFILE_MMAP, PERR("Error mmap()-ing tmpfile"))

#define ERROR_EXAMPLE_ARGS 0

#define DO_CLEANUP assert(p) /* noop */
#define DO_INIT {.err = err, .num = num}

/*
 * Extend `struct result_base` to create a module-specific result_t.
 */
struct result_tmpfile {
	struct result_base base;
	enum { ERROR_TABLE(INTO_ENUM) } err;
	int num;
};
DEFINE_RESULT(result_tmpfile, DO_CLEANUP, DO_INIT, int err, int num)
#define make_result make_result_tmpfile

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
	check_if(fs == NULL, ERR_TMPFILE, errno);

	/*
	 * dup the underlying file descriptor behind the tmpfile stream, and
	 * then close the original stream. I believe (though I'm not totally
	 * sure) that this is necessary to avoid leaking the FILE* itself.
	 */

	int inner_fd = fileno(fs);
	check_if(inner_fd < 0, ERR_TMPFILE_FILENO, errno);

	int dup_fd = dup(inner_fd);
	check_if(dup_fd < 0, ERR_TMPFILE_DUP, errno);

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
	check_if(fstat(fd, &st) < 0, ERR_TMPFILE_FSTAT, errno);
	*sz = st.st_size;

	*addr = mmap(NULL, *sz, PROT_READ, MAP_PRIVATE, fd, 0);
	check_if(*addr == MAP_FAILED, ERR_TMPFILE_MMAP, errno);

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

#undef DO_CLEANUP
#undef DO_INIT
#undef ERROR_EXAMPLE_ARGS
#undef ERROR_TABLE
