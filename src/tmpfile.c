#include "tmpfile.h"

#include "debug.h"

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>  /* for P_tmpdir */
#include <stdlib.h> /* for free() */
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * Extend `struct result_base` to create a module-specific result_t.
 */
struct result_tmpfile {
	struct result_base base;
	enum {
		OK = 0,
		ERR_TMPFILE,
		ERR_TMPFILE_FILENO,
		ERR_TMPFILE_DUP,
		ERR_TMPFILE_FSTAT,
		ERR_TMPFILE_MMAP,
	} err;
	int num;
};

static WARN_UNUSED bool
result_ok(result_t r)
{
	struct result_tmpfile *p = (struct result_tmpfile *)r;
	return p->err == OK;
}

static WARN_UNUSED const char *
my_result_to_str(result_t r)
{
	struct result_tmpfile *p = (struct result_tmpfile *)r;
	int printed = 0;
	char *s = NULL;

	switch (p->err) {
	case OK:
		s = strdup("Success in " __FILE_NAME__);
		break;
	case ERR_TMPFILE:
		printed = asprintf(&s,
		                   "Error in tmpfile(): %s",
		                   strerror(p->num));
		break;
	case ERR_TMPFILE_FILENO:
		printed = asprintf(&s,
		                   "Error fileno()-ing tmpfile: %s",
		                   strerror(p->num));
		break;
	case ERR_TMPFILE_DUP:
		printed = asprintf(&s,
		                   "Error dup()-ing tmpfile: %s",
		                   strerror(p->num));
		break;
	case ERR_TMPFILE_FSTAT:
		printed = asprintf(&s,
		                   "Error fstat()-ing tmpfile: %s",
		                   strerror(p->num));
		break;
	case ERR_TMPFILE_MMAP:
		printed = asprintf(&s,
		                   "Error mmap()-ing tmpfile: %s",
		                   strerror(p->num));
		break;
	}

	if (printed < 0) {
		return NULL;
		// TODO: use RESULT_CANNOT_ALLOC instead?
	}

	return s;
}

static void
my_result_cleanup(result_t r)
{
	if (r == NULL) {
		return;
	}

	struct result_tmpfile *p = (struct result_tmpfile *)r;
	free(p);
}

static struct result_ops RESULT_OPS = {
	.result_ok = result_ok,
	.result_to_str = my_result_to_str,
	.result_cleanup = my_result_cleanup,
};

static result_t WARN_UNUSED
make_result(int err_type, int my_errno)
{
	struct result_tmpfile *r = malloc(sizeof(*r));
	if (r == NULL) {
		return RESULT_CANNOT_ALLOC;
	}

	r->base.ops = &RESULT_OPS;
	r->err = err_type;
	r->num = my_errno;
	return (result_t)r;
}

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
	if (fs == NULL) {
		return make_result(ERR_TMPFILE, errno);
	}

	/*
	 * dup the underlying file descriptor behind the tmpfile stream, and
	 * then close the original stream. I believe (though I'm not totally
	 * sure) that this is necessary to avoid leaking the FILE* itself.
	 */

	int inner_fd = fileno(fs);
	if (inner_fd < 0) {
		return make_result(ERR_TMPFILE_FILENO, errno);
	}

	int dup_fd = dup(inner_fd);
	if (dup_fd < 0) {
		return make_result(ERR_TMPFILE_DUP, errno);
	}

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
	if (fstat(fd, &st) < 0) {
		return make_result(ERR_TMPFILE_FSTAT, errno);
	}
	*sz = st.st_size;

	*addr = mmap(NULL, *sz, PROT_READ, MAP_PRIVATE, fd, 0);
	if (*addr == MAP_FAILED) {
		return make_result(ERR_TMPFILE_MMAP, errno);
	}

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
