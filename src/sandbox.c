#include "sandbox.h"

#include "array.h"
#include "debug.h"
#include "landlock.h"

#include <stdio.h>

static const char *ALLOWED_PATHS[] = {
	/* for temporary files */
	P_tmpdir,
	/* for outbound HTTPS */
	"/etc/resolv.conf",
	"/etc/ssl/certs/ca-certificates.crt",
};
static const int ALLOWED_HTTPS_PORT = 443;

void
require_only_io_inet(void)
{
	const size_t sz = ARRAY_SIZE(ALLOWED_PATHS);
	landlock_apply(ALLOWED_PATHS, sz, &ALLOWED_HTTPS_PORT);
	landlock_check(ALLOWED_PATHS, sz, sz, true);
}
/* TODO on openbsd: unveil("/tmp", "rw"); unveil(NULL, NULL); */
/* TODO on openbsd: pledge("inet rpath stdio tmppath") */

void
require_only_io(void)
{
	landlock_apply(ALLOWED_PATHS, 1, NULL);
	landlock_check(ALLOWED_PATHS, 1, ARRAY_SIZE(ALLOWED_PATHS), false);
}
/* TODO on openbsd: pledge("stdio") */
