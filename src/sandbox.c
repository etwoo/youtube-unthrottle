#include "sandbox.h"

// TODO: if linux landlock APIs work, add this to README.md as something i wanted to learn -- sandboxing techniques (landlock, pledge/unveil, etc)
void
enter_chroot(void)
{
	// TODO on openbsd:
	// unveil("/tmp", "rw");
	// unveil(NULL, NULL);
	// TODO on linux, implement with landlock?
}

void
require_only_io_inet(void)
{
	// TODO on openbsd:
	// pledge("inet rpath stdio tmppath")
	// TODO on linux, implement with landlock?
}

void
require_only_io(void)
{
	// TODO on openbsd:
	// pledge("stdio")
	// TODO on linux, implement with landlock?
}
