#include "sandbox.h"

#include "greatest.h"

TEST
sandbox_ok_does_not_crash(void)
{
	sandbox_handle_t context = sandbox_init();
	ASSERT_NEQ(NULL, context);
	ASSERT_EQ(OK, sandbox_only_io_inet_tmpfile(context).err);
	ASSERT_EQ(OK, sandbox_only_io_inet_rpath(context).err);
	ASSERT_EQ(OK, sandbox_only_io(context).err);
	sandbox_cleanup(context);
	PASS();
}

SUITE(sandbox_smoke_test)
{
	RUN_TEST(sandbox_ok_does_not_crash);
}
