#include "sandbox.h"

#include "greatest.h"

TEST
sandbox_ok_does_not_crash(void)
{
	ASSERT_EQ(OK, sandbox_only_io_inet_tmpfile().err);
	ASSERT_EQ(OK, sandbox_only_io_inet_rpath().err);
	ASSERT_EQ(OK, sandbox_only_io().err);
	PASS();
}

SUITE(sandbox_smoke_test)
{
	RUN_TEST(sandbox_ok_does_not_crash);
}
