#include "sandbox.h"

#include "greatest.h"

TEST
sandbox_ok(void)
{
	sandbox_handle_t context __attribute__((cleanup(sandbox_cleanup))) =
		sandbox_init();
	ASSERT_NEQ(NULL, context);

	auto_result err = sandbox_only_io_inet_tmpfile(context);
	ASSERT_EQ(OK, err.err);
	err = sandbox_only_io_inet_rpath(context);
	ASSERT_EQ(OK, err.err);
	err = sandbox_only_io(context);
	ASSERT_EQ(OK, err.err);

	PASS();
}

SUITE(sandbox_smoke_test)
{
	RUN_TEST(sandbox_ok);
}
