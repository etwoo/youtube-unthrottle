#include "protocol/stream.h"

#include "greatest.h"

TEST
protocol_ump_read_vle(void)
{
	PASS();
}

SUITE(protocol_ump)
{
	RUN_TEST(protocol_ump_read_vle);
}
