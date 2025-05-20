#include "greatest.h"
#include "protocol/stream.h"
#include "sys/debug.h"

static enum greatest_test_res
test_ump_varint_read_n(size_t n, char *bytes_to_parse, uint64_t expected)
{
	const struct string_view view = {
		.data = bytes_to_parse,
		.sz = n + 1,
	};
	size_t pos = 0;
	uint64_t actual = 0;

	auto_result err = ump_varint_read(&view, &pos, &actual);
	debug("Comparing expected %" PRIu64 " vs actual %" PRIu64,
	      expected,
	      actual);
	ASSERT_EQ(OK, err.err);
	ASSERT_EQ(n, pos);
	ASSERT_EQ(expected, actual);

	PASS();
}

TEST
protocol_ump_read_vle(void)
{
	CHECK_CALL(test_ump_varint_read_n(1, (char[2]){0x00, 0}, 0));
	CHECK_CALL(test_ump_varint_read_n(1, (char[2]){0x01, 0}, 1));
	CHECK_CALL(test_ump_varint_read_n(1, (char[2]){0x08, 0}, 8));
	CHECK_CALL(test_ump_varint_read_n(1, (char[2]){0x10, 0}, 16));
	CHECK_CALL(test_ump_varint_read_n(1, (char[2]){0x7F, 0}, 127));
	CHECK_CALL(test_ump_varint_read_n(2, (char[3]){0xBF, 0x01, 0}, 127));
	CHECK_CALL(test_ump_varint_read_n(2, (char[3]){0xBF, 0x08, 0}, 575));
	CHECK_CALL(test_ump_varint_read_n(2, (char[3]){0xBF, 0x10, 0}, 1087));
	CHECK_CALL(test_ump_varint_read_n(2, (char[3]){0xBF, 0x7F, 0}, 8191));
	CHECK_CALL(test_ump_varint_read_n(2, (char[3]){0xBF, 0xFF, 0}, 16383));
	CHECK_CALL(test_ump_varint_read_n(3, (char[4]){0xDF, 0xFF, 0x01, 0}, 16383));
	CHECK_CALL(test_ump_varint_read_n(3, (char[4]){0xDF, 0xFF, 0x08, 0}, 73727));
	CHECK_CALL(test_ump_varint_read_n(3, (char[4]){0xDF, 0xFF, 0x10, 0}, 139263));
	CHECK_CALL(test_ump_varint_read_n(3, (char[4]){0xDF, 0xFF, 0x7F, 0}, 1048575));
	// CHECK_CALL(test_ump_varint_read_n(3, (char[4]){0xDF, 0xFF, 0xFF, 0}, 2097151));
	PASS();
}

SUITE(protocol_ump)
{
	RUN_TEST(protocol_ump_read_vle);
}
