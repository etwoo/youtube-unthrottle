#include "greatest.h"
#include "protocol/stream.h"

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
	ASSERT_EQ(OK, err.err);
	ASSERT_EQ(n, pos);
	ASSERT_EQ(expected, actual);

	PASS();
}

TEST
protocol_ump_read_vle(void)
{
	CHECK_CALL(test_ump_varint_read_n(1, (char[2]){0x00, 0x00}, 0));
	CHECK_CALL(test_ump_varint_read_n(2, (char[3]){0x80, 0x01, 0x00}, 64));
	CHECK_CALL(test_ump_varint_read_n(2, (char[3]){0x81, 0x01, 0x00}, 65));
	CHECK_CALL(test_ump_varint_read_n(2, (char[3]){0x88, 0x01, 0x00}, 72));
	CHECK_CALL(test_ump_varint_read_n(2, (char[3]){0x8F, 0x01, 0x00}, 79));
	CHECK_CALL(test_ump_varint_read_n(2, (char[3]){0xA0, 0x01, 0x00}, 96));
	CHECK_CALL(test_ump_varint_read_n(2, (char[3]){0xAA, 0x01, 0x00}, 106));
	CHECK_CALL(test_ump_varint_read_n(2, (char[3]){0xBF, 0x01, 0x00}, 127));
	PASS();
}

SUITE(protocol_ump)
{
	RUN_TEST(protocol_ump_read_vle);
}
