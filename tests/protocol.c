#include "greatest.h"
#include "protocol/stream.h"
#include "sys/debug.h"

static enum greatest_test_res
test_ump_varint_read_n(uint64_t expected, size_t n, char *bytes_to_parse)
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

#define test_ump_varint_read(EXPECTED, N, ...)                                 \
	test_ump_varint_read_n(EXPECTED, N, (char[N + 1]) __VA_ARGS__)

TEST
protocol_ump_read_vle(void)
{
	CHECK_CALL(test_ump_varint_read(0, 1, {0x00, 0}));
	CHECK_CALL(test_ump_varint_read(1, 1, {0x01, 0}));
	CHECK_CALL(test_ump_varint_read(8, 1, {0x08, 0}));
	CHECK_CALL(test_ump_varint_read(16, 1, {0x10, 0}));
	CHECK_CALL(test_ump_varint_read(127, 1, {0x7F, 0}));
	CHECK_CALL(test_ump_varint_read(127, 2, {0xBF, 0x01, 0}));
	CHECK_CALL(test_ump_varint_read(575, 2, {0xBF, 0x08, 0}));
	CHECK_CALL(test_ump_varint_read(1087, 2, {0xBF, 0x10, 0}));
	CHECK_CALL(test_ump_varint_read(8191, 2, {0xBF, 0x7F, 0}));
	CHECK_CALL(test_ump_varint_read(16383, 2, {0xBF, 0xFF, 0}));
	CHECK_CALL(test_ump_varint_read(16383, 3, {0xDF, 0xFF, 0x01, 0}));
	CHECK_CALL(test_ump_varint_read(73727, 3, {0xDF, 0xFF, 0x08, 0}));
	CHECK_CALL(test_ump_varint_read(139263, 3, {0xDF, 0xFF, 0x10, 0}));
	CHECK_CALL(test_ump_varint_read(1048575, 3, {0xDF, 0xFF, 0x7F, 0}));
	CHECK_CALL(test_ump_varint_read(2097151, 3, {0xDF, 0xFF, 0xFF, 0}));
	PASS();
}

#undef test_ump_varint_read

SUITE(protocol_ump)
{
	RUN_TEST(protocol_ump_read_vle);
}
