#include "greatest.h"
#include "protocol/stream.h"
#include "sys/debug.h"

static enum greatest_test_res
test_ump_varint_read_n(uint64_t expected,
                       size_t n,
                       const unsigned char *bytes_to_parse)
{
	const struct string_view view = {
		.data = (const char *)bytes_to_parse,
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

#define test_ump_varint(EXPECTED, N, ...)                                      \
	test_ump_varint_read_n(EXPECTED, N, (unsigned char[N + 1]) __VA_ARGS__)

TEST
protocol_ump_varint_read_byte_length_1(void)
{
	CHECK_CALL(test_ump_varint(0, 1, {0x00, 0}));
	CHECK_CALL(test_ump_varint(1, 1, {0x01, 0}));
	CHECK_CALL(test_ump_varint(8, 1, {0x08, 0}));
	CHECK_CALL(test_ump_varint(16, 1, {0x10, 0}));
	CHECK_CALL(test_ump_varint(127, 1, {0x7F, 0}));
	PASS();
}

TEST
protocol_ump_varint_read_byte_length_2(void)
{
	CHECK_CALL(test_ump_varint(127, 2, {0xBF, 0x01, 0}));
	CHECK_CALL(test_ump_varint(575, 2, {0xBF, 0x08, 0}));
	CHECK_CALL(test_ump_varint(1087, 2, {0xBF, 0x10, 0}));
	CHECK_CALL(test_ump_varint(8191, 2, {0xBF, 0x7F, 0}));
	CHECK_CALL(test_ump_varint(16383, 2, {0xBF, 0xFF, 0}));
	PASS();
}

TEST
protocol_ump_varint_read_byte_length_3(void)
{
	CHECK_CALL(test_ump_varint(16383, 3, {0xDF, 0xFF, 0x01, 0}));
	CHECK_CALL(test_ump_varint(73727, 3, {0xDF, 0xFF, 0x08, 0}));
	CHECK_CALL(test_ump_varint(139263, 3, {0xDF, 0xFF, 0x10, 0}));
	CHECK_CALL(test_ump_varint(1048575, 3, {0xDF, 0xFF, 0x7F, 0}));
	CHECK_CALL(test_ump_varint(2097151, 3, {0xDF, 0xFF, 0xFF, 0}));
	PASS();
}

TEST
protocol_ump_varint_read_byte_length_4(void)
{
	CHECK_CALL(test_ump_varint(2097151, 4, {0xEF, 0xFF, 0xFF, 0x01, 0}));
	CHECK_CALL(test_ump_varint(9437183, 4, {0xEF, 0xFF, 0xFF, 0x08, 0}));
	CHECK_CALL(test_ump_varint(17825791, 4, {0xEF, 0xFF, 0xFF, 0x10, 0}));
	CHECK_CALL(test_ump_varint(134217727, 4, {0xEF, 0xFF, 0xFF, 0x7F, 0}));
	CHECK_CALL(test_ump_varint(268435455, 4, {0xEF, 0xFF, 0xFF, 0xFF, 0}));
	PASS();
}

TEST
protocol_ump_varint_read_byte_length_5(void)
{
	CHECK_CALL(test_ump_varint(33554431,
	                           5,
	                           {0xF0, 0xFF, 0xFF, 0xFF, 0x01, 0}));
	CHECK_CALL(test_ump_varint(150994943,
	                           5,
	                           {0xF0, 0xFF, 0xFF, 0xFF, 0x08, 0}));
	CHECK_CALL(test_ump_varint(285212671,
	                           5,
	                           {0xF0, 0xFF, 0xFF, 0xFF, 0x10, 0}));
	CHECK_CALL(test_ump_varint(2147483647,
	                           5,
	                           {0xF0, 0xFF, 0xFF, 0xFF, 0x7F, 0}));
	CHECK_CALL(test_ump_varint(UINT32_MAX,
	                           5,
	                           {0xF0, 0xFF, 0xFF, 0xFF, 0xFF, 0}));
	PASS();
}

#undef test_ump_varint

TEST
protocol_ump_varint_read_precondition(void)
{
	uint64_t value = 0;

	const struct string_view null_view = {
		.data = NULL,
		.sz = 0,
	};
	{
		size_t pos = 0;
		auto_result err = ump_varint_read(&null_view, &pos, &value);
		ASSERT_EQ(ERR_PROTOCOL_VARINT_READ_PRE, err.err);
		ASSERT_EQ(pos, (size_t)err.num);
	}

	const struct string_view some_view = {
		.data = "Hello, World!",
		.sz = 13,
	};
	{
		size_t pos = 15;
		auto_result err = ump_varint_read(&some_view, &pos, &value);
		ASSERT_EQ(ERR_PROTOCOL_VARINT_READ_PRE, err.err);
		ASSERT_EQ(pos, (size_t)err.num);
	}

	PASS();
}

TEST
protocol_ump_varint_read_out_of_bounds(void)
{
	uint64_t value = 0;

	const struct string_view read_past_sz = {
		.data = (char[1]){0xF0 /* bytes_to_read=5 */},
		.sz = 1, /* note: bytes_to_read >= sz */
	};
	{
		size_t pos = 0;
		auto_result err = ump_varint_read(&read_past_sz, &pos, &value);
		ASSERT_EQ(ERR_PROTOCOL_VARINT_READ_OUT_OF_BOUNDS, err.err);
		ASSERT_EQ(/* bytes_to_read */ 5, err.num);
	}

	const struct string_view pos_plus_read_past_sz = {
		.data = (char[4]){0x00, 0xF0 /* bytes_to_read=5 */, 0x0F, 0},
		.sz = 4,
	};
	{
		size_t pos = 1;
		auto_result err =
			ump_varint_read(&pos_plus_read_past_sz, &pos, &value);
		ASSERT_EQ(ERR_PROTOCOL_VARINT_READ_OUT_OF_BOUNDS, err.err);
		ASSERT_EQ(/* bytes_to_read */ 5, err.num);
	}

	PASS();
}

TEST
protocol_ump_varint_read_invalid_size(void)
{
	// TODO: ERR_PROTOCOL_VARINT_READ_INVALID_SIZE is unreachable; remove?
	PASS();
}

TEST
protocol_ump_varint_read_postcondition(void)
{
	size_t pos = 0;
	uint64_t value = 0;

	const struct string_view no_remainder = {
		.data = (char[2]){0x80 /* bytes_to_read=2 */, 0x0F},
		.sz = 2,
	};
	auto_result err = ump_varint_read(&no_remainder, &pos, &value);
	ASSERT_EQ(ERR_PROTOCOL_VARINT_READ_POST, err.err);
	ASSERT_EQ(/* bytes_to_read */ 2, err.num);

	PASS();
}

SUITE(protocol_ump_varint_read)
{
	RUN_TEST(protocol_ump_varint_read_byte_length_1);
	RUN_TEST(protocol_ump_varint_read_byte_length_2);
	RUN_TEST(protocol_ump_varint_read_byte_length_3);
	RUN_TEST(protocol_ump_varint_read_byte_length_4);
	RUN_TEST(protocol_ump_varint_read_byte_length_5);
	RUN_TEST(protocol_ump_varint_read_precondition);
	RUN_TEST(protocol_ump_varint_read_out_of_bounds);
	RUN_TEST(protocol_ump_varint_read_invalid_size);
	RUN_TEST(protocol_ump_varint_read_postcondition);
}
