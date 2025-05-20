#include "greatest.h"
#include "protocol/stream.h"

static enum greatest_test_res
test_ump_varint_read(char byte_to_parse, uint64_t expected)
{
	char buf[2] = { byte_to_parse, 0 };
	const struct string_view view = {
		.data = buf,
		.sz = sizeof(buf),
	};
	size_t pos = 0;
	uint64_t actual = 0;

	auto_result err = ump_varint_read(&view, &pos, &actual);
	ASSERT_EQ(OK, err.err);
	ASSERT_EQ(1, pos);
	ASSERT_EQ(expected, actual);

	PASS();
}

TEST
protocol_ump_read_vle_byte_length_one(void)
{
	CHECK_CALL(test_ump_varint_read(0x00, 0));
#if 0
	ump_read_vle(0x81, &bytes_to_read, &first_byte_mask);
	ASSERT_EQ(2, bytes_to_read);
	ASSERT_EQ(0x3F, first_byte_mask);
	ASSERT_EQ(1, 0x81 & first_byte_mask);

	ump_read_vle(0x88, &bytes_to_read, &first_byte_mask);
	ASSERT_EQ(2, bytes_to_read);
	ASSERT_EQ(0x3F, first_byte_mask);
	ASSERT_EQ(8, 0x88 & first_byte_mask);

	ump_read_vle(0x8F, &bytes_to_read, &first_byte_mask);
	ASSERT_EQ(2, bytes_to_read);
	ASSERT_EQ(0x3F, first_byte_mask);
	ASSERT_EQ(15, 0x8F & first_byte_mask);

	ump_read_vle(0xA0, &bytes_to_read, &first_byte_mask);
	ASSERT_EQ(2, bytes_to_read);
	ASSERT_EQ(0x3F, first_byte_mask);
	ASSERT_EQ(32, 0xA0 & first_byte_mask);

	ump_read_vle(0xAA, &bytes_to_read, &first_byte_mask);
	ASSERT_EQ(2, bytes_to_read);
	ASSERT_EQ(0x3F, first_byte_mask);
	ASSERT_EQ(42, 0xAA & first_byte_mask);

	ump_read_vle(0xBF, &bytes_to_read, &first_byte_mask);
	ASSERT_EQ(2, bytes_to_read);
	ASSERT_EQ(0x3F, first_byte_mask);
	ASSERT_EQ(63, 0xBF & first_byte_mask);
#endif
	PASS();
}

SUITE(protocol_ump)
{
	RUN_TEST(protocol_ump_read_vle_byte_length_one);
}
