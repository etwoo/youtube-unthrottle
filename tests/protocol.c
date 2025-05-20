#include "greatest.h"
#include "protocol/stream.h"

TEST
protocol_ump_read_vle_byte_length_one(void)
{
	size_t bytes_to_read = 0;
	unsigned char first_byte_mask = 0;

	ump_read_vle(0x00, &bytes_to_read, &first_byte_mask);
	ASSERT_EQ(1, bytes_to_read);
	ASSERT_EQ(0xFF, first_byte_mask);
	ASSERT_EQ(0, 0x00 & first_byte_mask);

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

	PASS();
}

SUITE(protocol_ump)
{
	RUN_TEST(protocol_ump_read_vle_byte_length_one);
}
