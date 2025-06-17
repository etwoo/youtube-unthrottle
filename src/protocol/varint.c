#include "protocol/varint.h"

#include "sys/array.h"
#include "sys/debug.h"

static const unsigned char CHAR_BIT_0 = 0x80; /* bit pattern: 10000000 */
static const unsigned char CHAR_BIT_1 = 0x40; /* bit pattern: 01000000 */
static const unsigned char CHAR_BIT_2 = 0x20; /* bit pattern: 00100000 */
static const unsigned char CHAR_BIT_3 = 0x10; /* bit pattern: 00010000 */
static const unsigned char CHAR_BIT_4 = 0x08; /* bit pattern: 00001000 */

typedef enum {
	VARINT_BYTES_ONE = 1,
	VARINT_BYTES_TWO,
	VARINT_BYTES_THREE,
	VARINT_BYTES_FOUR,
	VARINT_BYTES_FIVE,
} ump_varint_bytes;

static void
ump_read_vle(unsigned char first_byte,
             ump_varint_bytes *bytes_to_read,
             unsigned char *first_byte_mask)
{
	*bytes_to_read = VARINT_BYTES_ONE;
	*first_byte_mask = 0xFF; /* bit pattern: 11111111 */
	if (0 == (first_byte & CHAR_BIT_0)) {
		return;
	}

	*bytes_to_read = VARINT_BYTES_TWO;
	*first_byte_mask ^= CHAR_BIT_0;
	*first_byte_mask ^= CHAR_BIT_1;

	if (0 == (first_byte & CHAR_BIT_1)) {
		return;
	}

	*bytes_to_read = VARINT_BYTES_THREE;
	*first_byte_mask ^= CHAR_BIT_2;

	if (0 == (first_byte & CHAR_BIT_2)) {
		return;
	}

	*bytes_to_read = VARINT_BYTES_FOUR;
	*first_byte_mask ^= CHAR_BIT_3;

	if (0 == (first_byte & CHAR_BIT_3)) {
		return;
	}

	*bytes_to_read = VARINT_BYTES_FIVE;
	*first_byte_mask ^= CHAR_BIT_4;
}

result_t
ump_varint_read(const struct string_view *ump, size_t *pos, uint64_t *value)
{
	if (*pos >= ump->sz) {
		return make_result(ERR_PROTOCOL_VARINT_READ_PRE, (int)*pos);
	}

	ump_varint_bytes bytes_to_read = VARINT_BYTES_ONE;
	unsigned char first_byte_mask = 0xFF;
	ump_read_vle(ump->data[*pos], &bytes_to_read, &first_byte_mask);

	debug("Got first_byte=%hhu, bytes_to_read=%u, first_byte_mask=%02X",
	      ump->data[*pos],
	      bytes_to_read,
	      first_byte_mask);

	if (*pos > SIZE_MAX - bytes_to_read || /* 1) avoid overflow         */
	    bytes_to_read > ump->sz ||         /* 2) avoid underflow in (3) */
	    *pos > ump->sz - bytes_to_read) {  /* 3) avoid OOB read         */
		return make_result(ERR_PROTOCOL_VARINT_READ_OUT_OF_BOUNDS,
		                   (int)bytes_to_read);
	}

	uint64_t parsed[5] = {0};
	switch (bytes_to_read) {
	case VARINT_BYTES_FIVE:
		parsed[4] = ((uint32_t)ump->data[*pos + 4] << 24) +
		            ((unsigned char)ump->data[*pos + 3] << 16) +
		            ((unsigned char)ump->data[*pos + 2] << 8) +
		            (unsigned char)ump->data[*pos + 1];
		break;
	case VARINT_BYTES_FOUR:
		parsed[3] = (unsigned char)ump->data[*pos + 3]
		            << (16 + (8 - bytes_to_read));
		__attribute__((fallthrough));
	case VARINT_BYTES_THREE:
		parsed[2] = (unsigned char)ump->data[*pos + 2]
		            << (8 + (8 - bytes_to_read));
		__attribute__((fallthrough));
	case VARINT_BYTES_TWO:
		parsed[1] = (unsigned char)ump->data[*pos + 1]
		            << (8 - bytes_to_read);
		__attribute__((fallthrough));
	case VARINT_BYTES_ONE:
		parsed[0] = ump->data[*pos] & first_byte_mask;
		break;
	}
	*pos += bytes_to_read;

	/*
	 * Note: this postcondition assumes a buffer never ends with a dangling
	 * (so to speak) varint, i.e. that a varint always describes the type
	 * or size of an upcoming payload.
	 */
	if (*pos >= ump->sz) {
		return make_result(ERR_PROTOCOL_VARINT_READ_POST, (int)*pos);
	}

	*value = 0;
	for (size_t i = 0; i < ARRAY_SIZE(parsed); ++i) {
		*value += parsed[i];
	}

	return RESULT_OK;
}
