#include "greatest.h"
#include "protocol/stream.h"
#include "sys/debug.h"
#include "test_macros.h"
#include "video_streaming/video_playback_abr_request.pb-c.h"

#include <unistd.h>

static void
str_free(char **strp)
{
	free(*strp);
}

static void
protocol_cleanup_p(protocol *pp)
{
	protocol_cleanup(*pp);
}

static void
video_playback_request_cleanup(VideoStreaming__VideoPlaybackAbrRequest **p)
{
	video_streaming__video_playback_abr_request__free_unpacked(*p, NULL);
}

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

	const struct string_view empty_view = MAKE_TEST_STRING("");
	{
		size_t pos = 0;
		auto_result err = ump_varint_read(&empty_view, &pos, &value);
		ASSERT_EQ(ERR_PROTOCOL_VARINT_READ_PRE, err.err);
		ASSERT_EQ(pos, (size_t)err.num);
	}

	const struct string_view some_view = MAKE_TEST_STRING("Hello, World!");
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

typedef VideoStreaming__VideoPlaybackAbrRequest Request;

static enum greatest_test_res
parse_and_get_next(const struct string_view *response, Request **out)
{
	const struct string_view PLAYBACK = MAKE_TEST_STRING("UExBWUJBQ0sK");
	int TEST_FD[2] = {
		STDOUT_FILENO,
		STDOUT_FILENO,
	};

	protocol p __attribute__((cleanup(protocol_cleanup_p))) =
		protocol_init("UE9UCg==", &PLAYBACK, TEST_FD);
	char *url __attribute__((cleanup(str_free))) = NULL;

	auto_result parse = protocol_parse_response(p, response, &url);
	ASSERT_EQ(OK, parse.err);

	char *blob __attribute__((cleanup(str_free))) = NULL;
	size_t blob_sz = 0;

	auto_result next = protocol_next_request(p, &blob, &blob_sz);
	ASSERT_EQ(OK, next.err);

	*out = video_streaming__video_playback_abr_request__unpack(
		NULL,
		blob_sz,
		(uint8_t *)blob);
	ASSERT_NEQ(NULL, *out);

	PASS();
}

#define auto_request                                                           \
	Request *__attribute__((cleanup(video_playback_request_cleanup)))

TEST
protocol_parse_response_media_header(void)
{
	auto_request request;

	const struct string_view response = {
		// clang-format off
		.data = (char[12]){
			0x14, /* part_type = MEDIA_HEADER */
			0x0A, /* part_size = 10 */
			/*
			 * $ cat /tmp/media_header.txt
			 * header_id: 2
			 * itag: 299
			 * sequence_number: 4
			 * duration_ms: 1000
			 * $ cat /tmp/media_header.txt | protoc --proto_path=build/_deps/googlevideo-src/protos --encode=video_streaming.MediaHeader $(find build/_deps -type f -name '*.proto') | hexdump -C
			 */
			0x08, 0x02, 0x18, 0xAB,
			0x02, 0x48, 0x04, 0x60,
			0xE8, 0x07,
		},
		// clang-format on
		.sz = 12,
	};
	CHECK_CALL(parse_and_get_next(&response, &request));

	/*
	 * Verify that the <response> above affected the <next> request's
	 * sequence numbers, duration values, et cetera as expected.
	 */
	ASSERT_EQ(5, request->buffered_ranges[1]->end_segment_index);
	ASSERT_EQ(1000, request->buffered_ranges[1]->duration_ms);

	PASS();
}

TEST
protocol_parse_response_next_request_policy(void)
{
	PASS();
}

#undef auto_request

SUITE(protocol_parse)
{
	RUN_TEST(protocol_parse_response_media_header);
	RUN_TEST(protocol_parse_response_next_request_policy);
}
