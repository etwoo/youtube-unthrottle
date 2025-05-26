#include "greatest.h"
#include "protocol/stream.h"
#include "sys/debug.h"
#include "sys/tmpfile.h"
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
parse_and_get_next(const struct string_view *response,
		   int32_t *ends_at,
                   Request **out,
                   char **url,
                   int *pfd)
{
	const struct string_view PLAYBACK = MAKE_TEST_STRING("UExBWUJBQ0sK");
	int fd = pfd ? *pfd : STDOUT_FILENO;
	int fds[2] = {
		fd,
		fd,
	};

	protocol p __attribute__((cleanup(protocol_cleanup_p))) =
		protocol_init("UE9UCg==", &PLAYBACK, fds);
	auto_result parse = protocol_parse_response(p, response, url);
	ASSERT_EQ(OK, parse.err);

	if (ends_at) {
		*ends_at = protocol_ends_at(p);
	}

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
protocol_parse_response_media_header_and_blob(void)
{
	auto_request request;
	char *url __attribute__((cleanup(str_free))) = NULL;

	int fd = -1;
	auto_result err = tmpfd(&fd);
	ASSERT_EQ(OK, err.err);
	ASSERT_LTE(0, fd);

	const struct string_view response = {
		// clang-format off
		.data = (char[63]){
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
			0x15, /* part_type = MEDIA */
			0x07, /* part_size = 7 */
			0x02, /* header_id = 2 */
			0x46, 0x4F, 0x4F, 0x46, 0x4F, 0x4F, /* FOOFOO */
			0x14, /* part_type = MEDIA_HEADER */
			0x0A, /* part_size = 10 */
			/*
			 * $ cat /tmp/media_header.txt
			 * header_id: 2
			 * itag: 299
			 * sequence_number: 3
			 * duration_ms: 1000
			 */
			0x08, 0x02, 0x18, 0xAB,
			0x02, 0x48, 0x03, 0x60,
			0xE8, 0x07,
			0x15, /* part_type = MEDIA */
			0x07, /* part_size = 7 */
			0x02, /* header_id = 2 */
			0x4E, 0x4F, 0x4E, 0x4F, 0x4E, 0x4F, /* NONONO */
			0x14, /* part_type = MEDIA_HEADER */
			0x0A, /* part_size = 10 */
			/*
			 * $ cat /tmp/media_header.txt
			 * header_id: 2
			 * itag: 299
			 * sequence_number: 5
			 * duration_ms: 1000
			 */
			0x08, 0x02, 0x18, 0xAB,
			0x02, 0x48, 0x05, 0x60,
			0xE8, 0x07,
			0x15, /* part_type = MEDIA */
			0x07, /* part_size = 7 */
			0x02, /* header_id = 2 */
			0x42, 0x41, 0x52, 0x42, 0x41, 0x52, /* BARBAR */
		},
		// clang-format on
		.sz = 63,
	};
	CHECK_CALL(parse_and_get_next(&response, NULL, &request, &url, &fd));

	/*
	 * Verify that the <response> above affected the <next> request's
	 * sequence numbers, duration values, et cetera as expected.
	 */
	ASSERT_EQ(6, request->buffered_ranges[1]->end_segment_index);
	ASSERT_EQ(2000, request->buffered_ranges[1]->duration_ms);

	/*
	 * Verify that:
	 *
	 * 1) FOOFOO media blob writes to provided fd
	 * 2) NONONO media blob triggers skip_media_blobs_until_next == true
	 * 3) BARBAR media blob triggers skip_media_blobs_until_next == false
	 */
	char written[6];
	{
		const off_t pos = lseek(fd, -2 * sizeof(written), SEEK_END);
		ASSERT_LTE(0, pos);
		const ssize_t got_bytes = read(fd, written, sizeof(written));
		ASSERT_EQ(sizeof(written), got_bytes);
	}
	ASSERT_STRN_EQ("FOOFOO", written, sizeof(written));
	{
		const ssize_t got_bytes = read(fd, written, sizeof(written));
		ASSERT_EQ(sizeof(written), got_bytes);
	}
	ASSERT_STRN_EQ("BARBAR", written, sizeof(written));

	const int rc = close(fd);
	ASSERT_EQ(0, rc);

	PASS();
}

TEST
protocol_parse_response_next_request_policy(void)
{
	auto_request request;
	char *url __attribute__((cleanup(str_free))) = NULL;

	const struct string_view response = {
		// clang-format off
		.data = (char[14]){
			0x23, /* part_type = NEXT_REQUEST_POLICY */
			0x0C, /* part_size = 12 */
			/*
			 * $ cat /tmp/next_request_policy.txt
			 * playback_cookie {
			 *     video_fmt {
			 *         itag: 299
			 *     }
			 *     audio_fmt {
			 *         itag: 251
			 *     }
			 * }
			 * $ cat /tmp/next_request_policy.txt | protoc --proto_path=build/_deps/googlevideo-src/protos --encode=video_streaming.NextRequestPolicy $(find build/_deps -type f -name '*.proto') | hexdump -C
			 */
			0x3A, 0x0A, 0x3A, 0x03,
			0x08, 0xAB, 0x02, 0x42,
			0x03, 0x08, 0xFB, 0x01,
		},
		// clang-format on
		.sz = 14,
	};
	CHECK_CALL(parse_and_get_next(&response, NULL, &request, &url, NULL));

	/*
	 * Verify that the <response> above affected the <next> request's
	 * playback cookie as expected.
	 */
	ASSERT(request->streamer_context->has_playback_cookie);
	ASSERT_EQ(10, request->streamer_context->playback_cookie.len);
	const char expected_cookie[10] = {
		0x3A,
		0x03,
		0x08,
		0xAB,
		0x02,
		0x42,
		0x03,
		0x08,
		0xFB,
		0x01,
	};
	ASSERT_STRN_EQ(expected_cookie,
	               request->streamer_context->playback_cookie.data,
	               request->streamer_context->playback_cookie.len);

	PASS();
}

TEST
protocol_parse_response_format_initialization_metadata(void)
{
	int32_t end = -1;
	auto_request request;
	char *url __attribute__((cleanup(str_free))) = NULL;

	const struct string_view response = {
		// clang-format off
		.data = (char[6]){
			0x2A, /* part_type = FORMAT_INITIALIZATION_METADATA */
			0x04, /* part_size = 4 */
			/*
			 * $ cat /tmp/format_initialization_metadata.txt
			 * duration_ms: 600000
			 * $ cat /tmp/format_initialization_metadata.txt | protoc --proto_path=build/_deps/googlevideo-src/protos --encode=video_streaming.FormatInitializationMetadata $(find build/_deps -type f -name '*.proto') | hexdump -C
			 */
			0x48, 0xC0, 0xCF, 0x24,
		},
		// clang-format on
		.sz = 6,
	};
	CHECK_CALL(parse_and_get_next(&response, &end, &request, &url, NULL));

	ASSERT_EQ(600000, end);
	PASS();
}

TEST
protocol_parse_response_sabr_redirect(void)
{
	auto_request request;
	char *url __attribute__((cleanup(str_free))) = NULL;

	const struct string_view response = {
		// clang-format off
		.data = (char[24]){
			0x2B, /* part_type = SABR_REDIRECT */
			0x16, /* part_size = 22 */
			/*
			 * $ cat /tmp/sabr_redirect.txt
			 * url: "https://foo.test/bar"
			 * $ cat /tmp/sabr_redirect.txt | protoc --proto_path=build/_deps/googlevideo-src/protos --encode=video_streaming.SabrRedirect $(find build/_deps -type f -name '*.proto') | hexdump -C
			 */
			0x0A, 0x14, 0x68, 0x74,
			0x74, 0x70, 0x73, 0x3A,
			0x2F, 0x2F, 0x66, 0x6F,
			0x6F, 0x2E, 0x74, 0x65,
			0x73, 0x74, 0x2F, 0x62,
			0x61, 0x72,
		},
		// clang-format on
		.sz = 24,
	};
	CHECK_CALL(parse_and_get_next(&response, NULL, &request, &url, NULL));

	/*
	 * Verify that the <response> above affected the <next> request's
	 * target URL as expected.
	 */
	ASSERT_STRN_EQ("https://foo.test/bar", url, 20);

	PASS();
}

#undef auto_request

SUITE(protocol_parse)
{
	RUN_TEST(protocol_parse_response_media_header_and_blob);
	RUN_TEST(protocol_parse_response_next_request_policy);
	RUN_TEST(protocol_parse_response_format_initialization_metadata);
	RUN_TEST(protocol_parse_response_sabr_redirect);
	// TODO: test FORMAT_INITIALIZATION_METADATA; check total duration?
}
