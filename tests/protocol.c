#include "greatest.h"
#include "protocol/stream.h"
#include "protocol/varint.h"
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
protocol_cleanup_p(struct protocol_state **p)
{
	protocol_cleanup(*p);
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
		size_t pos = some_view.sz + 2;
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

	const struct string_view read_past_sz =
		MAKE_TEST_STRING("\xF0"); /* bytes_to_read=5, exceeds sz=1 */
	{
		size_t pos = 0;
		auto_result err = ump_varint_read(&read_past_sz, &pos, &value);
		ASSERT_EQ(ERR_PROTOCOL_VARINT_READ_OUT_OF_BOUNDS, err.err);
		ASSERT_EQ(/* bytes_to_read */ 5, err.num);
	}

	const struct string_view pos_plus_read_past_sz =
		MAKE_TEST_STRING("\x00"
	                         "\xF0" /* bytes_to_read=5, out of bounds! */
	                         "\x0F"
	                         "\x00");
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
protocol_ump_varint_read_postcondition(void)
{
	size_t pos = 0;
	uint64_t value = 0;

	const struct string_view no_remainder =
		MAKE_TEST_STRING("\x80" /* bytes_to_read=2 */ "\x0F");
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
	RUN_TEST(protocol_ump_varint_read_postcondition);
}

TEST
protocol_init_base64_decode_negative(void)
{
	const struct string_view invalid_base64 = MAKE_TEST_STRING("A");
	int fds[2] = {
		STDOUT_FILENO,
		STDOUT_FILENO,
	};

	struct protocol_state *p __attribute__((cleanup(protocol_cleanup_p))) =
		NULL;
	auto_result err =
		protocol_init(&invalid_base64, &invalid_base64, 0, fds, &p);
	ASSERT_EQ(ERR_PROTOCOL_STATE_BASE64_DECODE, err.err);

	PASS();
}

TEST
protocol_init_base64_decode_positive(void)
{
	const struct string_view underscore_to_slash =
		MAKE_TEST_STRING("QUJDREVGR0g_Cg==");
	const struct string_view dash_to_plus =
		MAKE_TEST_STRING("QUJDREVGR0g-Cg==");
	int fds[2] = {
		STDOUT_FILENO,
		STDOUT_FILENO,
	};

	struct protocol_state *p __attribute__((cleanup(protocol_cleanup_p))) =
		NULL;
	auto_result err =
		protocol_init(&underscore_to_slash, &dash_to_plus, 0, fds, &p);
	ASSERT_EQ(OK, err.err);

	PASS();
}

static enum greatest_test_res
parse_and_get_next(const struct string_view *response,
                   bool *knows_end_and_has_next,
                   VideoStreaming__VideoPlaybackAbrRequest **out,
                   char **url,
                   int *retry_after,
                   const int *pfd)
{
	const struct string_view proof = MAKE_TEST_STRING("UE9U");
	const struct string_view playback = MAKE_TEST_STRING("UExBWUJBQ0s=");
	const long long int itag = 299;
	int fd = pfd ? *pfd : STDOUT_FILENO;
	int fds[2] = {
		fd,
		fd,
	};

	int unused_num = -1;
	if (retry_after == NULL) {
		retry_after = &unused_num;
	}

	struct protocol_state *p __attribute__((cleanup(protocol_cleanup_p))) =
		NULL;
	auto_result alloc = protocol_init(&proof, &playback, itag, fds, &p);
	ASSERT_EQ(OK, alloc.err);

	auto_result parse =
		protocol_parse_response(p, response, url, retry_after);
	ASSERT_EQ(OK, parse.err);

	if (knows_end_and_has_next) {
		*knows_end_and_has_next =
			protocol_knows_end(p) && !protocol_done(p);
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

TEST
protocol_parse_response_media_header_init_seg(void)
{
	VideoStreaming__VideoPlaybackAbrRequest *request
		__attribute__((cleanup(video_playback_request_cleanup))) = NULL;
	char *url __attribute__((cleanup(str_free))) = NULL;

	/* clang-format off */
	/*
	 * To generate binary protobuf blobs below:
	 *
	 * $ cat /tmp/media_header.txt | protoc --proto_path=build/_deps/googlevideo-src/protos --encode=video_streaming.MediaHeader $(find build/_deps -type f -name '*.proto') | hexdump -C
	 */
	/* clang-format on */
	const struct string_view resp = MAKE_TEST_STRING(
		"\x14" /* part_type = MEDIA_HEADER */
		"\x0A" /* part_size = 10 */

		"\x08" /************ protobuf blob ************/
		"\x02" /*                                     */
		"\x18" /* $ cat /tmp/media_header.txt         */
		"\xAB" /* header_id: 2                        */
		"\x02" /* itag: 299                           */
		"\x40" /* is_init_seg: true                   */
		"\x01" /* duration_ms: 10000                  */
		"\x60" /*                                     */
		"\x90" /*                                     */
		"\x4E" /***************************************/

		"\x14" /* part_type = MEDIA_HEADER */
		"\x0B" /* part_size = 11 */

		"\x08" /************ protobuf blob ************/
		"\x02" /*                                     */
		"\x18" /*                                     */
		"\xAB" /* $ cat /tmp/media_header.txt         */
		"\x02" /* header_id: 2                        */
		"\x40" /* itag: 299                           */
		"\x01" /* is_init_seg: true                   */
		"\x60" /* duration_ms: 100000                 */
		"\xA0" /*                                     */
		"\x8D" /*                                     */
		"\x06" /***************************************/
	);
	CHECK_CALL(parse_and_get_next(&resp, NULL, &request, &url, NULL, NULL));

	/*
	 * Verify that the <response> above affected the next request's
	 * duration values like so: first init_seg used, second ignored.
	 */
	ASSERT_EQ(10000, request->buffered_ranges[1]->duration_ms);
	PASS();
}

TEST
protocol_parse_response_media_header_and_blob(void)
{
	VideoStreaming__VideoPlaybackAbrRequest *request
		__attribute__((cleanup(video_playback_request_cleanup))) = NULL;
	char *url __attribute__((cleanup(str_free))) = NULL;

	int fd = -1;
	auto_result err = tmpfd(&fd);
	ASSERT_EQ(OK, err.err);
	ASSERT_VALID_DESCRIPTOR(fd);
	/* clang-format off */
	/*
	 * To generate binary protobuf blobs below:
	 *
	 * $ cat /tmp/media_header.txt | protoc --proto_path=build/_deps/googlevideo-src/protos --encode=video_streaming.MediaHeader $(find build/_deps -type f -name '*.proto') | hexdump -C
	 */
	/* clang-format on */
	const struct string_view resp = MAKE_TEST_STRING(
		"\x14" /* part_type = MEDIA_HEADER */
		"\x0A" /* part_size = 10 */

		"\x08" /************ protobuf blob ************/
		"\x02" /*                                     */
		"\x18" /* $ cat /tmp/media_header.txt         */
		"\xAB" /* header_id: 2                        */
		"\x02" /* itag: 299                           */
		"\x48" /* sequence_number: 4                  */
		"\x04" /* duration_ms: 1000                   */
		"\x60" /*                                     */
		"\xE8" /*                                     */
		"\x07" /***************************************/

		"\x15" /* part_type = MEDIA */
		"\x04" /* part_size = 4 */

		"\x02" /* header_id = 2 */
		"FOO"

		"\x14" /* part_type = MEDIA_HEADER */
		"\x0A" /* part_size = 10 */

		"\x08" /************ protobuf blob ************/
		"\x02" /*                                     */
		"\x18" /* $ cat /tmp/media_header.txt         */
		"\xAB" /* header_id: 2                        */
		"\x02" /* itag: 299                           */
		"\x48" /* sequence_number: 3                  */
		"\x03" /* duration_ms: 1000                   */
		"\x60" /*                                     */
		"\xE8" /*                                     */
		"\x07" /***************************************/

		"\x15" /* part_type = MEDIA */
		"\x04" /* part_size = 4 */

		"\x02" /* header_id = 2 */
		"NOO"

		"\x14" /* part_type = MEDIA_HEADER */
		"\x0A" /* part_size = 10 */

		"\x08" /************ protobuf blob ************/
		"\x02" /*                                     */
		"\x18" /* $ cat /tmp/media_header.txt         */
		"\xAB" /* header_id: 2                        */
		"\x02" /* itag: 299                           */
		"\x48" /* sequence_number: 5                  */
		"\x05" /* duration_ms: 1000                   */
		"\x60" /*                                     */
		"\xE8" /*                                     */
		"\x07" /***************************************/

		"\x15" /* part_type = MEDIA */
		"\x04" /* part_size = 4 */

		"\x02" /* header_id = 2 */
		"BAR");
	CHECK_CALL(parse_and_get_next(&resp, NULL, &request, &url, NULL, &fd));

	/*
	 * Verify that the <response> above affected the next request's
	 * sequence numbers, duration values, etc as expected.
	 */
	ASSERT_EQ(6, request->buffered_ranges[1]->end_segment_index);
	ASSERT_EQ(2000, request->buffered_ranges[1]->duration_ms);

	/*
	 * Verify that:
	 *
	 * 1) FOOFOO media blob writes to provided fd
	 * 2) NONONO media blob not written due to sequence number
	 * 3) BARBAR media blob writes to provided fd
	 */
	char written[3];
	{
		const off_t target = -2 * (off_t)sizeof(written);
		const off_t pos = lseek(fd, target, SEEK_END);
		ASSERT_LTE(0, pos);
		const ssize_t got_bytes = read(fd, written, sizeof(written));
		ASSERT_EQ(sizeof(written), got_bytes);
	}
	ASSERT_STRN_EQ("FOO", written, sizeof(written));
	{
		const ssize_t got_bytes = read(fd, written, sizeof(written));
		ASSERT_EQ(sizeof(written), got_bytes);
	}
	ASSERT_STRN_EQ("BAR", written, sizeof(written));

	ASSERT_EQ(0, close(fd));
	PASS();
}

TEST
protocol_parse_response_next_request_policy(void)
{
	VideoStreaming__VideoPlaybackAbrRequest *request
		__attribute__((cleanup(video_playback_request_cleanup))) = NULL;
	char *url __attribute__((cleanup(str_free))) = NULL;

	/* clang-format off */
	/*
	 * To generate binary protobuf blobs below:
	 *
	 * $ cat /tmp/next_request_policy.txt | protoc --proto_path=build/_deps/googlevideo-src/protos --encode=video_streaming.NextRequestPolicy $(find build/_deps -type f -name '*.proto') | hexdump -C
	 */
	/* clang-format on */
	const struct string_view resp = MAKE_TEST_STRING(
		"\x23" /* part_type = NEXT_REQUEST_POLICY */
		"\x0C" /* part_size = 12 */

		"\x3A" /************ protobuf blob ************/
		"\x0A" /*                                     */
		"\x3A" /* $ cat /tmp/next_request_policy.txt  */
		"\x03" /* playback_cookie {                   */
		"\x08" /*     video_fmt {                     */
		"\xAB" /*         itag: 299                   */
		"\x02" /*     }                               */
		"\x42" /*     audio_fmt {                     */
		"\x03" /*         itag: 251                   */
		"\x08" /*     }                               */
		"\xFB" /* }                                   */
		"\x01" /***************************************/

		/*
	         * Verify that setting the playback cookie a second
	         * time does not leak memory (assuming this test runs
	         * with LSan enabled).
	         */
		"\x23" /* part_type = NEXT_REQUEST_POLICY */
		"\x0C" /* part_size = 12 */
		"\x3A\x0A\x3A\x03\x08\xAB\x02\x42\x03\x08\xFB\x01");
	CHECK_CALL(parse_and_get_next(&resp, NULL, &request, &url, NULL, NULL));

	/*
	 * Verify that the <response> above affected the next request's
	 * playback cookie as expected.
	 */
	ASSERT(request->streamer_context->has_playback_cookie);
	ASSERT_EQ(10, request->streamer_context->playback_cookie.len);
	const char *expected_cookie =
		"\x3A\x03\x08\xAB\x02\x42\x03\x08\xFB\x01";
	ASSERT_STRN_EQ(expected_cookie,
	               request->streamer_context->playback_cookie.data,
	               request->streamer_context->playback_cookie.len);

	PASS();
}

TEST
protocol_parse_response_next_request_policy_backoff(void)
{
	VideoStreaming__VideoPlaybackAbrRequest *req
		__attribute__((cleanup(video_playback_request_cleanup))) = NULL;
	char *url __attribute__((cleanup(str_free))) = NULL;
	int retry = -1;

	/* clang-format off */
	/*
	 * To generate binary protobuf blobs below:
	 *
	 * $ cat /tmp/next_request_policy.txt | protoc --proto_path=build/_deps/googlevideo-src/protos --encode=video_streaming.NextRequestPolicy $(find build/_deps -type f -name '*.proto') | hexdump -C
	 */
	/* clang-format on */
	const struct string_view resp = MAKE_TEST_STRING(
		"\x23" /* part_type = NEXT_REQUEST_POLICY */
		"\x04" /* part_size = 4 */

		"\x20" /************ protobuf blob ************/
		"\xB0" /* $ cat /tmp/next_request_policy.txt  */
		"\xEA" /* backoff_time_ms: 30000              */
		"\x01" /***************************************/
	);
	CHECK_CALL(parse_and_get_next(&resp, NULL, &req, &url, &retry, NULL));

	ASSERT_EQ(30, retry);
	PASS();
}

TEST
protocol_parse_response_format_initialization_metadata(void)
{
	bool b = false;
	VideoStreaming__VideoPlaybackAbrRequest *request
		__attribute__((cleanup(video_playback_request_cleanup))) = NULL;
	char *url __attribute__((cleanup(str_free))) = NULL;

	/* clang-format off */
	/*
	 * To generate binary protobuf blobs below:
	 *
	 * $ cat /tmp/format_init_metadata.txt | protoc --proto_path=build/_deps/googlevideo-src/protos --encode=video_streaming.FormatInitializationMetadata $(find build/_deps -type f -name '*.proto') | hexdump -C
	 */
	/* clang-format on */
	const struct string_view resp = MAKE_TEST_STRING(
		"\x2A" /* part_type = FORMAT_INITIALIZATION_METADATA */
		"\x07" /* part_size = 7 */

		"\x12" /************ protobuf blob ************/
		"\x03" /* $ cat /tmp/format_init_metadata.txt */
		"\x08" /* format_id {                         */
		"\xFB" /*     itag: 251                       */
		"\x01" /* }                                   */
		"\x20" /* end_segment_number: 8               */
		"\x08" /***************************************/

		"\x2A" /* part_type = FORMAT_INITIALIZATION_METADATA */
		"\x07" /* part_size = 7 */

		"\x12" /************ protobuf blob ************/
		"\x03" /* $ cat /tmp/format_init_metadata.txt */
		"\x08" /* format_id {                         */
		"\xAB" /*     itag: 299                       */
		"\x02" /* }                                   */
		"\x20" /* end_segment_number: 9               */
		"\x09" /***************************************/
	);
	CHECK_CALL(parse_and_get_next(&resp, &b, &request, &url, NULL, NULL));

	ASSERT(b); /* protocol_knows_end() && !protocol_done() */
	PASS();
}

TEST
protocol_parse_response_sabr_redirect(void)
{
	VideoStreaming__VideoPlaybackAbrRequest *request
		__attribute__((cleanup(video_playback_request_cleanup))) = NULL;
	char *url __attribute__((cleanup(str_free))) = NULL;

	/* clang-format off */
	/*
	 * To generate binary protobuf blobs below:
	 *
	 * $ cat /tmp/sabr_redirect.txt | protoc --proto_path=build/_deps/googlevideo-src/protos --encode=video_streaming.SabrRedirect $(find build/_deps -type f -name '*.proto') | hexdump -C
	 */
	/* clang-format on */
	const struct string_view resp = MAKE_TEST_STRING(
		"\x2B" /* part_type = SABR_REDIRECT */
		"\x16" /* part_size = 22 */

		"\x0A\x14\x68\x74" /************ protobuf blob ************/
		"\x74\x70\x73\x3A" /*                                     */
		"\x2F\x2F\x66\x6F" /* $ cat /tmp/sabr_redirect.txt        */
		"\x6F\x2E\x74\x65" /* url: "https://foo.test/bar"         */
		"\x73\x74\x2F\x62" /*                                     */
		"\x61\x72"         /***************************************/
	);
	CHECK_CALL(parse_and_get_next(&resp, NULL, &request, &url, NULL, NULL));

	/*
	 * Verify that the <response> above affected the next request's target
	 * URL as expected.
	 */
	ASSERT_STRN_EQ("https://foo.test/bar", url, 20);
	PASS();
}

TEST
protocol_parse_response_sabr_context_update(void)
{
	VideoStreaming__VideoPlaybackAbrRequest *request
		__attribute__((cleanup(video_playback_request_cleanup))) = NULL;
	char *url __attribute__((cleanup(str_free))) = NULL;

	/* clang-format off */
	/*
	 * To generate binary protobuf blobs below:
	 *
	 * $ cat /tmp/sabr_context_update.txt | protoc --proto_path=build/_deps/googlevideo-src/protos --encode=video_streaming.SabrContextUpdate $(find build/_deps -type f -name '*.proto') | hexdump -C
	 */
	/* clang-format on */
	const struct string_view resp = MAKE_TEST_STRING(
		"\x39" /* part_type = SABR_CONTEXT_UPDATE */
		"\x10" /* part_size = 16 */

		"\x08" /************ protobuf blob ************/
		"\x00" /*                                     */
		"\x10" /*                                     */
		"\x02" /*                                     */
		"\x1A" /*                                     */
		"\x08" /* $ cat /tmp/sabr_context_update.txt  */
		"\x46" /* type: 0                             */
		"\x55" /* scope: REQUEST                      */
		"\x5A" /* value: "FUZZFUZZ"                   */
		"\x5A" /* write_policy: KEEP_EXISTING         */
		"\x46" /*                                     */
		"\x55" /*                                     */
		"\x5A" /*                                     */
		"\x5A" /*                                     */
		"\x28" /*                                     */
		"\x02" /***************************************/

		/*
	         * Verify that a second SABR context update does not leak
	         * memory (assuming this test runs with LSan enabled).
	         */
		"\x39" /* part_type = SABR_CONTEXT_UPDATE */
		"\x10" /* part_size = 16 */
		"\x08\x00\x10\x02\x1A\x08\x46\x55"
		"\x5A\x5A\x46\x55\x5A\x5A\x28\x02");
	CHECK_CALL(parse_and_get_next(&resp, NULL, &request, &url, NULL, NULL));

	/*
	 * Verify that the <response> above affected the next request's SABR
	 * context as expected.
	 */
	ASSERT_EQ(1, request->streamer_context->n_sabr_contexts);
	ASSERT(request->streamer_context->sabr_contexts[0]->has_value);
	ASSERT_EQ(8, request->streamer_context->sabr_contexts[0]->value.len);
	ASSERT_STRN_EQ("FUZZFUZZ",
	               request->streamer_context->sabr_contexts[0]->value.data,
	               request->streamer_context->sabr_contexts[0]->value.len);
	PASS();
}

SUITE(protocol_parse)
{
	RUN_TEST(protocol_init_base64_decode_negative);
	RUN_TEST(protocol_init_base64_decode_positive);
	RUN_TEST(protocol_parse_response_media_header_init_seg);
	RUN_TEST(protocol_parse_response_media_header_and_blob);
	RUN_TEST(protocol_parse_response_next_request_policy);
	RUN_TEST(protocol_parse_response_next_request_policy_backoff);
	RUN_TEST(protocol_parse_response_format_initialization_metadata);
	RUN_TEST(protocol_parse_response_sabr_redirect);
	RUN_TEST(protocol_parse_response_sabr_context_update);
}
