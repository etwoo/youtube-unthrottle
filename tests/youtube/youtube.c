#include "youtube.h"

#include "coverage.h"
#include "debug.h"
#include "greatest.h"
#include "url.h"
#include "write.h"

#include <assert.h>
#include <stdbool.h>
#include <unistd.h>

#define RESULT_CLEANUP __attribute__((cleanup(result_cleanup)))

static const char PATH_WANTS_JSON_RESPONSE[] = "/youtubei/v1/player";
static const char FAKE_YT_URL[] = "https://www.youtube.com/watch?v=FOOBAR";
static const char FAKE_HTML_RESPONSE[] = "\"/s/player/foobar/base.js\"";
static const char FAKE_JSON_RESPONSE[] =
	"{\"streamingData\": {\"adaptiveFormats\": ["
	"{\"mimeType\": \"audio/foobar\",\"url\": \"http://a.test?n=aaa\"},"
	"{\"mimeType\": \"video/foobar\",\"url\": \"http://v.test?n=vvv\"}"
	"]}}";
static const char FAKE_JS_RESPONSE[] =
	"{signatureTimestamp:12345}"
	"&&(c=X[0](c),\nvar X=[Y];\nY=function(a)"
	"{b=[a.toUpperCase()]; return b.join(\"\")};";

static const char *(*test_request_path_to_response)(const char *) = NULL;

static WARN_UNUSED int
test_fixture_request_handler(void *request, const char *path, int fd)
{
	debug("Mocking request: CURL* %p, %s, fd=%d", request, path, fd);

	const char *to_write = NULL;
	if (test_request_path_to_response) {
		to_write = test_request_path_to_response(path);
	}

	if (to_write) {
		/* got a custom value from test-specific handler */
	} else if (0 == strlen(path)) {
		to_write = ""; /* handle thread warmup in url_global_init() */
	} else if (strstr(path, "/watch?v=")) {
		to_write = FAKE_HTML_RESPONSE;
	} else if (strstr(path, PATH_WANTS_JSON_RESPONSE)) {
		to_write = FAKE_JSON_RESPONSE;
	} else if (strstr(path, "/base.js")) {
		to_write = FAKE_JS_RESPONSE;
	}

	assert(to_write && "Test logic bug? No fixture for given path!");

	ssize_t written = write_with_retry(fd, to_write, strlen(to_write));
	info_m_if(written < 0, "Cannot write to tmpfile");
	return 0;
}

static WARN_UNUSED result_t
setup_callback_noop(youtube_handle_t h __attribute__((unused)))
{
	return RESULT_OK;
}

struct youtube_setup_ops NOOP = {
	.before = setup_callback_noop,
	.before_inet = setup_callback_noop,
	.after_inet = setup_callback_noop,
	.before_parse = setup_callback_noop,
	.after_parse = setup_callback_noop,
	.before_eval = setup_callback_noop,
	.after_eval = setup_callback_noop,
	.after = setup_callback_noop,
};

static bool GOT_CORRECT_URLS = true;
static const char *EXPECTED_AUDIO_URL = NULL;
static const char *EXPECTED_VIDEO_URL = NULL;

static void
check_url(const char *url)
{
	if (0 == strcmp(EXPECTED_AUDIO_URL, url)) {
		debug("Got expected audio URL: %s", url);
	} else if (0 == strcmp(EXPECTED_VIDEO_URL, url)) {
		debug("Got expected video URL: %s", url);
	} else {
		GOT_CORRECT_URLS = false;
		info("check_url() fails: %s", url);
	}
}

TEST
global_setup(void)
{
	result_t err RESULT_CLEANUP = youtube_global_init();
	ASSERT_TRUE(is_ok(err));
	PASS();
}

TEST
stream_setup_with_redirected_network_io(const char *(*custom_fn)(const char *),
                                        const char *expected_audio_url,
                                        const char *expected_video_url)
{
	youtube_handle_t stream = youtube_stream_init();
	ASSERT(stream);

	test_request_path_to_response = custom_fn;
	result_t err RESULT_CLEANUP =
		youtube_stream_setup(stream, &NOOP, FAKE_YT_URL);
	test_request_path_to_response = NULL;

	ASSERT_TRUE(is_ok(err));

	GOT_CORRECT_URLS = true;
	EXPECTED_AUDIO_URL = expected_audio_url;
	EXPECTED_VIDEO_URL = expected_video_url;

	err = youtube_stream_visitor(stream, check_url);

	EXPECTED_AUDIO_URL = NULL;
	EXPECTED_VIDEO_URL = NULL;

	ASSERT_TRUE(is_ok(err));
	ASSERT(GOT_CORRECT_URLS);

	youtube_stream_cleanup(stream);
	PASS();
}

struct youtube_setup_ops NULL_OPS = {
	.before = NULL,
	.before_inet = NULL,
	.after_inet = NULL,
	.before_parse = NULL,
	.after_parse = NULL,
	.before_eval = NULL,
	.after_eval = NULL,
	.after = NULL,
};

TEST
stream_setup_with_null_ops(void)
{
	youtube_handle_t stream = youtube_stream_init();
	ASSERT(stream);

	result_t err RESULT_CLEANUP =
		youtube_stream_setup(stream, &NULL_OPS, FAKE_YT_URL);
	ASSERT_TRUE(is_ok(err));

	youtube_stream_cleanup(stream);
	PASS();
}

SUITE(stream_setup_simple)
{
	url_global_set_request_handler(test_fixture_request_handler);
	RUN_TEST(global_setup);
	RUN_TESTp(stream_setup_with_redirected_network_io,
	          NULL,
	          "http://a.test/?n=AAA",
	          "http://v.test/?n=VVV");
	RUN_TEST(stream_setup_with_null_ops);
}

static const char YT_URL_MISSING_ID[] = "https://www.youtube.com/watch?v=";

TEST
stream_setup_edge_cases_target_url_missing_stream_id(void)
{
	youtube_handle_t stream = youtube_stream_init();
	ASSERT(stream);

	result_t err RESULT_CLEANUP =
		youtube_stream_setup(stream, &NOOP, YT_URL_MISSING_ID);
	ASSERT_FALSE(is_ok(err));

	youtube_stream_cleanup(stream);
	PASS();
}

SUITE(stream_setup_target_url_variations)
{
	url_global_set_request_handler(test_fixture_request_handler);
	RUN_TEST(global_setup);
	RUN_TEST(stream_setup_edge_cases_target_url_missing_stream_id);
}

static WARN_UNUSED const char *
test_request_n_param_pos_middle(const char *path)
{
	if (NULL == strstr(path, PATH_WANTS_JSON_RESPONSE)) {
		return NULL;
	}
	return "{\"streamingData\": {\"adaptiveFormats\": ["
	       "{\"mimeType\": \"audio/foobar\",\"url\": \""
	       "http://a.test?first=foo&n=aaa&last=bar"
	       "\"},"
	       "{\"mimeType\": \"video/foobar\",\"url\": \""
	       "http://v.test?first=foo&n=vvv&last=bar"
	       "\"}"
	       "]}}";
}

static WARN_UNUSED const char *
test_request_n_param_pos_first(const char *path)
{
	if (NULL == strstr(path, PATH_WANTS_JSON_RESPONSE)) {
		return NULL;
	}
	return "{\"streamingData\": {\"adaptiveFormats\": ["
	       "{\"mimeType\": \"audio/foobar\",\"url\": \""
	       "http://a.test?n=aaa&second=foo&third=bar"
	       "\"},"
	       "{\"mimeType\": \"video/foobar\",\"url\": \""
	       "http://v.test?n=vvv&second=foo&third=bar"
	       "\"}"
	       "]}}";
}

static WARN_UNUSED const char *
test_request_n_param_pos_last(const char *path)
{
	if (NULL == strstr(path, PATH_WANTS_JSON_RESPONSE)) {
		return NULL;
	}
	return "{\"streamingData\": {\"adaptiveFormats\": ["
	       "{\"mimeType\": \"audio/foobar\",\"url\": \""
	       "http://a.test?first=foo&second=bar&n=aaa"
	       "\"},"
	       "{\"mimeType\": \"video/foobar\",\"url\": \""
	       "http://v.test?first=foo&second=bar&n=vvv"
	       "\"}"
	       "]}}";
}

static WARN_UNUSED const char *
test_request_n_param_empty_or_missing(const char *path)
{
	if (NULL == strstr(path, PATH_WANTS_JSON_RESPONSE)) {
		return NULL;
	}
	return "{\"streamingData\": {\"adaptiveFormats\": ["
	       "{\"mimeType\": \"audio/foobar\",\"url\": \"http://a.test?n=\"},"
	       "{\"mimeType\": \"video/foobar\",\"url\": \"http://v.test?x=y\"}"
	       "]}}";
}

TEST
stream_setup_edge_cases_n_param_missing(void)
{
	youtube_handle_t stream = youtube_stream_init();
	ASSERT(stream);

	test_request_path_to_response = test_request_n_param_empty_or_missing;
	result_t err RESULT_CLEANUP =
		youtube_stream_setup(stream, &NULL_OPS, FAKE_YT_URL);
	test_request_path_to_response = NULL;

	ASSERT_FALSE(is_ok(err));

	youtube_stream_cleanup(stream);
	PASS();
}

static WARN_UNUSED const char *
test_request_entire_url_missing(const char *path)
{
	if (NULL == strstr(path, PATH_WANTS_JSON_RESPONSE)) {
		return NULL;
	}
	return "{\"streamingData\": {\"adaptiveFormats\": []}}";
}

TEST
stream_setup_edge_cases_entire_url_missing(void)
{
	youtube_handle_t stream = youtube_stream_init();
	ASSERT(stream);

	test_request_path_to_response = test_request_entire_url_missing;
	result_t err RESULT_CLEANUP =
		youtube_stream_setup(stream, &NULL_OPS, FAKE_YT_URL);
	test_request_path_to_response = NULL;

	ASSERT_FALSE(is_ok(err));

	youtube_stream_cleanup(stream);
	PASS();
}

SUITE(stream_setup_n_param_positions)
{
	url_global_set_request_handler(test_fixture_request_handler);
	RUN_TEST(global_setup);
	RUN_TESTp(stream_setup_with_redirected_network_io,
	          test_request_n_param_pos_middle,
	          "http://a.test/?first=foo&last=bar&n=AAA",
	          "http://v.test/?first=foo&last=bar&n=VVV");
	RUN_TESTp(stream_setup_with_redirected_network_io,
	          test_request_n_param_pos_first,
	          "http://a.test/?second=foo&third=bar&n=AAA",
	          "http://v.test/?second=foo&third=bar&n=VVV");
	RUN_TESTp(stream_setup_with_redirected_network_io,
	          test_request_n_param_pos_last,
	          "http://a.test/?first=foo&second=bar&n=AAA",
	          "http://v.test/?first=foo&second=bar&n=VVV");
	RUN_TEST(stream_setup_edge_cases_n_param_missing);
	RUN_TEST(stream_setup_edge_cases_entire_url_missing);
}

GREATEST_MAIN_DEFS();

int
main(int argc, char **argv)
{
	int fd __attribute__((cleanup(coverage_cleanup))) = coverage_open();

	GREATEST_MAIN_BEGIN();

	RUN_SUITE(stream_setup_simple);
	RUN_SUITE(stream_setup_target_url_variations);
	RUN_SUITE(stream_setup_n_param_positions);

	youtube_global_cleanup();
	GREATEST_MAIN_END();
}
