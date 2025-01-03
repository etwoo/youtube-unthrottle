#include "youtube.h"

#include "debug.h"
#include "greatest.h"
#include "url.h"
#include "write.h"

#include <assert.h>
#include <stdbool.h>
#include <unistd.h>

static const char PATH_WANTS_JSON_RESPONSE[] = "/youtubei/v1/player";
static const char FAKE_YT_URL[] = "https://www.youtube.com/watch?v=FOOBAR";
static const char FAKE_HTML_RESPONSE[] = "\"/s/player/foobar/base.js\"";
static const char FAKE_JSON_RESPONSE[] =
	"{\"streamingData\": {\"adaptiveFormats\": ["
	"{"
	"\"mimeType\": \"audio/foobar\","
	"\"qualityLabel\": \"high\","
	"\"url\": \"http://a.test?n=aaa\""
	"},"
	"{\""
	"mimeType\": \"video/foobar\","
	"\"qualityLabel\": \"high\","
	"\"url\": \"http://v.test?n=vvv\""
	"}"
	"]}}";
static const char FAKE_JS_RESPONSE[] =
	"{signatureTimestamp:12345}"
	"var mmm=88888888;"
	"&&(c=X[0](c),\nvar X=[Y];\n"
	"Y=function(a){"
	"if (typeof mmm === \"undefined\") { return \"FAIL_MAGIC_TYPEOF\"; }"
	"b=[a.toUpperCase()]; return b.join(\"\")"
	"};";

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
	} else if (path == NULL || 0 == strlen(path)) {
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
setup_callback_noop(void *userdata __attribute__((unused)))
{
	return RESULT_OK;
}

static WARN_UNUSED result_t
parse_callback_noop(const char *val __attribute__((unused)),
                    void *userdata __attribute__((unused)))
{
	return RESULT_OK;
}

struct youtube_setup_ops NOOP = {
	.before = setup_callback_noop,
	.before_inet = setup_callback_noop,
	.after_inet = setup_callback_noop,
	.before_parse = setup_callback_noop,
	.during_parse_choose_quality = parse_callback_noop,
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
	result_t err = youtube_global_init();
	ASSERT_EQ(OK, err.err);
	PASS();
}

#define youtube_stream_init() youtube_stream_init("POT", "VISITOR_DATA")

TEST
stream_setup_with_redirected_network_io(const char *(*custom_fn)(const char *),
                                        const char *expected_audio_url,
                                        const char *expected_video_url)
{
	youtube_handle_t stream = youtube_stream_init();
	ASSERT(stream);

	test_request_path_to_response = custom_fn;
	result_t err = youtube_stream_setup(stream, &NOOP, NULL, FAKE_YT_URL);
	test_request_path_to_response = NULL;

	ASSERT_EQ(OK, err.err);

	GOT_CORRECT_URLS = true;
	EXPECTED_AUDIO_URL = expected_audio_url;
	EXPECTED_VIDEO_URL = expected_video_url;

	err = youtube_stream_visitor(stream, check_url);

	EXPECTED_AUDIO_URL = NULL;
	EXPECTED_VIDEO_URL = NULL;

	ASSERT_EQ(OK, err.err);
	ASSERT(GOT_CORRECT_URLS);

	youtube_stream_cleanup(stream);
	PASS();
}

struct youtube_setup_ops NULLOP = {
	.before = NULL,
	.before_inet = NULL,
	.after_inet = NULL,
	.before_parse = NULL,
	.during_parse_choose_quality = NULL,
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

	result_t err = youtube_stream_setup(stream, &NULLOP, NULL, FAKE_YT_URL);
	ASSERT_EQ(OK, err.err);

	youtube_stream_cleanup(stream);
	PASS();
}

SUITE(stream_setup_simple)
{
	url_global_set_request_handler(test_fixture_request_handler);
	RUN_TEST(global_setup);
	RUN_TESTp(stream_setup_with_redirected_network_io,
	          NULL,
	          "http://a.test/?pot=POT&n=AAA",
	          "http://v.test/?pot=POT&n=VVV");
	RUN_TEST(stream_setup_with_null_ops);
}

static const char YT_MISSING_ID[] = "https://www.youtube.com/watch?v=";

TEST
stream_setup_edge_cases_target_url_missing_stream_id(void)
{
	youtube_handle_t stream = youtube_stream_init();
	ASSERT(stream);

	result_t err = youtube_stream_setup(stream, &NOOP, NULL, YT_MISSING_ID);
	ASSERT_EQ(ERR_JS_MAKE_INNERTUBE_JSON_ID, err.err);

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
	result_t err = youtube_stream_setup(stream, &NULLOP, NULL, FAKE_YT_URL);
	test_request_path_to_response = NULL;

	ASSERT_EQ(ERR_YOUTUBE_N_PARAM_FIND_IN_QUERY, err.err);

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
	result_t err = youtube_stream_setup(stream, &NULLOP, NULL, FAKE_YT_URL);
	test_request_path_to_response = NULL;

	ASSERT_EQ(ERR_YOUTUBE_N_PARAM_QUERY_GET, err.err);

	youtube_stream_cleanup(stream);
	PASS();
}

SUITE(stream_setup_n_param_positions)
{
	url_global_set_request_handler(test_fixture_request_handler);
	RUN_TEST(global_setup);
	RUN_TESTp(stream_setup_with_redirected_network_io,
	          test_request_n_param_pos_middle,
	          "http://a.test/?first=foo&last=bar&pot=POT&n=AAA",
	          "http://v.test/?first=foo&last=bar&pot=POT&n=VVV");
	RUN_TESTp(stream_setup_with_redirected_network_io,
	          test_request_n_param_pos_first,
	          "http://a.test/?second=foo&third=bar&pot=POT&n=AAA",
	          "http://v.test/?second=foo&third=bar&pot=POT&n=VVV");
	RUN_TESTp(stream_setup_with_redirected_network_io,
	          test_request_n_param_pos_last,
	          "http://a.test/?first=foo&second=bar&pot=POT&n=AAA",
	          "http://v.test/?first=foo&second=bar&pot=POT&n=VVV");
	RUN_TEST(stream_setup_edge_cases_n_param_missing);
	RUN_TEST(stream_setup_edge_cases_entire_url_missing);
}

TEST
global_cleanup(void)
{
	youtube_global_cleanup();
	PASS();
}

SUITE(stream_cleanup)
{
	RUN_TEST(global_cleanup);
}
