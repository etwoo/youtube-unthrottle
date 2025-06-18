#include "youtube.h"

#include "greatest.h"
#include "sys/debug.h"
#include "sys/write.h"

#include <assert.h>
#include <stdbool.h>
#include <unistd.h>

static const char FAKE_URL[] = "https://a.test/watch?v=FOOBAR";
static const char PATH_WANTS_JSON_RESPONSE[] = "/youtubei/v1/player";
static const char FAKE_HTML_RESPONSE[] = "\"/s/player/foobar/base.js\"\n";
static const char FAKE_JS_RESPONSE[] =
	"'use strict';var zzz=666666,aaa,bbb,ccc,ddd,eee,fff,ggg,hhh;"
	"{signatureTimestamp:12345}"
	"var mmm=88888888;"
	"&&(c=X[0](c),\nvar X=[Y];\n"
	"Y=function(a){"
	"if (typeof mmm === \"undefined\") { return \"FAIL_MAGIC_TYPEOF\"; }"
	"b=[a.toUpperCase()]; return b.join(\"\")"
	"};\nnext_global=0";

#define MAKE_FAKE_JSON(sabrUrl)                                                \
	"{\"streamingData\": {"                                                \
	"\"adaptiveFormats\": [{"                                              \
	"\"mimeType\": \"video/foobar\","                                      \
	"\"qualityLabel\": \"fuzzbuzz\","                                      \
	"\"itag\": 200"                                                        \
	"}],"                                                                  \
	"\"serverAbrStreamingUrl\": \"" sabrUrl "\"},"                         \
	"\"playerConfig\": {"                                                  \
	"\"mediaCommonConfig\": {"                                             \
	"\"mediaUstreamerRequestConfig\": {"                                   \
	"\"videoPlaybackUstreamerConfig\": \"cGxheWJhY2sK\""                   \
	"}}}}"
static const char FAKE_JSON_RESPONSE[] =
	MAKE_FAKE_JSON("https://a.test/sabr?n=aaa");

static const char *(*test_request_path_to_response)(const char *) = NULL;

static WARN_UNUSED const char *
url_simulate(const char *path)
{
	debug("Simulating request with url=%s", path);

	const char *to_write = NULL;
	if (test_request_path_to_response) {
		to_write = test_request_path_to_response(path);
	}

	if (to_write) {
		/* got a custom value from test-specific handler */
	} else if (0 == strcmp(path, "/")) {
		to_write = ""; /* handle thread warmup in url_context_init() */
	} else if (strstr(path, "/watch")) {
		to_write = FAKE_HTML_RESPONSE;
	} else if (strstr(path, "/base.js")) {
		to_write = FAKE_JS_RESPONSE;
	} else if (strstr(path, PATH_WANTS_JSON_RESPONSE)) {
		to_write = FAKE_JSON_RESPONSE;
	} else if (strstr(path, "/sabr")) {
		to_write = "\1\1\1"; /* return an empty-ish UMP response */
	}

	assert(to_write && "Test logic bug? No fixture for given path!");
	return to_write;
}

struct check_url_state {
	bool got_correct_urls;
	const char *expected_url;
};

static void
check_url(const char *url, size_t sz, void *userdata)
{
	struct check_url_state *p = (struct check_url_state *)userdata;
	if (strlen(p->expected_url) == sz &&
	    0 == strncmp(p->expected_url, url, sz)) {
		debug("Got expected URL: %.*s", (int)sz, url);
	} else {
		p->got_correct_urls = false;
		info("check_url() fails: %.*s != %s",
		     (int)sz,
		     url,
		     p->expected_url);
	}
}

TEST
global_setup(void)
{
	auto_result err = youtube_global_init();
	ASSERT_EQ(OK, err.err);
	PASS();
}

static int OFD[2] = {
	STDOUT_FILENO,
	STDOUT_FILENO,
};

const struct youtube_setup_ops OPS = {
	.io_simulator = url_simulate,
	.choose_quality = NULL,
	.choose_quality_userdata = NULL,
};

#define do_test_init() youtube_stream_init("UE9UCg==", "VkQK", &OPS)

TEST
stream_setup_with_redirected_network_io(const char *(*custom_fn)(const char *),
                                        const char *expected_url)
{
	youtube_handle_t stream = do_test_init();
	ASSERT(stream);

	auto_result err = youtube_stream_prepare_tmpfiles(stream);
	ASSERT_EQ(OK, err.err);

	test_request_path_to_response = custom_fn;
	err = youtube_stream_open(stream, FAKE_URL, OFD);
	test_request_path_to_response = NULL;
	ASSERT_EQ(OK, err.err);

	int retry_after = -1;
	err = youtube_stream_next(stream, &retry_after);
	ASSERT_EQ(ERR_YOUTUBE_EARLY_END_STREAM, err.err);
	ASSERT_EQ(-1, retry_after);
	ASSERT(youtube_stream_done(stream));

	struct check_url_state cus = {
		.got_correct_urls = true,
		.expected_url = expected_url,
	};
	err = youtube_stream_visitor(stream, check_url, &cus);

	ASSERT_EQ(OK, err.err);
	ASSERT(cus.got_correct_urls);

	youtube_stream_cleanup(stream);
	PASS();
}

SUITE(stream_setup_simple)
{
	RUN_TEST(global_setup);
	RUN_TESTp(stream_setup_with_redirected_network_io,
	          NULL,
	          "https://a.test/sabr?n=AAA");
}

static WARN_UNUSED const char *
test_request_n_param_pos_middle(const char *path)
{
	if (NULL == strstr(path, PATH_WANTS_JSON_RESPONSE)) {
		return NULL;
	}
	return MAKE_FAKE_JSON("https://a.test/sabr?first=foo&n=aaa&last=bar");
}

static WARN_UNUSED const char *
test_request_n_param_pos_first(const char *path)
{
	if (NULL == strstr(path, PATH_WANTS_JSON_RESPONSE)) {
		return NULL;
	}
	return MAKE_FAKE_JSON("https://a.test/sabr?n=aaa&second=foo&third=bar");
}

static WARN_UNUSED const char *
test_request_n_param_pos_last(const char *path)
{
	if (NULL == strstr(path, PATH_WANTS_JSON_RESPONSE)) {
		return NULL;
	}
	return MAKE_FAKE_JSON("https://a.test/sabr?first=foo&second=bar&n=aaa");
}

SUITE(stream_setup_n_param_positions)
{
	RUN_TEST(global_setup);
	RUN_TESTp(stream_setup_with_redirected_network_io,
	          test_request_n_param_pos_middle,
	          "https://a.test/sabr?first=foo&n=AAA&last=bar");
	RUN_TESTp(stream_setup_with_redirected_network_io,
	          test_request_n_param_pos_first,
	          "https://a.test/sabr?n=AAA&second=foo&third=bar");
	RUN_TESTp(stream_setup_with_redirected_network_io,
	          test_request_n_param_pos_last,
	          "https://a.test/sabr?first=foo&second=bar&n=AAA");
}

static const char YT_MISSING_ID[] = "https://a.test/watch?v=";

TEST
edge_cases_target_url_missing_stream_id(void)
{
	youtube_handle_t stream = do_test_init();
	ASSERT(stream);

	auto_result err = youtube_stream_prepare_tmpfiles(stream);
	ASSERT_EQ(OK, err.err);

	err = youtube_stream_open(stream, YT_MISSING_ID, OFD);
	ASSERT_EQ(ERR_JS_MAKE_INNERTUBE_JSON_ID, err.err);
	ASSERT(youtube_stream_done(stream));

	youtube_stream_cleanup(stream);
	PASS();
}

TEST
edge_cases_with(const char *(*custom_fn)(const char *),
                unsigned expected_result_type)
{
	youtube_handle_t stream = do_test_init();
	ASSERT(stream);

	auto_result err = youtube_stream_prepare_tmpfiles(stream);
	ASSERT_EQ(OK, err.err);

	test_request_path_to_response = custom_fn;
	err = youtube_stream_open(stream, FAKE_URL, OFD);
	test_request_path_to_response = NULL;

	ASSERT_EQ(expected_result_type, err.err);
	ASSERT(youtube_stream_done(stream));

	youtube_stream_cleanup(stream);
	PASS();
}

static WARN_UNUSED const char *
test_request_n_param_missing(const char *path)
{
	if (NULL == strstr(path, PATH_WANTS_JSON_RESPONSE)) {
		return NULL;
	}
	return MAKE_FAKE_JSON("https://a.test/sabr?x=y");
}

static WARN_UNUSED const char *
test_request_invalid_url(const char *path)
{
	if (NULL == strstr(path, PATH_WANTS_JSON_RESPONSE)) {
		return NULL;
	}
	return MAKE_FAKE_JSON("!@#$%^&*()");
}

#define RUN_TEST_WITH_SUFFIX(base, suffix, expected_result_type)               \
	do {                                                                   \
		greatest_set_test_suffix(#suffix);                             \
		RUN_TESTp(base, test_request_##suffix, expected_result_type);  \
	} while (0)

SUITE(stream_setup_weird_urls)
{
	RUN_TEST(edge_cases_target_url_missing_stream_id);
	RUN_TEST_WITH_SUFFIX(edge_cases_with,
	                     n_param_missing,
	                     ERR_YOUTUBE_N_PARAM_FIND_IN_QUERY);
	RUN_TEST_WITH_SUFFIX(edge_cases_with,
	                     invalid_url,
	                     ERR_YOUTUBE_STREAM_URL_INVALID);
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

#undef do_test_init
#undef MAKE_FAKE_JSON
