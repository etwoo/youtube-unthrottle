#include "youtube.h"

#include "greatest.h"
#include "sys/debug.h"
#include "sys/write.h"

#include <assert.h>
#include <stdbool.h>
#include <unistd.h>

TEST
global_setup(void)
{
	auto_result err = youtube_global_init();
	ASSERT_EQ(OK, err.err);
	PASS();
}

SUITE(setup)
{
	RUN_TEST(global_setup);
}

#define T(base, suffix, ...)                                                   \
	do {                                                                   \
		greatest_set_test_suffix(#suffix);                             \
		RUN_TESTp(base, test_request_##suffix, __VA_ARGS__);           \
	} while (0)

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

#define SABR(getargs) "https://a.test/sabr?" getargs
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
static const char FAKE_JSON_RESPONSE[] = MAKE_FAKE_JSON(SABR("n=aaa"));

static const char *(*test_request_default)(const char *) = NULL;

static WARN_UNUSED const char *
url_simulate(const char *path)
{
	debug("Simulating request with url=%s", path);

	const char *to_write = NULL;
	if (test_request_default) {
		to_write = test_request_default(path);
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

const struct youtube_setup_ops SIMULATE_OPS = {
	.io_simulator = url_simulate,
	.choose_quality = NULL,
	.choose_quality_userdata = NULL,
};

#define MAKE_STREAM() youtube_stream_init("UE9UCg==", "VkQK", &SIMULATE_OPS)

static int STDERR_FDS[2] = {
	STDERR_FILENO,
	STDERR_FILENO,
};

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
stream_with(const char *(*custom_fn)(const char *), const char *expected_url)
{
	youtube_handle_t stream = MAKE_STREAM();
	ASSERT(stream);

	auto_result err = youtube_stream_prepare_tmpfiles(stream);
	ASSERT_EQ(OK, err.err);

	if (test_request_default != custom_fn) {
		test_request_default = custom_fn;
	}
	err = youtube_stream_open(stream, FAKE_URL, STDERR_FDS);
	test_request_default = NULL;
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

static WARN_UNUSED const char *
test_request_n_param_pos_middle(const char *path)
{
	if (NULL == strstr(path, PATH_WANTS_JSON_RESPONSE)) {
		return NULL;
	}
	return MAKE_FAKE_JSON(SABR("first=foo&n=aaa&last=bar"));
}

static WARN_UNUSED const char *
test_request_n_param_pos_first(const char *path)
{
	if (NULL == strstr(path, PATH_WANTS_JSON_RESPONSE)) {
		return NULL;
	}
	return MAKE_FAKE_JSON(SABR("n=aaa&second=foo&third=bar"));
}

static WARN_UNUSED const char *
test_request_n_param_pos_last(const char *path)
{
	if (NULL == strstr(path, PATH_WANTS_JSON_RESPONSE)) {
		return NULL;
	}
	return MAKE_FAKE_JSON(SABR("first=foo&second=bar&n=aaa"));
}

SUITE(stream_n_param_positions)
{
	T(stream_with, default, SABR("n=AAA"));
	T(stream_with, n_param_pos_middle, SABR("first=foo&n=AAA&last=bar"));
	T(stream_with, n_param_pos_first, SABR("n=AAA&second=foo&third=bar"));
	T(stream_with, n_param_pos_last, SABR("first=foo&second=bar&n=AAA"));
}

static const char YT_MISSING_ID[] = "https://a.test/watch?v=";

TEST
edge_cases_target_url_missing_stream_id(void)
{
	youtube_handle_t stream = MAKE_STREAM();
	ASSERT(stream);

	auto_result err = youtube_stream_prepare_tmpfiles(stream);
	ASSERT_EQ(OK, err.err);

	err = youtube_stream_open(stream, YT_MISSING_ID, STDERR_FDS);
	ASSERT_EQ(ERR_JS_MAKE_INNERTUBE_JSON_ID, err.err);
	ASSERT(youtube_stream_done(stream));

	youtube_stream_cleanup(stream);
	PASS();
}

TEST
edge_cases_with(const char *(*custom_fn)(const char *), unsigned expected)
{
	youtube_handle_t stream = MAKE_STREAM();
	ASSERT(stream);

	auto_result err = youtube_stream_prepare_tmpfiles(stream);
	ASSERT_EQ(OK, err.err);

	if (test_request_default != custom_fn) {
		test_request_default = custom_fn;
	}
	err = youtube_stream_open(stream, FAKE_URL, STDERR_FDS);
	test_request_default = NULL;

	ASSERT_EQ(expected, err.err);
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
	return MAKE_FAKE_JSON(SABR("x=y"));
}

static WARN_UNUSED const char *
test_request_invalid_url(const char *path)
{
	if (NULL == strstr(path, PATH_WANTS_JSON_RESPONSE)) {
		return NULL;
	}
	return MAKE_FAKE_JSON("!@#$%^&*()");
}

SUITE(stream_edge_cases)
{
	RUN_TEST(edge_cases_target_url_missing_stream_id);
	T(edge_cases_with, n_param_missing, ERR_YOUTUBE_N_PARAM_FIND_IN_QUERY);
	T(edge_cases_with, invalid_url, ERR_YOUTUBE_STREAM_URL_INVALID);
}

TEST
global_cleanup(void)
{
	youtube_global_cleanup();
	PASS();
}

SUITE(cleanup)
{
	RUN_TEST(global_cleanup);
}

#undef MAKE_STREAM
#undef MAKE_FAKE_JSON
#undef SABR
#undef T
