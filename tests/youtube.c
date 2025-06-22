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

static const char MOCK_HTML_RESPONSE[] = "\"/s/player/foobar/base.js\"";
static const char MOCK_JS_RESPONSE[] =
	"'use strict';var zzz=666666,aaa,bbb,ccc,ddd,eee,fff,ggg,hhh;"
	"{signatureTimestamp:12345}"
	"var mmm=88888888;"
	"&&(c=X[0](c),\nvar X=[Y];\n"
	"Y=function(a){"
	"if (typeof mmm === \"undefined\") { return \"FAIL_MAGIC_TYPEOF\"; }"
	"b=[a.toUpperCase()]; return b.join(\"\")"
	"};\nnext_global=0";

#define SABR(get_args) "https://a.test/sabr?" get_args

#define MAKE_JSON_LITERAL(sabr_url)                                            \
	"{\"streamingData\": {"                                                \
	"\"adaptiveFormats\": [{"                                              \
	"\"mimeType\": \"video/foobar\","                                      \
	"\"qualityLabel\": \"fuzzbuzz\","                                      \
	"\"itag\": 200"                                                        \
	"}],"                                                                  \
	"\"serverAbrStreamingUrl\": \"" sabr_url "\"},"                        \
	"\"playerConfig\": {"                                                  \
	"\"mediaCommonConfig\": {"                                             \
	"\"mediaUstreamerRequestConfig\": {"                                   \
	"\"videoPlaybackUstreamerConfig\": \"cGxheWJhY2sK\""                   \
	"}}}}"

#define T(base, testname_suffix, json_fragment, ...)                           \
	do {                                                                   \
		greatest_set_test_suffix(#testname_suffix);                    \
		MOCK_JSON_RESPONSE = MAKE_JSON_LITERAL(json_fragment);         \
		RUN_TESTp(base, __VA_ARGS__);                                  \
		MOCK_JSON_RESPONSE = NULL;                                     \
	} while (0)

static const char *MOCK_JSON_RESPONSE = NULL;

static WARN_UNUSED const char *
url_simulate(const char *path)
{
	debug("Simulating request with url=%s", path);
	const char *to_write = NULL;

	if (0 == strcmp(path, "https://www.youtube.com")) {
		to_write = ""; /* handle thread warmup in url_context_init() */
	} else if (strstr(path, "/watch")) {
		to_write = MOCK_HTML_RESPONSE;
	} else if (strstr(path, "/base.js")) {
		to_write = MOCK_JS_RESPONSE;
	} else if (strstr(path, "/youtubei/v1/player")) {
		assert(MOCK_JSON_RESPONSE && "Test bug? Missing JSON mock!");
		to_write = MOCK_JSON_RESPONSE;
	} else if (strstr(path, "/sabr")) {
		to_write = "\1\1\1"; /* return an empty-ish UMP response */
	}

	assert(to_write && "Test logic bug? No fixture for given path!");
	return to_write;
}

static const char TEST_U[] = "https://a.test/watch?v=FOOBAR";
static const char TEST_U_NOID[] = "https://a.test/watch?v=";
static const char TEST_P[] = "UE9UCg=="; /* base64-encoded "POT" */
static const char TEST_V[] = "VkQK";     /* base64-encoded "VD" */
static const struct youtube_stream_ops TEST_OP = {
	.io_simulator = url_simulate,
	.choose_quality = NULL,
	.choose_quality_userdata = NULL,
};
static const int TEST_OFD[2] = {
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
stream_with(const char *expected_url)
{
	youtube_handle_t stream = youtube_stream_init(TEST_P, TEST_V, &TEST_OP);
	ASSERT(stream);

	auto_result err = youtube_stream_prepare_tmpfiles(stream);
	ASSERT_EQ(OK, err.err);

	err = youtube_stream_open(stream, TEST_U, TEST_OFD);
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

SUITE(stream_n_param_positions)
{
	T(stream_with, n_param_only, SABR("n=a_b_c_d_e"), SABR("n=A_B_C_D_E"));
	T(stream_with, n_param_first, SABR("n=a&b=b&c=c"), SABR("n=A&b=b&c=c"));
	T(stream_with, n_param_mid, SABR("a=a&n=b&c=c"), SABR("a=a&n=B&c=c"));
	T(stream_with, n_param_last, SABR("a=a&b=b&n=c"), SABR("a=a&b=b&n=C"));
}

TEST
err_with(const char *target_url, unsigned expected_result_type)
{
	youtube_handle_t stream = youtube_stream_init(TEST_P, TEST_V, &TEST_OP);
	ASSERT(stream);

	auto_result err = youtube_stream_prepare_tmpfiles(stream);
	ASSERT_EQ(OK, err.err);

	err = youtube_stream_open(stream, target_url, TEST_OFD);
	ASSERT_EQ(expected_result_type, err.err);
	ASSERT(youtube_stream_done(stream));

	youtube_stream_cleanup(stream);
	PASS();
}

SUITE(stream_edge_cases)
{
	T(err_with, missing_id, "", TEST_U_NOID, ERR_JS_MAKE_INNERTUBE_JSON_ID);
	T(err_with, missing_N, SABR(""), TEST_U, ERR_YOUTUBE_N_PARAM_MISSING);
	T(err_with, invalid_url, ":-(", TEST_U, ERR_YOUTUBE_STREAM_URL_INVALID);
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

#undef T
#undef MAKE_JSON_LITERAL
#undef SABR
