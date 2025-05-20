#include "youtube.h"

#include "greatest.h"
#include "sys/debug.h"
#include "sys/write.h"

#include <assert.h>
#include <stdbool.h>
#include <unistd.h>

static const char FAKE_URL[] = "https://a.test/watch?v=FOOBAR";
static const char FAKE_HTML_RESPONSE[] =
	"\"/s/player/foobar/base.js\"\n"
	"\"serverAbrStreamingUrl\":\"https://a.test/sabr?n=aaa\"\n"
	"\"videoPlaybackUstreamerConfig\":\"Zm9vYmFyCg==\"";
static const char FAKE_JS_RESPONSE[] =
	"'use strict';var zzz=666666,aaa,bbb,ccc,ddd,eee,fff,ggg,hhh;"
	"var mmm=88888888;"
	"&&(c=X[0](c),\nvar X=[Y];\n"
	"Y=function(a){"
	"if (typeof mmm === \"undefined\") { return \"FAIL_MAGIC_TYPEOF\"; }"
	"b=[a.toUpperCase()]; return b.join(\"\")"
	"};\nnext_global=0";

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
	} else if (strstr(path, "/sabr")) {
		to_write = "some_protobuf_payload"; // TODO: real protobuf?
	}

	assert(to_write && "Test logic bug? No fixture for given path!");
	return to_write;
}

static WARN_UNUSED result_t
setup_callback_noop(void *userdata __attribute__((unused)))
{
	return RESULT_OK;
}

static const struct youtube_setup_ops NOOP = {
	.before_tmpfile = setup_callback_noop,
	.after_tmpfile = setup_callback_noop,
	.before_inet = setup_callback_noop,
	.after_inet = setup_callback_noop,
};

struct check_url_state {
	bool got_correct_urls;
	const char *expected_url;
};

static void
check_url(const char *url, size_t sz, void *userdata)
{
	struct check_url_state *p = (struct check_url_state *)userdata;
	if (0 == strncmp(p->expected_url, url, sz)) {
		debug("Got expected URL: %s", url);
	} else {
		p->got_correct_urls = false;
		info("check_url() fails: %s", url);
	}
}

TEST
global_setup(void)
{
	auto_result err = youtube_global_init();
	ASSERT_EQ(OK, err.err);
	PASS();
}

static int TEST_FD[2] = {
	STDOUT_FILENO,
	STDOUT_FILENO,
};

#define do_test_init()                                                         \
	youtube_stream_init("UE9UCg==", "X", url_simulate, TEST_FD)

TEST
stream_setup_with_redirected_network_io(const char *(*custom_fn)(const char *),
                                        const char *expected_url)
{
	youtube_handle_t stream = do_test_init();
	ASSERT(stream);

	test_request_path_to_response = custom_fn;
	auto_result err = youtube_stream_setup(stream, &NOOP, NULL, FAKE_URL);
	test_request_path_to_response = NULL;

	fprintf(stderr, "Got err: %s\n", result_to_str(err));
	ASSERT_EQ(OK, err.err);

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

static const struct youtube_setup_ops NULLOP = {
	.before_tmpfile = NULL,
	.after_tmpfile = NULL,
	.before_inet = NULL,
	.after_inet = NULL,
};

TEST
stream_setup_with_null_ops(void)
{
	youtube_handle_t stream = do_test_init();
	ASSERT(stream);

	auto_result err = youtube_stream_setup(stream, &NULLOP, NULL, FAKE_URL);
	ASSERT_EQ(OK, err.err);

	youtube_stream_cleanup(stream);
	PASS();
}

SUITE(stream_setup_simple)
{
	RUN_TEST(global_setup);
	RUN_TESTp(stream_setup_with_redirected_network_io,
	          NULL,
	          "https://a.test/sabr?n=AAA");
	RUN_TEST(stream_setup_with_null_ops);
}

static const char YT_MISSING_ID[] = "https://a.test/watch?v=";

TEST
stream_setup_edge_cases_target_url_missing_stream_id(void)
{
	youtube_handle_t stream = do_test_init();
	ASSERT(stream);

	auto_result err =
		youtube_stream_setup(stream, &NOOP, NULL, YT_MISSING_ID);
	ASSERT_EQ(ERR_YOUTUBE_STREAM_URL_MISSING, err.err);

	youtube_stream_cleanup(stream);
	PASS();
}

SUITE(stream_setup_target_url_variations)
{
	RUN_TEST(global_setup);
	RUN_TEST(stream_setup_edge_cases_target_url_missing_stream_id);
}

static WARN_UNUSED const char *
test_request_n_param_pos_middle(const char *path)
{
	if (path == NULL || NULL == strstr(FAKE_URL, path)) {
		return NULL;
	}
	return "\"/s/player/foobar/base.js\"\n"
	       "\"serverAbrStreamingUrl\":\"https://a.test/"
	       "sabr?first=foo&n=aaa&last=bar\"\n"
	       "\"videoPlaybackUstreamerConfig\":\"Zm9vYmFyCg==\"";
}

static WARN_UNUSED const char *
test_request_n_param_pos_first(const char *path)
{
	if (path == NULL || NULL == strstr(FAKE_URL, path)) {
		return NULL;
	}
	return "\"/s/player/foobar/base.js\"\n"
	       "\"serverAbrStreamingUrl\":\"https://a.test/"
	       "sabr?n=aaa&second=foo&third=bar\"\n"
	       "\"videoPlaybackUstreamerConfig\":\"Zm9vYmFyCg==\"";
}

static WARN_UNUSED const char *
test_request_n_param_pos_last(const char *path)
{
	if (path == NULL || NULL == strstr(FAKE_URL, path)) {
		return NULL;
	}
	return "\"/s/player/foobar/base.js\"\n"
	       "\"serverAbrStreamingUrl\":\"https://a.test/"
	       "sabr?first=foo&second=bar&n=aaa\"\n"
	       "\"videoPlaybackUstreamerConfig\":\"Zm9vYmFyCg==\"";
}

static WARN_UNUSED const char *
test_request_n_param_empty_or_missing(const char *path)
{
	if (path == NULL || NULL == strstr(FAKE_URL, path)) {
		return NULL;
	}
	return "\"/s/player/foobar/base.js\"\n"
	       "\"serverAbrStreamingUrl\":\"https://a.test/"
	       "sabr?first=foo&second=bar&n=\"\n"
	       "\"videoPlaybackUstreamerConfig\":\"Zm9vYmFyCg==\"";
}

TEST
stream_setup_edge_cases_n_param_missing(void)
{
	youtube_handle_t stream = do_test_init();
	ASSERT(stream);

	test_request_path_to_response = test_request_n_param_empty_or_missing;
	auto_result err = youtube_stream_setup(stream, &NOOP, NULL, FAKE_URL);
	test_request_path_to_response = NULL;

	ASSERT_EQ(ERR_YOUTUBE_N_PARAM_FIND_IN_QUERY, err.err);

	youtube_stream_cleanup(stream);
	PASS();
}

SUITE(stream_setup_n_param_positions)
{
	RUN_TEST(global_setup);
	RUN_TESTp(stream_setup_with_redirected_network_io,
	          test_request_n_param_pos_middle,
	          "https://a.test/?first=foo&n=AAA&last=bar&pot=POT");
	RUN_TESTp(stream_setup_with_redirected_network_io,
	          test_request_n_param_pos_first,
	          "https://a.test/?n=AAA&second=foo&third=bar&pot=POT");
	RUN_TESTp(stream_setup_with_redirected_network_io,
	          test_request_n_param_pos_last,
	          "https://a.test/?first=foo&second=bar&n=AAA&pot=POT");
	RUN_TEST(stream_setup_edge_cases_n_param_missing);
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
