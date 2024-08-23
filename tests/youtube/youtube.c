#include "youtube.h"

#include "coverage.h"
#include "debug.h"
#include "greatest.h"
#include "url.h"

#include <unistd.h>

GREATEST_MAIN_DEFS();

static const char FAKE_YT_URL[] = "https://www.youtube.com/watch?v=FOOBAR";
static const char FAKE_HTML_RESPONSE[] = "\"/s/player/foobar/base.js\"";
static const char FAKE_JSON_RESPONSE[] =
	"{\"streamingData\": {\"adaptiveFormats\": ["
	"{\"mimeType\": \"audio/foobar\",\"url\": \"http://a.test?n=aaa\"},"
	"{\"mimeType\": \"video/foobar\",\"url\": \"http://v.test?n=vvv\"}"
	"]}}";
static const char FAKE_JS_RESPONSE[] =
	"&&(c=X[0](c),\nvar X=[Y];\nY=function(a)"
	"{b=[a.toUpperCase()]; return b.join(\"\")};";

static int
test_fixture_request_handler(void *request, const char *path, int fd)
{
	debug("Mocking request: CURL* %p, %s, fd=%d", request, path, fd);

	const char *to_write = NULL;
	if (strstr(path, "/watch?v=")) {
		to_write = FAKE_HTML_RESPONSE;
	} else if (strstr(path, "/youtubei/v1/player")) {
		to_write = FAKE_JSON_RESPONSE;
	} else if (strstr(path, "/base.js")) {
		to_write = FAKE_JS_RESPONSE;
	} else {
		warn_then_return_1("No test fixture for URL path: %s", path);
	}

	for (size_t remaining_bytes = strlen(to_write); remaining_bytes > 0;) {
		const ssize_t written = write(fd, to_write, remaining_bytes);
		if (written < 0) {
			warn_then_return_1("Error writing to tmpfile");
		}
		to_write += written;
		remaining_bytes -= written;
	}

	return 0;
}

static void
setup_callback_noop(youtube_handle_t h __attribute__((unused)))
{
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

static bool CHECK_URL_RESULT = true;

static void
check_url(const char *url)
{
	if (0 == strcmp("http://a.test/?n=AAA", url)) {
		debug("Got expected audio URL: %s", url);
	} else if (0 == strcmp("http://v.test/?n=VVV", url)) {
		debug("Got expected video URL: %s", url);
	} else {
		CHECK_URL_RESULT = false;
		warn_then_return("check_url() fails: %s", url);
	}
}

TEST
stream_setup_with_redirected_network_io(void)
{
	youtube_handle_t stream = youtube_stream_init();
	ASSERT(stream);

	bool rc = youtube_stream_setup(stream, &NOOP, FAKE_YT_URL);
	ASSERT(rc);

	youtube_stream_visitor(stream, check_url);
	ASSERT(CHECK_URL_RESULT);

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

	bool rc = youtube_stream_setup(stream, &NULL_OPS, FAKE_YT_URL);
	ASSERT(rc);

	youtube_stream_cleanup(stream);
	PASS();
}

SUITE(stream_setup)
{
	url_global_set_request_handler(test_fixture_request_handler);
	RUN_TEST(stream_setup_with_redirected_network_io);
	RUN_TEST(stream_setup_with_null_ops);
}

int
main(int argc, char **argv)
{
	int fd __attribute__((cleanup(coverage_cleanup))) = coverage_open();

	GREATEST_MAIN_BEGIN();

	/*
	 * Note: youtube_global_init() and youtube_global_cleanup() are treated
	 * as test fixtures, not TEST() cases, in case we ever want to run the
	 * individual suites and testcases above in shuffled order.
	 */
	youtube_global_init();
	RUN_SUITE(stream_setup);
	youtube_global_cleanup();

	GREATEST_MAIN_END();
}
