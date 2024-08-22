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
	"{\"mimeType\": \"audio/foobar\",\"url\": \"http://a.test?n=aaa&\"},"
	"{\"mimeType\": \"video/foobar\",\"url\": \"http://v.test?n=vvv&\"}"
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
		warn("No test fixture for URL path: %s", path);
		return 1;
	}

	for (size_t remaining_bytes = strlen(to_write); remaining_bytes > 0;) {
		const ssize_t written = write(fd, to_write, remaining_bytes);
		if (written < 0) {
			pwarn("Error writing to tmpfile");
			return 1;
		}
		to_write += written;
		remaining_bytes -= written;
	}

	return 0;
}

struct youtube_setup_ops NOOP = {
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
stream_setup_with_redirected_network_io(void)
{
	url_global_set_request_handler(test_fixture_request_handler);

	youtube_handle_t stream = youtube_stream_init();
	ASSERT(stream);

	bool rc = youtube_stream_setup(stream, &NOOP, FAKE_YT_URL);
	ASSERT(rc);

	// TODO: add something like youtube_stream_print() that lets us examine the char* URL values, so that we can verify deobfuscation functions were called, e.g. convert to uppercase, or whatever we return in test_fixture_request_handler()
	youtube_stream_print(stream);
	youtube_stream_cleanup(stream);
	PASS();
}

SUITE(stream_setup)
{
	RUN_TEST(stream_setup_with_redirected_network_io);
}

int
main(int argc, char **argv)
{
	GREATEST_MAIN_BEGIN();

	int fd = coverage_open();
	/*
	 * Note: youtube_global_init() and youtube_global_cleanup() are treated
	 * as test fixtures, not TEST() cases, in case we ever want to run the
	 * individual suites and testcases above in shuffled order.
	 */
	youtube_global_init();

	RUN_SUITE(stream_setup);

	youtube_global_cleanup();
	coverage_write_and_close(fd);

	GREATEST_MAIN_END();
}
