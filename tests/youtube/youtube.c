#include "youtube.h"

#include "coverage.h"
#include "greatest.h"

GREATEST_MAIN_DEFS();

TEST
stream_setup_preconditions(void)
{
	youtube_handle_t stream = youtube_stream_init();
	ASSERT(stream);
	ASSERT_FALSE(youtube_stream_valid(stream));
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

// TODO: register test callback that redirects IO, then add test assertions that static IO payloads lead to expected results in stream->url[0], stream->url[1]
TEST
stream_setup_with_redirected_network_io(void)
{
	youtube_handle_t stream = youtube_stream_init();
	ASSERT(stream);

	ASSERT(youtube_stream_setup(stream, &NOOP, "https://youtube.test"));
	ASSERT(youtube_stream_valid(stream));

	youtube_stream_print(stream);
	youtube_stream_cleanup(stream);
	PASS();
}

SUITE(stream_setup)
{
	RUN_TEST(stream_setup_preconditions);
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
