/*
 * Extract video and audio stream URLs from a YouTube link passed via argv[1],
 * and then print the results to stdout, for subsequent use by mpv.
 *
 * The main challenge here is that the stream URLs contain parameters
 * that must be deobfuscated using JavaScript fragments supplied elsewhere
 * in the YouTube payload. This is why solving this puzzle requires the use
 * of an embedded JavaScript engine (in this case, Duktape).
 */

#include "coverage.h"
#include "sandbox.h"
#include "youtube.h"

#include <stdio.h>
#include <string.h>
#include <sysexits.h>

static const char ARG_HELP[] = "--help";
static const char ARG_SANDBOX[] = "--try-sandbox";

const char *__asan_default_options(void) __attribute__((used));

const char *
__asan_default_options(void)
{
	/*
	 * Disable LSan by default, as StopTheWorld() seems to misbehave when
	 * running under the seccomp sandbox. Even if syscalls like clone() and
	 * ptrace() are allowed, StopTheWorld() seems to hang at process exit,
	 * while repeatedly calling sched_yield().
	 */
	return "detect_leaks=0";
}

static int
usage(const char *cmd, int rc)
{
	fprintf(stderr, "Usage: %s [URL]\n", cmd);
	return rc;
}

static void
before_inet(youtube_handle_t h __attribute__((unused)))
{
	sandbox_only_io_inet_rpath();
}

static void
after_inet(youtube_handle_t h __attribute__((unused)))
{
	sandbox_only_io();
}

static void
print_url(const char *url)
{
	puts(url);
}

int
main(int argc, const char *argv[])
{
	int rc = EX_OK;
	int fd = coverage_open();

	if (argc < 2) {
		rc = usage(argv[0], EX_USAGE);
		goto done;
	}

	if (0 == strncmp(ARG_HELP, argv[1], strlen(ARG_HELP))) {
		rc = usage(argv[0], EX_OK);
		goto done;
	} else if (0 == strncmp(ARG_SANDBOX, argv[1], strlen(ARG_SANDBOX))) {
		sandbox_only_io_inet_tmpfile();
		sandbox_only_io_inet_rpath();
		sandbox_only_io();
		goto done;
	}

	youtube_global_init();
	sandbox_only_io_inet_tmpfile();

	youtube_handle_t stream = youtube_stream_init();

	struct youtube_setup_ops sops = {
		.before = NULL,
		.before_inet = before_inet,
		.after_inet = after_inet,
		.before_parse = NULL,
		.after_parse = NULL,
		.before_eval = NULL,
		.after_eval = NULL,
		.after = NULL,
	};

	if (youtube_stream_setup(stream, &sops, argv[1])) {
		youtube_stream_visitor(stream, print_url);
	} else {
		rc = EX_DATAERR;
	}

	youtube_stream_cleanup(stream);
	youtube_global_cleanup();

done:
	coverage_write_and_close(fd);
	return rc;
}
