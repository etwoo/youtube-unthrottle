/*
 * Extract video and audio stream URLs from a YouTube link passed via argv[1],
 * and then print the results to stdout, for subsequent use by mpv.
 *
 * The main challenge here is that the stream URLs contain parameters
 * that must be deobfuscated using JavaScript fragments supplied elsewhere
 * in the YouTube payload. This is why solving this puzzle requires the use
 * of an embedded JavaScript engine (in this case, Duktape).
 */

#include "compiler_features.h"
#include "coverage.h"
#include "result.h"
#include "sandbox.h"
#include "youtube.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h> /* for free() */
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

static WARN_UNUSED int
usage(const char *cmd, int rc)
{
	fprintf(stderr, "Usage: %s [URL]\n", cmd);
	return rc;
}

static void
to_stderr(result_t r)
{
	char *msg = result_to_str(r);
	fprintf(stderr, "ERROR %s\n", msg ? msg : "[cannot print result]");
	free(msg);
}

static WARN_UNUSED result_t
try_sandbox(void)
{
	check(sandbox_only_io_inet_tmpfile());
	check(sandbox_only_io_inet_rpath());
	check(sandbox_only_io());
	return RESULT_OK;
}

static WARN_UNUSED result_t
before_inet(youtube_handle_t h __attribute__((unused)))
{
	return sandbox_only_io_inet_rpath();
}

static WARN_UNUSED result_t
after_inet(youtube_handle_t h __attribute__((unused)))
{
	return sandbox_only_io();
}

static void
print_url(const char *url)
{
	puts(url);
}

static WARN_UNUSED result_t
do_unthrottle(const char *target, youtube_handle_t stream)
{
	check(youtube_global_init());
	check(sandbox_only_io_inet_tmpfile());

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

	check(youtube_stream_setup(stream, &sops, target));
	check(youtube_stream_visitor(stream, print_url));

	youtube_stream_cleanup(stream);
	youtube_global_cleanup();
	return RESULT_OK;
}

int
main(int argc, const char *argv[])
{
	int fd __attribute__((cleanup(coverage_cleanup))) = coverage_open();

	if (argc < 2) {
		return usage(argv[0], EX_USAGE);
	}

	if (0 == strncmp(ARG_HELP, argv[1], strlen(ARG_HELP))) {
		return usage(argv[0], EX_OK);
	} else if (0 == strncmp(ARG_SANDBOX, argv[1], strlen(ARG_SANDBOX))) {
		result_t err __attribute__((cleanup(result_cleanup))) =
			try_sandbox();
		return is_ok(err) ? EX_OK : EX_SOFTWARE;
	}

	youtube_handle_t stream = youtube_stream_init();
	if (stream == NULL) {
		fprintf(stderr, "Cannot allocate stream object\n");
		return EX_OSERR;
	}

	result_t err __attribute__((cleanup(result_cleanup))) =
		do_unthrottle(argv[1], stream);
	if (!is_ok(err)) {
		to_stderr(err);
		return EX_SOFTWARE;
	}
	return EX_OK;
}
