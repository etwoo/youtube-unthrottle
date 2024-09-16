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
	fprintf(stderr, "ERROR: %s\n", result_to_str(r));
}

static WARN_UNUSED int
try_sandbox(void)
{
	result_t err = RESULT_OK;

	err = sandbox_only_io_inet_tmpfile();
	if (err.err) {
		goto cleanup;
	}

	err = sandbox_only_io_inet_rpath();
	if (err.err) {
		goto cleanup;
	}

	err = sandbox_only_io();
	if (err.err) {
		goto cleanup;
	}

cleanup:
	if (err.err) {
		to_stderr(err);
		return EX_SOFTWARE;
	}
	return EX_OK;
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

#define check_stderr(expr, status)                                             \
	do {                                                                   \
		result_t x = expr;                                             \
		if (x.err) {                                                   \
			to_stderr(x);                                          \
			rc = status;                                           \
			goto cleanup;                                          \
		}                                                              \
	} while (0)

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
		return try_sandbox();
	}

	int rc = EX_OK;
	youtube_handle_t stream = NULL;

	check_stderr(youtube_global_init(), EX_SOFTWARE);
	check_stderr(sandbox_only_io_inet_tmpfile(), EX_OSERR);

	stream = youtube_stream_init();
	if (stream == NULL) {
		fprintf(stderr, "Cannot allocate stream object\n");
		rc = EX_OSERR;
		goto cleanup;
	}

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

	check_stderr(youtube_stream_setup(stream, &sops, argv[1]), EX_DATAERR);
	check_stderr(youtube_stream_visitor(stream, print_url), EX_DATAERR);

cleanup:
	youtube_stream_cleanup(stream);
	youtube_global_cleanup();
	return rc;
}
