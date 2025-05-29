/*
 * Extract video and audio stream URLs from a YouTube link passed via argv[1],
 * and then print the results to stdout, for use by mpv.
 *
 * Our main challenge: YouTube stream URLs contain obfuscated parameters, and
 * YouTube web payloads contain JavaScript fragments that deobfuscate these
 * parameters. To solve this puzzle then requires applying the latter to the
 * former with a JavaScript engine (in this case, Duktape).
 */

#include "result.h"
#include "sandbox.h"
#include "youtube.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>  /* for open() */
#include <getopt.h> /* for getopt_long() */
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>    /* for strerror(), strlen() */
#include <sys/param.h> /* for MAX() */
#include <sysexits.h>
#include <unistd.h> /* for close() */

const char *__asan_default_options(void) // NOLINT(bugprone-reserved-identifier)
	__attribute__((used));
const char *
__asan_default_options(void)
{
	/*
	 * Disable LSan by default, as StopTheWorld() seems to misbehave when
	 * running under the seccomp sandbox. Even if we allow syscalls like
	 * clone() and ptrace(), StopTheWorld() seems to hang at process exit,
	 * while repeatedly calling sched_yield().
	 */
	return "detect_leaks=0";
}

static __attribute__((format(printf, 1, 2))) void
to_stderr(const char *pattern, ...)
{
	va_list ap;
	va_start(ap, pattern);
	fprintf(stderr, "ERROR: ");
	vfprintf(stderr, pattern, ap);
	fputc('\n', stderr);
	va_end(ap);
}

static __attribute__((warn_unused_result)) int
result_to_status(result_t r)
{
	auto_result owner = r;
	if (owner.err) {
		auto_result_str str = result_to_str(owner);
		to_stderr("%s", str ? str : "[result_to_str() -> NULL]");
		return EX_SOFTWARE;
	}
	return EX_OK;
}

static __attribute__((warn_unused_result)) result_t
try_sandbox(void)
{
	check(sandbox_only_io_inet_tmpfile());
	check(sandbox_only_io_inet_rpath());
	check(sandbox_only_io());
	return RESULT_OK;
}

static __attribute__((warn_unused_result)) result_t
after_tmpfile(void)
{
	return sandbox_only_io_inet_rpath();
}

static __attribute__((warn_unused_result)) result_t
after_inet(void)
{
	return sandbox_only_io();
}

static __attribute__((warn_unused_result)) int
get_output_fd(const char *path)
{
	int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
	if (fd < 0) {
		to_stderr("Can't open %s: %s", path, strerror(errno));
	}
	return fd;
}

static void
close_output_fd(int fd)
{
	if (close(fd) < 0) {
		to_stderr("Error closing output: %s", strerror(errno));
	}
}

static __attribute__((warn_unused_result)) result_t
unthrottle(const char *target,
           const char *proof_of_origin,
           int output[2],
           youtube_handle_t *stream)
{
	check(youtube_global_init());
	check_if(output[0] < 0 || output[1] < 0, OK);

	*stream = youtube_stream_init(proof_of_origin, NULL);
	check_if(*stream == NULL, OK);

	check(sandbox_only_io_inet_tmpfile());

	struct youtube_setup_ops sops = {
		.before_tmpfile = NULL,
		.after_tmpfile = after_tmpfile,
		.before_inet = NULL,
		.after_inet = after_inet,
	};
	check(youtube_stream_setup(*stream, &sops, target, output));
	return RESULT_OK;
}

int
main(int argc, char *argv[])
{
	enum {
		ACTION_YOUTUBE_UNTHROTTLE,
		ACTION_TRY_SANDBOX,
		ACTION_USAGE_HELP,
		ACTION_USAGE_ERROR,
	} action = 0;
	const char *proof_of_origin = NULL;

	int synonym = 0;
	struct option lo[] = {
		{"help", no_argument, &synonym, 'h'},
		{"try-sandbox", no_argument, &synonym, 't'},
		{"proof-of-origin", required_argument, &synonym, 'p'},
		{NULL, 0, NULL, 0},
	};

	int opt = 0;
	while ((opt = getopt_long(argc, argv, "htp:", lo, NULL)) != -1) {
		switch (opt == 0 ? synonym : opt) {
		case 'h':
			action = MAX(action, ACTION_USAGE_HELP);
			break;
		case 't':
			action = MAX(action, ACTION_TRY_SANDBOX);
			break;
		case 'p':
			proof_of_origin = optarg;
			break;
		default:
			action = MAX(action, ACTION_USAGE_ERROR);
			break;
		}
	}

	int rc = EX_USAGE;  /* assume invalid arguments by default */
	FILE *out = stderr; /* assume output to stderr by default */

	switch (action) {
	case ACTION_YOUTUBE_UNTHROTTLE:
		if (optind >= argc) {
			to_stderr("Missing URL argument after options");
		} else if (!proof_of_origin || *proof_of_origin == '\0') {
			to_stderr("Missing --proof-of-origin value");
		} else {
			int output[2] = {
				get_output_fd("audio.out"),
				get_output_fd("video.out"),
			};
			youtube_handle_t stream = NULL;
			rc = result_to_status(unthrottle(argv[optind],
			                                 proof_of_origin,
			                                 output,
			                                 &stream));

			if (output[0] < 0 || output[1] < 0) {
				/* get_output_fd() already logs to stderr */
				rc = EX_CANTCREAT;
			} else if (stream == NULL) {
				to_stderr("Can't alloc stream");
				rc = EX_OSERR;
			}
			youtube_stream_cleanup(stream);
			youtube_global_cleanup();
			close_output_fd(output[0]);
			close_output_fd(output[1]);
		}
		break;
	case ACTION_TRY_SANDBOX:
		rc = result_to_status(try_sandbox());
		break;
	case ACTION_USAGE_HELP:
		rc = EX_OK;
		out = stdout;
		__attribute__((fallthrough));
	case ACTION_USAGE_ERROR:
		fprintf(out, "Usage: %s [options] <url>\nOptions:\n", argv[0]);
		for (struct option *o = lo; o->name; ++o) {
			fprintf(out, "  -%c, --%s\n", o->val, o->name);
		}
		break;
	}

	return rc;
}
