/*
 * Extract video and audio stream URLs from a YouTube link passed via argv[1],
 * and offer the resulting stream data for download on localhost:20000.
 *
 * Our main challenge: YouTube stream URLs contain obfuscated parameters, and
 * YouTube web payloads contain JavaScript fragments that deobfuscate these
 * parameters. To solve this puzzle then requires applying the latter to the
 * former with a JavaScript engine (in this case, Duktape).
 *
 * A secondary challenge: media players like mpv do not (currently) support
 * YouTube's streaming SABR/UMP format. This program bridges the gap by acting
 * as a proxy, translating SABR/UMP traffic into plain video/audio data.
 */

#include "result.h"
#include "sandbox.h"
#include "youtube.h"

#include <assert.h>
#include <errno.h>
#include <getopt.h> /* for getopt_long() */
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h> /* for MAX() */
#include <sys/socket.h>
#include <sysexits.h>
#include <unistd.h> /* for close() */

const char *__asan_default_options(void) __attribute__((used));
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
	va_list ap = {0};
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
	sandbox_handle_t sandbox __attribute__((cleanup(sandbox_cleanup))) =
		sandbox_init();
	check_if(sandbox == NULL, ERR_SANDBOX_ALLOC);
	check(sandbox_only_io_inet_tmpfile(sandbox));
	check(sandbox_only_io_inet_rpath(sandbox));
	check(sandbox_only_io(sandbox));
	return RESULT_OK;
}

static void
str_free(char **strp)
{
	free(*strp);
}

static const result_t RESULT_QUALITY_BLOCK = {
	.err = ERR_JS_PARSE_JSON_CALLBACK_QUALITY,
};

static __attribute__((warn_unused_result)) result_t
choose_quality(const char *val, void *userdata)
{
	assert(userdata != NULL);

	char *deepcopy __attribute__((cleanup(str_free))) = strdup(userdata);
	if (deepcopy == NULL) {
		to_stderr("Cannot create working copy of quality string");
		return RESULT_QUALITY_BLOCK;
	}

	char *token = NULL;
	char *cursor = deepcopy;
	while ((token = strsep(&cursor, "|")) != NULL) {
		if (strstr(val, token) != NULL) {
			/*
			 * clang-tidy seems to misinterpret strsep() as
			 * allocating memory for <token>, rather than returning
			 * a pointer into <deepcopy>. As a workaround, suppress
			 * false positives of clang-analyzer-unix.Malloc.
			 */
			return RESULT_OK; // NOLINT(clang-analyzer-unix.Malloc)
		}
	}

	return RESULT_QUALITY_BLOCK;
}

static void
close_output_fd(int fd)
{
	if (fd >= 0 && close(fd) < 0) {
		to_stderr("Error closing output: %s", strerror(errno));
	}
}

static const in_port_t DEFAULT_PORT_LISTEN = 20000;

#pragma GCC diagnostic push
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wanalyzer-fd-leak"
#endif

static void
get_output_fd(in_port_t port, int *out, size_t out_sz)
{
	int sfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sfd < 0) {
		to_stderr("Can't create socket %d: %s", port, strerror(errno));
		goto cleanup;
	}

	int rc = -1;
	const int on = 1;

	rc = setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	if (rc < 0) {
		to_stderr("Can't set SO_REUSEADDR for %d: %s",
		          port,
		          strerror(errno));
		goto cleanup;
	}

	rc = setsockopt(sfd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
	if (rc < 0) {
		to_stderr("Can't set SO_REUSEPORT for %d: %s",
		          port,
		          strerror(errno));
		goto cleanup;
	}

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = htonl(INADDR_ANY);

	rc = bind(sfd, (struct sockaddr *)&sa, sizeof(sa));
	if (rc < 0) {
		to_stderr("Can't bind to port %d: %s", port, strerror(errno));
		goto cleanup;
	}

	rc = listen(sfd, /* backlog */ 2);
	if (rc < 0) {
		to_stderr("Can't listen on port %d: %s", port, strerror(errno));
		goto cleanup;
	}

	struct sockaddr_storage their_addr;

	for (size_t i = 0; i < out_sz; ++i) {
		socklen_t their_sz = sizeof(their_addr);
		int fd = accept(sfd, (struct sockaddr *)&their_addr, &their_sz);
		if (fd < 0) {
			to_stderr("Can't accept %d: %s", port, strerror(errno));
			goto cleanup;
		}
		out[i] = fd;
	}

cleanup:
	if (sfd >= 0) {
		close_output_fd(sfd); /* done accepting connections */
	}
}

#pragma GCC diagnostic pop /* restore -Wanalyzer-fd-leak */

static __attribute__((warn_unused_result)) result_t
unthrottle(const char *target,
           const char *proof_of_origin,
           const char *visitor_data,
           char *quality,
           int output[2],
           youtube_handle_t *stream,
           sandbox_handle_t *sandbox)
{
	check(youtube_global_init());
	check_if(output[0] < 0 || output[1] < 0, OK);

	const struct youtube_stream_ops sops = {
		.io_simulator = NULL,
		.choose_quality = choose_quality,
		.choose_quality_userdata = quality,
	};
	*stream = youtube_stream_init(proof_of_origin, visitor_data, &sops);
	check_if(*stream == NULL, OK);

	*sandbox = sandbox_init();
	check_if(*sandbox == NULL, OK);

	check(sandbox_only_io_inet_tmpfile(*sandbox));
	check(youtube_stream_prepare_tmpfiles(*stream));

	check(sandbox_only_io_inet_rpath(*sandbox));
	check(youtube_stream_open(*stream, target, output));

	int retry_after = -1;
	do {
		check(youtube_stream_next(*stream, &retry_after));
		if (retry_after > 0) {
			to_stderr("Retrying after %d second(s)", retry_after);
			sleep(retry_after);
		}
	} while (retry_after > 0 || !youtube_stream_done(*stream));

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
	const char *visitor_data = NULL;
	char *quality = NULL;

	int synonym = 0;
	struct option lo[] = {
		{"help", no_argument, &synonym, 'h'},
		{"try-sandbox", no_argument, &synonym, 't'},
		{"quality", required_argument, &synonym, 'q'},
		{"proof-of-origin", required_argument, &synonym, 'p'},
		{"visitor-data", required_argument, &synonym, 'v'},
		{NULL, 0, NULL, 0},
	};

	int opt = 0;
	while ((opt = getopt_long(argc, argv, "htq:p:v:", lo, NULL)) != -1) {
		switch (opt == 0 ? synonym : opt) {
		case 'h':
			action = MAX(action, ACTION_USAGE_HELP);
			break;
		case 't':
			action = MAX(action, ACTION_TRY_SANDBOX);
			break;
		case 'q':
			quality = optarg;
			break;
		case 'p':
			proof_of_origin = optarg;
			break;
		case 'v':
			visitor_data = optarg;
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
		} else if (!visitor_data || *visitor_data == '\0') {
			to_stderr("Missing --visitor-data value");
		} else if (!quality || *quality == '\0') {
			to_stderr("Missing --quality value");
		} else {
			int output[2] = {
				-1,
				-1,
			};
			get_output_fd(DEFAULT_PORT_LISTEN, output, 2);

			youtube_handle_t stream = NULL;
			sandbox_handle_t sandbox
				__attribute__((cleanup(sandbox_cleanup))) =
					NULL;
			rc = result_to_status(unthrottle(argv[optind],
			                                 proof_of_origin,
			                                 visitor_data,
			                                 quality,
			                                 output,
			                                 &stream,
			                                 &sandbox));

			if (output[0] < 0 || output[1] < 0) {
				/* get_output_fd() already logs to stderr */
				rc = EX_CANTCREAT;
			} else if (stream == NULL || sandbox == NULL) {
				to_stderr("Can't alloc stream");
				rc = EX_OSERR;
			}

			youtube_stream_free(stream);
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
