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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>    /* for strerror() */
#include <sys/param.h> /* for MAX() */
#include <sys/socket.h>
#include <sysexits.h>
#include <unistd.h> /* for close() */

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

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
	va_list ap; // NOLINT(cppcoreguidelines-init-variables)
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
	sandbox_handle_t sandbox = sandbox_init();
	check_if(sandbox == NULL, ERR_SANDBOX_ALLOC);
	check(sandbox_only_io_inet_tmpfile(sandbox));
	check(sandbox_only_io_inet_rpath(sandbox));
	check(sandbox_only_io(sandbox));
	return RESULT_OK;
}

struct quality {
	pcre2_code *re;
	pcre2_match_data *md;
};

static __attribute__((warn_unused_result)) bool
parse_quality_choices(const char *str, struct quality *q)
{
	assert(q->re == NULL && q->md == NULL);

	int rc = 0;
	PCRE2_SIZE loc = 0;
	PCRE2_SPTR pat = (PCRE2_SPTR)str;
	PCRE2_UCHAR err[256];

	const char *action = "compiling";
	q->re = pcre2_compile(pat, PCRE2_ZERO_TERMINATED, 0, &rc, &loc, NULL);
	if (q->re == NULL) {
		goto err;
	}

	action = "allocating match data block";
	q->md = pcre2_match_data_create_from_pattern(q->re, NULL);
	if (q->md == NULL) {
		goto err;
	}

	return true;

err:
	if (pcre2_get_error_message(rc, err, sizeof(err)) < 0) {
		to_stderr("(no details) %s regex \"%s\"", action, str);
		return false;
	}

	to_stderr("%s \"%s\" at offset %zu: %s", action, str, loc, err);
	return false;
}

static const result_t RESULT_QUALITY_BLOCK = {
	.err = ERR_JS_PARSE_JSON_CALLBACK_QUALITY,
};

static __attribute__((warn_unused_result)) result_t
choose_quality(const char *val, void *userdata)
{
	struct quality *q = (struct quality *)userdata;
	size_t sz = strlen(val);

	if (q->re == NULL || q->md == NULL) {
		return RESULT_OK;
	}

	PCRE2_SPTR subject = (PCRE2_SPTR)val;
	int rc = pcre2_match(q->re, subject, sz, 0, 0, q->md, NULL);
	if (rc > 0) {
		return RESULT_OK;
	} else if (rc == PCRE2_ERROR_NOMATCH) {
		return RESULT_QUALITY_BLOCK;
	}

	PCRE2_UCHAR err[256];
	if (pcre2_get_error_message(rc, err, sizeof(err)) < 0) {
		to_stderr("(no details) matching \"%.*s\"", (int)sz, val);
		return RESULT_QUALITY_BLOCK;
	}

	to_stderr("matching \"%.*s\": %s", (int)sz, val, err);
	return RESULT_QUALITY_BLOCK;
}

static void
close_output_fd(int fd)
{
	if (fd >= 0 && close(fd) < 0) {
		to_stderr("Error closing output: %s", strerror(errno));
	}
}

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
	const int maxbuf = 33554432; /* 32MB */

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

	rc = setsockopt(sfd, SOL_SOCKET, SO_SNDBUF, &maxbuf, sizeof(maxbuf));
	if (rc < 0) {
		to_stderr("Can't set SO_SNDBUF for %d: %s",
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

	rc = listen(sfd, /* backlog */ 10);
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

static __attribute__((warn_unused_result)) result_t
unthrottle(const char *target,
           const char *proof_of_origin,
           const char *visitor_data,
           struct quality *q,
           int output[2],
           youtube_handle_t *stream,
           sandbox_handle_t *sandbox)
{
	check(youtube_global_init());
	check_if(output[0] < 0 || output[1] < 0, OK);

	const struct youtube_stream_ops sops = {
		.io_simulator = NULL,
		.choose_quality = choose_quality,
		.choose_quality_userdata = q,
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
	const char *q_str = NULL;
	const char *proof_of_origin = NULL;
	const char *visitor_data = NULL;

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
			q_str = optarg;
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
	struct quality q = {NULL, NULL};

	switch (action) {
	case ACTION_YOUTUBE_UNTHROTTLE:
		if (optind >= argc) {
			to_stderr("Missing URL argument after options");
		} else if (!proof_of_origin || *proof_of_origin == '\0') {
			to_stderr("Missing --proof-of-origin value");
		} else if (!visitor_data || *visitor_data == '\0') {
			to_stderr("Missing --visitor-data value");
		} else if (q_str && !parse_quality_choices(q_str, &q)) {
			to_stderr("Invalid --quality value: %s", q_str);
		} else {
			int output[2] = {
				-1,
				-1,
			};
			get_output_fd(20000, output, 2);

			youtube_handle_t stream = NULL;
			sandbox_handle_t sandbox = NULL;
			rc = result_to_status(unthrottle(argv[optind],
			                                 proof_of_origin,
			                                 visitor_data,
			                                 &q,
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

			youtube_stream_cleanup(stream);
			youtube_global_cleanup();
			sandbox_cleanup(sandbox);
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

	pcre2_match_data_free(q.md); /* handles NULL gracefully */
	pcre2_code_free(q.re);       /* handles NULL gracefully */
	return rc;
}
