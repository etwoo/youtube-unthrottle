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
#include <getopt.h> /* for getopt_long() */
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sysexits.h>

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

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

static void __attribute__((format(printf, 1, 2)))
to_stderr(const char *pattern, ...)
{
	va_list ap;
	va_start(ap, pattern);
	fprintf(stderr, "ERROR: ");
	vfprintf(stderr, pattern, ap);
	fputc('\n', stderr);
	va_end(ap);
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
before_inet(void *userdata __attribute__((unused)))
{
	return sandbox_only_io_inet_rpath();
}

static WARN_UNUSED result_t
after_inet(void *userdata __attribute__((unused)))
{
	return sandbox_only_io();
}

struct quality {
	pcre2_code *re;
	pcre2_match_data *md;
};

static WARN_UNUSED bool
parse_quality_choices(const char *str, struct quality *q)
{
	assert(q->re == NULL && q->md == NULL);

	const char *action = "preparing";
	int rc = 0;
	PCRE2_SIZE loc = 0;
	PCRE2_SPTR pat = (PCRE2_SPTR)str;
	PCRE2_UCHAR err[256];

	action = "compiling";
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

	to_stderr("%s \"%s\" at offset %zd: %s", action, str, (size_t)loc, err);
	return false;
}

static const result_t RESULT_QUALITY_BLOCK = {
	.err = ERR_JS_PARSE_JSON_CALLBACK_QUALITY,
};

static WARN_UNUSED result_t
during_parse_choose_quality(const char *val, size_t sz, void *userdata)
{
	struct quality *q = (struct quality *)userdata;

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
print_url(const char *url)
{
	puts(url);
}

static WARN_UNUSED result_t
unthrottle(const char *target,
           const char *proof_of_origin,
           const char *visitor_data,
           struct quality *q,
           youtube_handle_t *stream)
{
	check(youtube_global_init());
	check(sandbox_only_io_inet_tmpfile());

	*stream = youtube_stream_init(proof_of_origin, visitor_data);
	check_if(*stream == NULL, OK);

	struct youtube_setup_ops sops = {
		.before = NULL,
		.before_inet = before_inet,
		.after_inet = after_inet,
		.before_parse = NULL,
		.during_parse_choose_quality = during_parse_choose_quality,
		.after_parse = NULL,
		.before_eval = NULL,
		.after_eval = NULL,
		.after = NULL,
	};
	check(youtube_stream_setup(*stream, &sops, q, target));

	check(youtube_stream_visitor(*stream, print_url));
	return RESULT_OK;
}

int
main(int argc, char *argv[])
{
	int fd __attribute__((cleanup(coverage_cleanup))) = coverage_open();
	int rc = EX_USAGE; /* assume invalid arguments by default */
	result_t err = RESULT_OK;
	youtube_handle_t yt = NULL;
	struct quality q = {NULL, NULL};
	const char *proof_of_origin = NULL;
	const char *visitor_data = NULL;
	const char *quality_str = NULL;

	int synonym = 0;
	struct option lo[] = {
		{"help", no_argument, &synonym, 'h'},
		{"try-sandbox", no_argument, &synonym, 't'},
		{"quality", required_argument, &synonym, 'q'},
		{"proof-of-origin", required_argument, &synonym, 'p'},
		{"visitor-data", required_argument, &synonym, 'v'},
	};

	int opt = 0;
	while ((opt = getopt_long(argc, argv, "htq:p:v:", lo, NULL)) != -1) {
		switch (opt == 0 ? synonym : opt) {
		case 'h':
			fprintf(stdout, "Usage: %s [URL]\n", argv[0]);
			rc = EX_OK;
			goto check_result;
		case 't':
			err = try_sandbox();
			rc = err.err ? EX_SOFTWARE : EX_OK;
			goto check_result;
		case 'q':
			quality_str = optarg;
			break;
		case 'p':
			proof_of_origin = optarg;
			break;
		case 'v':
			visitor_data = optarg;
			break;
		default:
			goto check_result;
		}
	}

	assert(rc == EX_USAGE); /* still assuming invalid arguments */
	if (optind >= argc) {
		fprintf(stderr, "Missing URL argument after options\n");
	} else if (proof_of_origin == NULL || *proof_of_origin == '\0') {
		fprintf(stderr, "Missing --proof-of-origin value\n");
	} else if (visitor_data == NULL || *visitor_data == '\0') {
		fprintf(stderr, "Missing --visitor-data value\n");
	} else if (quality_str && !parse_quality_choices(quality_str, &q)) {
		fprintf(stderr, "Invalid --quality value: %s\n", quality_str);
	} else {
		const char *url = argv[optind];
		err = unthrottle(url, proof_of_origin, visitor_data, &q, &yt);
		if (yt == NULL) {
			fprintf(stderr, "ERROR: Could not allocate stream\n");
			rc = EX_OSERR;
			goto cleanup;
		}
check_result:
		if (rc == EX_OK) {
			/* already succeeded at some earlier stage */
		} else if (err.err) {
			to_stderr("%s", result_to_str(err));
			rc = EX_SOFTWARE;
		}
	}
cleanup:
	pcre2_match_data_free(q.md); /* handles NULL gracefully */
	pcre2_code_free(q.re);       /* handles NULL gracefully */
	youtube_stream_cleanup(yt);  /* handles NULL gracefully */
	youtube_global_cleanup();
	return rc;
}
