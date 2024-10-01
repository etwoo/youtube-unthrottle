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
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sysexits.h>

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

static const char ARG_HELP[] = "--help";
static const char ARG_SANDBOX[] = "--try-sandbox";
static const char ARG_QUALITY[] = "--quality=";

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

static void
result_to_stderr(result_t r)
{
	to_stderr("%s", result_to_str(r));
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
		result_to_stderr(err);
		return EX_SOFTWARE;
	}
	return EX_OK;
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

static bool
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

#define check_stderr(expr, status)                                             \
	do {                                                                   \
		result_t x = expr;                                             \
		if (x.err) {                                                   \
			result_to_stderr(x);                                   \
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

	int idx = 1;
	const char *arg1 = argv[idx];
	struct quality q = {NULL, NULL};
	if (0 == strncmp(ARG_HELP, arg1, strlen(ARG_HELP))) {
		return usage(argv[0], EX_OK);
	} else if (0 == strncmp(ARG_SANDBOX, arg1, strlen(ARG_SANDBOX))) {
		return try_sandbox();
	} else if (0 == strncmp(ARG_QUALITY, arg1, strlen(ARG_QUALITY))) {
		if (!parse_quality_choices(arg1 + strlen(ARG_QUALITY), &q)) {
			return EX_DATAERR;
		}
		++idx;
	}

	int rc = EX_OK;
	youtube_handle_t stream = NULL;

	check_stderr(youtube_global_init(), EX_SOFTWARE);
	check_stderr(sandbox_only_io_inet_tmpfile(), EX_OSERR);

	stream = youtube_stream_init();
	if (stream == NULL) {
		fprintf(stderr, "ERROR: Cannot allocate stream object\n");
		rc = EX_OSERR;
		goto cleanup;
	}

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

	const char *url = argv[idx];
	check_stderr(youtube_stream_setup(stream, &sops, &q, url), EX_DATAERR);
	check_stderr(youtube_stream_visitor(stream, print_url), EX_DATAERR);

cleanup:
	youtube_stream_cleanup(stream);
	youtube_global_cleanup();
	pcre2_match_data_free(q.md); /* handles NULL gracefully */
	pcre2_code_free(q.re);       /* handles NULL gracefully */
	return rc;
}
