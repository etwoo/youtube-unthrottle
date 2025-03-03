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
#include <getopt.h> /* for getopt_long() */
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>    /* for strlen() */
#include <sys/param.h> /* for MAX() */
#include <sysexits.h>

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
before_inet(void *userdata __attribute__((unused)))
{
#if defined(__APPLE__)
	/* macOS sandbox can drop filesystem access entirely at this point */
	return sandbox_only_io();
#else
	return sandbox_only_io_inet_rpath();
#endif
}

static __attribute__((warn_unused_result)) result_t
after_inet(void *userdata __attribute__((unused)))
{
#if defined(__APPLE__)
	return RESULT_OK;
#else
	return sandbox_only_io();
#endif
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
during_parse_choose_quality(const char *val, void *userdata)
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
print_url(const char *url, size_t sz, void *userdata __attribute((unused)))
{
	printf("%.*s\n", (int)sz, url);
}

static __attribute__((warn_unused_result)) result_t
unthrottle(const char *target,
           const char *proof_of_origin,
           const char *visitor_data,
           struct quality *q,
           youtube_handle_t *stream)
{
	check(youtube_global_init());

	*stream = youtube_stream_init(proof_of_origin, visitor_data, NULL);
	check_if(*stream == NULL, OK);

	check(sandbox_only_io_inet_tmpfile());

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
	check(youtube_stream_visitor(*stream, print_url, NULL));
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
			youtube_handle_t stream = NULL;
			rc = result_to_status(unthrottle(argv[optind],
			                                 proof_of_origin,
			                                 visitor_data,
			                                 &q,
			                                 &stream));
			if (stream == NULL) {
				to_stderr("Can't alloc stream");
				rc = EX_OSERR;
			}
			youtube_stream_cleanup(stream);
			youtube_global_cleanup();
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
