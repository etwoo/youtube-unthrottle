#include "re.h"

#include "debug.h"

#include <assert.h>
#include <stdarg.h> /* for va_list(), va_start(), va_end() */
#include <stdio.h>
#include <string.h>

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

bool
re_capture(const char *pattern_in,
           const char *subject_in,
           size_t sz,
           const char **capture_p,
           size_t *capture_sz)
{
	bool matched = false;
	const char *action_that_caused_error = "";
	pcre2_code *re = NULL;
	pcre2_match_data *md = NULL;
	PCRE2_SPTR pattern = (PCRE2_SPTR)pattern_in;
	PCRE2_SPTR subject = (PCRE2_SPTR)subject_in;
	int rc = 0;
	PCRE2_SIZE loc = 0;

	re = pcre2_compile(pattern, PCRE2_ZERO_TERMINATED, 0, &rc, &loc, NULL);
	if (re == NULL) {
		action_that_caused_error = "compiling";
		goto cleanup;
	}

	md = pcre2_match_data_create_from_pattern(re, NULL);
	if (md == NULL) {
		action_that_caused_error = "creating match structure for";
		goto cleanup;
	}

	rc = pcre2_match(re, subject, sz, 0, 0, md, NULL);
	if (rc > 0) {
		matched = true;
		assert(rc == 2); /* pattern_in must contain one capture group */
	} else {
		if (rc != PCRE2_ERROR_NOMATCH) {
			action_that_caused_error = "matching";
		} /* else: *_NOMATCH is a non-error for our purposes */
		goto cleanup;
	}

	PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(md);
	assert(ovector != NULL); /* md!=NULL should guarantee ovector!=NULL */

	debug("Regex \"%s\" matched at offset %zd within subject of size %zd",
	      pattern_in,
	      (size_t)ovector[0],
	      sz);

	*capture_p = subject_in + ovector[2];
	*capture_sz = ovector[3] - ovector[2];

cleanup:
	pcre2_match_data_free(md); /* handles NULL gracefully */
	pcre2_code_free(re);       /* handles NULL gracefully */

	if (0 == strlen(action_that_caused_error)) {
		return matched;
	} /* else: fallthrough to error handler */

	PCRE2_UCHAR err[256];
	if (pcre2_get_error_message(rc, err, sizeof(err)) < 0) {
		warn("Error (no details) while %s regex \"%s\"",
		     action_that_caused_error,
		     pattern_in);
	} else {
		warn("Error %s regex \"%s\" at offset %zd: %s",
		     action_that_caused_error,
		     pattern_in,
		     (size_t)loc,
		     err);
	}
	return false;
}

bool
re_capturef(const char *subject_in,
            size_t sz,
            const char **capture_p,
            size_t *capture_sz,
            const char *my_format,
            ...)
{
	char pattern[4096];
	const int capacity = sizeof(pattern);

	va_list ap;
	va_start(ap, my_format);

	const int printed = vsnprintf(pattern, capacity, my_format, ap);
	if (printed >= capacity || pattern[printed] != '\0') {
		warn("%d bytes is too small for vsnprintf()", capacity);
		return false;
	}

	va_end(ap);

	return re_capture(pattern, subject_in, sz, capture_p, capture_sz);
}

bool
re_pattern_escape(const char *in, size_t in_sz, char *out, size_t out_capacity)
{
	size_t in_pos = 0;
	size_t out_pos = 0;
	while (in_pos < in_sz && out_pos < out_capacity) {
		char c = in[in_pos++];
		switch (c) {
		case '\\':
		case '^':
		case '$':
		case '.':
		case '[':
		case '|':
		case '(':
		case ')':
		case '*':
		case '+':
		case '?':
		case '{':
			if (out_pos + 1 >= out_capacity) {
				out_pos = out_capacity;
				break;
			}
			out[out_pos++] = '\\';
			out[out_pos++] = c;
			break;
		default:
			out[out_pos++] = c;
			break;
		}
	}

	if (out_pos >= out_capacity) {
		warn("Escaped function name exceeds %zd bytes", out_capacity);
		return false;
	}

	out[out_pos] = '\0';
	return true;
}
