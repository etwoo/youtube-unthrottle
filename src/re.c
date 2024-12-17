#include "re.h"

#include "debug.h"

#include <assert.h>
#include <stdarg.h> /* for va_list(), va_start(), va_end() */
#include <stdio.h>
#include <string.h>

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

static void
re_cleanup(pcre2_code **re)
{
	pcre2_code_free(*re); /* handles NULL gracefully */
}

static void
re_match_cleanup(pcre2_match_data **md)
{
	pcre2_match_data_free(*md); /* handles NULL gracefully */
}

static void
re_info_message(const char *action_that_caused_error,
                int rc,
                const char *pattern_in,
                PCRE2_SIZE loc)
{
	PCRE2_UCHAR err[256];
	if (pcre2_get_error_message(rc, err, sizeof(err)) < 0) {
		info("Error (no details) while %s regex \"%s\"",
		     action_that_caused_error,
		     pattern_in);
	} else {
		info("Error %s regex \"%s\" at offset %zd: %s",
		     action_that_caused_error,
		     pattern_in,
		     (size_t)loc,
		     err);
	}
}

bool
re_capture(const char *pattern_in,
           const struct string_view *subject_in,
           struct string_view *capture)
{
	int rc = 0;
	PCRE2_SIZE loc = 0;

	PCRE2_SPTR pat = (PCRE2_SPTR)pattern_in;
	pcre2_code *re __attribute__((cleanup(re_cleanup))) =
		pcre2_compile(pat, PCRE2_ZERO_TERMINATED, 0, &rc, &loc, NULL);
	if (re == NULL) {
		re_info_message("compiling", rc, pattern_in, loc);
		return false;
	}

	pcre2_match_data *md __attribute__((cleanup(re_match_cleanup))) =
		pcre2_match_data_create_from_pattern(re, NULL);
	if (md == NULL) {
		re_info_message("allocating match for", rc, pattern_in, loc);
		return false;
	}

	PCRE2_SPTR sbj = (PCRE2_SPTR)subject_in->data;
	rc = pcre2_match(re, sbj, subject_in->sz, 0, 0, md, NULL);
	if (rc > 0) {
		assert(rc == 2); /* pattern must contain one capture group */
	} else {
		if (rc != PCRE2_ERROR_NOMATCH) {
			re_info_message("matching", rc, pattern_in, loc);
		} /* else: *_NOMATCH, not an error for our purposes */
		return false;
	}

	PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(md);
	assert(ovector != NULL); /* md!=NULL should guarantee ovector!=NULL */

	debug("Regex \"%s\" matched at offset %zd within subject of size %zd",
	      pattern_in,
	      (size_t)ovector[0],
	      subject_in->sz);

	capture->data = subject_in->data + ovector[2];
	capture->sz = ovector[3] - ovector[2];
	return true;
}
