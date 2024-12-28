#include "re.h"

#include "debug.h"

#include <assert.h>

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

result_t
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
		return make_result_re(ERR_RE_COMPILE, rc, pattern_in, loc);
	}

	pcre2_match_data *md __attribute__((cleanup(re_match_cleanup))) =
		pcre2_match_data_create_from_pattern(re, NULL);
	check_if(md == NULL, ERR_RE_ALLOC_MATCH_DATA);

	PCRE2_SPTR sbj = (PCRE2_SPTR)subject_in->data;
	rc = pcre2_match(re, sbj, subject_in->sz, 0, 0, md, NULL);
	if (rc > 0) {
		if (rc != 2) { /* pattern must have exactly one capture group */
			return make_result(ERR_RE_CAPTURE_GROUP_COUNT,
			                   pattern_in);
		} /* else: continue to <ovector> processing */
	} else if (rc == PCRE2_ERROR_NOMATCH) {
		capture->data = NULL;
		capture->sz = 0;
		return RESULT_OK;
	} else {
		return make_result_re(ERR_RE_TRY_MATCH, rc, pattern_in, 0);
	}

	PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(md);
	assert(ovector != NULL); /* non-NULL <md> implies non-NULL <ovector> */

	debug("Regex \"%s\" matched at offset %zd within subject of size %zd",
	      pattern_in,
	      (size_t)ovector[0],
	      subject_in->sz);

	capture->data = subject_in->data + ovector[2];
	capture->sz = ovector[3] - ovector[2];
	return RESULT_OK;
}
