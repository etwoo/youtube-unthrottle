#include "re.h"

#include "greatest.h"
#include "test_macros.h"

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

TEST
capture_pattern_compile_fail(void)
{
	const char *pattern = "012345678[";
	const struct string_view hay = MAKE_TEST_STRING("");

	struct string_view needle = {0};
	result_t err = re_capture(pattern, &hay, &needle);

	ASSERT_EQ(ERR_RE_COMPILE, err.err);
	ASSERT_EQ(PCRE2_ERROR_MISSING_SQUARE_BRACKET, err.num);
	ASSERT_STR_EQ(pattern, err.re.pattern);
	ASSERT_EQ(10, err.re.offset);
	ASSERT_NEQ(NULL,
	           strstr(result_to_str(err),
	                  "missing terminating ] for character class"));
	ASSERT_EQ(NULL, needle.data);
	ASSERT_EQ(0, needle.sz);
	PASS();
}

TEST
capture_pattern_match_one(void)
{
	const struct string_view hay = MAKE_TEST_STRING("bbbaaabbb");

	struct string_view needle = {0};
	result_t err = re_capture("b+(a+)b+", &hay, &needle);

	static const char expected[] = "aaa";
	ASSERT_EQ(OK, err.err);
	ASSERT_EQ(strlen(expected), needle.sz);
	ASSERT_STRN_EQ(expected, needle.data, needle.sz);
	PASS();
}

TEST
capture_pattern_mismatch(void)
{
	const struct string_view hay = MAKE_TEST_STRING("bbbAAAbbb");

	struct string_view needle = {0};
	result_t err = re_capture("b+(a+)b+", &hay, &needle);

	ASSERT_EQ(OK, err.err);
	ASSERT_EQ(NULL, needle.data);
	ASSERT_EQ(0, needle.sz);
	PASS();
}

TEST
capture_pattern_wrong_num_of_capture_groups(const char *pattern)
{
	const struct string_view hay = MAKE_TEST_STRING("bbbaaabbb");

	struct string_view needle = {0};
	result_t err = re_capture(pattern, &hay, &needle);

	ASSERT_EQ(ERR_RE_CAPTURE_GROUP_COUNT, err.err);
	ASSERT_EQ(NULL, needle.data);
	ASSERT_EQ(0, needle.sz);
	PASS();
}

TEST
capture_pattern_match_fail_on_null_haystack(void)
{
	const char *pattern = ".";
	const struct string_view hay = {.data = NULL, .sz = 8};

	struct string_view needle = {0};
	result_t err = re_capture(pattern, &hay, &needle);

	ASSERT_EQ(ERR_RE_TRY_MATCH, err.err);
	ASSERT_EQ(PCRE2_ERROR_NULL, err.num);
	ASSERT_STR_EQ(pattern, err.re.pattern);
	ASSERT_EQ(0, err.re.offset);
	ASSERT_NEQ(NULL,
	           strstr(result_to_str(err),
	                  "NULL argument passed with non-zero length"));
	ASSERT_EQ(NULL, needle.data);
	ASSERT_EQ(0, needle.sz);
	PASS();
}

SUITE(capture)
{
	RUN_TEST(capture_pattern_compile_fail);
	RUN_TEST(capture_pattern_match_one);
	RUN_TEST(capture_pattern_mismatch);
	RUN_TESTp(capture_pattern_wrong_num_of_capture_groups, "b+a+b+");
	RUN_TESTp(capture_pattern_wrong_num_of_capture_groups, "(b+)(a+)(b+)");
	RUN_TEST(capture_pattern_match_fail_on_null_haystack);
}
