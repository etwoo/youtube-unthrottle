#include "re.h"

#include "greatest.h"
#include "test_macros.h"

TEST
capture_pattern_compile_fail(void)
{
	const struct string_view hay = MAKE_TEST_STRING("");

	struct string_view needle = {0};
	bool rc = re_capture("+", &hay, &needle);

	ASSERT_FALSE(rc);
	ASSERT_EQ(NULL, needle.data);
	ASSERT_EQ(0, needle.sz);
	PASS();
}

TEST
capture_pattern_match_one(void)
{
	const struct string_view hay = MAKE_TEST_STRING("bbbaaabbb");

	struct string_view needle = {0};
	bool rc = re_capture("b+(a+)b+", &hay, &needle);

	static const char expected[] = "aaa";
	ASSERT(rc);
	ASSERT_EQ(strlen(expected), needle.sz);
	ASSERT_STRN_EQ(expected, needle.data, needle.sz);
	PASS();
}

TEST
capture_pattern_match_none(void)
{
	const struct string_view hay = MAKE_TEST_STRING("bbbAAAbbb");

	struct string_view needle = {0};
	bool rc = re_capture("b+(a+)b+", &hay, &needle);

	ASSERT_FALSE(rc);
	ASSERT_EQ(NULL, needle.data);
	ASSERT_EQ(0, needle.sz);
	PASS();
}

TEST
capture_pattern_match_fail_on_null_haystack(void)
{
	const struct string_view hay = {.data = NULL, .sz = 8};

	struct string_view needle = {0};
	bool rc = re_capture("b+(a+)b+", &hay, &needle);

	ASSERT_FALSE(rc);
	ASSERT_EQ(NULL, needle.data);
	ASSERT_EQ(0, needle.sz);
	PASS();
}

SUITE(capture)
{
	RUN_TEST(capture_pattern_compile_fail);
	RUN_TEST(capture_pattern_match_one);
	RUN_TEST(capture_pattern_match_none);
	RUN_TEST(capture_pattern_match_fail_on_null_haystack);
}
