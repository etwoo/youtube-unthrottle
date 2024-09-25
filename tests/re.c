#include "re.h"

#include "coverage.h"
#include "greatest.h"

TEST
capture_pattern_compile_fail(void)
{
	bool rc = re_capture("+", "", 0, NULL, NULL);
	ASSERT_FALSE(rc);
	PASS();
}

TEST
capture_pattern_match_one(void)
{
	const char *needle = NULL;
	size_t sz = 0;

	static const char hay[] = "bbbaaabbb";
	bool rc = re_capture("b+(a+)b+", hay, strlen(hay), &needle, &sz);

	static const char expected[] = "aaa";
	ASSERT(rc);
	ASSERT_EQ(sz, strlen(expected));
	ASSERT_STRN_EQ(needle, expected, sz);
	PASS();
}

TEST
capture_pattern_match_none(void)
{
	const char *needle = NULL;
	size_t sz = 0;

	static const char hay[] = "bbbAAAbbb";
	bool rc = re_capture("b+(a+)b+", hay, strlen(hay), &needle, &sz);

	ASSERT_FALSE(rc);
	ASSERT_EQ(needle, NULL);
	ASSERT_EQ(sz, 0);
	PASS();
}

TEST
capture_pattern_match_fail_on_null_haystack(void)
{
	bool rc = re_capture("b+(a+)b+", NULL, 8, NULL, NULL);
	ASSERT_FALSE(rc);
	PASS();
}

SUITE(capture)
{
	RUN_TEST(capture_pattern_compile_fail);
	RUN_TEST(capture_pattern_match_one);
	RUN_TEST(capture_pattern_match_none);
	RUN_TEST(capture_pattern_match_fail_on_null_haystack);
}

int re(int argc, char **argv);
int
re(int argc, char **argv)
{
	int fd __attribute__((cleanup(coverage_cleanup))) = coverage_open();

	GREATEST_MAIN_BEGIN();

	RUN_SUITE(capture);

	GREATEST_MAIN_END();
}
