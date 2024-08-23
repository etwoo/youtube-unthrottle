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

TEST
capturef_pattern_too_large(void)
{
	bool rc = re_capturef("", 0, NULL, NULL, "%0*d", 8192, 'Z');
	ASSERT_FALSE(rc);
	PASS();
}

TEST
capturef_pattern_match_one(void)
{
	const char *needle = NULL;
	size_t sz = 0;

	static const char hay[] = "bbbaaaaabbb";
	bool rc = re_capturef(hay, strlen(hay), &needle, &sz, "(%c+)", 'a');

	static const char expected[] = "aaaaa";
	ASSERT(rc);
	ASSERT_EQ(sz, strlen(expected));
	ASSERT_STRN_EQ(needle, expected, sz);
	PASS();
}

SUITE(capturef)
{
	RUN_TEST(capturef_pattern_too_large);
	RUN_TEST(capturef_pattern_match_one);
}

TEST
pattern_escape_noop(void)
{
	char escaped[256];

	static const char in[] = "ABCDEFGH";
	bool rc = re_pattern_escape(in, strlen(in), escaped, sizeof(escaped));

	ASSERT(rc);
	ASSERT_STR_EQ(in, escaped);
	PASS();
}

TEST
pattern_escape_special_chars(void)
{
	char escaped[256];

	static const char in[] = "ABCD\\^$.[|()*+?{";
	bool rc = re_pattern_escape(in, strlen(in), escaped, sizeof(escaped));

	ASSERT(rc);
	ASSERT_STR_EQ(escaped, "ABCD\\\\\\^\\$\\.\\[\\|\\(\\)\\*\\+\\?\\{");
	PASS();
}

TEST
pattern_escape_exceeds_capacity(void)
{
	char buf[1];
	bool rc = re_pattern_escape("hi", 2, buf, sizeof(buf));
	ASSERT_FALSE(rc);
	PASS();
}

TEST
pattern_escape_exceeds_capacity_by_one_escape_char(void)
{
	char buf[1];
	bool rc = re_pattern_escape(".", 1, buf, sizeof(buf));
	ASSERT_FALSE(rc);
	PASS();
}

SUITE(pattern_escape)
{
	RUN_TEST(pattern_escape_noop);
	RUN_TEST(pattern_escape_special_chars);
	RUN_TEST(pattern_escape_exceeds_capacity);
	RUN_TEST(pattern_escape_exceeds_capacity_by_one_escape_char);
}

GREATEST_MAIN_DEFS();

int
main(int argc, char **argv)
{
	int fd __attribute__((cleanup(coverage_cleanup))) = coverage_open();

	GREATEST_MAIN_BEGIN();

	RUN_SUITE(capture);
	RUN_SUITE(capturef);
	RUN_SUITE(pattern_escape);

	GREATEST_MAIN_END();
}
