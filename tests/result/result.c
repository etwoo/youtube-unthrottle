#include "result.h"

#include "coverage.h"
#include "debug.h"
#include "greatest.h"

static const char CANNOT_ALLOC[] = "Cannot allocate";
static const char CANNOT_GET[] = "Cannot get";
static const char CANNOT_FIND[] = "Cannot find";
static const char CANNOT_SET[] = "Cannot set";

static void
rs_free(char **strp)
{
	free(*strp);
}

static WARN_UNUSED bool
startswith(const char *s, const char *prefix)
{
	return (0 == strncmp(s, prefix, strlen(prefix)));
}

static WARN_UNUSED bool
test_startswith(result_t r, const char *expected)
{
	char *actual __attribute__((cleanup(rs_free))) = result_to_str(r);
	const bool match = startswith(actual, expected);

	const char *pass_or_fail = match ? "PASS" : "FAIL";
	debug("%s: \"%s\" starts with \"%s\"?", pass_or_fail, actual, expected);

	return match;
}

static bool RESULT_JS_MATCH = true;
static void
test_result_js_visit(size_t pos, result_t r)
{
	static const char *EXPECTED[] = {
		"Success",
		CANNOT_ALLOC,
		"Error in duk_json_decode",
		CANNOT_GET,
		CANNOT_GET,
		"Cannot iter",
		"adaptiveFormats element is not object",
		CANNOT_GET,
		CANNOT_GET,
		CANNOT_FIND,
		CANNOT_FIND,
		"Error in strtoll",
		CANNOT_ALLOC,
		CANNOT_FIND,
		CANNOT_FIND,
		CANNOT_FIND,
		CANNOT_ALLOC,
		"Error in duk_pcompile",
		"Error in duk_pcall",
		"Error fetching",
	};
	const bool cur = test_startswith(r, EXPECTED[pos]);
	RESULT_JS_MATCH = cur && RESULT_JS_MATCH;
}

extern void test_result_js_foreach(void (*visit)(size_t, result_t));

TEST
print_to_str_result_js(void)
{
	test_result_js_foreach(test_result_js_visit);
	ASSERT(RESULT_JS_MATCH);
	PASS();
}

static bool RESULT_LANDLOCK_MATCH = true;
static void
test_result_ll_visit(size_t pos, result_t r)
{
	static const char *EXPECTED[] = {
		"Success",
		"Error in landlock",
		"Error in open() with O_PATH",
		"Error in landlock",
		"Error in landlock",
		"Error in prctl",
		"Error in landlock",
	};
	const bool cur = test_startswith(r, EXPECTED[pos]);
	RESULT_LANDLOCK_MATCH = cur && RESULT_LANDLOCK_MATCH;
}

extern void test_result_ll_foreach(void (*visit)(size_t, result_t));

TEST
print_to_str_result_landlock(void)
{
	test_result_ll_foreach(test_result_ll_visit);
	ASSERT(RESULT_LANDLOCK_MATCH);
	PASS();
}

static bool RESULT_SECCOMP_MATCH = true;
static void
test_result_seccomp_visit(size_t pos, result_t r)
{
	static const char *EXPECTED[] = {
		"Success",
		"Error in seccomp_init",
		"Error in seccomp_load",
	};
	const bool cur = test_startswith(r, EXPECTED[pos]);
	RESULT_SECCOMP_MATCH = cur && RESULT_SECCOMP_MATCH;
}

extern void test_result_seccomp_foreach(void (*visit)(size_t, result_t));

TEST
print_to_str_result_seccomp(void)
{
	test_result_seccomp_foreach(test_result_seccomp_visit);
	ASSERT(RESULT_LANDLOCK_MATCH);
	PASS();
}

static bool RESULT_TMPFILE_MATCH = true;
static void
test_result_tmpfile_visit(size_t pos, result_t r)
{
	static const char *EXPECTED[] = {
		"Success",
		"Error in tmpfile",
		"Error fileno",
		"Error dup",
		"Error fstat",
		"Error mmap",
	};
	const bool cur = test_startswith(r, EXPECTED[pos]);
	RESULT_TMPFILE_MATCH = cur && RESULT_TMPFILE_MATCH;
}

extern void test_result_tmpfile_foreach(void (*visit)(size_t, result_t));

TEST
print_to_str_result_tmpfile(void)
{
	test_result_tmpfile_foreach(test_result_tmpfile_visit);
	ASSERT(RESULT_TMPFILE_MATCH);
	PASS();
}

static bool RESULT_URL_MATCH = true;
static void
test_result_url_visit(size_t pos, result_t r)
{
	static const char *EXPECTED[] = {
		"Success",
		"Cannot use URL functions",
		CANNOT_ALLOC,
		CANNOT_SET,
		CANNOT_SET,
		CANNOT_SET,
		CANNOT_ALLOC,
		CANNOT_SET,
		CANNOT_SET,
		CANNOT_SET,
		CANNOT_SET,
		CANNOT_SET,
		CANNOT_SET,
		CANNOT_SET,
		"Error performing",
	};
	const bool cur = test_startswith(r, EXPECTED[pos]);
	RESULT_URL_MATCH = cur && RESULT_URL_MATCH;
}

extern void test_result_url_foreach(void (*visit)(size_t, result_t));

TEST
print_to_str_result_url(void)
{
	test_result_url_foreach(test_result_url_visit);
	ASSERT(RESULT_URL_MATCH);
	PASS();
}

static bool RESULT_YOUTUBE_MATCH = true;
static void
test_result_youtube_visit(size_t pos, result_t r)
{
	static const char *EXPECTED[] = {
		"Success",
		CANNOT_SET,
		"Cannot strndup",
		CANNOT_FIND,
		CANNOT_ALLOC,
		CANNOT_ALLOC,
		CANNOT_GET,
		"Cannot clear",
		"No n-parameter",
		CANNOT_ALLOC,
		"Cannot append",
		CANNOT_GET,
	};
	const bool cur = test_startswith(r, EXPECTED[pos]);
	RESULT_YOUTUBE_MATCH = cur && RESULT_YOUTUBE_MATCH;
}

extern void test_result_youtube_foreach(void (*visit)(size_t, result_t));

TEST
print_to_str_result_youtube(void)
{
	test_result_youtube_foreach(test_result_youtube_visit);
	ASSERT(RESULT_YOUTUBE_MATCH);
	PASS();
}

SUITE(print_to_str)
{
	RUN_TEST(print_to_str_result_js);
	RUN_TEST(print_to_str_result_landlock);
	RUN_TEST(print_to_str_result_seccomp);
	RUN_TEST(print_to_str_result_tmpfile);
	RUN_TEST(print_to_str_result_url);
	RUN_TEST(print_to_str_result_youtube);
}

GREATEST_MAIN_DEFS();

int
main(int argc, char **argv)
{
	int fd __attribute__((cleanup(coverage_cleanup))) = coverage_open();

	GREATEST_MAIN_BEGIN();

	RUN_SUITE(print_to_str);

	GREATEST_MAIN_END();
}
