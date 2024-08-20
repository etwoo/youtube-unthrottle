#include "js.h"

#include "coverage.h"
#include "greatest.h"

static void
got_video(const char *val __attribute__((unused)),
          size_t sz __attribute__((unused)),
          void *userdata __attribute__((unused)))
{
}

static void
got_audio(const char *val __attribute__((unused)),
          size_t sz __attribute__((unused)),
          void *userdata __attribute__((unused)))
{
}

static struct parse_ops NOOP = {
	.got_audio = got_video,
	.got_video = got_audio,
};

static void
parse_json_with_noop(const char *str)
{
	parse_json(str, strlen(str), &NOOP, NULL);
}

TEST
root_empty(void)
{
	parse_json_with_noop("");
	PASS();
}

TEST
root_number_NaN(void)
{
	parse_json_with_noop("NaN");
	PASS();
}

TEST
root_number_too_large(void)
{
	parse_json_with_noop("9007199254740992"); /* 2^53 */
	PASS();
}

TEST
root_string_missing_quotes(void)
{
	parse_json_with_noop("Hello, World!");
	PASS();
}

TEST
root_string_missing_opening_quote(void)
{
	parse_json_with_noop("Hello, World!\"");
	PASS();
}

TEST
root_string_missing_closing_quote(void)
{
	parse_json_with_noop("\"Hello, World!");
	PASS();
}

TEST
root_boolean_uppercase(void)
{
	parse_json_with_noop("FALSE");
	PASS();
}

TEST
root_array_only_opening_brace(void)
{
	parse_json_with_noop("[");
	PASS();
}

TEST
root_array_only_closing_brace(void)
{
	parse_json_with_noop("]");
	PASS();
}

TEST
root_array_missing_opening_brace(void)
{
	parse_json_with_noop("1, 2, 3]");
	PASS();
}

TEST
root_array_missing_closing_brace(void)
{
	parse_json_with_noop("[1, 2, 3");
	PASS();
}

TEST
root_object_only_closing_brace(void)
{
	parse_json_with_noop("}");
	PASS();
}

TEST
root_object_only_opening_brace(void)
{
	parse_json_with_noop("{");
	PASS();
}

TEST
root_object_missing_closing_brace(void)
{
	parse_json_with_noop("{ \"foo\" : \"bar\"");
	PASS();
}

TEST
root_object_missing_opening_brace(void)
{
	parse_json_with_noop("\"foo\" : \"bar\"}");
	PASS();
}

/*
 * Test that invalid JSON does not crash.
 */
SUITE(invalid_json)
{
	RUN_TEST(root_empty);
	RUN_TEST(root_number_NaN);
	RUN_TEST(root_number_too_large);
	RUN_TEST(root_string_missing_quotes);
	RUN_TEST(root_string_missing_opening_quote);
	RUN_TEST(root_string_missing_closing_quote);
	RUN_TEST(root_boolean_uppercase);
	RUN_TEST(root_array_only_opening_brace);
	RUN_TEST(root_array_only_closing_brace);
	RUN_TEST(root_array_missing_opening_brace);
	RUN_TEST(root_array_missing_closing_brace);
	RUN_TEST(root_object_only_opening_brace);
	RUN_TEST(root_object_only_closing_brace);
	RUN_TEST(root_object_missing_opening_brace);
	RUN_TEST(root_object_missing_closing_brace);
}

TEST
root_null(void)
{
	parse_json_with_noop("null");
	PASS();
}

TEST
root_number(void)
{
	parse_json_with_noop("-123.456");
	PASS();
}

TEST
root_string_empty(void)
{
	parse_json_with_noop("\"\"");
	PASS();
}

TEST
root_string_nonempty(void)
{
	parse_json_with_noop("\"Hello, World!\"");
	PASS();
}

TEST
root_boolean(void)
{
	parse_json_with_noop("false");
	PASS();
}

TEST
root_array_empty(void)
{
	parse_json_with_noop("[]");
	PASS();
}

TEST
root_array_nonempty(void)
{
	parse_json_with_noop("[1, 2, 3]");
	PASS();
}

/*
 * Test that incorrect root JSON type does not crash.
 */
SUITE(incorrect_root_type)
{
	RUN_TEST(root_null);
	RUN_TEST(root_number);
	RUN_TEST(root_string_empty);
	RUN_TEST(root_string_nonempty);
	RUN_TEST(root_boolean);
	RUN_TEST(root_array_empty);
	RUN_TEST(root_array_nonempty);
}

TEST
root_object_empty(void)
{
	parse_json_with_noop("{}");
	PASS();
}

/*
 * Test that incorrect JSON content does not crash.
 */
SUITE(incorrect_root_content)
{
	RUN_TEST(root_object_empty);
}

GREATEST_MAIN_DEFS();

int
main(int argc, char **argv)
{
	GREATEST_MAIN_BEGIN();

	int fd = coverage_open();

	RUN_SUITE(invalid_json);
	RUN_SUITE(incorrect_root_type);
	RUN_SUITE(incorrect_root_content);

	coverage_write_and_close(fd);

	GREATEST_MAIN_END();
}
