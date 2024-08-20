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
parse(const char *str)
{
	parse_json(str, strlen(str), &NOOP, NULL);
}

TEST
root_empty(void)
{
	parse("");
	PASS();
}

TEST
root_number_NaN(void)
{
	parse("NaN");
	PASS();
}

TEST
root_number_too_large(void)
{
	parse("9007199254740992"); /* 2^53 */
	PASS();
}

TEST
root_string_missing_quotes(void)
{
	parse("Hello, World!");
	PASS();
}

TEST
root_string_missing_opening_quote(void)
{
	parse("Hello, World!\"");
	PASS();
}

TEST
root_string_missing_closing_quote(void)
{
	parse("\"Hello, World!");
	PASS();
}

TEST
root_boolean_uppercase(void)
{
	parse("FALSE");
	PASS();
}

TEST
root_array_only_opening_brace(void)
{
	parse("[");
	PASS();
}

TEST
root_array_only_closing_brace(void)
{
	parse("]");
	PASS();
}

TEST
root_array_missing_opening_brace(void)
{
	parse("1, 2, 3]");
	PASS();
}

TEST
root_array_missing_closing_brace(void)
{
	parse("[1, 2, 3");
	PASS();
}

TEST
root_object_only_closing_brace(void)
{
	parse("}");
	PASS();
}

TEST
root_object_only_opening_brace(void)
{
	parse("{");
	PASS();
}

TEST
root_object_missing_closing_brace(void)
{
	parse("{\"foo\": \"bar\"");
	PASS();
}

TEST
root_object_missing_opening_brace(void)
{
	parse("\"foo\": \"bar\"}");
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
	parse("null");
	PASS();
}

TEST
root_number(void)
{
	parse("-123.456");
	PASS();
}

TEST
root_string_empty(void)
{
	parse("\"\"");
	PASS();
}

TEST
root_string_nonempty(void)
{
	parse("\"Hello, World!\"");
	PASS();
}

TEST
root_boolean(void)
{
	parse("false");
	PASS();
}

TEST
root_array_empty(void)
{
	parse("[]");
	PASS();
}

TEST
root_array_nonempty(void)
{
	parse("[1, 2, 3]");
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
	parse("{}");
	PASS();
}

TEST
missing_streamingData_key(void)
{
	parse("{\"foo\": \"bar\"}");
	PASS();
}

TEST
incorrect_streamingData_value_type(void)
{
	parse("{\"streamingData\": 1}");
	PASS();
}

TEST
missing_adaptiveFormats_key(void)
{
	parse("{\"streamingData\": {\"foo\": \"bar\"}}");
	PASS();
}

TEST
incorrect_adaptiveFormats_value_type(void)
{
	parse("{\"streamingData\": {\"adaptiveFormats\": 2}}");
	PASS();
}

TEST
incorrect_adaptiveFormats_element_type(void)
{
	parse("{\"streamingData\": {\"adaptiveFormats\": [3]}}");
	PASS();
}

TEST
missing_mimeType_key(void)
{
	parse("{\"streamingData\": {\"adaptiveFormats\": "
	      "[{\"foo\": \"bar\"}]"
	      "}}");
	PASS();
}

TEST
incorrect_mimeType_value_type(void)
{
	parse("{\"streamingData\": {\"adaptiveFormats\": "
	      "[{\"mimeType\": 4}]"
	      "}}");
	PASS();
}

TEST
missing_url_key(void)
{
	parse("{\"streamingData\": {\"adaptiveFormats\": "
	      "[{\"mimeType\": \"audio/foobar\"}]"
	      "}}");
	PASS();
}

TEST
incorrect_url_value_type(void)
{
	parse("{\"streamingData\": {\"adaptiveFormats\": "
	      "[{\"mimeType\": \"audio/foobar\", \"url\": 5}]"
	      "}}");
	PASS();
}

TEST
unsupported_signatureCipher_key(void)
{
	parse("{\"streamingData\": {\"adaptiveFormats\": [{"
	      "\"mimeType\": \"audio/foobar\","
	      "\"url\": \"foobar\","
	      "\"signatureCipher\": \"foobar\""
	      "}]}}");
	PASS();
}

/*
 * Test that incorrect JSON content shape does not crash.
 */
SUITE(incorrect_shape)
{
	RUN_TEST(root_object_empty);
	RUN_TEST(missing_streamingData_key);
	RUN_TEST(incorrect_streamingData_value_type);
	RUN_TEST(missing_adaptiveFormats_key);
	RUN_TEST(incorrect_adaptiveFormats_value_type);
	RUN_TEST(incorrect_adaptiveFormats_element_type);
	RUN_TEST(missing_mimeType_key);
	RUN_TEST(incorrect_mimeType_value_type);
	RUN_TEST(missing_url_key);
	RUN_TEST(incorrect_url_value_type);
	RUN_TEST(unsupported_signatureCipher_key);
}

TEST
minimum_json_with_correct_shape(void)
{
	parse("{\"streamingData\": {\"adaptiveFormats\": ["
	      "{\"mimeType\": \"audio/foobar\",\"url\": \"foobar\"},"
	      "{\"mimeType\": \"video/foobar\",\"url\": \"foobar\"}"
	      "]}}");
	PASS();
}

TEST
extra_adaptiveFormats_elements(void)
{
	parse("{\"streamingData\": {\"adaptiveFormats\": ["
	      "{\"mimeType\": \"audio/foobar\",\"url\": \"foobar\"},"
	      "{\"mimeType\": \"audio/extra\",\"url\": \"foobar\"},"
	      "{\"mimeType\": \"video/foobar\",\"url\": \"foobar\"},"
	      "{\"mimeType\": \"video/extra\",\"url\": \"foobar\"}"
	      "]}}");
	PASS();
}

SUITE(correct_shape)
{
	RUN_TEST(minimum_json_with_correct_shape);
	RUN_TEST(extra_adaptiveFormats_elements);
}

GREATEST_MAIN_DEFS();

int
main(int argc, char **argv)
{
	GREATEST_MAIN_BEGIN();

	int fd = coverage_open();

	RUN_SUITE(invalid_json);
	RUN_SUITE(incorrect_root_type);
	RUN_SUITE(incorrect_shape);
	RUN_SUITE(correct_shape);

	coverage_write_and_close(fd);

	GREATEST_MAIN_END();
}
