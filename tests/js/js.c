#include "js.h"

#include "coverage.h"
#include "debug.h"
#include "greatest.h"

#include <assert.h>

static void
parse_callback_noop(const char *val __attribute__((unused)),
                    size_t sz __attribute__((unused)),
                    void *userdata __attribute__((unused)))
{
}

static struct parse_ops NOOP = {
	.got_video = parse_callback_noop,
	.got_audio = parse_callback_noop,
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

struct copies {
	char video[16];
	char audio[16];
};

static void
copies_init(struct copies *c)
{
	c->video[0] = '\0';
	c->audio[0] = '\0';
}

static void
copy_video(const char *val, size_t sz, void *userdata)
{
	struct copies *urls = (struct copies *)userdata;
	assert(sizeof(urls->video) >= sz);
	strlcpy(urls->video, val, sizeof(urls->video));
	debug("Copied video URL: %s", urls->video);
}

static void
copy_audio(const char *val, size_t sz, void *userdata)
{
	struct copies *urls = (struct copies *)userdata;
	assert(sizeof(urls->audio) >= sz);
	strlcpy(urls->audio, val, sizeof(urls->audio));
	debug("Copied audio URL: %s", urls->audio);
}

static struct parse_ops COPY_OPS = {
	.got_video = copy_video,
	.got_audio = copy_audio,
};

TEST
minimum_json_with_correct_shape(void)
{
	static const char json[] =
		"{\"streamingData\": {\"adaptiveFormats\": ["
		"{\"mimeType\": \"audio/foo\",\"url\": \"http://a.test\"},"
		"{\"mimeType\": \"video/foo\",\"url\": \"http://v.test\"}"
		"]}}";

	struct copies urls;
	copies_init(&urls);
	parse_json(json, strlen(json), &COPY_OPS, &urls);

	ASSERT_STR_EQ(urls.audio, "http://a.test");
	ASSERT_STR_EQ(urls.video, "http://v.test");
	PASS();
}

TEST
extra_adaptiveFormats_elements(void)
{
	static const char json[] =
		"{\"streamingData\": {\"adaptiveFormats\": ["
		"{\"mimeType\": \"audio/foo\",\"url\": \"http://a.test\"},"
		"{\"mimeType\": \"audio/bar\",\"url\": \"http://extra.test\"},"
		"{\"mimeType\": \"video/foo\",\"url\": \"http://v.test\"},"
		"{\"mimeType\": \"video/bar\",\"url\": \"http://extra.test\"}"
		"]}}";

	struct copies urls;
	copies_init(&urls);
	parse_json(json, strlen(json), &COPY_OPS, &urls);

	ASSERT_STR_EQ(urls.audio, "http://a.test");
	ASSERT_STR_EQ(urls.video, "http://v.test");
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
