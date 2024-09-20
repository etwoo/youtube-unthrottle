#include "js.h"

#include "array.h"
#include "coverage.h"
#include "debug.h"
#include "greatest.h"

#include <assert.h>
#include <limits.h>

static WARN_UNUSED result_t
parse_callback_noop(const char *val __attribute__((unused)),
                    size_t sz __attribute__((unused)),
                    void *userdata __attribute__((unused)))
{
	return RESULT_OK;
}

static struct parse_ops NOOP = {
	.got_video = parse_callback_noop,
	.got_audio = parse_callback_noop,
};

#define RESULT_CLEANUP __attribute__((cleanup(result_cleanup)))

static WARN_UNUSED bool
parse(const char *str)
{
	result_t err RESULT_CLEANUP =
		parse_json(str, strlen(str), &NOOP, NULL);
	return is_ok(err);
}

TEST
root_empty(void)
{
	ASSERT_FALSE(parse(""));
	PASS();
}

TEST
root_number_NaN(void)
{
	ASSERT_FALSE(parse("NaN"));
	PASS();
}

TEST
root_string_missing_quotes(void)
{
	ASSERT_FALSE(parse("Hello, World!"));
	PASS();
}

TEST
root_string_missing_opening_quote(void)
{
	ASSERT_FALSE(parse("Hello, World!\""));
	PASS();
}

TEST
root_string_missing_closing_quote(void)
{
	ASSERT_FALSE(parse("\"Hello, World!"));
	PASS();
}

TEST
root_boolean_uppercase(void)
{
	ASSERT_FALSE(parse("FALSE"));
	PASS();
}

TEST
root_array_only_opening_brace(void)
{
	ASSERT_FALSE(parse("["));
	PASS();
}

TEST
root_array_only_closing_brace(void)
{
	ASSERT_FALSE(parse("]"));
	PASS();
}

TEST
root_array_missing_opening_brace(void)
{
	ASSERT_FALSE(parse("1, 2, 3]"));
	PASS();
}

TEST
root_array_missing_closing_brace(void)
{
	ASSERT_FALSE(parse("[1, 2, 3"));
	PASS();
}

TEST
root_object_only_closing_brace(void)
{
	ASSERT_FALSE(parse("}"));
	PASS();
}

TEST
root_object_only_opening_brace(void)
{
	ASSERT_FALSE(parse("{"));
	PASS();
}

TEST
root_object_missing_closing_brace(void)
{
	ASSERT_FALSE(parse("{\"foo\": \"bar\""));
	PASS();
}

TEST
root_object_missing_opening_brace(void)
{
	ASSERT_FALSE(parse("\"foo\": \"bar\"}"));
	PASS();
}

/*
 * Test that invalid JSON does not crash.
 */
SUITE(invalid_json)
{
	RUN_TEST(root_empty);
	RUN_TEST(root_number_NaN);
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
	ASSERT_FALSE(parse("null"));
	PASS();
}

TEST
root_number(void)
{
	ASSERT_FALSE(parse("-123.456"));
	PASS();
}

TEST
root_string_empty(void)
{
	ASSERT_FALSE(parse("\"\""));
	PASS();
}

TEST
root_string_nonempty(void)
{
	ASSERT_FALSE(parse("\"Hello, World!\""));
	PASS();
}

TEST
root_boolean(void)
{
	ASSERT_FALSE(parse("false"));
	PASS();
}

TEST
root_array_empty(void)
{
	ASSERT_FALSE(parse("[]"));
	PASS();
}

TEST
root_array_nonempty(void)
{
	ASSERT_FALSE(parse("[1, 2, 3]"));
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
	ASSERT_FALSE(parse("{}"));
	PASS();
}

TEST
missing_streamingData_key(void)
{
	ASSERT_FALSE(parse("{\"foo\": \"bar\"}"));
	PASS();
}

TEST
incorrect_streamingData_value_type(void)
{
	ASSERT_FALSE(parse("{\"streamingData\": 1}"));
	PASS();
}

TEST
missing_adaptiveFormats_key(void)
{
	ASSERT_FALSE(parse("{\"streamingData\": {\"foo\": \"bar\"}}"));
	PASS();
}

TEST
incorrect_adaptiveFormats_value_type(void)
{
	ASSERT_FALSE(parse("{\"streamingData\": {\"adaptiveFormats\": 2}}"));
	PASS();
}

TEST
incorrect_adaptiveFormats_element_type(void)
{
	ASSERT_FALSE(parse("{\"streamingData\": {\"adaptiveFormats\": [3]}}"));
	PASS();
}

TEST
missing_mimeType_key(void)
{
	ASSERT_FALSE(parse("{\"streamingData\": {\"adaptiveFormats\": "
	                   "[{\"foo\": \"bar\"}]"
	                   "}}"));
	PASS();
}

TEST
incorrect_mimeType_value_type(void)
{
	ASSERT_FALSE(parse("{\"streamingData\": {\"adaptiveFormats\": "
	                   "[{\"mimeType\": 4}]"
	                   "}}"));
	PASS();
}

TEST
missing_url_key(void)
{
	ASSERT_FALSE(parse("{\"streamingData\": {\"adaptiveFormats\": "
	                   "[{\"mimeType\": \"audio/foobar\"}]"
	                   "}}"));
	PASS();
}

TEST
incorrect_url_value_type(void)
{
	ASSERT_FALSE(parse("{\"streamingData\": {\"adaptiveFormats\": "
	                  "[{\"mimeType\": \"audio/foobar\", \"url\": 5}]"
	                  "}}"));
	PASS();
}

TEST
unsupported_signatureCipher_key(void)
{
	ASSERT_TRUE(parse("{\"streamingData\": {\"adaptiveFormats\": [{"
	                  "\"mimeType\": \"audio/foobar\","
	                  "\"url\": \"foobar\","
	                  "\"signatureCipher\": \"foobar\""
	                  "}]}}"));
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

struct url_copy {
	char video[16];
	char audio[16];
};

static void
url_copy_init(struct url_copy *c)
{
	c->video[0] = '\0';
	c->audio[0] = '\0';
}

static WARN_UNUSED result_t
copy_video(const char *val, size_t sz, void *userdata)
{
	struct url_copy *urls = (struct url_copy *)userdata;
	assert(sizeof(urls->video) >= sz);
	memcpy(urls->video, val, sz);
	urls->video[sz] = '\0';
	debug("Copied video URL: %s", urls->video);
	return RESULT_OK;
}

static WARN_UNUSED result_t
copy_audio(const char *val, size_t sz, void *userdata)
{
	struct url_copy *urls = (struct url_copy *)userdata;
	assert(sizeof(urls->audio) >= sz);
	memcpy(urls->audio, val, sz);
	urls->audio[sz] = '\0';
	debug("Copied audio URL: %s", urls->audio);
	return RESULT_OK;
}

static struct parse_ops URL_COPY_OPS = {
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

	struct url_copy urls;
	url_copy_init(&urls);

	result_t err RESULT_CLEANUP =
		parse_json(json, strlen(json), &URL_COPY_OPS, &urls);
	ASSERT_TRUE(is_ok(err));

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

	struct url_copy urls;
	url_copy_init(&urls);

	result_t err RESULT_CLEANUP =
		parse_json(json, strlen(json), &URL_COPY_OPS, &urls);
	ASSERT_TRUE(is_ok(err));

	ASSERT_STR_EQ(urls.audio, "http://a.test");
	ASSERT_STR_EQ(urls.video, "http://v.test");
	PASS();
}

SUITE(correct_shape)
{
	RUN_TEST(minimum_json_with_correct_shape);
	RUN_TEST(extra_adaptiveFormats_elements);
}

TEST
find_base_js_url_negative(void)
{
	const char *p = NULL;
	size_t sz = 0;

	static const char html[] = "<html/>";
	result_t err RESULT_CLEANUP =
		find_base_js_url(html, sizeof(html), &p, &sz);
	ASSERT_FALSE(is_ok(err));

	ASSERT_EQ(p, NULL);
	ASSERT_EQ(sz, 0);
	PASS();
}

TEST
find_base_js_url_positive(void)
{
	const char *got_url = NULL;
	size_t got_sz = 0;

	static const char html[] =
		"<script "
		"src=\"/s/player/deadbeef/player_ias.vflset/en_US/base.js\" "
		"nonce=\"AAAAAAAAAAAAAAAAAAAAAA\""
		">"
		"</script>";
	result_t err RESULT_CLEANUP =
		find_base_js_url(html, sizeof(html), &got_url, &got_sz);
	ASSERT_TRUE(is_ok(err));

	static const char expected[] =
		"/s/player/deadbeef/player_ias.vflset/en_US/base.js";
	ASSERT_EQ(got_sz, strlen(expected));
	ASSERT_STRN_EQ(got_url, expected, got_sz);
	PASS();
}

TEST
find_js_timestamp_negative_re_pattern(void)
{
	static const char json[] = "{signatureTimestamp:\"foobar\"}";
	long long int timestamp = -1;
	result_t err RESULT_CLEANUP =
		find_js_timestamp(json, sizeof(json), &timestamp);
	ASSERT_FALSE(is_ok(err));
	ASSERT_LT(timestamp, 0);
	PASS();
}

TEST
find_js_timestamp_negative_strtoll_erange(void)
{
	static const char json[] = "{signatureTimestamp:9223372036854775808}";
	long long int timestamp = -1;
	result_t err RESULT_CLEANUP =
		find_js_timestamp(json, sizeof(json), &timestamp);
	ASSERT_FALSE(is_ok(err));
	ASSERT_EQ(errno, ERANGE);
	ASSERT_LT(timestamp, 0);
	PASS();
}

TEST
find_js_timestamp_positive_strtoll_max(void)
{
	static const char json[] = "{signatureTimestamp:9223372036854775807}";
	long long int timestamp = 0;
	result_t err RESULT_CLEANUP =
		find_js_timestamp(json, sizeof(json), &timestamp);
	ASSERT_EQ(err.err, OK);
	ASSERT_EQ(timestamp, LLONG_MAX);
	PASS();
}

TEST
find_js_timestamp_positive_simple(void)
{
	static const char json[] = "{signatureTimestamp:19957}";
	long long int timestamp = 0;
	result_t err RESULT_CLEANUP =
		find_js_timestamp(json, sizeof(json), &timestamp);
	ASSERT_EQ(err.err, OK);
	ASSERT_EQ(timestamp, 19957);
	PASS();
}

TEST
find_js_deobfuscator_negative_first_match_fail(void)
{
	const char *deobfuscator = NULL;
	size_t sz = 0;

	static const char js[] =
		"var _yt_player={};(function(g){})(_yt_player);";
	result_t err RESULT_CLEANUP =
		find_js_deobfuscator(js, sizeof(js), &deobfuscator, &sz);
	ASSERT_FALSE(is_ok(err));

	ASSERT_EQ(deobfuscator, NULL);
	ASSERT_EQ(sz, 0);
	PASS();
}

TEST
find_js_deobfuscator_negative_second_match_fail(void)
{
	const char *deobfuscator = NULL;
	size_t sz = 0;

	static const char js[] = "&&(c=ODa[0](c),";
	result_t err RESULT_CLEANUP =
		find_js_deobfuscator(js, sizeof(js), &deobfuscator, &sz);
	ASSERT_FALSE(is_ok(err));

	ASSERT_EQ(deobfuscator, NULL);
	ASSERT_EQ(sz, 0);
	PASS();
}

TEST
find_js_deobfuscator_negative_third_match_fail(void)
{
	const char *deobfuscator = NULL;
	size_t sz = 0;

	static const char js[] = "&&(c=ODa[0](c),\nvar ODa=[Pma];";
	result_t err RESULT_CLEANUP =
		find_js_deobfuscator(js, sizeof(js), &deobfuscator, &sz);
	ASSERT_FALSE(is_ok(err));

	ASSERT_EQ(deobfuscator, NULL);
	ASSERT_EQ(sz, 0);
	PASS();
}

TEST
find_js_deobfuscator_positive_simple(void)
{
	const char *deobfuscator = NULL;
	size_t sz = 0;

	static const char js[] =
		"&&(c=ODa[0](c),\nvar ODa=[Pma];\nPma=function(a)"
		"{return b.join(\"\")};";
	result_t err RESULT_CLEANUP =
		find_js_deobfuscator(js, sizeof(js), &deobfuscator, &sz);
	ASSERT_TRUE(is_ok(err));

	static const char expected[] = "function(a){return b.join(\"\")};";
	ASSERT_EQ(sz, strlen(expected));
	ASSERT_STRN_EQ(deobfuscator, expected, sz);
	PASS();
}

TEST
find_js_deobfuscator_positive_with_escaping(void)
{
	const char *deobfuscator = NULL;
	size_t sz = 0;

	static const char js[] =
		"&&(c=$aa[0](c),\nvar $aa=[$bb];\n$bb=function(a)"
		"{return b.join(\"\")};";
	result_t err RESULT_CLEANUP =
		find_js_deobfuscator(js, sizeof(js), &deobfuscator, &sz);
	ASSERT_TRUE(is_ok(err));

	static const char expected[] = "function(a){return b.join(\"\")};";
	ASSERT_EQ(sz, strlen(expected));
	ASSERT_STRN_EQ(deobfuscator, expected, sz);
	PASS();
}

SUITE(find_with_pcre)
{
	RUN_TEST(find_base_js_url_negative);
	RUN_TEST(find_base_js_url_positive);
	RUN_TEST(find_js_timestamp_negative_re_pattern);
	RUN_TEST(find_js_timestamp_negative_strtoll_erange);
	RUN_TEST(find_js_timestamp_positive_strtoll_max);
	RUN_TEST(find_js_timestamp_positive_simple);
	RUN_TEST(find_js_deobfuscator_negative_first_match_fail);
	RUN_TEST(find_js_deobfuscator_negative_second_match_fail);
	RUN_TEST(find_js_deobfuscator_negative_third_match_fail);
	RUN_TEST(find_js_deobfuscator_positive_simple);
	RUN_TEST(find_js_deobfuscator_positive_with_escaping);
}

TEST
call_with_duktape_pcompile_fail(void)
{
	static const char js[] = "\"Not a valid function definition!\"";
	result_t err RESULT_CLEANUP =
		call_js_foreach(js, sizeof(js), NULL, 0, NULL, NULL);
	ASSERT_FALSE(is_ok(err));
	PASS();
}

TEST
call_with_duktape_pcall_fail(void)
{
	char *args[1];
	args[0] = "Hello, World!";

	static const char js[] = "function(a){return not_defined;};";
	result_t err RESULT_CLEANUP = call_js_foreach(js,
	                                              sizeof(js),
	                                              args,
	                                              ARRAY_SIZE(args),
	                                              NULL,
	                                              NULL);
	ASSERT_FALSE(is_ok(err));
	PASS();
}

TEST
call_with_duktape_pcall_incorrect_result_type(void)
{
	char *args[1];
	args[0] = "Hello, World!";

	static const char js[] = "function(a){return true;};";
	result_t err RESULT_CLEANUP = call_js_foreach(js,
	                                              sizeof(js),
	                                              args,
	                                              ARRAY_SIZE(args),
	                                              NULL,
	                                              NULL);
	ASSERT_FALSE(is_ok(err));
	PASS();
}

struct result_copy {
	char str[16];
};

static void
result_copy_init(struct result_copy *c)
{
	c->str[0] = '\0';
}

static WARN_UNUSED result_t
copy_result(const char *val,
            size_t sz,
            size_t pos __attribute__((unused)),
            void *userdata)
{
	struct result_copy *result = (struct result_copy *)userdata;
	assert(sizeof(result->str) >= sz);
	memcpy(result->str, val, sz);
	result->str[sz] = '\0';
	debug("Copied result: %s", result->str);
	return RESULT_OK;
}

TEST
call_with_duktape_minimum_valid_function(void)
{
	struct call_ops cops = {
		.got_result = copy_result,
	};

	struct result_copy result;
	result_copy_init(&result);

	char *args[1];
	args[0] = "Hello, World!";

	static const char js[] = "function(a){return a.toUpperCase();};";
	result_t err RESULT_CLEANUP = call_js_foreach(js,
	                                              sizeof(js),
	                                              args,
	                                              ARRAY_SIZE(args),
	                                              &cops,
	                                              &result);
	ASSERT_TRUE(is_ok(err));
	ASSERT_STR_EQ(result.str, "HELLO, WORLD!");
	PASS();
}

SUITE(call_with_duktape)
{
	RUN_TEST(call_with_duktape_pcompile_fail);
	RUN_TEST(call_with_duktape_pcall_fail);
	RUN_TEST(call_with_duktape_pcall_incorrect_result_type);
	RUN_TEST(call_with_duktape_minimum_valid_function);
}

#undef RESULT_CLEANUP

GREATEST_MAIN_DEFS();

int
main(int argc, char **argv)
{
	int fd __attribute__((cleanup(coverage_cleanup))) = coverage_open();

	GREATEST_MAIN_BEGIN();

	RUN_SUITE(invalid_json);
	RUN_SUITE(incorrect_root_type);
	RUN_SUITE(incorrect_shape);
	RUN_SUITE(correct_shape);
	RUN_SUITE(find_with_pcre);
	RUN_SUITE(call_with_duktape);

	GREATEST_MAIN_END();
}
