#include "lib/js.h"

#include "greatest.h"
#include "sys/array.h"
#include "sys/debug.h"
#include "test_macros.h"

#include <assert.h>
#include <limits.h>

static WARN_UNUSED result_t
parse_callback_noop(const char *val __attribute__((unused)),
                    void *userdata __attribute__((unused)))
{
	return RESULT_OK;
}

static const struct parse_ops NOOP = {
	.got_video = parse_callback_noop,
	.got_video_userdata = NULL,
	.got_audio = parse_callback_noop,
	.got_audio_userdata = NULL,
	.choose_quality = parse_callback_noop,
	.choose_quality_userdata = NULL,
};

static WARN_UNUSED int
parse(const char *str)
{
	struct string_view tmp = {.data = str, .sz = strlen(str)};
	auto_result err = parse_json(&tmp, &NOOP);
	return err.err;
}

TEST
root_empty(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_DECODE, parse(""));
	PASS();
}

TEST
root_number_NaN(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_DECODE, parse("NaN"));
	PASS();
}

TEST
root_string_missing_quotes(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_DECODE, parse("Hello, World!"));
	PASS();
}

TEST
root_string_missing_opening_quote(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_DECODE, parse("Hello, World!\""));
	PASS();
}

TEST
root_string_missing_closing_quote(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_DECODE, parse("\"Hello, World!"));
	PASS();
}

TEST
root_boolean_uppercase(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_DECODE, parse("FALSE"));
	PASS();
}

TEST
root_array_only_opening_brace(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_DECODE, parse("["));
	PASS();
}

TEST
root_array_only_closing_brace(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_DECODE, parse("]"));
	PASS();
}

TEST
root_array_missing_opening_brace(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_DECODE, parse("1, 2, 3]"));
	PASS();
}

TEST
root_array_missing_closing_brace(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_DECODE, parse("[1, 2, 3"));
	PASS();
}

TEST
root_object_only_closing_brace(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_DECODE, parse("}"));
	PASS();
}

TEST
root_object_only_opening_brace(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_DECODE, parse("{"));
	PASS();
}

TEST
root_object_missing_closing_brace(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_DECODE, parse("{\"foo\": \"bar\""));
	PASS();
}

TEST
root_object_missing_opening_brace(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_DECODE, parse("\"foo\": \"bar\"}"));
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
	ASSERT_EQ(ERR_JS_PARSE_JSON_DECODE, parse("null"));
	PASS();
}

TEST
root_number(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_DECODE, parse("-123.456"));
	PASS();
}

TEST
root_string_empty(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_DECODE, parse("\"\""));
	PASS();
}

TEST
root_string_nonempty(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_DECODE, parse("\"Hello, World!\""));
	PASS();
}

TEST
root_boolean(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_DECODE, parse("false"));
	PASS();
}

TEST
root_array_empty(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_GET_STREAMINGDATA, parse("[]"));
	PASS();
}

TEST
root_array_nonempty(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_GET_STREAMINGDATA, parse("[1, 2, 3]"));
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
	ASSERT_EQ(ERR_JS_PARSE_JSON_GET_STREAMINGDATA, parse("{}"));
	PASS();
}

TEST
missing_streamingData_key(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_GET_STREAMINGDATA,
	          parse("{\"foo\": \"bar\"}"));
	PASS();
}

TEST
incorrect_streamingData_value_type(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_GET_ADAPTIVEFORMATS,
	          parse("{\"streamingData\": 1}"));
	PASS();
}

TEST
missing_adaptiveFormats_key(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_GET_ADAPTIVEFORMATS,
	          parse("{\"streamingData\": {\"foo\": \"bar\"}}"));
	PASS();
}

TEST
incorrect_adaptiveFormats_value_type(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_ADAPTIVEFORMATS_TYPE,
	          parse("{\"streamingData\": {\"adaptiveFormats\": 2}}"));
	PASS();
}

TEST
incorrect_adaptiveFormats_element_type(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_ELEM_TYPE,
	          parse("{\"streamingData\": {\"adaptiveFormats\": [3]}}"));
	PASS();
}

TEST
missing_mimeType_key(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_ELEM_MIMETYPE,
	          parse("{\"streamingData\": {\"adaptiveFormats\": "
	                "[{\"foo\": \"bar\"}]"
	                "}}"));
	PASS();
}

TEST
incorrect_mimeType_value_type(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_ELEM_MIMETYPE,
	          parse("{\"streamingData\": {\"adaptiveFormats\": "
	                "[{\"mimeType\": 4}]"
	                "}}"));
	PASS();
}

TEST
missing_url_key(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_ELEM_URL,
	          parse("{\"streamingData\": {\"adaptiveFormats\": "
	                "[{\"mimeType\": \"audio/foobar\"}]"
	                "}}"));
	PASS();
}

TEST
incorrect_url_value_type(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_ELEM_URL,
	          parse("{\"streamingData\": {\"adaptiveFormats\": "
	                "[{\"mimeType\": \"audio/foobar\", \"url\": 5}]"
	                "}}"));
	PASS();
}

TEST
unsupported_signatureCipher_key(void)
{
	ASSERT_EQ(OK,
	          parse("{\"streamingData\": {\"adaptiveFormats\": [{"
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
copy_video(const char *val, void *userdata)
{
	struct url_copy *urls = (struct url_copy *)userdata;
	const size_t sz = strlen(val);
	assert(sizeof(urls->video) >= sz);
	memcpy(urls->video, val, sz);
	urls->video[sz] = '\0';
	debug("Copied video URL: %s", urls->video);
	return RESULT_OK;
}

static WARN_UNUSED result_t
copy_audio(const char *val, void *userdata)
{
	struct url_copy *urls = (struct url_copy *)userdata;
	const size_t sz = strlen(val);
	assert(sizeof(urls->audio) >= sz);
	memcpy(urls->audio, val, sz);
	urls->audio[sz] = '\0';
	debug("Copied audio URL: %s", urls->audio);
	return RESULT_OK;
}

TEST
minimum_json_with_correct_shape(void)
{
	const struct string_view json = MAKE_TEST_STRING(
		"{\"streamingData\": {\"adaptiveFormats\": ["
		"{\"mimeType\": \"audio/foo\",\"url\": \"http://a.test\"},"
		"{\"mimeType\": \"video/foo\",\"url\": \"http://v.test\"}"
		"]}}");

	struct url_copy urls;
	url_copy_init(&urls);

	struct parse_ops pops = {
		.got_video = copy_video,
		.got_video_userdata = &urls,
		.got_audio = copy_audio,
		.got_audio_userdata = &urls,
		.choose_quality = parse_callback_noop,
		.choose_quality_userdata = NULL,
	};
	auto_result err = parse_json(&json, &pops);
	ASSERT_EQ(OK, err.err);

	ASSERT_STR_EQ("http://a.test", urls.audio);
	ASSERT_STR_EQ("http://v.test", urls.video);
	PASS();
}

TEST
extra_adaptiveFormats_elements(void)
{
	const struct string_view json = MAKE_TEST_STRING(
		"{\"streamingData\": {\"adaptiveFormats\": ["
		"{\"mimeType\": \"audio/foo\",\"url\": \"http://a.test\"},"
		"{\"mimeType\": \"audio/bar\",\"url\": \"http://extra.test\"},"
		"{\"mimeType\": \"video/foo\",\"url\": \"http://v.test\"},"
		"{\"mimeType\": \"video/bar\",\"url\": \"http://extra.test\"}"
		"]}}");

	struct url_copy urls;
	url_copy_init(&urls);

	struct parse_ops pops = {
		.got_video = copy_video,
		.got_video_userdata = &urls,
		.got_audio = copy_audio,
		.got_audio_userdata = &urls,
		.choose_quality = parse_callback_noop,
		.choose_quality_userdata = NULL,
	};
	auto_result err = parse_json(&json, &pops);
	ASSERT_EQ(OK, err.err);

	ASSERT_STR_EQ("http://a.test", urls.audio);
	ASSERT_STR_EQ("http://v.test", urls.video);
	PASS();
}

static WARN_UNUSED result_t
choose_quality_skip_marked_entries(const char *val, void *userdata)
{
	const char *skip_pattern = (const char *)userdata;
	if (0 == strcmp(skip_pattern, val)) {
		return make_result(ERR_JS_PARSE_JSON_CALLBACK_QUALITY);
	}
	return RESULT_OK;
}

TEST
choose_adaptiveFormats_elements(void)
{
	const struct string_view json = MAKE_TEST_STRING(
		"{ \"streamingData\": {\"adaptiveFormats\": [ {"
		"\"mimeType\": \"audio/foo\","
		"\"qualityLabel\": \"skip\","
		"\"url\": \"http://bad.test\""
		"},"
		"{"
		"\"mimeType\": \"audio/bar\","
		"\"url\": \"http://a.test\""
		"},"
		"{\"mimeType\": \"video/foo\","
		"\"qualityLabel\": \"skip\","
		"\"url\": \"http://bad.test\""
		"},"
		"{\"mimeType\": \"video/bar\","
		"\"url\": \"http://v.test\""
		"} ] }}");

	struct url_copy urls;
	url_copy_init(&urls);

	struct parse_ops pops = {
		.got_video = copy_video,
		.got_video_userdata = &urls,
		.got_audio = copy_audio,
		.got_audio_userdata = &urls,
		.choose_quality = choose_quality_skip_marked_entries,
		.choose_quality_userdata = "skip",
	};
	auto_result err = parse_json(&json, &pops);
	ASSERT_EQ(OK, err.err);

	ASSERT_STR_EQ("http://a.test", urls.audio);
	ASSERT_STR_EQ("http://v.test", urls.video);
	PASS();
}

SUITE(correct_shape)
{
	RUN_TEST(minimum_json_with_correct_shape);
	RUN_TEST(extra_adaptiveFormats_elements);
	RUN_TEST(choose_adaptiveFormats_elements);
}

TEST
find_base_js_url_negative(void)
{
	struct string_view p = {0};
	const struct string_view html = MAKE_TEST_STRING("<html/>");

	auto_result err = find_base_js_url(&html, &p);
	ASSERT_EQ(ERR_JS_BASEJS_URL_FIND, err.err);

	ASSERT_EQ(NULL, p.data);
	ASSERT_EQ(0, p.sz);
	PASS();
}

TEST
find_base_js_url_positive(void)
{
	struct string_view p = {0};
	const struct string_view html = MAKE_TEST_STRING(
		"<script "
		"src=\"/s/player/deadbeef/player_ias.vflset/en_US/base.js\" "
		"nonce=\"AAAAAAAAAAAAAAAAAAAAAA\""
		">"
		"</script>");

	auto_result err = find_base_js_url(&html, &p);
	ASSERT_EQ(OK, err.err);

	const char expected[] =
		"/s/player/deadbeef/player_ias.vflset/en_US/base.js";
	ASSERT_EQ(strlen(expected), p.sz);
	ASSERT_STRN_EQ(expected, p.data, p.sz);
	PASS();
}

TEST
find_js_timestamp_negative_re_pattern(void)
{
	const struct string_view json =
		MAKE_TEST_STRING("{signatureTimestamp:\"foobar\"}");

	long long int timestamp = -1;
	auto_result err = find_js_timestamp(&json, &timestamp);

	ASSERT_EQ(ERR_JS_TIMESTAMP_FIND, err.err);
	ASSERT_GT(0, timestamp);
	PASS();
}

TEST
find_js_timestamp_negative_strtoll_erange(void)
{
	const struct string_view json =
		MAKE_TEST_STRING("{signatureTimestamp:9223372036854775808}");

	long long int timestamp = -1;
	auto_result err = find_js_timestamp(&json, &timestamp);

	ASSERT_EQ(ERR_JS_TIMESTAMP_PARSE_LL, err.err);
	ASSERT_EQ(ERANGE, err.num);
	ASSERT_STR_EQ("9223372036854775808", err.msg);
	ASSERT_GT(0, timestamp);
	PASS();
}

TEST
find_js_timestamp_positive_strtoll_max(void)
{
	const struct string_view json =
		MAKE_TEST_STRING("{signatureTimestamp:9223372036854775807}");

	long long int timestamp = 0;
	auto_result err = find_js_timestamp(&json, &timestamp);

	ASSERT_EQ(OK, err.err);
	ASSERT_EQ(LLONG_MAX, timestamp);
	PASS();
}

TEST
find_js_timestamp_positive_simple(void)
{
	const struct string_view json =
		MAKE_TEST_STRING("{signatureTimestamp:19957}");

	long long int timestamp = 0;
	auto_result err = find_js_timestamp(&json, &timestamp);

	ASSERT_EQ(OK, err.err);
	ASSERT_EQ(19957, timestamp);
	PASS();
}

TEST
find_js_deobfuscator_magic_global_negative(void)
{
	struct string_view magic = {0};

	const struct string_view js =
		MAKE_TEST_STRING("var magic=\"not an integer\";");
	auto_result err = find_js_deobfuscator_magic_global(&js, &magic);

	ASSERT_EQ(ERR_JS_DEOBFUSCATOR_MAGIC_FIND, err.err);
	ASSERT_EQ(NULL, magic.data);
	ASSERT_EQ(0, magic.sz);
	PASS();
}

TEST
find_js_deobfuscator_magic_global_positive(void)
{
	struct string_view magic = {0};

	const struct string_view js = MAKE_TEST_STRING("var magic=7777777;");
	auto_result err = find_js_deobfuscator_magic_global(&js, &magic);

	ASSERT_EQ(OK, err.err);
	ASSERT_EQ(js.sz - 1, magic.sz);
	ASSERT_STRN_EQ(js.data, magic.data, magic.sz);
	PASS();
}

TEST
find_js_deobfuscator_negative_first_match_fail(void)
{
	struct string_view deobfuscator = {0};

	const struct string_view js = MAKE_TEST_STRING(
		"var _yt_player={};(function(g){})(_yt_player);");
	auto_result err = find_js_deobfuscator(&js, &deobfuscator);

	ASSERT_EQ(ERR_JS_DEOB_FIND_FUNC_ONE, err.err);
	ASSERT_EQ(NULL, deobfuscator.data);
	ASSERT_EQ(0, deobfuscator.sz);
	PASS();
}

TEST
find_js_deobfuscator_negative_second_match_fail(void)
{
	struct string_view deobfuscator = {0};

	const struct string_view js = MAKE_TEST_STRING("&&(c=ODa[0](c),");
	auto_result err = find_js_deobfuscator(&js, &deobfuscator);

	ASSERT_EQ(ERR_JS_DEOB_FIND_FUNC_TWO, err.err);
	ASSERT_EQ(NULL, deobfuscator.data);
	ASSERT_EQ(0, deobfuscator.sz);
	PASS();
}

TEST
find_js_deobfuscator_negative_third_match_fail(void)
{
	struct string_view deobfuscator = {0};

	const struct string_view js =
		MAKE_TEST_STRING("&&(c=ODa[0](c),\nvar ODa=[Pma];");
	auto_result err = find_js_deobfuscator(&js, &deobfuscator);

	ASSERT_EQ(ERR_JS_DEOB_FIND_FUNC_BODY, err.err);
	ASSERT_EQ(NULL, deobfuscator.data);
	ASSERT_EQ(0, deobfuscator.sz);
	PASS();
}

TEST
find_js_deobfuscator_positive_simple(void)
{
	struct string_view deobfuscator = {0};

	const struct string_view js = MAKE_TEST_STRING(
		"&&(c=ODa[0](c),\nvar ODa=[Pma];\nPma=function(a)"
		"{return b.join(\"\")};");
	auto_result err = find_js_deobfuscator(&js, &deobfuscator);
	ASSERT_EQ(OK, err.err);

	const char expected[] = "function(a){return b.join(\"\")};";
	ASSERT_EQ(strlen(expected), deobfuscator.sz);
	ASSERT_STRN_EQ(expected, deobfuscator.data, deobfuscator.sz);
	PASS();
}

TEST
find_js_deobfuscator_positive_with_escaping(void)
{
	struct string_view deobfuscator = {0};

	const struct string_view js = MAKE_TEST_STRING(
		"&&(c=$aa[0](c),\nvar $aa=[$bb];\n$bb=function(a)"
		"{return b.join(\"\")};");
	auto_result err = find_js_deobfuscator(&js, &deobfuscator);
	ASSERT_EQ(OK, err.err);

	const char expected[] = "function(a){return b.join(\"\")};";
	ASSERT_EQ(strlen(expected), deobfuscator.sz);
	ASSERT_STRN_EQ(expected, deobfuscator.data, deobfuscator.sz);
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
	RUN_TEST(find_js_deobfuscator_magic_global_negative);
	RUN_TEST(find_js_deobfuscator_magic_global_positive);
	RUN_TEST(find_js_deobfuscator_negative_first_match_fail);
	RUN_TEST(find_js_deobfuscator_negative_second_match_fail);
	RUN_TEST(find_js_deobfuscator_negative_third_match_fail);
	RUN_TEST(find_js_deobfuscator_positive_simple);
	RUN_TEST(find_js_deobfuscator_positive_with_escaping);
}

static const struct string_view MAGIC = MAKE_TEST_STRING("var MY_MAGIC=123456");

static WARN_UNUSED result_t
got_result_noop(const char *val __attribute__((unused)),
                size_t pos __attribute__((unused)),
                void *userdata __attribute__((unused)))
{
	return RESULT_OK;
}

static const struct call_ops CALL_NOOP = {
	.got_result = got_result_noop,
};

TEST
call_with_duktape_pcompile_fail(void)
{
	char *args[2];
	args[0] = "Hello, World!";
	args[1] = NULL;

	const struct string_view js =
		MAKE_TEST_STRING("\"Not a valid function definition!\"");

	auto_result err = call_js_foreach(&MAGIC, &js, args, &CALL_NOOP, NULL);
	ASSERT_EQ(ERR_JS_CALL_COMPILE, err.err);
	PASS();
}

TEST
call_with_duktape_pcall_fail(void)
{
	char *args[2];
	args[0] = "Hello, World!";
	args[1] = NULL;

	const struct string_view js =
		MAKE_TEST_STRING("function(a){return not_defined;};");

	auto_result err = call_js_foreach(&MAGIC, &js, args, &CALL_NOOP, NULL);
	ASSERT_EQ(ERR_JS_CALL_INVOKE, err.err);
	PASS();
}

TEST
call_with_duktape_pcall_incorrect_result_type(void)
{
	char *args[2];
	args[0] = "Hello, World!";
	args[1] = NULL;

	const struct string_view js =
		MAKE_TEST_STRING("function(a){return true;};");

	auto_result err = call_js_foreach(&MAGIC, &js, args, &CALL_NOOP, NULL);
	ASSERT_EQ(ERR_JS_CALL_GET_RESULT, err.err);
	PASS();
}

struct result_copy {
	char str[24];
};

static void
result_copy_init(struct result_copy *c)
{
	c->str[0] = '\0';
}

static WARN_UNUSED result_t
copy_result(const char *val, size_t pos __attribute__((unused)), void *userdata)
{
	struct result_copy *result = (struct result_copy *)userdata;
	const size_t sz = strlen(val);
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

	char *args[2];
	args[0] = "Hello, World!";
	args[1] = NULL;

	const struct string_view js = MAKE_TEST_STRING(
		"function(a){return a.toUpperCase() + \" \" + MY_MAGIC;};");

	auto_result err = call_js_foreach(&MAGIC, &js, args, &cops, &result);
	ASSERT_EQ(OK, err.err);
	ASSERT_STR_EQ("HELLO, WORLD! 123456", result.str);
	PASS();
}

SUITE(call_with_duktape)
{
	RUN_TEST(call_with_duktape_pcompile_fail);
	RUN_TEST(call_with_duktape_pcall_fail);
	RUN_TEST(call_with_duktape_pcall_incorrect_result_type);
	RUN_TEST(call_with_duktape_minimum_valid_function);
}
