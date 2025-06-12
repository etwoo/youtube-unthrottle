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
	.choose_quality = parse_callback_noop,
	.userdata = NULL,
};

static WARN_UNUSED int
parse(const char *str)
{
	struct string_view tmp = {.data = str, .sz = strlen(str)};
	struct parse_values parsed = {0};
	auto_result err = parse_json(&tmp, &NOOP, &parsed);
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
missing_itag_key(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_ELEM_ITAG,
	          parse("{\"streamingData\": {\"adaptiveFormats\": [{"
	                "\"mimeType\": \"video/foo\","
	                "\"qualityLabel\": \"foobar\""
	                "}]}}"));
	PASS();
}

TEST
incorrect_itag_value_type(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_ELEM_ITAG,
	          parse("{\"streamingData\": {\"adaptiveFormats\": [{"
	                "\"mimeType\": \"video/foo\","
	                "\"qualityLabel\": \"foobar\","
	                "\"itag\": \"fuzzbuzz\""
	                "}]}}"));
	PASS();
}

TEST
missing_sabr_url_key(void)
{
	ASSERT_EQ(ERR_JS_SABR_URL_FIND,
	          parse("{\"streamingData\": {\"adaptiveFormats\": [{"
	                "\"mimeType\": \"video/foo\","
	                "\"qualityLabel\": \"foobar\","
	                "\"itag\": 299"
	                "}]}}"));
	PASS();
}

TEST
incorrect_sabr_url_value_type(void)
{
	ASSERT_EQ(ERR_JS_SABR_URL_FIND,
	          parse("{\"streamingData\": {\"adaptiveFormats\": [{"
	                "\"mimeType\": \"video/foo\","
	                "\"qualityLabel\": \"foobar\","
	                "\"itag\": 299"
	                "}]},"
	                "\"serverAbrStreamingUrl\": 123"
	                "}"));
	PASS();
}

TEST
missing_playback_config_key(void)
{
	ASSERT_EQ(ERR_JS_PLAYBACK_CONFIG_FIND,
	          parse("{\"streamingData\": {\"adaptiveFormats\": [{"
	                "\"mimeType\": \"video/foo\","
	                "\"qualityLabel\": \"foobar\","
	                "\"itag\": 299"
	                "}]},"
	                "\"serverAbrStreamingUrl\": \"https://foo.test\""
	                "}"));
	PASS();
}

TEST
incorrect_playback_config_value_type(void)
{
	ASSERT_EQ(ERR_JS_PLAYBACK_CONFIG_FIND,
	          parse("{\"streamingData\": {\"adaptiveFormats\": [{"
	                "\"mimeType\": \"video/foo\","
	                "\"qualityLabel\": \"foobar\","
	                "\"itag\": 299"
	                "}]},"
	                "\"serverAbrStreamingUrl\": \"https://foo.test\","
	                "\"videoPlaybackUstreamerConfig\": 456"
	                "}"));
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
	RUN_TEST(missing_itag_key);
	RUN_TEST(incorrect_itag_value_type);
	RUN_TEST(missing_sabr_url_key);
	RUN_TEST(incorrect_sabr_url_value_type);
	RUN_TEST(missing_playback_config_key);
	RUN_TEST(incorrect_playback_config_value_type);
}

TEST
minimum_json_with_correct_shape(void)
{
	const struct string_view json = MAKE_TEST_STRING(
		"{\"streamingData\": {\"adaptiveFormats\": [{"
		"\"mimeType\": \"video/foo\","
		"\"qualityLabel\": \"foobar\","
		"\"itag\": 299"
		"}]},"
		"\"serverAbrStreamingUrl\": \"https://foo.test\","
		"\"videoPlaybackUstreamerConfig\": \"cGxheWJhY2sK\""
		"}");

	struct parse_values parsed = {0};
	auto_result err = parse_json(&json, &NOOP, &parsed);
	ASSERT_EQ(OK, err.err);
	ASSERT_EQ(299, parsed.itag);

	PASS();
}

TEST
extra_adaptiveFormats_elements(void)
{
	const struct string_view json = MAKE_TEST_STRING(
		"{\"streamingData\": {\"adaptiveFormats\": ["
		"{\"mimeType\": \"video/foo\","
		" \"qualityLabel\": \"foobar\","
		" \"itag\": 100},"
		"{\"mimeType\": \"video/foo\","
		" \"qualityLabel\": \"foobar\","
		" \"itag\": 200}]},"
		"\"serverAbrStreamingUrl\": \"https://foo.test\","
		"\"videoPlaybackUstreamerConfig\": \"cGxheWJhY2sK\""
		"}");

	struct parse_values parsed = {0};
	auto_result err = parse_json(&json, &NOOP, &parsed);
	ASSERT_EQ(OK, err.err);
	ASSERT_EQ(100, parsed.itag);

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
		"{\"streamingData\": {\"adaptiveFormats\": ["
		"{\"mimeType\": \"video/foo\","
		" \"qualityLabel\": \"skip\","
		" \"itag\": 100},"
		"{\"mimeType\": \"video/foo\","
		" \"qualityLabel\": \"foobar\","
		" \"itag\": 200}]},"
		"\"serverAbrStreamingUrl\": \"https://foo.test\","
		"\"videoPlaybackUstreamerConfig\": \"cGxheWJhY2sK\""
		"}");

	struct parse_ops pops = {
		.choose_quality = choose_quality_skip_marked_entries,
		.userdata = "skip",
	};
	struct parse_values parsed = {0};
	auto_result err = parse_json(&json, &pops, &parsed);
	ASSERT_EQ(OK, err.err);
	ASSERT_EQ(200, parsed.itag);

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
find_js_deobfuscator_magic_global_negative_first(void)
{
	struct deobfuscator d = {0};

	const struct string_view js = MAKE_TEST_STRING("var m1=\"wrongtype\";");
	auto_result err = find_js_deobfuscator_magic_global(&js, &d);

	ASSERT_EQ(ERR_JS_DEOB_FIND_MAGIC_ONE, err.err);
	ASSERT_EQ(NULL, d.magic[0].data);
	ASSERT_EQ(0, d.magic[0].sz);
	PASS();
}

TEST
find_js_deobfuscator_magic_global_negative_second(void)
{
	struct deobfuscator d = {0};

	const struct string_view js = MAKE_TEST_STRING("var m1=7777777;");
	auto_result err = find_js_deobfuscator_magic_global(&js, &d);

	ASSERT_EQ(ERR_JS_DEOB_FIND_MAGIC_TWO, err.err);
	ASSERT_EQ(NULL, d.magic[1].data);
	ASSERT_EQ(0, d.magic[1].sz);
	PASS();
}

TEST
find_js_deobfuscator_magic_global_positive(void)
{
	struct deobfuscator d = {0};

	const struct string_view js = MAKE_TEST_STRING(
		"'use strict';var m2='MAGIC',aa,bb,cc,dd,ee,ff,gg,hh;"
		"var m1=7777777;");
	auto_result err = find_js_deobfuscator_magic_global(&js, &d);

	ASSERT_EQ(OK, err.err);
	ASSERT_STRN_EQ("var m1=7777777", d.magic[0].data, d.magic[0].sz);
	ASSERT_STRN_EQ("var m2='MAGIC'", d.magic[1].data, d.magic[1].sz);
	PASS();
}

TEST
find_js_deobfuscator_magic_global_positive_with_newlines(void)
{
	struct deobfuscator d = {0};

	const struct string_view js = MAKE_TEST_STRING(
		"'use strict';var m2=['MA',\n'GIC'],aa,bb,cc,dd,ee,ff,gg,hh;"
		"var m1=7777777;");
	auto_result err = find_js_deobfuscator_magic_global(&js, &d);

	ASSERT_EQ(OK, err.err);
	ASSERT_STRN_EQ("var m1=7777777", d.magic[0].data, d.magic[0].sz);
	ASSERT_STRN_EQ("var m2=['MA',\n'GIC']", d.magic[1].data, d.magic[1].sz);
	PASS();
}

TEST
find_js_deobfuscator_negative_first_match_fail(void)
{
	struct deobfuscator d = {0};

	const struct string_view js = MAKE_TEST_STRING(
		"var _yt_player={};(function(g){})(_yt_player);");
	auto_result err = find_js_deobfuscator(&js, &d);

	ASSERT_EQ(ERR_JS_DEOB_FIND_FUNC_ONE, err.err);
	ASSERT_EQ(NULL, d.code.data);
	ASSERT_EQ(0, d.code.sz);
	PASS();
}

TEST
find_js_deobfuscator_negative_second_match_fail(void)
{
	struct deobfuscator d = {0};

	const struct string_view js = MAKE_TEST_STRING("&&(c=ODa[0](c),");
	auto_result err = find_js_deobfuscator(&js, &d);

	ASSERT_EQ(ERR_JS_DEOB_FIND_FUNC_TWO, err.err);
	ASSERT_EQ(NULL, d.code.data);
	ASSERT_EQ(0, d.code.sz);
	PASS();
}

TEST
find_js_deobfuscator_negative_third_match_fail(void)
{
	struct deobfuscator d = {0};

	const struct string_view js =
		MAKE_TEST_STRING("&&(c=ODa[0](c),\nvar ODa=[Pma];");
	auto_result err = find_js_deobfuscator(&js, &d);

	ASSERT_EQ(ERR_JS_DEOB_FIND_FUNC_BODY, err.err);
	ASSERT_EQ(NULL, d.code.data);
	ASSERT_EQ(0, d.code.sz);
	PASS();
}

TEST
find_js_deobfuscator_positive_simple(void)
{
	struct deobfuscator d = {0};

	const struct string_view js = MAKE_TEST_STRING(
		"&&(c=ODa[0](c),\nvar ODa=[Pma];\nPma=function(a)"
		"{return 'ABCDEF'};\nnext_global=0");
	auto_result err = find_js_deobfuscator(&js, &d);
	ASSERT_EQ(OK, err.err);

	const char expected[] = "function(a){return 'ABCDEF'};";
	ASSERT_EQ(strlen(expected), d.code.sz);
	ASSERT_STRN_EQ(expected, d.code.data, d.code.sz);
	PASS();
}

TEST
find_js_deobfuscator_positive_with_escaping_and_newlines(void)
{
	struct deobfuscator d = {0};

	const struct string_view js = MAKE_TEST_STRING(
		"&&(c=$aa[0](c),\nvar $aa=[$bb];\n$bb=function(a)"
		"{\nreturn\n'GHI'+'JKL'\n};\nnext_global=0");
	auto_result err = find_js_deobfuscator(&js, &d);
	ASSERT_EQ(OK, err.err);

	const char expected[] = "function(a){\nreturn\n'GHI'+'JKL'\n};";
	ASSERT_EQ(strlen(expected), d.code.sz);
	ASSERT_STRN_EQ(expected, d.code.data, d.code.sz);
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
	RUN_TEST(find_js_deobfuscator_magic_global_negative_first);
	RUN_TEST(find_js_deobfuscator_magic_global_negative_second);
	RUN_TEST(find_js_deobfuscator_magic_global_positive);
	RUN_TEST(find_js_deobfuscator_magic_global_positive_with_newlines);
	RUN_TEST(find_js_deobfuscator_negative_first_match_fail);
	RUN_TEST(find_js_deobfuscator_negative_second_match_fail);
	RUN_TEST(find_js_deobfuscator_negative_third_match_fail);
	RUN_TEST(find_js_deobfuscator_positive_simple);
	RUN_TEST(find_js_deobfuscator_positive_with_escaping_and_newlines);
}

#define MAGIC_VARS MAKE_TEST_STRING("var M1=56"), MAKE_TEST_STRING("var M2=78")

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
call_with_duktape_peval_fail(void)
{
	char *args[2];
	args[0] = "Hello, World!";
	args[1] = NULL;

	const struct deobfuscator d = {
		{
			MAKE_TEST_STRING("var MY_MAGIC=123456"),
			MAKE_TEST_STRING("var BAD_MAGIC=\"dangling"),
		},
		MAKE_TEST_STRING("\"Not a valid function definition\""),
	};

	auto_result err = call_js_foreach(&d, args, &CALL_NOOP, NULL);
	ASSERT_EQ(ERR_JS_CALL_EVAL_MAGIC, err.err);
	PASS();
}

TEST
call_with_duktape_pcompile_fail(void)
{
	char *args[2];
	args[0] = "Hello, World!";
	args[1] = NULL;

	const struct deobfuscator d = {
		{
			MAGIC_VARS,
		},
		MAKE_TEST_STRING("\"Not a valid function definition\""),
	};

	auto_result err = call_js_foreach(&d, args, &CALL_NOOP, NULL);
	ASSERT_EQ(ERR_JS_CALL_COMPILE, err.err);
	PASS();
}

TEST
call_with_duktape_pcall_fail(void)
{
	char *args[2];
	args[0] = "Hello, World!";
	args[1] = NULL;

	const struct deobfuscator d = {
		{
			MAGIC_VARS,
		},
		MAKE_TEST_STRING("function(a){return not_defined;};"),
	};

	auto_result err = call_js_foreach(&d, args, &CALL_NOOP, NULL);
	ASSERT_EQ(ERR_JS_CALL_INVOKE, err.err);
	PASS();
}

TEST
call_with_duktape_pcall_incorrect_result_type(void)
{
	char *args[2];
	args[0] = "Hello, World!";
	args[1] = NULL;

	const struct deobfuscator d = {
		{
			MAGIC_VARS,
		},
		MAKE_TEST_STRING("function(a){return true;};"),
	};

	auto_result err = call_js_foreach(&d, args, &CALL_NOOP, NULL);
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

	const struct deobfuscator d = {
		{
			MAGIC_VARS,
		},
		MAKE_TEST_STRING("function(a){return a.split(',')[0]+M1+M2;};"),
	};

	auto_result err = call_js_foreach(&d, args, &cops, &result);
	ASSERT_EQ(OK, err.err);
	ASSERT_STR_EQ("Hello5678", result.str);
	PASS();
}

#undef MAGIC_VARS

SUITE(call_with_duktape)
{
	RUN_TEST(call_with_duktape_peval_fail);
	RUN_TEST(call_with_duktape_pcompile_fail);
	RUN_TEST(call_with_duktape_pcall_fail);
	RUN_TEST(call_with_duktape_pcall_incorrect_result_type);
	RUN_TEST(call_with_duktape_minimum_valid_function);
}
