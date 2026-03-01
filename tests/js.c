#include "lib/js.h"

#include "greatest.h"
#include "sys/array.h"
#include "sys/debug.h"
#include "test_macros.h"

#include <assert.h>
#include <limits.h>

static WARN_UNUSED result_t
parse_callback_noop(const char *val MAYBE_UNUSED, void *userdata MAYBE_UNUSED)
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
	struct parse_values parsed
		__attribute__((cleanup(parse_values_cleanup))) = {0};
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
root_number_nan(void)
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
extern SUITE(invalid_json)
{
	RUN_TEST(root_empty);
	RUN_TEST(root_number_nan);
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
	ASSERT_EQ(ERR_JS_PARSE_JSON_GET_STREAMINGDATA, parse("null"));
	PASS();
}

TEST
root_number(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_GET_STREAMINGDATA, parse("-123.456"));
	PASS();
}

TEST
root_string_empty(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_GET_STREAMINGDATA, parse("\"\""));
	PASS();
}

TEST
root_string_nonempty(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_GET_STREAMINGDATA,
	          parse("\"Hello, World!\""));
	PASS();
}

TEST
root_boolean(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_GET_STREAMINGDATA, parse("false"));
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
extern SUITE(incorrect_root_type)
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
missing_streaming_data_key(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_GET_STREAMINGDATA,
	          parse("{\"foo\": \"bar\"}"));
	PASS();
}

TEST
incorrect_streaming_data_value_type(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_GET_STREAMINGDATA,
	          parse("{\"streamingData\": 1}"));
	PASS();
}

TEST
missing_adaptive_formats_key(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_GET_ADAPTIVEFORMATS,
	          parse("{\"streamingData\": {\"foo\": \"bar\"}}"));
	PASS();
}

TEST
incorrect_adaptive_formats_value_type(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_GET_ADAPTIVEFORMATS,
	          parse("{\"streamingData\": {\"adaptiveFormats\": 2}}"));
	PASS();
}

TEST
incorrect_adaptive_formats_element_type(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_ELEM_TYPE,
	          parse("{\"streamingData\": {\"adaptiveFormats\": [3]}}"));
	PASS();
}

TEST
missing_mime_type_key(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_ELEM_MIMETYPE,
	          parse("{\"streamingData\": {\"adaptiveFormats\": "
	                "[{\"foo\": \"bar\"}]"
	                "}}"));
	PASS();
}

TEST
incorrect_mime_type_value_type(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_ELEM_MIMETYPE,
	          parse("{\"streamingData\": {\"adaptiveFormats\": "
	                "[{\"mimeType\": 4}]"
	                "}}"));
	PASS();
}

TEST
missing_quality_label_key(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_ELEM_QUALITY,
	          parse("{\"streamingData\": {\"adaptiveFormats\": [{"
	                "\"mimeType\": \"video/foo\""
	                "}]}}"));
	PASS();
}

TEST
incorrect_quality_label_value_type(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_ELEM_QUALITY,
	          parse("{\"streamingData\": {\"adaptiveFormats\": [{"
	                "\"mimeType\": \"video/foo\","
	                "\"qualityLabel\": 5"
	                "}]}}"));
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
no_matching_adaptive_formats_element_because_empty(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_NO_MATCH,
	          parse("{\"streamingData\": {\"adaptiveFormats\": []}}"));
	PASS();
}

TEST
no_matching_adaptive_formats_element_because_mimetype(void)
{
	ASSERT_EQ(ERR_JS_PARSE_JSON_NO_MATCH,
	          parse("{\"streamingData\": {\"adaptiveFormats\": [{"
	                "\"mimeType\": \"audio/foo\","
	                "\"qualityLabel\": \"foobar\","
	                "\"itag\": 251"
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
	          parse("{\"streamingData\": {"
	                "\"adaptiveFormats\": [{"
	                "\"mimeType\": \"video/foo\","
	                "\"qualityLabel\": \"foobar\","
	                "\"itag\": 299"
	                "}],"
	                "\"serverAbrStreamingUrl\": 6"
	                "}}"));
	PASS();
}

TEST
missing_playback_config_key(void)
{
	ASSERT_EQ(ERR_JS_PLAYBACK_CONFIG_FIND,
	          parse("{\"streamingData\": {"
	                "\"adaptiveFormats\": [{"
	                "\"mimeType\": \"video/foo\","
	                "\"qualityLabel\": \"foobar\","
	                "\"itag\": 299"
	                "}],"
	                "\"serverAbrStreamingUrl\": \"https://foo.test\""
	                "}}"));
	PASS();
}

TEST
incorrect_playback_config_value_type(void)
{
	ASSERT_EQ(ERR_JS_PLAYBACK_CONFIG_FIND,
	          parse("{\"streamingData\": {"
	                "\"adaptiveFormats\": [{"
	                "\"mimeType\": \"video/foo\","
	                "\"qualityLabel\": \"foobar\","
	                "\"itag\": 299"
	                "}],"
	                "\"serverAbrStreamingUrl\": \"https://foo.test\","
	                "\"videoPlaybackUstreamerConfig\": 456"
	                "}}"));
	PASS();
}

/*
 * Test that incorrect JSON content shape does not crash.
 */
extern SUITE(incorrect_shape)
{
	RUN_TEST(root_object_empty);
	RUN_TEST(missing_streaming_data_key);
	RUN_TEST(incorrect_streaming_data_value_type);
	RUN_TEST(missing_adaptive_formats_key);
	RUN_TEST(incorrect_adaptive_formats_value_type);
	RUN_TEST(incorrect_adaptive_formats_element_type);
	RUN_TEST(missing_mime_type_key);
	RUN_TEST(incorrect_mime_type_value_type);
	RUN_TEST(missing_quality_label_key);
	RUN_TEST(incorrect_quality_label_value_type);
	RUN_TEST(missing_itag_key);
	RUN_TEST(incorrect_itag_value_type);
	RUN_TEST(no_matching_adaptive_formats_element_because_empty);
	RUN_TEST(no_matching_adaptive_formats_element_because_mimetype);
	RUN_TEST(missing_sabr_url_key);
	RUN_TEST(incorrect_sabr_url_value_type);
	RUN_TEST(missing_playback_config_key);
	RUN_TEST(incorrect_playback_config_value_type);
}

TEST
minimum_json_with_correct_shape(void)
{
	const struct string_view json = MAKE_TEST_STRING(
		"{\"streamingData\": {"
		"\"adaptiveFormats\": [{"
		"\"mimeType\": \"video/foo\","
		"\"qualityLabel\": \"foobar\","
		"\"itag\": 299"
		"}],"
		"\"serverAbrStreamingUrl\": \"https://foo.test\"},"
		"\"playerConfig\": {"
		"\"mediaCommonConfig\": {"
		"\"mediaUstreamerRequestConfig\": {"
		"\"videoPlaybackUstreamerConfig\": \"cGxheWJhY2sK\""
		"}}}}");

	struct parse_values parsed
		__attribute__((cleanup(parse_values_cleanup))) = {0};
	auto_result err = parse_json(&json, &NOOP, &parsed);
	ASSERT_EQ(OK, err.err);
	ASSERT_EQ(299, parsed.itag);

	PASS();
}

TEST
extra_adaptive_formats_elements(void)
{
	const struct string_view json = MAKE_TEST_STRING(
		"{\"streamingData\": {"
		"\"adaptiveFormats\": ["
		"{\"mimeType\": \"video/foo\","
		" \"qualityLabel\": \"foobar\","
		" \"itag\": 100},"
		"{\"mimeType\": \"video/foo\","
		" \"qualityLabel\": \"foobar\","
		" \"itag\": 200}"
		"],"
		"\"serverAbrStreamingUrl\": \"https://foo.test\"},"
		"\"playerConfig\": {"
		"\"mediaCommonConfig\": {"
		"\"mediaUstreamerRequestConfig\": {"
		"\"videoPlaybackUstreamerConfig\": \"cGxheWJhY2sK\""
		"}}}}");

	struct parse_values parsed
		__attribute__((cleanup(parse_values_cleanup))) = {0};
	auto_result err = parse_json(&json, &NOOP, &parsed);
	ASSERT_EQ(OK, err.err);
	ASSERT_EQ(100, parsed.itag);

	PASS();
}

TEST
skip_non_video_adaptive_formats_elements(void)
{
	const struct string_view json = MAKE_TEST_STRING(
		"{\"streamingData\": {"
		"\"adaptiveFormats\": ["
		"{\"mimeType\": \"audio/foo\","
		" \"qualityLabel\": \"foobar\","
		" \"itag\": 100},"
		"{\"mimeType\": \"video/foo\","
		" \"qualityLabel\": \"foobar\","
		" \"itag\": 10}"
		"],"
		"\"serverAbrStreamingUrl\": \"https://foo.test\"},"
		"\"playerConfig\": {"
		"\"mediaCommonConfig\": {"
		"\"mediaUstreamerRequestConfig\": {"
		"\"videoPlaybackUstreamerConfig\": \"cGxheWJhY2sK\""
		"}}}}");

	struct parse_values parsed
		__attribute__((cleanup(parse_values_cleanup))) = {0};
	auto_result err = parse_json(&json, &NOOP, &parsed);
	ASSERT_EQ(OK, err.err);
	ASSERT_EQ(10, parsed.itag);

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
choose_adaptive_formats_elements(void)
{
	const struct string_view json = MAKE_TEST_STRING(
		"{\"streamingData\": {"
		"\"adaptiveFormats\": ["
		"{\"mimeType\": \"video/foo\","
		" \"qualityLabel\": \"skip\","
		" \"itag\": 100},"
		"{\"mimeType\": \"video/foo\","
		" \"qualityLabel\": \"foobar\","
		" \"itag\": 200}"
		"],"
		"\"serverAbrStreamingUrl\": \"https://foo.test\"},"
		"\"playerConfig\": {"
		"\"mediaCommonConfig\": {"
		"\"mediaUstreamerRequestConfig\": {"
		"\"videoPlaybackUstreamerConfig\": \"cGxheWJhY2sK\""
		"}}}}");

	struct parse_ops pops = {
		.choose_quality = choose_quality_skip_marked_entries,
		.userdata = "skip",
	};
	struct parse_values parsed
		__attribute__((cleanup(parse_values_cleanup))) = {0};
	auto_result err = parse_json(&json, &pops, &parsed);
	ASSERT_EQ(OK, err.err);
	ASSERT_EQ(200, parsed.itag);

	PASS();
}

extern SUITE(correct_shape)
{
	RUN_TEST(minimum_json_with_correct_shape);
	RUN_TEST(extra_adaptive_formats_elements);
	RUN_TEST(skip_non_video_adaptive_formats_elements);
	RUN_TEST(choose_adaptive_formats_elements);
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
	ASSERT_EQ(NULL, d.magic[1].data);
	ASSERT_EQ(0, d.magic[1].sz);
	PASS();
}

TEST
find_js_deobfuscator_magic_global_positive(void)
{
	struct deobfuscator d = {0};

	const struct string_view js =
		MAKE_TEST_STRING("var _yt_player={};(function(g){'use strict';"
	                         "var m2='MAGIC'"
	                         "})(_yt_player);");
	auto_result err = find_js_deobfuscator_magic_global(&js, &d);

	ASSERT_EQ(OK, err.err);
	ASSERT_STRN_EQ("var g = {}", d.magic[0].data, 10);
	ASSERT_STRN_EQ("var m2='MAGIC'", d.magic[1].data, d.magic[1].sz);
	PASS();
}

TEST
find_js_deobfuscator_magic_global_positive_with_newlines(void)
{
	struct deobfuscator d = {0};

	const struct string_view js =
		MAKE_TEST_STRING("var _yt_player={};(function(g){'use strict';"
	                         "var m2=['MA',\n'GIC']"
	                         "})(_yt_player);");
	auto_result err = find_js_deobfuscator_magic_global(&js, &d);

	ASSERT_EQ(OK, err.err);
	ASSERT_STRN_EQ("var g = {}", d.magic[0].data, 10);
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
	ASSERT_EQ(NULL, d.funcname.data);
	ASSERT_EQ(0, d.funcname.sz);
	PASS();
}

TEST
find_js_deobfuscator_negative_second_match_fail(void)
{
	struct deobfuscator d = {0};

	const struct string_view js = MAKE_TEST_STRING("c=ODa[0](c),");
	auto_result err = find_js_deobfuscator(&js, &d);

	ASSERT_EQ(ERR_JS_DEOB_FIND_FUNC_TWO, err.err);
	ASSERT_EQ(NULL, d.funcname.data);
	ASSERT_EQ(0, d.funcname.sz);
	PASS();
}

TEST
find_js_deobfuscator_positive_simple(void)
{
	struct deobfuscator d = {0};

	const struct string_view js =
		MAKE_TEST_STRING("c=ODa[0](c);var ODa=[Pma];");
	auto_result err = find_js_deobfuscator(&js, &d);
	ASSERT_EQ(OK, err.err);

	ASSERT_EQ(3, d.funcname.sz);
	ASSERT_STRN_EQ("Pma", d.funcname.data, d.funcname.sz);
	PASS();
}

TEST
find_js_deobfuscator_positive_with_escaping_and_newlines(void)
{
	struct deobfuscator d = {0};

	const struct string_view js =
		MAKE_TEST_STRING("c=$aa[0](c);\nvar $aa=[$bb];");
	auto_result err = find_js_deobfuscator(&js, &d);
	ASSERT_EQ(OK, err.err);

	ASSERT_EQ(3, d.funcname.sz);
	ASSERT_STRN_EQ("$bb", d.funcname.data, d.funcname.sz);
	PASS();
}

extern SUITE(find_with_pcre)
{
	RUN_TEST(find_base_js_url_negative);
	RUN_TEST(find_base_js_url_positive);
	RUN_TEST(find_js_timestamp_negative_re_pattern);
	RUN_TEST(find_js_timestamp_negative_strtoll_erange);
	RUN_TEST(find_js_timestamp_positive_strtoll_max);
	RUN_TEST(find_js_timestamp_positive_simple);
	RUN_TEST(find_js_deobfuscator_magic_global_negative_first);
	RUN_TEST(find_js_deobfuscator_magic_global_positive);
	RUN_TEST(find_js_deobfuscator_magic_global_positive_with_newlines);
	RUN_TEST(find_js_deobfuscator_negative_first_match_fail);
	RUN_TEST(find_js_deobfuscator_negative_second_match_fail);
	RUN_TEST(find_js_deobfuscator_positive_simple);
	RUN_TEST(find_js_deobfuscator_positive_with_escaping_and_newlines);
}

static const char *const TEST_ARGS[] = {
	"Hello, World!",
	NULL,
};

static WARN_UNUSED result_t
got_result_noop(const char *val MAYBE_UNUSED,
                size_t pos MAYBE_UNUSED,
                void *userdata MAYBE_UNUSED)
{
	return RESULT_OK;
}

static const struct call_ops CALL_NOOP = {
	.got_result = got_result_noop,
};

TEST
js_eval_fail(void)
{
	const struct deobfuscator d = {
		{
			MAKE_TEST_STRING("var M1=function(){return 123}"),
			MAKE_TEST_STRING("var BAD_MAGIC=\"dangling"),
		},
		MAKE_TEST_STRING("M1"),
	};

	auto_result err = call_js_foreach(&d, TEST_ARGS, &CALL_NOOP, NULL);
	ASSERT_EQ(ERR_JS_CALL_EVAL_MAGIC, err.err);
	PASS();
}

TEST
js_function_lookup_fail(void)
{
	const struct deobfuscator d = {
		{
			MAKE_TEST_STRING("var M1=function(){return 123}"),
			MAKE_TEST_STRING("var M2=function(){return 456}"),
		},
		MAKE_TEST_STRING("function_does_not_exist"),
	};

	auto_result err = call_js_foreach(&d, TEST_ARGS, &CALL_NOOP, NULL);
	ASSERT_EQ(ERR_JS_CALL_INVOKE, err.err);
	PASS();
}

TEST
js_call_fail(void)
{
	const struct deobfuscator d = {
		{
			MAKE_TEST_STRING("var M1=function(){return nodef}"),
			MAKE_TEST_STRING("var M2=function(){return 456}"),
		},
		MAKE_TEST_STRING("M1"),
	};

	auto_result err = call_js_foreach(&d, TEST_ARGS, &CALL_NOOP, NULL);
	ASSERT_EQ(ERR_JS_CALL_INVOKE, err.err);
	PASS();
}

TEST
js_call_incorrect_result_type(void)
{
	const struct deobfuscator d = {
		{
			MAKE_TEST_STRING("var M1=function(){return true}"),
			MAKE_TEST_STRING("var M2=function(){return 456}"),
		},
		MAKE_TEST_STRING("M1"),
	};

	auto_result err = call_js_foreach(&d, TEST_ARGS, &CALL_NOOP, NULL);
	ASSERT_EQ(ERR_JS_CALL_GET_RESULT, err.err);
	PASS();
}

#define RESULT_BUFFER_SIZE 24

struct result_copy {
	char str[RESULT_BUFFER_SIZE];
};

static void
result_copy_init(struct result_copy *c)
{
	c->str[0] = '\0';
}

static WARN_UNUSED result_t
copy_result(const char *val, size_t pos MAYBE_UNUSED, void *userdata)
{
	struct result_copy *result = (struct result_copy *)userdata;
	const size_t sz = strlen(val);
	assert(RESULT_BUFFER_SIZE >= sz);
	memcpy(result->str, val, sz);
	result->str[sz] = '\0';
	debug("Copied result: %s", result->str);
	return RESULT_OK;
}

#undef RESULT_BUFFER_SIZE

TEST
js_minimum_valid_function(void)
{
	struct call_ops cops = {
		.got_result = copy_result,
	};

	struct result_copy result;
	result_copy_init(&result);

	const struct deobfuscator d = {
		{
			MAKE_TEST_STRING("var M1='56'"),
			MAKE_TEST_STRING("var M2=function(a){"
	                                 "return a.split(',')[0]+M1+'78'}"),
		},
		MAKE_TEST_STRING("M2"),
	};

	auto_result err = call_js_foreach(&d, TEST_ARGS, &cops, &result);
	ASSERT_EQ(OK, err.err);
	ASSERT_STR_EQ("Hello5678", result.str);
	PASS();
}

extern SUITE(js_engine)
{
	RUN_TEST(js_eval_fail);
	RUN_TEST(js_function_lookup_fail);
	RUN_TEST(js_call_fail);
	RUN_TEST(js_call_incorrect_result_type);
	RUN_TEST(js_minimum_valid_function);
}
