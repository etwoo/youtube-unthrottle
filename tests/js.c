#include "lib/js.h"

#include "greatest.h"
#include "sys/array.h"
#include "sys/debug.h"
#include "test_macros.h"

#include <assert.h>
#include <limits.h>

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
find_sabr_url_negative(void)
{
	struct string_view p = {0};
	const struct string_view html = MAKE_TEST_STRING("<html/>");

	auto_result err = find_sabr_url(&html, &p);
	ASSERT_EQ(ERR_JS_SABR_URL_FIND, err.err);

	ASSERT_EQ(NULL, p.data);
	ASSERT_EQ(0, p.sz);
	PASS();
}

TEST
find_sabr_url_positive(void)
{
	struct string_view p = {0};
	const struct string_view html = MAKE_TEST_STRING(
		"{ \"serverAbrStreamingUrl\": \"https://foo.test\" }");

	auto_result err = find_sabr_url(&html, &p);
	ASSERT_EQ(OK, err.err);

	const char expected[] = "https://foo.test";
	ASSERT_EQ(strlen(expected), p.sz);
	ASSERT_STRN_EQ(expected, p.data, p.sz);
	PASS();
}

TEST
find_playback_config_negative(void)
{
	struct string_view p = {0};
	const struct string_view html = MAKE_TEST_STRING("<html/>");

	auto_result err = find_playback_config(&html, &p);
	ASSERT_EQ(ERR_JS_PLAYBACK_CONFIG_FIND, err.err);

	ASSERT_EQ(NULL, p.data);
	ASSERT_EQ(0, p.sz);
	PASS();
}

TEST
find_playback_config_positive(void)
{
	struct string_view p = {0};
	const struct string_view html = MAKE_TEST_STRING(
		"{ \"videoPlaybackUstreamerConfig\": \"https://foo.test\" }");

	auto_result err = find_playback_config(&html, &p);
	ASSERT_EQ(OK, err.err);

	const char expected[] = "https://foo.test";
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
find_itag_video_negative_re_pattern(void)
{
	const struct string_view json = MAKE_TEST_STRING(
		"\n        \"itag\": \"foo\","
		"\n        \"quality\": \"hd1080\",");

	long long int itag_video = -1;
	auto_result err = find_itag_video(&json, &itag_video);

	ASSERT_EQ(ERR_JS_ITAG_VIDEO_FIND, err.err);
	ASSERT_GT(0, itag_video);
	PASS();
}

TEST
find_itag_video_negative_strtoll_erange(void)
{
	const struct string_view json = MAKE_TEST_STRING(
		"\n        \"itag\": 9223372036854775808,"
		"\n        \"quality\": \"hd1080\",");

	long long int itag_video = -1;
	auto_result err = find_itag_video(&json, &itag_video);

	ASSERT_EQ(ERR_JS_ITAG_VIDEO_PARSE_LL, err.err);
	ASSERT_EQ(ERANGE, err.num);
	ASSERT_STR_EQ("9223372036854775808", err.msg);
	ASSERT_GT(0, itag_video);
	PASS();
}

TEST
find_itag_video_positive_strtoll_max(void)
{
	const struct string_view json = MAKE_TEST_STRING(
		"\n        \"itag\": 9223372036854775807,"
		"\n        \"quality\": \"hd1080\",");

	long long int itag_video = 0;
	auto_result err = find_itag_video(&json, &itag_video);

	ASSERT_EQ(OK, err.err);
	ASSERT_EQ(LLONG_MAX, itag_video);
	PASS();
}

TEST
find_itag_video_positive_simple(void)
{
	const struct string_view json = MAKE_TEST_STRING(
		"\n        \"itag\": 400,"
		"\n        \"quality\": \"medium\","
		"\n      },"
		"\n      {"
		"\n        \"itag\": 299,"
		"\n        \"quality\": \"hd1080\",");

	long long int itag_video = 0;
	auto_result err = find_itag_video(&json, &itag_video);

	ASSERT_EQ(OK, err.err);
	ASSERT_EQ(299, itag_video);
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
	RUN_TEST(find_itag_video_negative_re_pattern);
	RUN_TEST(find_itag_video_negative_strtoll_erange);
	RUN_TEST(find_itag_video_positive_strtoll_max);
	RUN_TEST(find_itag_video_positive_simple);
	RUN_TEST(find_sabr_url_negative);
	RUN_TEST(find_sabr_url_positive);
	RUN_TEST(find_playback_config_negative);
	RUN_TEST(find_playback_config_positive);
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
