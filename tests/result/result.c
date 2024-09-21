#include "result.h"

#include "coverage.h"
#include "debug.h"
#include "greatest.h"

// TODO: add result enumeration method to each subsystem? then test here, or in each subsystem's test file?
// TODO: ... or just hook all enumeration methods up to a CLI command like `./youtube-unthrottle --list-errors`, and exercise error codepaths by running that CLI command, sorta like --try-sandbox?
#if 0
#define ASSERT_IN(haystack, needle)                                            \
	do {                                                                   \
		debug("Checking for \"%s\" in \"%s\"", needle, haystack);      \
		ASSERT_NEQ(NULL, strstr(haystack, needle));                    \
	} while (0)

static WARN_UNUSED const char *
make(int err_type)
{
	result_t err = {
		.err = err_type,
	};
	return result_to_str(err);
}

static WARN_UNUSED const char *
make_n(int err_type)
{
	result_t err = {
		.err = err_type,
		.num = 0,
	};
	return result_to_str(err);
}

static WARN_UNUSED const char *
make_s(int err_type)
{
	result_t err = {
		.err = err_type,
		.msg = "foobar",
	};
	return result_to_str(err);
}

static WARN_UNUSED const char *
make_ns(int err_type)
{
	result_t err = {
		.err = err_type,
		.num = 0,
		.msg = "foobar",
	};
	return result_to_str(err);
}

TEST
print_to_str_each_enum_value(void)
{
	ASSERT_IN(make(OK), "Success");
	ASSERT_IN(make(ERR_JS_PARSE_JSON_ALLOC_HEAP), CANNOT_ALLOC);
	ASSERT_IN(make_s(ERR_JS_PARSE_JSON_DECODE), "Error in duk_json_decode");
	ASSERT_IN(make(ERR_JS_PARSE_JSON_GET_STREAMINGDATA), CANNOT_GET);
	ASSERT_IN(make(ERR_JS_PARSE_JSON_GET_ADAPTIVEFORMATS), CANNOT_GET);
	ASSERT_IN(make(ERR_JS_PARSE_JSON_ADAPTIVEFORMATS_TYPE), "Cannot iter");
	ASSERT_IN(make(ERR_JS_PARSE_JSON_ELEM_TYPE), "not object-coercible");
	ASSERT_IN(make(ERR_JS_PARSE_JSON_ELEM_MIMETYPE), CANNOT_GET);
	ASSERT_IN(make(ERR_JS_PARSE_JSON_ELEM_URL), CANNOT_GET);
	ASSERT_IN(make_n(ERR_JS_PARSE_JSON_CALLBACK_GOT_CIPHERTEXT_URL),
	          "Cannot set ciphertext URL");
	ASSERT_IN(make(ERR_JS_BASEJS_URL_FIND), CANNOT_FIND);
	ASSERT_IN(make(ERR_JS_BASEJS_URL_ALLOC), "Cannot strndup");
	ASSERT_IN(make(ERR_JS_TIMESTAMP_FIND), CANNOT_FIND);
	ASSERT_IN(make_ns(ERR_JS_TIMESTAMP_PARSE_TO_LONGLONG),
	          "Error in strtoll");
	ASSERT_IN(make(ERR_JS_DEOBFUSCATOR_ALLOC), CANNOT_ALLOC);
	ASSERT_IN(make(ERR_JS_DEOBFUSCATOR_FIND_FUNCTION_ONE), CANNOT_FIND);
	ASSERT_IN(make(ERR_JS_DEOBFUSCATOR_FIND_FUNCTION_TWO), CANNOT_FIND);
	ASSERT_IN(make(ERR_JS_DEOBFUSCATOR_FIND_FUNCTION_BODY), CANNOT_FIND);
	ASSERT_IN(make(ERR_JS_CALL_ALLOC), CANNOT_ALLOC);
	ASSERT_IN(make(ERR_JS_CALL_COMPILE), "Error in duk_pcompile");
	ASSERT_IN(make(ERR_JS_CALL_INVOKE), "Error in duk_pcall");
	ASSERT_IN(make(ERR_JS_CALL_GET_RESULT), "Error fetching");
	ASSERT_IN(make_n(ERR_SANDBOX_LANDLOCK_CREATE_RULESET),
	          "Error in landlock");
	ASSERT_IN(make_ns(ERR_SANDBOX_LANDLOCK_OPEN_O_PATH), "Error opening");
	ASSERT_IN(make_ns(ERR_SANDBOX_LANDLOCK_ADD_RULE_PATH),
	          "Error in landlock");
	ASSERT_IN(make_n(ERR_SANDBOX_LANDLOCK_ADD_RULE_PORT),
	          "Error in landlock");
	ASSERT_IN(make_n(ERR_SANDBOX_LANDLOCK_SET_NO_NEW_PRIVS),
	          "Error in prctl");
	ASSERT_IN(make_n(ERR_SANDBOX_LANDLOCK_RESTRICT_SELF),
	          "Error in landlock");
	ASSERT_IN(make_n(ERR_SANDBOX_SECCOMP_INIT), "Error in seccomp_init");
	ASSERT_IN(make_n(ERR_SANDBOX_SECCOMP_LOAD), "Error in seccomp_load");
	ASSERT_IN(make_n(ERR_TMPFILE), "Error in tmpfile");
	ASSERT_IN(make_n(ERR_TMPFILE_FILENO), "Error fileno");
	ASSERT_IN(make_n(ERR_TMPFILE_DUP), "Error dup");
	ASSERT_IN(make_n(ERR_TMPFILE_FSTAT), "Error fstat");
	ASSERT_IN(make_n(ERR_TMPFILE_MMAP), "Error mmap");
	ASSERT_IN(make(ERR_URL_GLOBAL_INIT), "Cannot use URL functions");
	ASSERT_IN(make(ERR_URL_PREPARE_ALLOC), CANNOT_ALLOC);
	ASSERT_IN(make_n(ERR_URL_PREPARE_SET_PART_SCHEME), CANNOT_SET);
	ASSERT_IN(make_n(ERR_URL_PREPARE_SET_PART_HOST), CANNOT_SET);
	ASSERT_IN(make_n(ERR_URL_PREPARE_SET_PART_PATH), CANNOT_SET);
	ASSERT_IN(make(ERR_URL_DOWNLOAD_ALLOC), CANNOT_ALLOC);
	ASSERT_IN(make_n(ERR_URL_DOWNLOAD_SET_OPT_WRITEDATA), CANNOT_SET);
	ASSERT_IN(make_n(ERR_URL_DOWNLOAD_SET_OPT_WRITEFUNCTION), CANNOT_SET);
	ASSERT_IN(make_n(ERR_URL_DOWNLOAD_SET_OPT_USERAGENT), CANNOT_SET);
	ASSERT_IN(make_n(ERR_URL_DOWNLOAD_SET_OPT_URL_STRING), CANNOT_SET);
	ASSERT_IN(make_n(ERR_URL_DOWNLOAD_SET_OPT_URL_OBJECT), CANNOT_SET);
	ASSERT_IN(make_n(ERR_URL_DOWNLOAD_SET_OPT_HTTP_HEADER), CANNOT_SET);
	ASSERT_IN(make_n(ERR_URL_DOWNLOAD_SET_OPT_POST_BODY), CANNOT_SET);
	ASSERT_IN(make_n(ERR_URL_DOWNLOAD_PERFORM), "Error performing");
	ASSERT_IN(make(ERR_YOUTUBE_INNERTUBE_POST_ID), CANNOT_FIND);
	ASSERT_IN(make(ERR_YOUTUBE_INNERTUBE_POST_ALLOC), CANNOT_ALLOC);
	ASSERT_IN(make(ERR_YOUTUBE_N_PARAM_QUERY_ALLOC), CANNOT_ALLOC);
	ASSERT_IN(make_n(ERR_YOUTUBE_N_PARAM_QUERY_GET), CANNOT_GET);
	ASSERT_IN(make(ERR_YOUTUBE_N_PARAM_QUERY_SET), "Cannot clear");
	ASSERT_IN(make_s(ERR_YOUTUBE_N_PARAM_FIND_IN_QUERY), "No n-parameter");
	ASSERT_IN(make(ERR_YOUTUBE_N_PARAM_KVPAIR_ALLOC), CANNOT_ALLOC);
	ASSERT_IN(make_n(ERR_YOUTUBE_N_PARAM_QUERY_APPEND_PLAINTEXT),
	          "Cannot append");
	ASSERT_IN(make_n(ERR_YOUTUBE_STREAM_VISITOR_GET_URL), CANNOT_GET);
	PASS();
}

#endif

#define STARTSWITH(s, prefix) (0 == strncmp(s, prefix, strlen(prefix)))

static const char CANNOT_ALLOC[] = "Cannot allocate";
static const char CANNOT_GET[] = "Cannot get";
static const char CANNOT_FIND[] = "Cannot find";
static const char CANNOT_SET[] = "Cannot set";

static void
rs_free(char **strp)
{
	free(*strp);
}

extern void test_result_js_foreach(void (*visit)(size_t, result_t));

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

	char *msg __attribute__((cleanup(rs_free))) = result_to_str(r);
	const char *expected = EXPECTED[pos];

	const bool cur = STARTSWITH(msg, expected);
	const char *res = cur ? "PASS" : "FAIL";
	debug("%s: \"%s\" starts with \"%s\"?", res, msg, expected);
	RESULT_JS_MATCH = cur && RESULT_JS_MATCH;
}

TEST
print_to_str_result_js(void)
{
	test_result_js_foreach(test_result_js_visit);
	ASSERT(RESULT_JS_MATCH);
	PASS();
}

SUITE(print_to_str)
{
	RUN_TEST(print_to_str_result_js);
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
