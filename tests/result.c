#include "result.h"

#include "greatest.h"
#include "sys/compiler_features.h"
#include "sys/debug.h"

#define ASSERT_IN(haystack, needle)                                            \
	do {                                                                   \
		auto_result_str owner = haystack;                              \
		debug("Checking for \"%s\" in \"%s\"", needle, owner);         \
		ASSERT_NEQ(NULL, strstr(owner, needle));                       \
	} while (0)

static WARN_UNUSED char *
make(int err_type)
{
	auto_result err = make_result(err_type);
	return result_to_str(err);
}

static WARN_UNUSED char *
make_n(int err_type)
{
	auto_result err = make_result(err_type, 0);
	return result_to_str(err);
}

static const char MAKE_RESULT_PLACEHOLDER[] = "foobar";

static WARN_UNUSED char *
make_s(int err_type)
{
	auto_result err = make_result(err_type, MAKE_RESULT_PLACEHOLDER);
	return result_to_str(err);
}

static WARN_UNUSED char *
make_ns(int err_type)
{
	auto_result err = make_result(err_type, 0, MAKE_RESULT_PLACEHOLDER);
	return result_to_str(err);
}

static const char CANNOT_ALLOC[] = "Cannot allocate";
static const char CANNOT_APPEND[] = "Cannot append";
static const char CANNOT_FIND[] = "Cannot find";
static const char CANNOT_GET[] = "Cannot get";
static const char CANNOT_SET[] = "Cannot set";
static const char CANNOT_UNPACK[] = "Cannot unpack";
static const char CANNOT_ISSUE[] = "Error issuing";
static const char CANNOT_CONSUME[] = "Error consuming";
static const char CANNOT_RELEASE[] = "Error releasing";

TEST
print_to_str_each_enum_value(void)
{
	ASSERT_IN(make(OK), "Success");
	ASSERT_IN(make(ERR_JS_BASEJS_URL_FIND), CANNOT_FIND);
	ASSERT_IN(make(ERR_JS_BASEJS_URL_ALLOC), "Cannot strndup");
	ASSERT_IN(make(ERR_JS_SABR_URL_FIND), CANNOT_FIND);
	ASSERT_IN(make(ERR_JS_SABR_URL_ALLOC), "Cannot strndup");
	ASSERT_IN(make(ERR_JS_PLAYBACK_CONFIG_FIND), CANNOT_FIND);
	ASSERT_IN(make(ERR_JS_TIMESTAMP_FIND), CANNOT_FIND);
	ASSERT_IN(make_ns(ERR_JS_TIMESTAMP_PARSE_LL), "Error in strtoll");
	ASSERT_IN(make(ERR_JS_DEOB_FIND_MAGIC_ONE), CANNOT_FIND);
	ASSERT_IN(make(ERR_JS_DEOB_FIND_MAGIC_TWO), CANNOT_FIND);
	ASSERT_IN(make(ERR_JS_DEOBFUSCATOR_ALLOC), CANNOT_ALLOC);
	ASSERT_IN(make(ERR_JS_DEOB_FIND_FUNC_ONE), CANNOT_FIND);
	ASSERT_IN(make_s(ERR_JS_DEOB_FIND_FUNC_TWO), CANNOT_FIND);
	ASSERT_IN(make_s(ERR_JS_DEOB_FIND_FUNC_BODY), CANNOT_FIND);
	ASSERT_IN(make(ERR_JS_CALL_ALLOC), CANNOT_ALLOC);
	ASSERT_IN(make_s(ERR_JS_CALL_EVAL_MAGIC), "Error in duk_peval");
	ASSERT_IN(make_s(ERR_JS_CALL_COMPILE), "Error in duk_pcompile");
	ASSERT_IN(make_s(ERR_JS_CALL_INVOKE), "Error in duk_pcall");
	ASSERT_IN(make(ERR_JS_CALL_GET_RESULT), "Error fetching");
	ASSERT_IN(make(ERR_PROTOCOL_STATE_ALLOC), CANNOT_ALLOC);
	ASSERT_IN(make(ERR_PROTOCOL_SABR_POST_BODY_ALLOC), CANNOT_ALLOC);
	ASSERT_IN(make_n(ERR_PROTOCOL_VARINT_READ_PRE),
	          "UMP varint read fails precondition");
	ASSERT_IN(make_n(ERR_PROTOCOL_VARINT_READ_POST),
	          "UMP varint read fails postcondition");
	ASSERT_IN(make_n(ERR_PROTOCOL_VARINT_READ_OUT_OF_BOUNDS),
	          "UMP varint size exceeds");
	ASSERT_IN(make_n(ERR_PROTOCOL_VARINT_READ_INVALID_SIZE),
	          "UMP varint size is invalid");
	ASSERT_IN(make_n(ERR_PROTOCOL_MEDIA_BLOB_WRITE), "Error writing");
	ASSERT_IN(make(ERR_PROTOCOL_PLAYBACK_COOKIE_ALLOC), CANNOT_ALLOC);
	ASSERT_IN(make(ERR_PROTOCOL_UNPACK_MEDIA_HEADER), CANNOT_UNPACK);
	ASSERT_IN(make(ERR_PROTOCOL_UNPACK_NEXT_REQUEST_POLICY), CANNOT_UNPACK);
	ASSERT_IN(make(ERR_PROTOCOL_UNPACK_FORMAT_INIT), CANNOT_UNPACK);
	ASSERT_IN(make(ERR_PROTOCOL_UNPACK_SABR_REDIRECT), CANNOT_UNPACK);
	ASSERT_IN(make_s(ERR_RE_COMPILE), "Error in pcre2_compile");
	ASSERT_IN(make(ERR_RE_ALLOC_MATCH_DATA), CANNOT_ALLOC);
	ASSERT_IN(make_s(ERR_RE_CAPTURE_GROUP_COUNT), "Wrong number");
	ASSERT_IN(make_s(ERR_RE_TRY_MATCH), "Error in pcre2_match");
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
	ASSERT_IN(make(ERR_SANDBOX_SEATBELT_GETENV_TMPDIR),
	          "Seatbelt requires TMPDIR");
	ASSERT_IN(make(ERR_SANDBOX_SEATBELT_REALPATH_TMPDIR),
	          "Error resolving realpath");
	ASSERT_IN(make_n(ERR_SANDBOX_SEATBELT_INIT),
	          "Error in macOS Seatbelt sandbox_init");
	ASSERT_IN(make(ERR_SANDBOX_SEATBELT_ISSUE_INET), CANNOT_ISSUE);
	ASSERT_IN(make(ERR_SANDBOX_SEATBELT_ISSUE_TMPFILE), CANNOT_ISSUE);
	ASSERT_IN(make(ERR_SANDBOX_SEATBELT_ISSUE_RPATH), CANNOT_ISSUE);
	ASSERT_IN(make(ERR_SANDBOX_SEATBELT_CONSUME_INET), CANNOT_CONSUME);
	ASSERT_IN(make(ERR_SANDBOX_SEATBELT_CONSUME_TMPFILE), CANNOT_CONSUME);
	ASSERT_IN(make(ERR_SANDBOX_SEATBELT_CONSUME_RPATH), CANNOT_CONSUME);
	ASSERT_IN(make(ERR_SANDBOX_SEATBELT_RELEASE_INET), CANNOT_RELEASE);
	ASSERT_IN(make(ERR_SANDBOX_SEATBELT_RELEASE_TMPFILE), CANNOT_RELEASE);
	ASSERT_IN(make(ERR_SANDBOX_SEATBELT_RELEASE_RPATH), CANNOT_RELEASE);
	ASSERT_IN(make_n(ERR_SANDBOX_SECCOMP_INIT), "Error in seccomp_init");
	ASSERT_IN(make_n(ERR_SANDBOX_SECCOMP_RESOLVE_SYSCALL),
	          "Cannot resolve");
	ASSERT_IN(make_ns(ERR_SANDBOX_SECCOMP_RULE_ADD), "Error adding");
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
	ASSERT_IN(make(ERR_URL_DOWNLOAD_LIST_APPEND), CANNOT_APPEND);
	ASSERT_IN(make_n(ERR_URL_DOWNLOAD_SET_OPT_WRITEDATA), CANNOT_SET);
	ASSERT_IN(make_n(ERR_URL_DOWNLOAD_SET_OPT_WRITEFUNCTION), CANNOT_SET);
	ASSERT_IN(make_n(ERR_URL_DOWNLOAD_SET_OPT_USERAGENT), CANNOT_SET);
	ASSERT_IN(make_n(ERR_URL_DOWNLOAD_SET_OPT_URL_STRING), CANNOT_SET);
	ASSERT_IN(make_n(ERR_URL_DOWNLOAD_SET_OPT_URL_OBJECT), CANNOT_SET);
	ASSERT_IN(make_n(ERR_URL_DOWNLOAD_SET_OPT_HTTP_HEADER), CANNOT_SET);
	ASSERT_IN(make_n(ERR_URL_DOWNLOAD_SET_OPT_POST_BODY), CANNOT_SET);
	ASSERT_IN(make_n(ERR_URL_DOWNLOAD_PERFORM), "Error performing");
	ASSERT_IN(make(ERR_YOUTUBE_STREAM_URL_INVALID), "Error parsing");
	ASSERT_IN(make(ERR_YOUTUBE_STREAM_URL_MISSING), "Missing stream URL");
	ASSERT_IN(make(ERR_YOUTUBE_N_PARAM_QUERY_ALLOC), CANNOT_ALLOC);
	ASSERT_IN(make_s(ERR_YOUTUBE_N_PARAM_FIND_IN_QUERY), "No n-parameter");
	ASSERT_IN(make(ERR_YOUTUBE_VISITOR_DATA_HEADER_ALLOC), CANNOT_ALLOC);
	PASS();
}

SUITE(print_to_str)
{
	RUN_TEST(print_to_str_each_enum_value);
}
