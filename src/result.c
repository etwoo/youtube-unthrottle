#include "result.h"

#include "sys/compiler_features.h"

#include <assert.h>
#include <curl/curl.h>
#include <stdarg.h>
#include <string.h> /* for strerror() */

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h> /* for pcre2_get_error_message */

const result_t RESULT_OK = {
	.err = OK,
};

static WARN_UNUSED __attribute__((format(printf, 1, 2))) char *
my_asprintf(const char *pattern, ...)
{
	char *p = NULL;

	va_list ap;
	va_start(ap, pattern);
	int result = vasprintf(&p, pattern, ap);
	va_end(ap);

	return result < 0 ? NULL : p;
}

result_t
make_result_t(int typ)
{
	return (result_t){
		.err = typ,
		.num = 0,
		.msg = NULL,
	};
}

result_t
make_result_ti(int typ, int num)
{
	return (result_t){
		.err = typ,
		.num = num,
		.msg = NULL,
	};
}

result_t
make_result_ts(int typ, const char *msg)
{
	return (result_t){
		.err = typ,
		.num = 0,
		.msg = strdup(msg),
	};
}

result_t
make_result_tss(int typ, const char *msg, size_t sz)
{
	return (result_t){
		.err = typ,
		.num = 0,
		.msg = strndup(msg, sz),
	};
}

result_t
make_result_tis(int typ, int num, const char *msg)
{
	return (result_t){
		.err = typ,
		.num = num,
		.msg = strdup(msg),
	};
}

result_t
make_result_tiss(int typ, int num, const char *msg, size_t sz)
{
	return (result_t){
		.err = typ,
		.num = num,
		.msg = strndup(msg, sz),
	};
}

result_t
make_result_re(int typ, int num, const char *pattern, size_t offset)
{
	return (result_t){
		.err = typ,
		.num = num,
		.re.pattern = strdup(pattern),
		.re.offset = offset,
	};
}

void
result_cleanup(result_t *p)
{
	switch (p->err) {
	case ERR_RE_COMPILE:
	case ERR_RE_TRY_MATCH:
		free(p->re.pattern);
		break;
	default:
		free(p->msg);
		break;
	}
	memset(p, 0, sizeof(*p));
}

static WARN_UNUSED const char *
my_strerror(result_t r)
{
	return strerror(r.num);
}

static WARN_UNUSED const char *
easy_error(result_t r)
{
	return curl_easy_strerror(r.num);
}

static WARN_UNUSED const char *
url_error(result_t r)
{
	return curl_url_strerror(r.num);
}

static WARN_UNUSED const char *
regex_error(result_t r, PCRE2_UCHAR *buffer, size_t capacity)
{
	if (pcre2_get_error_message(r.num, buffer, capacity) < 0) {
		strlcpy((char *)buffer, "[no error details]", capacity);
	}
	return (const char *)buffer;
}

char *
result_to_str(result_t r)
{
	char *s = NULL;
	PCRE2_UCHAR err[256];

	switch (r.err) {
	case OK:
		s = strdup("Success");
		break;
	case ERR_JS_PARSE_JSON_ALLOC_HEAP:
		s = strdup("Cannot allocate JavaScript interpreter heap");
		break;
	case ERR_JS_PARSE_JSON_DECODE:
		s = my_asprintf("Error in json_load*(): %s", r.msg);
		break;
	case ERR_JS_PARSE_JSON_GET_STREAMINGDATA:
		s = strdup("Cannot get .streamingData");
		break;
	case ERR_JS_PARSE_JSON_GET_ADAPTIVEFORMATS:
		s = strdup("Cannot get .adaptiveFormats");
		break;
	case ERR_JS_PARSE_JSON_ADAPTIVEFORMATS_TYPE:
		s = strdup("Cannot iterate over .adaptiveFormats");
		break;
	case ERR_JS_PARSE_JSON_ELEM_TYPE:
		s = strdup("adaptiveFormats element is not object-coercible");
		break;
	case ERR_JS_PARSE_JSON_ELEM_MIMETYPE:
		s = strdup("Cannot get mimeType of adaptiveFormats element");
		break;
	case ERR_JS_PARSE_JSON_ELEM_URL:
		s = strdup("Cannot get url of adaptiveFormats element");
		break;
	case ERR_JS_PARSE_JSON_CALLBACK_INVALID_URL:
		s = my_asprintf("Cannot parse ciphertext URL: %s", r.msg);
		break;
	case ERR_JS_PARSE_JSON_CALLBACK_QUALITY:
		s = strdup("Chose to skip stream based on qualityLevel");
		break;
	case ERR_JS_MAKE_INNERTUBE_JSON_ID:
		s = strdup("Cannot find video ID for InnerTube POST");
		break;
	case ERR_JS_MAKE_INNERTUBE_JSON_ALLOC:
		s = strdup("Cannot allocate buffer for InnerTube POST");
		break;
	case ERR_JS_BASEJS_URL_FIND:
		s = strdup("Cannot find base.js URL in HTML document");
		break;
	case ERR_JS_BASEJS_URL_ALLOC:
		s = strdup("Cannot strndup() base.js URL");
		break;
	case ERR_JS_SABR_URL_FIND:
		s = strdup("Cannot find SABR URL in HTML document");
		break;
	case ERR_JS_SABR_URL_ALLOC:
		s = strdup("Cannot strndup() SABR URL");
		break;
	case ERR_JS_PLAYBACK_CONFIG_FIND:
		s = strdup("Cannot find playback config in HTML document");
		break;
	case ERR_JS_TIMESTAMP_FIND:
		s = strdup("Cannot find timestamp in base.js");
		break;
	case ERR_JS_TIMESTAMP_PARSE_LL:
		s = my_asprintf("Error in strtoll() on %s: %s",
		                r.msg,
		                my_strerror(r));
		break;
	case ERR_JS_DEOB_FIND_MAGIC_ONE:
		s = strdup("Cannot find first deobfuscator magic in base.js");
		break;
	case ERR_JS_DEOB_FIND_MAGIC_TWO:
		s = strdup("Cannot find second deobfuscator magic in base.js");
		break;
	case ERR_JS_DEOBFUSCATOR_ALLOC:
		s = strdup("Cannot allocate asprintf buffer");
		break;
	case ERR_JS_DEOB_FIND_FUNC_ONE:
		s = strdup("Cannot find deobfuscation function in base.js");
		break;
	case ERR_JS_DEOB_FIND_FUNC_TWO:
		s = my_asprintf("Cannot find ref to %s in base.js", r.msg);
		break;
	case ERR_JS_DEOB_FIND_FUNC_BODY:
		s = my_asprintf("Cannot find body of %s in base.js", r.msg);
		break;
	case ERR_JS_CALL_ALLOC:
		s = strdup("Cannot allocate JavaScript interpreter heap");
		break;
	case ERR_JS_CALL_EVAL_MAGIC:
		s = my_asprintf("Error in duk_peval_lstring(): %s", r.msg);
		break;
	case ERR_JS_CALL_COMPILE:
		s = my_asprintf("Error in duk_pcompile(): %s", r.msg);
		break;
	case ERR_JS_CALL_INVOKE:
		s = my_asprintf("Error in duk_pcall(): %s", r.msg);
		break;
	case ERR_JS_CALL_GET_RESULT:
		s = strdup("Error fetching function result");
		break;
	case ERR_RE_COMPILE:
		s = my_asprintf("Error in pcre2_compile() with "
		                "regex \"%s\" at offset %zu: %s",
		                r.re.pattern,
		                r.re.offset,
		                regex_error(r, err, sizeof(err)));
		break;
	case ERR_RE_ALLOC_MATCH_DATA:
		s = strdup("Cannot allocate pcre2 match data");
		break;
	case ERR_RE_CAPTURE_GROUP_COUNT:
		s = my_asprintf("Wrong number of capture groups in %s", r.msg);
		break;
	case ERR_RE_TRY_MATCH:
		s = my_asprintf("Error in pcre2_match() with "
		                "regex \"%s\" at offset %zu: %s",
		                r.re.pattern,
		                r.re.offset,
		                regex_error(r, err, sizeof(err)));
		break;
	case ERR_SANDBOX_LANDLOCK_CREATE_RULESET:
		s = my_asprintf("Error in landlock_create_ruleset(): %s",
		                my_strerror(r));
		break;
	case ERR_SANDBOX_LANDLOCK_OPEN_O_PATH:
		s = my_asprintf("Error opening %s with O_PATH for Landlock: %s",
		                r.msg,
		                my_strerror(r));
		break;
	case ERR_SANDBOX_LANDLOCK_ADD_RULE_PATH:
		s = my_asprintf("Error in landlock_add_rule() for path %s: %s",
		                r.msg,
		                my_strerror(r));
		break;
	case ERR_SANDBOX_LANDLOCK_ADD_RULE_PORT:
		s = my_asprintf("Error in landlock_add_rule() for port: %s",
		                my_strerror(r));
		break;
	case ERR_SANDBOX_LANDLOCK_SET_NO_NEW_PRIVS:
		s = my_asprintf("Error in prctl(PR_SET_NO_NEW_PRIVS): %s",
		                my_strerror(r));
		break;
	case ERR_SANDBOX_LANDLOCK_RESTRICT_SELF:
		s = my_asprintf("Error in landlock_restrict_self(): %s",
		                my_strerror(r));
		break;
	case ERR_SANDBOX_SEATBELT_GETENV_TMPDIR:
		s = strdup("Seatbelt requires TMPDIR environment variable");
		break;
	case ERR_SANDBOX_SEATBELT_REALPATH_TMPDIR:
		s = strdup("Error resolving realpath of TMPDIR value");
		break;
	case ERR_SANDBOX_SEATBELT_INIT:
		s = my_asprintf("Error in macOS Seatbelt sandbox_init(): %s",
		                my_strerror(r));
		break;
	case ERR_SANDBOX_SEATBELT_ISSUE_INET:
		s = strdup("Error issuing Seatbelt extension: inet");
		break;
	case ERR_SANDBOX_SEATBELT_ISSUE_TMPFILE:
		s = strdup("Error issuing Seatbelt extension: tmpfile");
		break;
	case ERR_SANDBOX_SEATBELT_ISSUE_RPATH:
		s = strdup("Error issuing Seatbelt extension: rpath");
		break;
	case ERR_SANDBOX_SEATBELT_CONSUME_INET:
		s = strdup("Error consuming Seatbelt extension: inet");
		break;
	case ERR_SANDBOX_SEATBELT_CONSUME_TMPFILE:
		s = strdup("Error consuming Seatbelt extension: tmpfile");
		break;
	case ERR_SANDBOX_SEATBELT_CONSUME_RPATH:
		s = strdup("Error consuming Seatbelt extension: rpath");
		break;
	case ERR_SANDBOX_SEATBELT_RELEASE_INET:
		s = strdup("Error releasing Seatbelt extension: inet");
		break;
	case ERR_SANDBOX_SEATBELT_RELEASE_TMPFILE:
		s = strdup("Error releasing Seatbelt extension: tmpfile");
		break;
	case ERR_SANDBOX_SEATBELT_RELEASE_RPATH:
		s = strdup("Error releasing Seatbelt extension: rpath");
		break;
	case ERR_SANDBOX_SECCOMP_INIT:
		s = my_asprintf("Error in seccomp_init(): %s", my_strerror(r));
		break;
	case ERR_SANDBOX_SECCOMP_RESOLVE_SYSCALL:
		s = my_asprintf("Cannot resolve number of syscall: %s", r.msg);
		break;
	case ERR_SANDBOX_SECCOMP_RULE_ADD:
		s = my_asprintf("Error adding seccomp rule for syscall %s: %s",
		                r.msg,
		                my_strerror(r));
		break;
	case ERR_SANDBOX_SECCOMP_LOAD:
		s = my_asprintf("Error in seccomp_load(): %s", my_strerror(r));
		break;
	case ERR_TMPFILE:
		s = my_asprintf("Error in tmpfile(): %s", my_strerror(r));
		break;
	case ERR_TMPFILE_FILENO:
		s = my_asprintf("Error fileno()-ing tmpfile: %s",
		                my_strerror(r));
		break;
	case ERR_TMPFILE_DUP:
		s = my_asprintf("Error dup()-ing tmpfile: %s", my_strerror(r));
		break;
	case ERR_TMPFILE_FSTAT:
		s = my_asprintf("Error fstat()-ing tmpfile: %s",
		                my_strerror(r));
		break;
	case ERR_TMPFILE_MMAP:
		s = my_asprintf("Error mmap()-ing tmpfile: %s", my_strerror(r));
		break;
	case ERR_URL_GLOBAL_INIT:
		s = strdup("Cannot use URL functions");
		break;
	case ERR_URL_PREPARE_ALLOC:
		s = strdup("Cannot allocate URL handle");
		break;
	case ERR_URL_PREPARE_SET_PART_SCHEME:
		s = my_asprintf("Cannot set URL scheme: %s", url_error(r));
		break;
	case ERR_URL_PREPARE_SET_PART_HOST:
		s = my_asprintf("Cannot set URL host: %s", url_error(r));
		break;
	case ERR_URL_PREPARE_SET_PART_PATH:
		s = my_asprintf("Cannot set URL path: %s", url_error(r));
		break;
	case ERR_URL_DOWNLOAD_ALLOC:
		s = strdup("Cannot allocate easy handle");
		break;
	case ERR_URL_DOWNLOAD_LIST_APPEND:
		s = strdup("Cannot append string to HTTP headers");
		break;
	case ERR_URL_DOWNLOAD_SET_OPT_WRITEDATA:
		s = my_asprintf("Cannot set WRITEDATA: %s", easy_error(r));
		break;
	case ERR_URL_DOWNLOAD_SET_OPT_WRITEFUNCTION:
		s = my_asprintf("Cannot set WRITEFUNCTION: %s", easy_error(r));
		break;
	case ERR_URL_DOWNLOAD_SET_OPT_USERAGENT:
		s = my_asprintf("Cannot set User-Agent: %s", easy_error(r));
		break;
	case ERR_URL_DOWNLOAD_SET_OPT_URL_STRING:
		s = my_asprintf("Cannot set URL via string: %s", easy_error(r));
		break;
	case ERR_URL_DOWNLOAD_SET_OPT_URL_OBJECT:
		s = my_asprintf("Cannot set URL via object: %s", easy_error(r));
		break;
	case ERR_URL_DOWNLOAD_SET_OPT_HTTP_HEADER:
		s = my_asprintf("Cannot set HTTP headers: %s", easy_error(r));
		break;
	case ERR_URL_DOWNLOAD_SET_OPT_POST_BODY:
		s = my_asprintf("Cannot set POST body: %s", easy_error(r));
		break;
	case ERR_URL_DOWNLOAD_PERFORM:
		s = my_asprintf("Error performing HTTP request: %s",
		                easy_error(r));
		break;
	case ERR_YOUTUBE_STREAM_URL_MISSING:
		s = strdup("Missing stream URL");
		break;
	case ERR_YOUTUBE_N_PARAM_QUERY_ALLOC:
		s = strdup("Cannot allocate ciphertext buffer");
		break;
	case ERR_YOUTUBE_N_PARAM_FIND_IN_QUERY:
		s = my_asprintf("No n-parameter in query string: %s", r.msg);
		break;
	case ERR_YOUTUBE_VISITOR_DATA_HEADER_ALLOC:
		s = strdup("Cannot allocate buffer for visitor data header");
		break;
	}

	return s;
}

void
result_str_cleanup(char **s)
{
	free(*s);
}
