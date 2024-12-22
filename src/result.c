#include "result.h"

#include "compiler_features.h"

#include <assert.h>
#include <curl/curl.h>
#include <string.h> /* for strerror() */

const result_t RESULT_OK = {
	.err = OK,
};

static WARN_UNUSED const char *
my_vsnprintf(const char *pattern, va_list ap)
{
	/*
	 * Bump-style allocator for dynamic strings in result_t structs
	 *
	 * If youtube-unthrottle ever becomes multithreaded, these static
	 * variables will need retrofits for thread safety.
	 */
	static char RESULT_HEAP[4096] = {0};
	static char *RESULT_HEAP_POS = RESULT_HEAP;

	int capacity = sizeof(RESULT_HEAP) - (RESULT_HEAP_POS - RESULT_HEAP);
	int written = vsnprintf(RESULT_HEAP_POS, capacity, pattern, ap);

	if (written < 0 || written >= capacity) {
		return "[vsnprintf() out of space]";
	} else {
		const char *result = RESULT_HEAP_POS;
		RESULT_HEAP_POS += written;
		++RESULT_HEAP_POS; /* seek past NUL byte */
		return result;
	}
}

static WARN_UNUSED const char *__attribute__((format(printf, 1, 2)))
my_snprintf(const char *pattern, ...)
{
	va_list ap;
	va_start(ap, pattern);
	const char *result = my_vsnprintf(pattern, ap);
	va_end(ap);

	return result;
}

static WARN_UNUSED const char *
result_strdup(const char *src)
{
	return my_snprintf("%s", src);
}

static WARN_UNUSED const char *
result_strdup_span(const char *src, size_t sz)
{
	return my_snprintf("%.*s", (int)sz, src);
}

result_t
makeresult_t(int typ)
{
	return (result_t){
		.err = typ,
		.num = 0,
		.msg = NULL,
	};
}

result_t
makeresult_ti(int typ, int num)
{
	return (result_t){
		.err = typ,
		.num = num,
		.msg = NULL,
	};
}

result_t
makeresult_ts(int typ, const char *msg)
{
	return (result_t){
		.err = typ,
		.num = 0,
		.msg = result_strdup(msg),
	};
}

result_t
makeresult_tss(int typ, const char *msg, size_t sz)
{
	return (result_t){
		.err = typ,
		.num = 0,
		.msg = result_strdup_span(msg, sz),
	};
}

result_t
makeresult_tis(int typ, int num, const char *msg)
{
	return (result_t){
		.err = typ,
		.num = num,
		.msg = result_strdup(msg),
	};
}

result_t
makeresult_tiss(int typ, int num, const char *msg, size_t sz)
{
	return (result_t){
		.err = typ,
		.num = num,
		.msg = result_strdup_span(msg, sz),
	};
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

const char *
result_to_str(result_t r)
{
	const char *s = NULL;

	switch (r.err) {
	case OK:
		s = "Success";
		break;
	case ERR_JS_PARSE_JSON_ALLOC_HEAP:
		s = "Cannot allocate JavaScript interpreter heap";
		break;
	case ERR_JS_PARSE_JSON_DECODE:
		s = my_snprintf("Error in json_load*(): %s", r.msg);
		break;
	case ERR_JS_PARSE_JSON_GET_STREAMINGDATA:
		s = "Cannot get .streamingData";
		break;
	case ERR_JS_PARSE_JSON_GET_ADAPTIVEFORMATS:
		s = "Cannot get .adaptiveFormats";
		break;
	case ERR_JS_PARSE_JSON_ADAPTIVEFORMATS_TYPE:
		s = "Cannot iterate over .adaptiveFormats";
		break;
	case ERR_JS_PARSE_JSON_ELEM_TYPE:
		s = "adaptiveFormats element is not object-coercible";
		break;
	case ERR_JS_PARSE_JSON_ELEM_MIMETYPE:
		s = "Cannot get mimeType of adaptiveFormats element";
		break;
	case ERR_JS_PARSE_JSON_ELEM_URL:
		s = "Cannot get url of adaptiveFormats element";
		break;
	case ERR_JS_PARSE_JSON_CALLBACK_GOT_CIPHERTEXT_URL:
		s = my_snprintf("Cannot set ciphertext URL: %s", url_error(r));
		break;
	case ERR_JS_PARSE_JSON_CALLBACK_QUALITY:
		s = "Chose to skip stream based on qualityLevel";
		break;
	case ERR_JS_MAKE_INNERTUBE_JSON_ID:
		s = "Cannot find video ID for InnerTube POST";
		break;
	case ERR_JS_MAKE_INNERTUBE_JSON_ALLOC:
		s = "Cannot allocate buffer for InnerTube POST";
		break;
	case ERR_JS_BASEJS_URL_FIND:
		s = "Cannot find base.js URL in HTML document";
		break;
	case ERR_JS_BASEJS_URL_ALLOC:
		s = "Cannot strndup() base.js URL";
		break;
	case ERR_JS_TIMESTAMP_FIND:
		s = "Cannot find timestamp in base.js";
		break;
	case ERR_JS_TIMESTAMP_PARSE_LL:
		s = my_snprintf("Error in strtoll() on %s: %s",
		                r.msg,
		                my_strerror(r));
		break;
	case ERR_JS_DEOBFUSCATOR_MAGIC_FIND:
		s = "Cannot find deobfuscator magic constant in base.js";
		break;
	case ERR_JS_DEOBFUSCATOR_ALLOC:
		s = "Cannot allocate asprintf buffer";
		break;
	case ERR_JS_DEOB_FIND_FUNC_ONE:
		s = "Cannot find deobfuscation function in base.js";
		break;
	case ERR_JS_DEOB_FIND_FUNC_TWO:
		s = my_snprintf("Cannot find ref to %s in base.js", r.msg);
		break;
	case ERR_JS_DEOB_FIND_FUNC_BODY:
		s = my_snprintf("Cannot find body of %s in base.js", r.msg);
		break;
	case ERR_JS_CALL_ALLOC:
		s = "Cannot allocate JavaScript interpreter heap";
		break;
	case ERR_JS_CALL_COMPILE:
		s = my_snprintf("Error in duk_pcompile(): %s", r.msg);
		break;
	case ERR_JS_CALL_INVOKE:
		s = my_snprintf("Error in duk_pcall(): %s", r.msg);
		break;
	case ERR_JS_CALL_GET_RESULT:
		s = "Error fetching function result";
		break;
	case ERR_SANDBOX_LANDLOCK_CREATE_RULESET:
		s = my_snprintf("Error in landlock_create_ruleset(): %s",
		                my_strerror(r));
		break;
	case ERR_SANDBOX_LANDLOCK_OPEN_O_PATH:
		s = my_snprintf("Error opening %s with O_PATH for Landlock: %s",
		                r.msg,
		                my_strerror(r));
		break;
	case ERR_SANDBOX_LANDLOCK_ADD_RULE_PATH:
		s = my_snprintf("Error in landlock_add_rule() for path %s: %s",
		                r.msg,
		                my_strerror(r));
		break;
	case ERR_SANDBOX_LANDLOCK_ADD_RULE_PORT:
		s = my_snprintf("Error in landlock_add_rule() for port: %s",
		                my_strerror(r));
		break;
	case ERR_SANDBOX_LANDLOCK_SET_NO_NEW_PRIVS:
		s = my_snprintf("Error in prctl(PR_SET_NO_NEW_PRIVS): %s",
		                my_strerror(r));
		break;
	case ERR_SANDBOX_LANDLOCK_RESTRICT_SELF:
		s = my_snprintf("Error in landlock_restrict_self(): %s",
		                my_strerror(r));
		break;
	case ERR_SANDBOX_SECCOMP_INIT:
		s = my_snprintf("Error in seccomp_init(): %s", my_strerror(r));
		break;
	case ERR_SANDBOX_SECCOMP_LOAD:
		s = my_snprintf("Error in seccomp_load(): %s", my_strerror(r));
		break;
	case ERR_TMPFILE:
		s = my_snprintf("Error in tmpfile(): %s", my_strerror(r));
		break;
	case ERR_TMPFILE_FILENO:
		s = my_snprintf("Error fileno()-ing tmpfile: %s",
		                my_strerror(r));
		break;
	case ERR_TMPFILE_DUP:
		s = my_snprintf("Error dup()-ing tmpfile: %s", my_strerror(r));
		break;
	case ERR_TMPFILE_FSTAT:
		s = my_snprintf("Error fstat()-ing tmpfile: %s",
		                my_strerror(r));
		break;
	case ERR_TMPFILE_MMAP:
		s = my_snprintf("Error mmap()-ing tmpfile: %s", my_strerror(r));
		break;
	case ERR_URL_GLOBAL_INIT:
		s = "Cannot use URL functions";
		break;
	case ERR_URL_PREPARE_ALLOC:
		s = "Cannot allocate URL handle";
		break;
	case ERR_URL_PREPARE_SET_PART_SCHEME:
		s = my_snprintf("Cannot set URL scheme: %s", url_error(r));
		break;
	case ERR_URL_PREPARE_SET_PART_HOST:
		s = my_snprintf("Cannot set URL host: %s", url_error(r));
		break;
	case ERR_URL_PREPARE_SET_PART_PATH:
		s = my_snprintf("Cannot set URL path: %s", url_error(r));
		break;
	case ERR_URL_DOWNLOAD_ALLOC:
		s = "Cannot allocate easy handle";
		break;
	case ERR_URL_DOWNLOAD_LIST_APPEND:
		s = "Cannot append string to linked list of HTTP headers";
		break;
	case ERR_URL_DOWNLOAD_SET_OPT_WRITEDATA:
		s = my_snprintf("Cannot set WRITEDATA: %s", easy_error(r));
		break;
	case ERR_URL_DOWNLOAD_SET_OPT_WRITEFUNCTION:
		s = my_snprintf("Cannot set WRITEFUNCTION: %s", easy_error(r));
		break;
	case ERR_URL_DOWNLOAD_SET_OPT_USERAGENT:
		s = my_snprintf("Cannot set User-Agent: %s", easy_error(r));
		break;
	case ERR_URL_DOWNLOAD_SET_OPT_URL_STRING:
		s = my_snprintf("Cannot set URL via string: %s", easy_error(r));
		break;
	case ERR_URL_DOWNLOAD_SET_OPT_URL_OBJECT:
		s = my_snprintf("Cannot set URL via object: %s", easy_error(r));
		break;
	case ERR_URL_DOWNLOAD_SET_OPT_HTTP_HEADER:
		s = my_snprintf("Cannot set HTTP headers: %s", easy_error(r));
		break;
	case ERR_URL_DOWNLOAD_SET_OPT_POST_BODY:
		s = my_snprintf("Cannot set POST body: %s", easy_error(r));
		break;
	case ERR_URL_DOWNLOAD_PERFORM:
		s = my_snprintf("Error performing HTTP request: %s",
		                easy_error(r));
		break;
	case ERR_YOUTUBE_N_PARAM_QUERY_ALLOC:
		s = "Cannot allocate ciphertext buffer";
		break;
	case ERR_YOUTUBE_N_PARAM_QUERY_GET:
		s = my_snprintf("Cannot get URL query string: %s",
		                url_error(r));
		break;
	case ERR_YOUTUBE_N_PARAM_QUERY_SET:
		s = "Cannot clear ciphertext n-parameter";
		break;
	case ERR_YOUTUBE_N_PARAM_FIND_IN_QUERY:
		s = my_snprintf("No n-parameter in query string: %s", r.msg);
		break;
	case ERR_YOUTUBE_N_PARAM_KVPAIR_ALLOC:
		s = "Cannot allocate kv-pair buffer for plaintext n-parameter";
		break;
	case ERR_YOUTUBE_N_PARAM_QUERY_APPEND:
		s = my_snprintf("Cannot append plaintext n-parameter: %s",
		                url_error(r));
		break;
	case ERR_YOUTUBE_POT_PARAM_KVPAIR_ALLOC:
		s = "Cannot allocate kv-pair buffer for proof of origin";
		break;
	case ERR_YOUTUBE_POT_PARAM_QUERY_APPEND:
		s = my_snprintf("Cannot append proof of origin parameter: %s",
		                url_error(r));
		break;
	case ERR_YOUTUBE_VISITOR_DATA_HEADER_ALLOC:
		s = "Cannot allocate asprintf buffer for visitor data header";
		break;
	case ERR_YOUTUBE_STREAM_VISITOR_GET_URL:
		s = my_snprintf("Cannot get URL as string: %s", url_error(r));
		break;
	}

	return s;
}
