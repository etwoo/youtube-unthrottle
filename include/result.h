#ifndef RESULT_H
#define RESULT_H

#include "compiler_features.h"

#include <stddef.h> /* for size_t */

// TODO change result_t to struct result *
// then use type-punning to allow each module to extend result type
// make callers responsible for free-ing with custom cleanup function that each module can override
// make RESULT_OK a pointer for caller convenience
// special-case RESULT_OK, don't free() it in cleanup function
// add result_ok() macro that checks for pointer equality with RESULT_OK _or_ deep-equality with enum OK value
// split big enum below into module-specific result_t "subclasses"

struct result {
	enum {
		OK = 0,
		ERR_JS_PARSE_JSON_ALLOC_HEAP,
		ERR_JS_PARSE_JSON_DECODE,
		ERR_JS_PARSE_JSON_GET_STREAMINGDATA,
		ERR_JS_PARSE_JSON_GET_ADAPTIVEFORMATS,
		ERR_JS_PARSE_JSON_ADAPTIVEFORMATS_TYPE,
		ERR_JS_PARSE_JSON_ELEM_TYPE,
		ERR_JS_PARSE_JSON_ELEM_MIMETYPE,
		ERR_JS_PARSE_JSON_ELEM_URL,
		ERR_JS_PARSE_JSON_CALLBACK_GOT_CIPHERTEXT_URL,
		ERR_JS_BASEJS_URL_FIND,
		ERR_JS_BASEJS_URL_ALLOC,
		ERR_JS_TIMESTAMP_FIND,
		ERR_JS_TIMESTAMP_PARSE_TO_LONGLONG,
		ERR_JS_DEOBFUSCATOR_ALLOC,
		ERR_JS_DEOBFUSCATOR_FIND_FUNCTION_ONE,
		ERR_JS_DEOBFUSCATOR_FIND_FUNCTION_TWO,
		ERR_JS_DEOBFUSCATOR_FIND_FUNCTION_BODY,
		ERR_JS_CALL_ALLOC,
		ERR_JS_CALL_COMPILE,
		ERR_JS_CALL_INVOKE,
		ERR_JS_CALL_GET_RESULT,
		ERR_SANDBOX_LANDLOCK_CREATE_RULESET,
		ERR_SANDBOX_LANDLOCK_OPEN_O_PATH,
		ERR_SANDBOX_LANDLOCK_ADD_RULE_PATH,
		ERR_SANDBOX_LANDLOCK_ADD_RULE_PORT,
		ERR_SANDBOX_LANDLOCK_SET_NO_NEW_PRIVS,
		ERR_SANDBOX_LANDLOCK_RESTRICT_SELF,
		ERR_SANDBOX_SECCOMP_INIT,
		ERR_SANDBOX_SECCOMP_LOAD,
		ERR_TMPFILE,
		ERR_TMPFILE_FILENO,
		ERR_TMPFILE_DUP,
		ERR_TMPFILE_FSTAT,
		ERR_TMPFILE_MMAP,
		ERR_URL_GLOBAL_INIT,
		ERR_URL_PREPARE_ALLOC,
		ERR_URL_PREPARE_SET_PART_SCHEME,
		ERR_URL_PREPARE_SET_PART_HOST,
		ERR_URL_PREPARE_SET_PART_PATH,
		ERR_URL_DOWNLOAD_ALLOC,
		ERR_URL_DOWNLOAD_SET_OPT_WRITEDATA,
		ERR_URL_DOWNLOAD_SET_OPT_WRITEFUNCTION,
		ERR_URL_DOWNLOAD_SET_OPT_USERAGENT,
		ERR_URL_DOWNLOAD_SET_OPT_URL_STRING,
		ERR_URL_DOWNLOAD_SET_OPT_URL_OBJECT,
		ERR_URL_DOWNLOAD_SET_OPT_HTTP_HEADER,
		ERR_URL_DOWNLOAD_SET_OPT_POST_BODY,
		ERR_URL_DOWNLOAD_PERFORM,
		ERR_YOUTUBE_INNERTUBE_POST_ID,
		ERR_YOUTUBE_INNERTUBE_POST_ALLOC,
		ERR_YOUTUBE_N_PARAM_QUERY_ALLOC,
		ERR_YOUTUBE_N_PARAM_QUERY_GET,
		ERR_YOUTUBE_N_PARAM_QUERY_SET,
		ERR_YOUTUBE_N_PARAM_FIND_IN_QUERY,
		ERR_YOUTUBE_N_PARAM_KVPAIR_ALLOC,
		ERR_YOUTUBE_N_PARAM_QUERY_APPEND_PLAINTEXT,
		ERR_YOUTUBE_STREAM_VISITOR_GET_URL,
	} err;
	int num; /* may hold errno, CURLcode, CURLUcode, etc */
	const char *msg;
};

typedef struct result result_t;

extern const result_t RESULT_OK;

/*
 * Return if <expr> yields a non-OK result_t.
 */
#define check(expr)                                                            \
	do {                                                                   \
		result_t x = expr;                                             \
		if (x.err) {                                                   \
			return x;                                              \
		}                                                              \
	} while (0)

/*
 * Return a result_t if a given (arbitrary) condition is true.
 *
 * Note: this currently only works well for zero-arg result_t values that do
 * not need to set extra values like an errno, CURLcode, or CURLUcode.
 */
#define check_if(cond, err_type)                                               \
	do {                                                                   \
		if (cond) {                                                    \
			return (result_t){                                     \
				.err = err_type,                               \
			};                                                     \
		}                                                              \
	} while (0)

/*
 * Return if <num> is non-zero, while also capturing <num> in the result_t.
 *
 * Note: <num> would typically be something like a CURLcode or CURLUcode.
 */
#define check_if_num(val, err_type)                                            \
	do {                                                                   \
		if (val) {                                                     \
			return (result_t){                                     \
				.err = err_type,                               \
				.num = val,                                    \
			};                                                     \
		}                                                              \
	} while (0)

/*
 * Like check_if(), while also capturing <errno> in the result_t.
 *
 * Note that while this captures <errno> in the result_t, the controlling
 * <cond> need not depend on <errno> explicitly!
 */
#define check_if_cond_with_errno(cond, err_type)                               \
	do {                                                                   \
		if (cond) {                                                    \
			return (result_t){                                     \
				.err = err_type,                               \
				.num = errno,                                  \
			};                                                     \
		}                                                              \
	} while (0)

/*
 * Duplicate <src>, using automatic storage managed by result.c module.
 */
const char *result_strdup(const char *src) WARN_UNUSED;

/*
 * Like result_strdup(), with an explicit span. Use this with strings that are
 * not guaranteed to be NUL-terminated.
 */
const char *result_strdup_span(const char *src, size_t sz) WARN_UNUSED;

/*
 * Convert a result_t into a human-readable error message.
 *
 * Note: the caller does not own the returned buffer.
 */
const char *result_to_str(result_t r) WARN_UNUSED;

#endif
