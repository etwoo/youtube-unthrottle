#ifndef RESULT_H
#define RESULT_H

#include "compiler_features.h"

#include <stddef.h> /* for size_t */

/*
 * result_t: generic result type used by various libyoutube subsystems
 *
 * Note: a modular, extensible, per-subsystem version of result_t is
 * implemented in branch `feature/add-modular-result-type`. However, the
 * associated complexity of this more modular implementation is not worth
 * incurring for a codebase of this size (e.g. less than 100k lines). In other
 * words, one-big-enum appears to be the more readable, maintainable approach
 * for error-handling (at least for now), despite the lack of encapsulation
 * across subsystems.
 */
typedef struct {
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
		ERR_JS_PARSE_JSON_CALLBACK_QUALITY,
		ERR_JS_BASEJS_URL_FIND,
		ERR_JS_BASEJS_URL_ALLOC,
		ERR_JS_TIMESTAMP_FIND,
		ERR_JS_TIMESTAMP_PARSE_LL,
		ERR_JS_DEOBFUSCATOR_ALLOC,
		ERR_JS_DEOB_FIND_FUNCTION_ONE,
		ERR_JS_DEOB_FIND_FUNCTION_TWO,
		ERR_JS_DEOB_FIND_FUNCTION_BODY,
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
} result_t;

/*
 * RESULT_OK: sentinel that represents generic success, not specific to any
 * particular subsystem or function
 */
extern const result_t RESULT_OK;

/*
 * Implementation details of make_result(); result_t users can ignore the
 * following macro glue.
 */

#define DECLARE_MAKERESULT_IMPL(x, ...)                                        \
	result_t makeresult_##x(__VA_ARGS__) WARN_UNUSED __attribute__((cold))

DECLARE_MAKERESULT_IMPL(t, int typ);
DECLARE_MAKERESULT_IMPL(ti, int typ, int num);
DECLARE_MAKERESULT_IMPL(ts, int typ, const char *msg);
DECLARE_MAKERESULT_IMPL(tss, int typ, const char *msg, size_t sz);
DECLARE_MAKERESULT_IMPL(tis, int typ, int num, const char *msg);
DECLARE_MAKERESULT_IMPL(tiss, int typ, int num, const char *msg, size_t sz);

#undef DECLARE_MAKERESULT_IMPL

#define makeresult_2arg(x, y)                                                  \
	_Generic(y, int: makeresult_ti, const char *: makeresult_ts)(x, y)
#define makeresult_3arg(x, y, z)                                               \
	_Generic(y, int: makeresult_tis, const char *: makeresult_tss)(x, y, z)

#define CHOOSE_MACRO_BY_ARGN(A0, A1, A3, A4, NAME, ...) NAME

/*
 * Create a result_t by passing any of the following sets of arguments:
 *
 * - an ERR_* value (alone)
 * - an ERR_* value and an errno (or similar int status code)
 * - an ERR_* value and a string (null-terminated or explicit span)
 * - an ERR_* value, an errno, and a string (null-terminated or explicit span)
 */
#define make_result(...)                                                       \
	CHOOSE_MACRO_BY_ARGN(__VA_ARGS__,                                      \
	                     makeresult_tiss,                                  \
	                     makeresult_3arg,                                  \
	                     makeresult_2arg,                                  \
	                     makeresult_t)                                     \
	(__VA_ARGS__)

/*
 * Return if <expr> yields a non-OK result_t.
 */
#define check(expr)                                                            \
	do {                                                                   \
		result_t x = expr;                                             \
		if (__builtin_expect(x.err != OK, 0)) {                        \
			return x;                                              \
		}                                                              \
	} while (0)

/*
 * Return a result_t if a given (arbitrary) condition is true.
 */
#define check_if(cond, ...)                                                    \
	do {                                                                   \
		if (cond) {                                                    \
			return make_result(__VA_ARGS__);                       \
		}                                                              \
	} while (0)

/*
 * Return if <num> is non-zero, while also capturing <num> in the result_t.
 *
 * Note: <num> would typically be something like a CURLcode or CURLUcode.
 */
#define check_if_num(val, err_type) check_if(val, err_type, (int)val)

/*
 * Convert a result_t into a human-readable error message.
 *
 * Note: the caller does not own the returned buffer.
 */
const char *result_to_str(result_t r) WARN_UNUSED;

#endif
