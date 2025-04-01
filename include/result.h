#ifndef RESULT_H
#define RESULT_H

#include <stddef.h> /* for size_t */

/*
 * result_t: generic result type used by libyoutube subsystems
 *
 * Note: a modular, per-subsystem version of result_t exists in branch
 * `feature/add-modular-result-type`. Unfortunately, the associated complexity
 * of this more modular implementation outweighs the benefits for a codebase of
 * this size (e.g. less than 100k lines). In other words, one-big-enum appears
 * the more readable, maintainable approach for error-handling (at least for
 * now), despite the lack of encapsulation across subsystems.
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
		ERR_JS_PARSE_JSON_CALLBACK_INVALID_URL,
		ERR_JS_PARSE_JSON_CALLBACK_QUALITY,
		ERR_JS_MAKE_INNERTUBE_JSON_ID,
		ERR_JS_MAKE_INNERTUBE_JSON_ALLOC,
		ERR_JS_BASEJS_URL_FIND,
		ERR_JS_BASEJS_URL_ALLOC,
		ERR_JS_TIMESTAMP_FIND,
		ERR_JS_TIMESTAMP_PARSE_LL,
		ERR_JS_DEOB_FIND_MAGIC_ONE,
		ERR_JS_DEOB_FIND_MAGIC_TWO,
		ERR_JS_DEOBFUSCATOR_ALLOC,
		ERR_JS_DEOB_FIND_FUNC_ONE,
		ERR_JS_DEOB_FIND_FUNC_TWO,
		ERR_JS_DEOB_FIND_FUNC_BODY,
		ERR_JS_CALL_ALLOC,
		ERR_JS_CALL_EVAL_MAGIC,
		ERR_JS_CALL_COMPILE,
		ERR_JS_CALL_INVOKE,
		ERR_JS_CALL_GET_RESULT,
		ERR_RE_COMPILE,
		ERR_RE_ALLOC_MATCH_DATA,
		ERR_RE_CAPTURE_GROUP_COUNT,
		ERR_RE_TRY_MATCH,
		ERR_SANDBOX_LANDLOCK_CREATE_RULESET,
		ERR_SANDBOX_LANDLOCK_OPEN_O_PATH,
		ERR_SANDBOX_LANDLOCK_ADD_RULE_PATH,
		ERR_SANDBOX_LANDLOCK_ADD_RULE_PORT,
		ERR_SANDBOX_LANDLOCK_SET_NO_NEW_PRIVS,
		ERR_SANDBOX_LANDLOCK_RESTRICT_SELF,
		ERR_SANDBOX_SEATBELT_GETENV_TMPDIR,
		ERR_SANDBOX_SEATBELT_REALPATH_TMPDIR,
		ERR_SANDBOX_SEATBELT_INIT,
		ERR_SANDBOX_SEATBELT_ISSUE_INET,
		ERR_SANDBOX_SEATBELT_ISSUE_TMPFILE,
		ERR_SANDBOX_SEATBELT_ISSUE_RPATH,
		ERR_SANDBOX_SEATBELT_CONSUME_INET,
		ERR_SANDBOX_SEATBELT_CONSUME_TMPFILE,
		ERR_SANDBOX_SEATBELT_CONSUME_RPATH,
		ERR_SANDBOX_SEATBELT_RELEASE_INET,
		ERR_SANDBOX_SEATBELT_RELEASE_TMPFILE,
		ERR_SANDBOX_SEATBELT_RELEASE_RPATH,
		ERR_SANDBOX_SECCOMP_INIT,
		ERR_SANDBOX_SECCOMP_RESOLVE_SYSCALL,
		ERR_SANDBOX_SECCOMP_RULE_ADD,
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
		ERR_URL_DOWNLOAD_LIST_APPEND,
		ERR_URL_DOWNLOAD_SET_OPT_WRITEDATA,
		ERR_URL_DOWNLOAD_SET_OPT_WRITEFUNCTION,
		ERR_URL_DOWNLOAD_SET_OPT_USERAGENT,
		ERR_URL_DOWNLOAD_SET_OPT_URL_STRING,
		ERR_URL_DOWNLOAD_SET_OPT_URL_OBJECT,
		ERR_URL_DOWNLOAD_SET_OPT_HTTP_HEADER,
		ERR_URL_DOWNLOAD_SET_OPT_POST_BODY,
		ERR_URL_DOWNLOAD_PERFORM,
		ERR_YOUTUBE_STREAM_URL_MISSING,
		ERR_YOUTUBE_N_PARAM_QUERY_ALLOC,
		ERR_YOUTUBE_N_PARAM_FIND_IN_QUERY,
		ERR_YOUTUBE_VISITOR_DATA_HEADER_ALLOC,
	} err;
	int num; /* may hold errno, CURLcode, CURLUcode, etc */
	union {
		char *msg;
		struct {
			char *pattern;
			size_t offset;
		} re;
	};
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
	result_t make_result_##x(__VA_ARGS__)                                  \
		__attribute__((warn_unused_result)) __attribute__((cold))

DECLARE_MAKERESULT_IMPL(t, int typ);
DECLARE_MAKERESULT_IMPL(ti, int typ, int num);
DECLARE_MAKERESULT_IMPL(ts, int typ, const char *msg);
DECLARE_MAKERESULT_IMPL(tss, int typ, const char *msg, size_t sz);
DECLARE_MAKERESULT_IMPL(tis, int typ, int num, const char *msg);
DECLARE_MAKERESULT_IMPL(tiss, int typ, int num, const char *msg, size_t sz);
DECLARE_MAKERESULT_IMPL(re, int typ, int num, const char *pat, size_t off);

#undef DECLARE_MAKERESULT_IMPL

#define make_result_str_arg(suffix)                                            \
	char * : make_result_##suffix, const char * : make_result_##suffix
#define make_result_2arg(x, y)                                                 \
	_Generic(y, int: make_result_ti, make_result_str_arg(ts))(x, y)
#define make_result_3arg(x, y, z)                                              \
	_Generic(y, int: make_result_tis, make_result_str_arg(tss))(x, y, z)

#define CHOOSE_MACRO_BY_ARGN(w, x, y, z, NAME, ...) NAME

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
	                     make_result_tiss,                                 \
	                     make_result_3arg,                                 \
	                     make_result_2arg,                                 \
	                     make_result_t,                                    \
	                     make_result_sentinel)                             \
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
 * Return a result_t if a given (arbitrary) condition evaluates to true.
 */
#define check_if(cond, ...)                                                    \
	do {                                                                   \
		if (cond) {                                                    \
			return make_result(__VA_ARGS__);                       \
		}                                                              \
	} while (0)

/*
 * Return on non-zero <val>, while also capturing <val> in the result_t.
 *
 * Note: <val> would typically originate from CURLcode, CURLUcode, or similar.
 */
#define check_if_num(val, err_type) check_if(val, err_type, (int)(val))

/*
 * Convenience helper for use with __attribute__((cleanup))
 */
void result_cleanup(result_t *p);

/*
 * Take ownership of a result_t value and free() its members upon completion.
 */
#define auto_result result_t __attribute__((cleanup(result_cleanup)))

/*
 * Convert a result_t into a human-readable error message.
 *
 * Note: caller has responsibility to free() the returned pointer.
 */
char *result_to_str(result_t r) __attribute__((warn_unused_result));

/*
 * Convenience helper for use with __attribute__((cleanup))
 */
void result_str_cleanup(char **s);

/*
 * Take ownership of a result_to_str() value and free() it upon completion.
 */
#define auto_result_str char *__attribute__((cleanup(result_str_cleanup)))

#endif
