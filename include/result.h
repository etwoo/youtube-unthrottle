#ifndef RESULT_H
#define RESULT_H

struct result_t {
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
		ERR_JS_BASEJS_URL_FIND,
		ERR_JS_BASEJS_URL_ALLOC,
		ERR_JS_TIMESTAMP_FIND,
		ERR_JS_TIMESTAMP_PARSE_TO_LONGLONG,
		ERR_JS_DEOBFUSCATOR_ALLOC,
		ERR_JS_DEOBFUSCATOR_FIND_FUNCTION_ONE,
		ERR_JS_DEOBFUSCATOR_FIND_FUNCTION_TWO,
		ERR_JS_DEOBFUSCATOR_FIND_FUNCTION_BODY,
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
	} err;
	union {
		int errno;
		int curl_code;
		int curlu_code;
		const char *msg;
	};
};

const result_t RESULT_OK;

/*
 * Convenience macro for checking (and returning) if x is a non-OK result_t.
 */
#define check(expr)                                                            \
	do {                                                                   \
		result_t x = expr;                                             \
		if (x.err) {                                                   \
			return x;                                              \
		}                                                              \
	} while (0)

/*
 * Convenience macro for returning a result_t if a given condition is true.
 *
 * Note: this currently only works well for zero-arg result_t values that do
 * not need to set extra values like errno, curl_code, curlu_code.
 */
#define check_if(cond, err_type)                                               \
	while (cond) {                                                         \
		result_t err = {                                               \
			.err = err_type,                                       \
		};                                                             \
		return err;                                                    \
	}

/*
 * Copy <src> into <r>, backed by automatic storage managed by result.c module.
 */
void result_strcpy(result_t *dst, const char *src);

/*
 * Like result_strcpy(), with an explicit span. Use this with strings that are
 * not guaranteed to be NUL-terminated.
 */
void result_strcpy_span(result_t *dst, const char *src, size_t sz);

/*
 * Convert a result_t into a human-readable error message.
 *
 * Note: the caller does not own the returned buffer.
 */
char *result_to_strerror(result_t r);

#endif
