#ifndef RESULT_H
#define RESULT_H

struct result_t {
	enum {
		OK = 0,
		ERR_JS_BASEJS_URL_FIND,
		ERR_JS_BASEJS_URL_ALLOC,
		ERR_JS_TIMESTAMP_FIND,
		ERR_JS_TIMESTAMP_PARSE_TO_LONGLONG,
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
 * Convert a result_t into a human-readable error message.
 *
 * Note: the caller must free() the returned NUL-terminated string.
 *
 * Note: this function may return NULL.
 */
char *result_to_strerror(result_t r);

#endif
