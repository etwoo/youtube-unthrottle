#include "result.h"

extern const result_t RESULT_OK = {
	.err = OK,
};

const char *
result_to_strerror(result_t r)
{
	int rc = 0;
	char *s = NULL;
	switch (r.err) {
	case OK:
		rc = asprintf(&s, "Success");
		break;
	case ERR_JS_BASEJS_URL_FIND:
		rc = asprintf(&s, "Cannot find base.js URL in HTML document");
		break;
	case ERR_JS_BASEJS_URL_ALLOC:
		rc = asprintf(&s, "Cannot strndup() base.js URL");
		break;
	case ERR_JS_TIMESTAMP_FIND:
		rc = asprintf(&s, "Cannot find timestamp in base.js");
		break;
	case ERR_JS_TIMESTAMP_PARSE_TO_LONGLONG:
		rc = asprintf(&s, "Error in strtoll() on timestamp string: %s", strerror(r.errno));
		break;
	case ERR_TMPFILE:
		rc = asprintf(&s, "Error in tmpfile(): %s", strerror(r.errno));
		break;
	case ERR_TMPFILE_FILENO:
		rc = asprintf(&s, "Error fileno()-ing tmpfile: %s", strerror(r.errno));
		break;
	case ERR_TMPFILE_DUP:
		rc = asprintf(&s, "Error dup()-ing tmpfile: %s", strerror(r.errno));
		break;
	case ERR_TMPFILE_FSTAT:
		rc = asprintf(&s, "Error fstat()-ing tmpfile: %s", strerror(r.errno));
		break;
	case ERR_TMPFILE_MMAP:
		rc = asprintf(&s, "Error mmap()-ing tmpfile: %s", strerror(r.errno));
		break;
	case ERR_URL_GLOBAL_INIT:
		rc = asprintf(&s, "Cannot use URL functions");
		break;
	case ERR_URL_PREPARE_ALLOC:
		rc = asprintf(&s, "Cannot allocate URL handle");
		break;
	case ERR_URL_PREPARE_SET_PART_SCHEME:
		rc = asprintf(&s, "Cannot set URL scheme: %s", curl_url_strerror(r.curlu_code));
		break;
	case ERR_URL_PREPARE_SET_PART_HOST:
		rc = asprintf(&s, "Cannot set URL host: %s", curl_url_strerror(r.curlu_code));
		break;
	case ERR_URL_PREPARE_SET_PART_PATH:
		rc = asprintf(&s, "Cannot set URL path: %s", curl_url_strerror(r.curlu_code));
		break;
	case ERR_URL_DOWNLOAD_ALLOC:
		rc = asprintf(&s, "Cannot allocate easy handle");
		break;
	case ERR_URL_DOWNLOAD_SET_OPT_WRITEDATA:
		rc = asprintf(&s, "Cannot set WRITEDATA: %s", curl_easy_strerror(r.curl_code));
		break;
	case ERR_URL_DOWNLOAD_SET_OPT_WRITEFUNCTION:
		rc = asprintf(&s, "Cannot set WRITEFUNCTION: %s", curl_easy_strerror(r.curl_code));
		break;
	case ERR_URL_DOWNLOAD_SET_OPT_USERAGENT:
		rc = asprintf(&s, "Cannot set User-Agent: %s", curl_easy_strerror(r.curl_code));
		break;
	case ERR_URL_DOWNLOAD_SET_OPT_URL_STRING:
		rc = asprintf(&s, "Cannot set URL via string: %s", curl_easy_strerror(r.curl_code));
		break;
	case ERR_URL_DOWNLOAD_SET_OPT_URL_OBJECT:
		rc = asprintf(&s, "Cannot set URL via object: %s", curl_easy_strerror(r.curl_code));
		break;
	case ERR_URL_DOWNLOAD_SET_OPT_HTTP_HEADER:
		rc = asprintf(&s, "Cannot set HTTP headers: %s", curl_easy_strerror(r.curl_code));
		break;
	case ERR_URL_DOWNLOAD_SET_OPT_POST_BODY:
		rc = asprintf(&s, "Cannot set POST body: %s", curl_easy_strerror(r.curl_code));
		break;
	case ERR_URL_DOWNLOAD_PERFORM:
		rc = asprintf(&s, "Error performing HTTP request: %s", curl_easy_strerror(r.curl_code));
		break;
	}
	if (rc < 0) {
		s = NULL;
	}
	return s;
}
