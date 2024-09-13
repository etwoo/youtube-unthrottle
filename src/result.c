#include "result.h"

extern const result_t RESULT_OK = {
	.typ = OK,
};

const char *
result_to_strerror(result_t r)
{
	int rc = 0;
	char *s = NULL;
	switch (r.typ) {
	case OK:
		rc = asprintf(&s, "Success");
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
	case ERR_URL_DOWNLOAD_PERFORM:
		rc = asprintf(&s, "Error performing HTTP request: %s", curl_easy_strerror(r.curl_code));
		break;
	}
	if (rc < 0) {
		s = NULL;
	}
	return s;
}
