#include "url.h"

#include "debug.h"
#include "write.h"

#include <assert.h>
#include <unistd.h>

/*
 * Some helpful libcurl references:
 *
 *   https://curl.se/libcurl/c/example.html
 *   https://curl.se/libcurl/c/xmlstream.html
 *   https://curl.se/libcurl/c/href_extractor.html
 *   https://curl.se/libcurl/c/parseurl.html
 */
#include <curl/curl.h>

static const int FD_DISCARD = -1;

static WARN_UNUSED size_t
write_to_tmpfile(char *ptr, size_t size, size_t nmemb, void *userdata)
{
	const size_t real_size = size * nmemb;
	const int *fd = (const int *)userdata;
	if (*fd == FD_DISCARD) {
		/*
		 * FD_DISCARD means caller wants data to be discarded.
		 */
		return real_size;
	}

	const ssize_t written = write_with_retry(*fd, ptr, real_size);
	info_m_if(written < 0, "Cannot write to tmpfile");

	return real_size; /* always consider buffer entirely consumed */
}

static WARN_UNUSED CURL *
get_easy_handle(void)
{
	static CURL *GLOBAL_CURL_EASY_HANDLE = NULL;
	/*
	 * Initialization of these static variables is not currently
	 * thread-safe. Ditto for callers of get_easy_handle() who use the
	 * resulting (cached, shared) curl easy handle.
	 *
	 * If youtube-unthrottle ever becomes multithreaded, this code will
	 * need to be retrofitted with a mutex and/or the callers will need
	 * to ensure that initialization happens while still single-threaded.
	 */
	if (!GLOBAL_CURL_EASY_HANDLE) {
		GLOBAL_CURL_EASY_HANDLE = curl_easy_init();
	}

	curl_easy_reset(GLOBAL_CURL_EASY_HANDLE);
	return GLOBAL_CURL_EASY_HANDLE;
}

/*
 * Extend `struct result_base` to create a module-specific result_t.
 */
struct result_url {
	struct result_base base;
	enum {
		OK = 0,
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
	} err;
	union {
		CURLcode curl_code;
		CURLUcode curlu_code;
	};
};

static WARN_UNUSED bool
result_ok(result_t r)
{
	struct result_url *p = (struct result_url *)r;
	return p->err == OK;
}

static WARN_UNUSED const char *
result_to_str(result_t r)
{
	struct result_url *p = (struct result_url *)r;
	int printed = 0;
	const char *s = NULL;

	switch (p->err) {
	case OK:
		s = strdup("Success in " __FILE_NAME__);
		break;
	case ERR_URL_GLOBAL_INIT:
		s = strdup("Cannot use URL functions");
		break;
	case ERR_URL_PREPARE_ALLOC:
		s = strdup("Cannot allocate URL handle");
		break;
	case ERR_URL_PREPARE_SET_PART_SCHEME:
		printed = asprintf(&s,
		                   "Cannot set URL scheme: %s",
		                   curl_url_strerror(p->curlu_code));
		break;
	case ERR_URL_PREPARE_SET_PART_HOST:
		printed = asprintf(&s,
		                   "Cannot set URL host: %s",
		                   curl_url_strerror(p->curlu_code));
		break;
	case ERR_URL_PREPARE_SET_PART_PATH:
		printed = asprintf(&s,
		                   "Cannot set URL path: %s",
		                   curl_url_strerror(p->curlu_code));
		break;
	case ERR_URL_DOWNLOAD_ALLOC:
		s = strdup("Cannot allocate easy handle");
		break;
	case ERR_URL_DOWNLOAD_SET_OPT_WRITEDATA:
		printed = asprintf(&s,
		                   "Cannot set WRITEDATA: %s",
		                   curl_easy_strerror(p->curl_code));
		break;
	case ERR_URL_DOWNLOAD_SET_OPT_WRITEFUNCTION:
		printed = asprintf(&s,
		                   "Cannot set WRITEFUNCTION: %s",
		                   curl_easy_strerror(p->curl_code));
		break;
	case ERR_URL_DOWNLOAD_SET_OPT_USERAGENT:
		printed = asprintf(&s,
		                   "Cannot set User-Agent: %s",
		                   curl_easy_strerror(p->curl_code));
		break;
	case ERR_URL_DOWNLOAD_SET_OPT_URL_STRING:
		printed = asprintf(&s,
		                   "Cannot set URL via string: %s",
		                   curl_easy_strerror(p->curl_code));
		break;
	case ERR_URL_DOWNLOAD_SET_OPT_URL_OBJECT:
		printed = asprintf(&s,
		                   "Cannot set URL via object: %s",
		                   curl_easy_strerror(p->curl_code));
		break;
	case ERR_URL_DOWNLOAD_SET_OPT_HTTP_HEADER:
		printed = asprintf(&s,
		                   "Cannot set HTTP headers: %s",
		                   curl_easy_strerror(p->curl_code));
		break;
	case ERR_URL_DOWNLOAD_SET_OPT_POST_BODY:
		printed = asprintf(&s,
		                   "Cannot set POST body: %s",
		                   curl_easy_strerror(p->curl_code));
		break;
	case ERR_URL_DOWNLOAD_PERFORM:
		printed = asprintf(&s,
		                   "Error performing HTTP request: %s",
		                   curl_easy_strerror(p->curl_code));
		break;
	}

	if (printed < 0) {
		return NULL;
		// TODO: use RESULT_CANNOT_ALLOC instead?
	}

	return s;
}

static void
result_cleanup(result_t r)
{
	if (r == NULL) {
		return;
	}

	struct result_url *p = (struct result_url *)r;
	free(p);
}

struct result_ops RESULT_OPS = {
	.result_ok = result_ok,
	.result_to_str = result_to_str,
	.result_cleanup = result_cleanup,
};

static result_t WARN_UNUSED
make_result_res(int err_type, CURLcode res)
{
	struct result_url *r = malloc(sizeof(*r));
	if (r == NULL) {
		return &RESULT_CANNOT_ALLOC;
	}

	r->base.ops = &RESULT_OPS;
	r->err = err_type;
	r->curl_code = res;
	return r;
}

#define check_if_res(res, err_type)                                            \
	do {                                                                   \
		if (res) {                                                     \
			return make_result_res(err_type, res);                 \
		}                                                              \
	} while (0)

static result_t WARN_UNUSED
make_result_uc(int err_type, CURLUcode uc)
{
	struct result_url *r = malloc(sizeof(*r));
	if (r == NULL) {
		return &RESULT_CANNOT_ALLOC;
	}

	r->base.ops = &RESULT_OPS;
	r->err = err_type;
	r->curlu_code = uc;
	return r;
}

#define check_if_uc(uc, err_type)                                              \
	do {                                                                   \
		if (uc) {                                                      \
			return make_result_uc(err_type, uc);                   \
		}                                                              \
	} while (0)

result_t
url_global_init(void)
{
	CURLcode res = curl_global_init(CURL_GLOBAL_DEFAULT);
	check_if_res(res, ERR_URL_GLOBAL_INIT);

	/*
	 * Nudge curl into creating its DNS resolver thread(s) now, before the
	 * the process sandbox closes and blocks the clone3() syscall.
	 */
	result_t err __attribute__((cleanup(result_cleanup))) =
		url_download("https://www.youtube.com",
	                     NULL,
	                     NULL,
	                     NULL,
	                     FD_DISCARD);
	info_if(!is_ok(err), "Error creating early URL worker threads");

	return RESULT_OK;
}

void
url_global_cleanup(void)
{
	curl_easy_cleanup(get_easy_handle()); /* handles NULL gracefully */
	curl_global_cleanup();
}

static WARN_UNUSED int
wrap_curl_easy_perform(void *request,
                       const char *path __attribute__((unused)),
                       int fd __attribute__((unused)))
{
	return curl_easy_perform(request);
}

int (*CURL_EASY_PERFORM)(void *, const char *, int) = wrap_curl_easy_perform;

void
url_global_set_request_handler(int (*handler)(void *, const char *, int))
{
	CURL_EASY_PERFORM = handler;
}

static WARN_UNUSED result_t
url_prepare(const char *hostp, const char *pathp, CURLU **url)
{
	*url = curl_url();
	CURLUcode uc = (*url == NULL) ? CURLUE_OUT_OF_MEMORY : CURLUE_OK;
	check_if_uc(uc, ERR_URL_PREPARE_ALLOC);

	uc = curl_url_set(*url, CURLUPART_SCHEME, "https", 0);
	check_if_uc(uc, ERR_URL_PREPARE_SET_PART_SCHEME);

	uc = curl_url_set(*url, CURLUPART_HOST, hostp, 0);
	check_if_uc(uc, ERR_URL_PREPARE_SET_PART_HOST);

	uc = curl_url_set(*url, CURLUPART_PATH, pathp, 0);
	check_if_uc(uc, ERR_URL_PREPARE_SET_PART_PATH);

	return RESULT_OK;
}

static const char BROWSER_USERAGENT[] =
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, "
	"like Gecko) Chrome/87.0.4280.101 Safari/537.36";
static const char CONTENT_TYPE_JSON[] = "Content-Type: application/json";
static const char DEFAULT_HOST_STR[] = "www.youtube.com";

result_t
url_download(const char *url_str,   /* may be NULL */
             const char *host_str,  /* may be NULL */
             const char *path_str,  /* may be NULL */
             const char *post_body, /* may be NULL */
             int fd)
{
	CURLU *url = NULL;
	struct curl_slist *headers = NULL;

	CURL *curl = get_easy_handle();
	CURLcode res = curl == NULL ? CURLE_OUT_OF_MEMORY : CURLE_OK;
	check_if_res(res, ERR_URL_DOWNLOAD_ALLOC);

	res = curl_easy_setopt(curl, CURLOPT_WRITEDATA, &fd);
	check_if_res(res, ERR_URL_DOWNLOAD_SET_OPT_WRITEDATA);

	res = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_to_tmpfile);
	check_if_res(res, ERR_URL_DOWNLOAD_SET_OPT_WRITEFUNCTION);

	res = curl_easy_setopt(curl, CURLOPT_USERAGENT, BROWSER_USERAGENT);
	check_if_res(res, ERR_URL_DOWNLOAD_SET_OPT_USERAGENT);

	const char *url_fragment_or_path_str = NULL;
	if (url_str) {
		res = curl_easy_setopt(curl, CURLOPT_URL, url_str);
		check_if_res(res, ERR_URL_DOWNLOAD_SET_OPT_URL_STRING);

		url_fragment_or_path_str = strstr(url_str, DEFAULT_HOST_STR);
		if (url_fragment_or_path_str) {
			url_fragment_or_path_str += strlen(DEFAULT_HOST_STR);
		}
	} else {
		assert(host_str != NULL && path_str != NULL);

		check(url_prepare(host_str, path_str, &url));

		res = curl_easy_setopt(curl, CURLOPT_CURLU, url);
		check_if_res(res, ERR_URL_DOWNLOAD_SET_OPT_URL_OBJECT);

		url_fragment_or_path_str = path_str;
	}

	if (post_body) {
		headers = curl_slist_append(headers, CONTENT_TYPE_JSON);
		res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		check_if_res(res, ERR_URL_DOWNLOAD_SET_OPT_HTTP_HEADER);

		res = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_body);
		/* Note: libcurl does not copy <post_body> */
		check_if_res(res, ERR_URL_DOWNLOAD_SET_OPT_POST_BODY);
	}

	res = CURL_EASY_PERFORM(curl, url_fragment_or_path_str, fd);
	check_if_res(res, ERR_URL_DOWNLOAD_PERFORM);

	curl_slist_free_all(headers); /* handles NULL gracefully */
	curl_url_cleanup(url);        /* handles NULL gracefully */
	return RESULT_OK;
}

#undef check_if_res
#undef check_if_uc
