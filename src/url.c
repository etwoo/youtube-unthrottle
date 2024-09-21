#include "url.h"

#include "debug.h"
#include "result_type.h"
#include "write.h"

#include <assert.h>
#include <stdlib.h> /* for free() */
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

/*
 * Set up codegen macros for module-specific result_t.
 */
#define ERR_URL(fmt) ASPRINTF(fmt ": %s", curl_url_strerror(p->code))
#define ERR_EASY(fmt) ASPRINTF(fmt ": %s", curl_easy_strerror(p->code))

#define ERROR_TABLE(X)                                                         \
	X(OK, LITERAL("Success in " __FILE_NAME__))                            \
	X(ERR_URL_GLOBAL_INIT, LITERAL("Cannot use URL functions"))            \
	X(ERR_URL_PREPARE_ALLOC, LITERAL("Cannot allocate URL handle"))        \
	X(ERR_URL_PREPARE_SET_PART_SCHEME, ERR_URL("Cannot set URL scheme"))   \
	X(ERR_URL_PREPARE_SET_PART_HOST, ERR_URL("Cannot set URL host"))       \
	X(ERR_URL_PREPARE_SET_PART_PATH, ERR_URL("Cannot set URL path"))       \
	X(ERR_URL_DOWNLOAD_ALLOC, LITERAL("Cannot allocate easy handle"))      \
	X(ERR_URL_DOWNLOAD_SET_OPT_WRITEDATA,                                  \
	  ERR_EASY("Cannot set WRITEDATA"))                                    \
	X(ERR_URL_DOWNLOAD_SET_OPT_WRITEFUNCTION,                              \
	  ERR_EASY("Cannot set WRITEFUNCTION"))                                \
	X(ERR_URL_DOWNLOAD_SET_OPT_USERAGENT,                                  \
	  ERR_EASY("Cannot set User-Agent"))                                   \
	X(ERR_URL_DOWNLOAD_SET_OPT_URL_STRING,                                 \
	  ERR_EASY("Cannot set URL via string"))                               \
	X(ERR_URL_DOWNLOAD_SET_OPT_URL_OBJECT,                                 \
	  ERR_EASY("Cannot set URL via object"))                               \
	X(ERR_URL_DOWNLOAD_SET_OPT_HTTP_HEADER,                                \
	  ERR_EASY("Cannot set headers"))                                      \
	X(ERR_URL_DOWNLOAD_SET_OPT_POST_BODY,                                  \
	  ERR_EASY("Cannot set POST body"))                                    \
	X(ERR_URL_DOWNLOAD_PERFORM, ERR_EASY("Error performing HTTP request"))

#define ERROR_EXAMPLE_ARGS 0

#define DO_CLEANUP assert(p) /* noop */
#define DO_INIT {.err = err, .code = code}

/*
 * Extend `struct result_base` to create a module-specific result_t.
 */
struct result_url {
	struct result_base base;
	enum { ERROR_TABLE(INTO_ENUM) } err;
	int code; /* either CURLcode or CURLUcode */
};
DEFINE_RESULT(result_url, DO_CLEANUP, DO_INIT, int err, int code)

#define check_if_res(res, err_type)                                            \
	do {                                                                   \
		if (res) {                                                     \
			return make_result_url(err_type, res);                 \
		}                                                              \
	} while (0)

#define check_if_uc(uc, err_type)                                              \
	do {                                                                   \
		if (uc) {                                                      \
			return make_result_url(err_type, uc);                  \
		}                                                              \
	} while (0)

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
#undef DO_CLEANUP
#undef DO_INIT
#undef ERROR_EXAMPLE_ARGS
#undef ERROR_TABLE
#undef ERR_EASY
#undef ERR_URL
