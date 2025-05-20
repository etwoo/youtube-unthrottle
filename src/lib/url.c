#include "lib/url.h"

#include "sys/debug.h"
#include "sys/write.h"

#include <ada_c.h>
#include <assert.h>
#include <stdlib.h>
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
write_to_tmpfile(const char *ptr, size_t size, size_t nmemb, void *userdata)
{
	const size_t real_size = size * nmemb;
	const int *fd = (const int *)userdata;
	if (*fd == FD_DISCARD) {
		/*
		 * FD_DISCARD means caller wants us to discard data
		 */
		return real_size;
	}

	const ssize_t written = write_with_retry(*fd, ptr, real_size);
	info_m_if(written < 0, "Cannot write to tmpfile");

	return real_size; /* always consider buffer entirely consumed */
}

static void
str_free(char **strp)
{
	free(*strp);
}

static WARN_UNUSED CURLcode
curl_simulate(const char *body, int fd)
{
	size_t x = write_to_tmpfile(body, strlen(body), sizeof(*body), &fd);
	assert(x == strlen(body));
	return CURLE_OK;
}

result_t
url_global_init(void)
{
	CURLcode res = curl_global_init(CURL_GLOBAL_DEFAULT);
	check_if_num(res, ERR_URL_GLOBAL_INIT);
	return RESULT_OK;
}

void
url_global_cleanup(void)
{
	curl_global_cleanup();
}

void
url_context_init(struct url_request_context *context)
{
	/*
	 * Nudge curl into creating its DNS resolver thread(s) now, before the
	 * the process sandbox closes and blocks the clone3() syscall.
	 */
	auto_result err = url_download("https://www.youtube.com",
	                               NULL,
	                               NULL,
	                               NULL,
	                               0,
	                               NULL,
	                               FD_DISCARD,
	                               context);
	info_if(err.err, "Error creating early URL worker threads");
}

void
url_context_cleanup(struct url_request_context *context)
{
	curl_easy_cleanup(context->state); /* handles NULL gracefully */
}

static WARN_UNUSED result_t
url_prepare(const char *hostp, const char *pathp, CURLU **url)
{
	*url = curl_url();
	CURLUcode uc = (*url == NULL) ? CURLUE_OUT_OF_MEMORY : CURLUE_OK;
	check_if_num(uc, ERR_URL_PREPARE_ALLOC);

	uc = curl_url_set(*url, CURLUPART_SCHEME, "https", 0);
	check_if_num(uc, ERR_URL_PREPARE_SET_PART_SCHEME);

	uc = curl_url_set(*url, CURLUPART_HOST, hostp, 0);
	check_if_num(uc, ERR_URL_PREPARE_SET_PART_HOST);

	uc = curl_url_set(*url, CURLUPART_PATH, pathp, 0);
	check_if_num(uc, ERR_URL_PREPARE_SET_PART_PATH);

	return RESULT_OK;
}

static WARN_UNUSED result_t
url_list_append(struct curl_slist **list, const char *str)
{
	struct curl_slist *tmp = curl_slist_append(*list, str);
	check_if(tmp == NULL, ERR_URL_DOWNLOAD_LIST_APPEND);
	*list = tmp;
	return RESULT_OK;
}

static const char BROWSER_USERAGENT[] =
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, "
	"like Gecko) Chrome/87.0.4280.101 Safari/537.36";
static const char CONTENT_TYPE_PROTOBUF[] =
	"Content-Type: application/x-protobuf";

result_t
url_download(const char *url_str,     /* maybe NULL */
             const char *host_str,    /* maybe NULL */
             const char *path_str,    /* maybe NULL */
             const char *post_body,   /* maybe NULL */
             size_t post_body_size,   /* meaningful iff post_body != NULL */
             const char *post_header, /* maybe NULL */
             int fd,
             struct url_request_context *context)
{
	CURLU *url = NULL;
	struct curl_slist *headers = NULL;

	if (context->state == NULL) {
		context->state = curl_easy_init();
		debug("Allocated easy handle: %p", context->state);
	} else {
		curl_easy_reset(context->state);
		debug("Reset easy handle: %p", context->state);
	}
	CURL *curl = context->state;
	url_simulator fn = context->simulator;

	CURLcode res = curl == NULL ? CURLE_OUT_OF_MEMORY : CURLE_OK;
	check_if_num(res, ERR_URL_DOWNLOAD_ALLOC);

	res = curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
	check_if_num(res, ERR_URL_DOWNLOAD_SET_VERBOSE);

	res = curl_easy_setopt(curl, CURLOPT_WRITEDATA, &fd);
	check_if_num(res, ERR_URL_DOWNLOAD_SET_OPT_WRITEDATA);

	res = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_to_tmpfile);
	check_if_num(res, ERR_URL_DOWNLOAD_SET_OPT_WRITEFUNCTION);

	res = curl_easy_setopt(curl, CURLOPT_USERAGENT, BROWSER_USERAGENT);
	check_if_num(res, ERR_URL_DOWNLOAD_SET_OPT_USERAGENT);

	char *url_or_path __attribute__((cleanup(str_free))) = NULL;
	if (url_str) {
		res = curl_easy_setopt(curl, CURLOPT_URL, url_str);
		check_if_num(res, ERR_URL_DOWNLOAD_SET_OPT_URL_STRING);

		if (fn) {
			ada_url tmp = ada_parse(url_str, strlen(url_str));
			if (tmp) {
				ada_string parsed = ada_get_pathname(tmp);
				url_or_path =
					strndup(parsed.data, parsed.length);
				debug("Got URL path for test io_simulator: %s",
				      url_or_path);
			}
			ada_free(tmp);
		}
	} else {
		assert(host_str != NULL && path_str != NULL);

		check(url_prepare(host_str, path_str, &url));

		res = curl_easy_setopt(curl, CURLOPT_CURLU, url);
		check_if_num(res, ERR_URL_DOWNLOAD_SET_OPT_URL_OBJECT);

		if (fn) {
			url_or_path = strdup(path_str);
			debug("Got standalone path for test io_simulator: %s",
			      url_or_path);
		}
	}

	if (post_body) {
		check(url_list_append(&headers, CONTENT_TYPE_PROTOBUF));

		res = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_body);
		/* Note: libcurl does not copy <post_body> */
		check_if_num(res, ERR_URL_DOWNLOAD_SET_OPT_POST_BODY);

		res = curl_easy_setopt(curl,
		                       CURLOPT_POSTFIELDSIZE_LARGE,
		                       post_body_size);
		check_if_num(res, ERR_URL_DOWNLOAD_SET_OPT_POST_BODY_SIZE);
	}

	if (post_header) {
		check(url_list_append(&headers, post_header));
	}

	if (headers) {
		res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		check_if_num(res, ERR_URL_DOWNLOAD_SET_OPT_HTTP_HEADER);
	}

	res = fn ? curl_simulate(fn(url_or_path), fd) : curl_easy_perform(curl);
	check_if_num(res, ERR_URL_DOWNLOAD_PERFORM);

	curl_slist_free_all(headers); /* handles NULL gracefully */
	curl_url_cleanup(url);        /* handles NULL gracefully */
	return RESULT_OK;
}
