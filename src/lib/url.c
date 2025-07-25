#include "lib/url.h"

#include "sys/debug.h"
#include "sys/write.h"

#include <assert.h>
#include <stdbool.h>
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

static WARN_UNUSED size_t
write_to_tmpfile(const char *ptr, size_t size, size_t nmemb, void *userdata)
{
	const size_t real_size = size * nmemb;
	const int *fd = (const int *)userdata;
	const ssize_t written = write_with_retry(*fd, ptr, real_size);
	info_m_if(written < 0, "Cannot write to tmpfile");
	return real_size; /* always consider buffer entirely consumed */
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
url_context_init(struct url_request_context *context MAYBE_UNUSED)
{
}

void
url_context_cleanup(struct url_request_context *context)
{
	curl_easy_cleanup(context->state); /* handles NULL gracefully */
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
static const char HEADER_CONTENT_TYPE_JSON[] = "Content-Type: application/json";
static const char HEADER_CONTENT_TYPE_PROTOBUF[] =
	"Content-Type: application/x-protobuf";

result_t
url_download(const char *url_str,
             const struct string_view *post_body,
             url_request_content_type post_content_type,
             const char *post_header,
             struct url_request_context *context,
             int fd)
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
	url_simulator sim = context->simulator;

	CURLcode res = curl == NULL ? CURLE_OUT_OF_MEMORY : CURLE_OK;
	check_if_num(res, ERR_URL_DOWNLOAD_ALLOC);

#ifdef WITH_CURL_VERBOSE
	res = curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
	check_if_num(res, ERR_URL_DOWNLOAD_SET_VERBOSE);
#endif

	res = curl_easy_setopt(curl, CURLOPT_WRITEDATA, &fd);
	check_if_num(res, ERR_URL_DOWNLOAD_SET_OPT_WRITEDATA);

	res = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_to_tmpfile);
	check_if_num(res, ERR_URL_DOWNLOAD_SET_OPT_WRITEFUNCTION);

	res = curl_easy_setopt(curl, CURLOPT_USERAGENT, BROWSER_USERAGENT);
	check_if_num(res, ERR_URL_DOWNLOAD_SET_OPT_USERAGENT);

	res = curl_easy_setopt(curl, CURLOPT_URL, url_str);
	check_if_num(res, ERR_URL_DOWNLOAD_SET_OPT_URL_STRING);

	if (post_body && post_body->data && post_body->sz > 0) {
		res = curl_easy_setopt(curl,
		                       CURLOPT_POSTFIELDS,
		                       post_body->data);
		check_if_num(res, ERR_URL_DOWNLOAD_SET_OPT_POST_BODY);

		res = curl_easy_setopt(curl,
		                       CURLOPT_POSTFIELDSIZE_LARGE,
		                       post_body->sz);
		check_if_num(res, ERR_URL_DOWNLOAD_SET_OPT_POST_BODY_SIZE);
	}

	switch (post_content_type) {
	case CONTENT_TYPE_UNSET:
		break;
	case CONTENT_TYPE_JSON:
		check(url_list_append(&headers, HEADER_CONTENT_TYPE_JSON));
		break;
	case CONTENT_TYPE_PROTOBUF:
		check(url_list_append(&headers, HEADER_CONTENT_TYPE_PROTOBUF));
		break;
	}

	if (post_header) {
		check(url_list_append(&headers, post_header));
	}

	if (headers) {
		res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		check_if_num(res, ERR_URL_DOWNLOAD_SET_OPT_HTTP_HEADER);
	}

	res = sim ? curl_simulate(sim(url_str), fd) : curl_easy_perform(curl);
	check_if_num(res, ERR_URL_DOWNLOAD_PERFORM);

	long status = -1;
	res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
	check_if_num(res, ERR_URL_DOWNLOAD_GET_STATUS);

	const bool is_ok = (status < 400); /* consider 1XX/2XX/3XX successful */
	check_if(!is_ok, ERR_URL_DOWNLOAD_4XX_5XX_STATUS, (int)status, url_str);

	curl_slist_free_all(headers); /* handles NULL gracefully */
	curl_url_cleanup(url);        /* handles NULL gracefully */
	return RESULT_OK;
}
