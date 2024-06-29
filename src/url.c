#include "url.h"

#include "debug.h"

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

static size_t
write_to_tmpfile(char *ptr, size_t size, size_t nmemb, void *userdata)
{
	const size_t real_size = size * nmemb;
	const int *fd = (const int *)userdata;

	for (size_t remaining_bytes = real_size; remaining_bytes > 0;) {
		const ssize_t written = write(*fd, ptr, remaining_bytes);
		if (written < 0) {
			pwarn("Error writing to tmpfile");
			break;
		}
		remaining_bytes -= written;
	}

	return real_size; /* always consider buffer entirely consumed */
}

static CURL *
get_easy_handle(void)
{
	CURL *curl = curl_easy_init();
	if (curl == NULL) {
		/*
		 * From the libcurl manpages:
		 *
		 *   If this function returns NULL, something went wrong
		 *   and you cannot use the other curl functions.
		 *
		 * ... so there isn't much we can do here to get details.
		 */
		warn("curl_easy_init() returned NULL");
		return NULL;
	}
	return curl;
}

static CURLU *
url_prepare(const char *hostp, const char *pathp)
{
	CURLUcode uc = CURLUE_OK;

	CURLU *url = curl_url();
	if (url == NULL) {
		warn("curl_url() returned NULL");
		goto cleanup;
	}

	uc = curl_url_set(url, CURLUPART_SCHEME, "https", 0);
	if (uc) {
		warn("Error setting CURLUPART_HOST value: %s",
		     curl_url_strerror(uc));
		goto cleanup;
	}

	uc = curl_url_set(url, CURLUPART_HOST, hostp, 0);
	if (uc) {
		warn("Error setting CURLUPART_HOST value: %s",
		     curl_url_strerror(uc));
		goto cleanup;
	}

	uc = curl_url_set(url, CURLUPART_PATH, pathp, 0);
	if (uc) {
		warn("Error setting CURLUPART_PATH of %s: %s",
		     pathp,
		     curl_url_strerror(uc));
		goto cleanup;
	}

cleanup:
	if (uc == CURLUE_OK) {
		return url;
	} else {
		curl_url_cleanup(url); /* handles NULL gracefully */
		return NULL;
	}
}

static const char BROWSER_USERAGENT[] =
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, "
	"like Gecko) Chrome/87.0.4280.101 Safari/537.36";

static bool
url_download_impl(const char *url_str,  /* may be NULL */
                  const char *host_str, /* may be NULL */
                  const char *path_str, /* may be NULL */
                  int fd)
{
	CURLcode res = CURLE_OK;
	CURLU *url = NULL;

	CURLU *curl = get_easy_handle();
	if (curl == NULL) {
		res = CURLE_OUT_OF_MEMORY;
		goto cleanup;
	}

	res = curl_easy_setopt(curl, CURLOPT_WRITEDATA, &fd);
	if (res) {
		warn("Error on CURLOPT_WRITEDATA of %p: %s",
		     &fd,
		     curl_easy_strerror(res));
		goto cleanup;
	}

	res = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_to_tmpfile);
	if (res) {
		warn("Error on CURLOPT_WRITEFUNCTION: %s",
		     curl_easy_strerror(res));
		goto cleanup;
	}

	res = curl_easy_setopt(curl, CURLOPT_USERAGENT, BROWSER_USERAGENT);
	if (res) {
		warn("Error on CURLOPT_USERAGENT: %s", curl_easy_strerror(res));
		goto cleanup;
	}

	if (url_str) {
		res = curl_easy_setopt(curl, CURLOPT_URL, url_str);
		if (res) {
			warn("Error on CURLOPT_URL of %s: %s",
			     url_str,
			     curl_easy_strerror(res));
			goto cleanup;
		}
	} else {
		assert(host_str != NULL && path_str != NULL);

		url = url_prepare(host_str, path_str);
		if (url == NULL) {
			res = CURLE_URL_MALFORMAT;
			goto cleanup;
		}

		res = curl_easy_setopt(curl, CURLOPT_CURLU, url);
		if (res) {
			warn("Error on CURLOPT_CURLU value: %s",
			     curl_easy_strerror(res));
			goto cleanup;
		}
	}

	res = curl_easy_perform(curl);
	if (res) {
		warn("Error in curl_easy_perform(): %s",
		     curl_easy_strerror(res));
		goto cleanup;
	}

cleanup:
	curl_url_cleanup(url);   /* handles NULL gracefully */
	curl_easy_cleanup(curl); /* handles NULL gracefully */
	return (res == CURLE_OK);
}

bool
url_download_from(const char *host, const char *path, int fd)
{
	return url_download_impl(NULL, host, path, fd);
}

bool
url_download(const char *url, int fd)
{
	return url_download_impl(url, NULL, NULL, fd);
}
