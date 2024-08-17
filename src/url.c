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

static const int FD_DISCARD = -1;

static size_t
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
	static bool GLOBAL_CURL_EASY_HANDLE_INIT = false;
	static CURLU *GLOBAL_CURL_EASY_HANDLE = NULL;
	/*
	 * Initialization of these static variables is not currently
	 * thread-safe. Ditto for callers of get_easy_handle() who use the
	 * resulting (cached, shared) curl easy handle.
	 *
	 * If youtube-unthrottle ever becomes multithreaded, this code will
	 * need to be retrofitted with a mutex and/or the callers will need
	 * to ensure that initialization happens while still single-threaded.
	 */
	if (!GLOBAL_CURL_EASY_HANDLE_INIT) {
		GLOBAL_CURL_EASY_HANDLE_INIT = true;
		GLOBAL_CURL_EASY_HANDLE = curl_easy_init();
	}

	if (GLOBAL_CURL_EASY_HANDLE == NULL) {
		/*
		 * From the libcurl manpages:
		 *
		 *   If this function returns NULL, something went wrong
		 *   and you cannot use the other curl functions.
		 *
		 * ... so there isn't much we can do here to get details.
		 */
		warn("curl_easy_init() returned NULL");
	} else {
		curl_easy_reset(GLOBAL_CURL_EASY_HANDLE);
	}

	return GLOBAL_CURL_EASY_HANDLE;
}

void
url_global_init(void)
{
	curl_global_init(CURL_GLOBAL_DEFAULT);

	/*
	 * Nudge curl into creating its DNS resolver thread(s) now, before the
	 * the process sandbox closes and blocks the clone3() syscall.
	 */
	if (!url_download("https://www.youtube.com",
	                  NULL,
	                  NULL,
	                  NULL,
	                  FD_DISCARD)) {
		warn("Error in url_prepare_threads");
	}
}

void
url_global_cleanup(void)
{
	curl_easy_cleanup(get_easy_handle()); /* handles NULL gracefully */
	curl_global_cleanup();
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
static const char CONTENT_TYPE_JSON[] = "Content-Type: application/json";

bool
url_download(const char *url_str,   /* may be NULL */
             const char *host_str,  /* may be NULL */
             const char *path_str,  /* may be NULL */
             const char *post_body, /* may be NULL */
             int fd)
{
	CURLcode res = CURLE_OK;
	CURLU *url = NULL;
	struct curl_slist *headers = NULL;

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

	if (post_body) {
		headers = curl_slist_append(headers, CONTENT_TYPE_JSON);
		res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		if (res) {
			warn("Error on CURLOPT_HTTPHEADER of \"%s\": %s",
			     CONTENT_TYPE_JSON,
			     curl_easy_strerror(res));
			goto cleanup;
		}

		res = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_body);
		/* Note: libcurl does not copy <post_body> */
		if (res) {
			warn("Error on CURLOPT_POSTFIELDS of \"%s\": %s",
			     post_body,
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
	curl_slist_free_all(headers); /* handles NULL gracefully */
	curl_url_cleanup(url);        /* handles NULL gracefully */
	return (res == CURLE_OK);
}
