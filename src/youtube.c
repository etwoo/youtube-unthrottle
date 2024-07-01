#include "youtube.h"

#include "array.h"
#include "debug.h"
#include "js.h"
#include "re.h"
#include "tmpfile.h"
#include "url.h"

#include <assert.h>
#include <curl/curl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct youtube_stream {
	char *basejs;
	size_t pos;
	CURLU *url[2];
};

void
youtube_global_init(void)
{
	curl_global_init(CURL_GLOBAL_DEFAULT);
}

void
youtube_global_cleanup(void)
{
	curl_global_cleanup();
}

struct youtube_stream *
youtube_stream_init(void)
{
	struct youtube_stream *p = malloc(sizeof(*p));
	if (p == NULL) {
		goto error;
	}

	p->basejs = NULL;
	p->pos = 0;
	memset(p->url, 0, sizeof(p->url)); /* zero early, just in case */

	for (size_t i = 0; i < ARRAY_SIZE(p->url); ++i) {
		p->url[i] = curl_url(); /* may return NULL! */
		if (p->url[i] == NULL) {
			warn("curl_url() returned NULL");
			goto error;
		}
	}

	return p;

error:
	free(p);
	return NULL;
}

void
youtube_stream_cleanup(struct youtube_stream *p)
{
	free(p->basejs);
	p->basejs = NULL;
	p->pos = 0;
	for (size_t i = 0; i < ARRAY_SIZE(p->url); ++i) {
		curl_url_cleanup(p->url[i]); /* handles NULL gracefully */
		p->url[i] = NULL;
	}
	free(p);
}

static bool
youtube_stream_valid(struct youtube_stream *p)
{
	assert(p->pos <= ARRAY_SIZE(p->url));
	for (size_t i = 0; i < ARRAY_SIZE(p->url); ++i) {
		if (p->url[i] == NULL) {
			return false;
		}
	}
	return true;
}

void
youtube_stream_print(struct youtube_stream *p)
{
	assert(youtube_stream_valid(p));
	for (size_t i = 0; i < ARRAY_SIZE(p->url); ++i) {
		char *s = NULL;
		CURLUcode uc = curl_url_get(p->url[i], CURLUPART_URL, &s, 0);
		if (!uc && s != NULL) {
			puts(s);
			curl_free(s);
		} else {
			warn("Error getting CURLUPART_URL: %s",
			     curl_url_strerror(uc));
		}
	}
}

static void
youtube_stream_set_basejs(const char *val, size_t sz, void *userdata)
{
	struct youtube_stream *p = (struct youtube_stream *)userdata;
	debug("Setting base.js URL: %.*s", (int)sz, val);
	p->basejs = strndup(val, sz);
}

static void
youtube_stream_set_one(struct youtube_stream *p,
                       int idx,
                       const char *val,
                       size_t sz)
{
	CURLUcode uc = curl_url_set(p->url[idx], CURLUPART_URL, val, 0);
	if (uc) {
		warn("Error setting CURLUPART_URL of %.*s: %s",
		     (int)sz,
		     val,
		     curl_url_strerror(uc));
	}
}

static void
youtube_stream_set_video(const char *val, size_t sz, void *userdata)
{
	struct youtube_stream *p = (struct youtube_stream *)userdata;
	debug("Setting video stream: %.*s", (int)sz, val);
	youtube_stream_set_one(p, 1, val, sz);
}

static void
youtube_stream_set_audio(const char *val, size_t sz, void *userdata)
{
	struct youtube_stream *p = (struct youtube_stream *)userdata;
	debug("Setting audio stream: %.*s", (int)sz, val);
	youtube_stream_set_one(p, 0, val, sz);
}

/*
 * Copy and clear n-parameters from query string in <url>.
 *
 * Caller is responsible for free()-ing the pointer returned in <result>.
 */
static void
pop_n_param_one(CURLU *url, char **result)
{
	*result = NULL; /* NULL out early, just in case */

	char *getargs = NULL;

	CURLUcode uc = curl_url_get(url, CURLUPART_QUERY, &getargs, 0);
	if (uc || getargs == NULL) {
		warn("Error getting CURLUPART_QUERY: %s",
		     curl_url_strerror(uc));
		goto cleanup;
	}

	const size_t getargs_sz = strlen(getargs);
	assert(*(getargs + getargs_sz) == '\0');
	char *ciphertext_within_getargs = NULL;
	size_t ciphertext_sz = 0;

	/* Note use of non-capturing group: (?:...) */
	if (!re_capture("(?:&|^)n=([^&]+)(?:&|$)",
	                getargs,
	                getargs_sz,
	                &ciphertext_within_getargs,
	                &ciphertext_sz)) {
		warn("No n-parameter in query: %s", getargs);
		goto cleanup;
	}

	*result = malloc((ciphertext_sz + 1) * sizeof(*result));
	if (*result == NULL) {
		warn("Error allocating %zd bytes for ciphertext",
		     ciphertext_sz + 1);
		goto cleanup;
	}

	/*
	 * Copy n-parameter value out of storage owned by CURLU <url>.
	 *
	 * For now, assume <ciphertext> does not require URI-encoding. If that
	 * ever becomes necessary, use curl_easy_escape().
	 */
	memcpy(*result, ciphertext_within_getargs, ciphertext_sz);
	(*result)[ciphertext_sz] = '\0';
	debug("Copied n-param ciphertext: %s", *result);

	debug("Before n-param ciphertext removal: %s", getargs);

	/*
	 * Remove ciphertext n-parameter (key and value) from query string.
	 *
	 * Note: memmove() supports overlapping <src> and <dst> pointers.
	 */
	char *dst = ciphertext_within_getargs - 3;
	/* magic number 3: two chars for preceding "n=", one char for '&' */
	char *after_ciphertext = ciphertext_within_getargs + ciphertext_sz;
	const size_t remaining = (getargs + getargs_sz) - after_ciphertext;
	memmove(dst, after_ciphertext, remaining);
	dst[remaining] = '\0';

	debug("After n-param ciphertext removal:  %s", getargs);

	uc = curl_url_set(url, CURLUPART_QUERY, getargs, 0);
	if (uc) {
		warn("Error clearing ciphertext n-parameter: %s",
		     curl_url_strerror(uc));
		goto cleanup;
	}

cleanup:
	curl_free(getargs); /* handles NULL gracefully */
}

/*
 * Copy and clear n-parameters from all query strings in <p>.
 *
 * Caller is responsible for free()-ing the pointers returned in <results>.
 */
static void
pop_n_param_all(struct youtube_stream *p, char **results, size_t capacity)
{
	assert(capacity >= ARRAY_SIZE(p->url));
	for (size_t i = 0; i < ARRAY_SIZE(p->url); ++i) {
		pop_n_param_one(p->url[i], results + i);
	}
}

static void
append_n_param(const char *plaintext, size_t sz, void *userdata)
{
	struct youtube_stream *p = (struct youtube_stream *)userdata;

	const size_t kv_sz = sz + 3;
	/* magic number 3: two chars for "n=", one char for NUL terminator */
	char *kv = malloc(kv_sz * sizeof(*kv));
	if (kv == NULL) {
		warn("Error allocating %zd bytes for kv-pair", kv_sz);
		goto cleanup;
	}

	kv[0] = 'n';
	kv[1] = '=';
	memcpy(kv + 2, plaintext, sz);
	kv[kv_sz - 1] = '\0';

	CURLU *url = p->url[p->pos++];

	CURLUcode uc =
		curl_url_set(url, CURLUPART_QUERY, kv, CURLU_APPENDQUERY);
	if (uc) {
		warn("Error appending plaintext n-parameter: %s",
		     curl_url_strerror(uc));
		goto cleanup;
	}

cleanup:
	free(kv);
}

static bool
download_and_mmap_tmpfd(const char *url,
                        const char *host,
                        const char *path,
                        int *fd,
                        void **addr,
                        unsigned int *sz)
{
	*fd = tmpfd();
	if (*fd < 0) {
		goto error;
	}

	if (url) {
		if (!url_download(url, *fd)) {
			goto error;
		}
	} else {
		assert(host != NULL && path != NULL);
		if (!url_download_from(host, path, *fd)) {
			goto error;
		}
	}

	if (!tmpmap(*fd, addr, sz)) {
		goto error;
	}

	return true;

error:
	return false;
}

bool
youtube_stream_setup(struct youtube_stream *p,
                     struct youtube_setup_ops *ops,
                     const char *target)
{
	bool result = false;

	int html_fd = -1; /* guarantee fd is invalid by default */
	unsigned int html_sz = 0;
	void *html = NULL;

	int js_fd = -1; /* guarantee fd is invalid by default */
	unsigned int js_sz = 0;
	void *js = NULL;

	const size_t ciphertexts_count = ARRAY_SIZE(p->url);
	char *ciphertexts[ciphertexts_count];

	if (ops && ops->before) {
		ops->before(p);
	}

	if (ops && ops->before_inet) {
		ops->before_inet(p);
	}

	if (!download_and_mmap_tmpfd(target,
	                             NULL,
	                             NULL,
	                             &html_fd,
	                             &html,
	                             &html_sz)) {
		goto cleanup;
	}

	struct parse_ops pops = {
		.got_basejs = youtube_stream_set_basejs,
		.got_audio = youtube_stream_set_audio,
		.got_video = youtube_stream_set_video,
	};
	parse_html_json(html, html_sz, &pops, p);
	if (p->basejs == NULL) {
		goto cleanup;
	}

	if (!download_and_mmap_tmpfd(NULL,
	                             "www.youtube.com",
	                             p->basejs,
	                             &js_fd,
	                             &js,
	                             &js_sz)) {
		goto cleanup;
	}

	if (ops && ops->after_inet) {
		ops->after_inet(p);
	}

	if (ops && ops->before_eval) {
		ops->before_eval(p);
	}

	char *deobfuscator = NULL;
	size_t deobfuscator_sz = 0;
	find_js_deobfuscator(js, js_sz, &deobfuscator, &deobfuscator_sz);
	if (deobfuscator == NULL || deobfuscator_sz == 0) {
		goto cleanup;
	}

	pop_n_param_all(p, ciphertexts, ciphertexts_count);
	for (size_t i = 0; i < ciphertexts_count; ++i) {
		if (ciphertexts[i] == NULL) {
			goto cleanup;
		}
	}

	struct call_ops cops = {
		.got_result = append_n_param,
	};
	call_js_foreach(deobfuscator,
	                deobfuscator_sz,
	                ciphertexts,
	                ciphertexts_count,
	                &cops,
	                p);

	if (ops && ops->after_eval) {
		ops->after_eval(p);
	}

	result = true;

cleanup:
	for (size_t i = 0; i < ciphertexts_count; ++i) {
		free(ciphertexts[i]);
		ciphertexts[i] = NULL;
	}
	tmpunmap(html, html_sz);
	tmpunmap(js, js_sz);
	if (html_fd >= 0 && close(html_fd) < 0) {
		pwarn("Ignoring error while close()-ing tmpfile");
	}
	if (js_fd >= 0 && close(js_fd) < 0) {
		pwarn("Ignoring error while close()-ing tmpfile");
	}
	if (ops && ops->after) {
		ops->after(p);
	}
	return result;
}
