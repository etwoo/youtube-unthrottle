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

#define error_if_uc_msg(uc, msg) error_if(uc, msg ": %s", curl_url_strerror(uc))

struct youtube_stream {
	char *basejs;
	size_t pos;
	CURLU *url[2];
};

void
youtube_global_init(void)
{
	url_global_init();
}

void
youtube_global_cleanup(void)
{
	url_global_cleanup();
}

struct youtube_stream *
youtube_stream_init(void)
{
	struct youtube_stream *p = malloc(sizeof(*p));
	error_if(p == NULL, "Cannot allocate youtube_stream struct");

	p->basejs = NULL;
	p->pos = 0;
	memset(p->url, 0, sizeof(p->url)); /* zero early, just in case */

	for (size_t i = 0; i < ARRAY_SIZE(p->url); ++i) {
		p->url[i] = curl_url(); /* may return NULL! */
		error_if(p->url[i] == NULL, "Cannot allocate URL handle");
	}

	return p;
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

static void
youtube_stream_valid(struct youtube_stream *p)
{
	assert(p->pos <= ARRAY_SIZE(p->url));
	for (size_t i = 0; i < ARRAY_SIZE(p->url); ++i) {
		assert(p->url[i] != NULL);
	}
}

void
youtube_stream_visitor(struct youtube_stream *p, void (*visit)(const char *))
{
	youtube_stream_valid(p);
	for (size_t i = 0; i < ARRAY_SIZE(p->url); ++i) {
		char *s = NULL;
		CURLUcode uc = curl_url_get(p->url[i], CURLUPART_URL, &s, 0);
		error_if_uc_msg(uc, "Cannot get CURLUPART_URL");
		assert(s);
		visit(s);
		curl_free(s);
	}
}

static void
youtube_stream_set_one(struct youtube_stream *p,
                       int idx,
                       const char *val,
                       size_t sz __attribute__((unused)))
{
	CURLUcode uc = curl_url_set(p->url[idx], CURLUPART_URL, val, 0);
	error_if_uc_msg(uc, "Cannot set CURLUPART_URL");
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

static void
curl_free_getargs(char **getargs)
{
	curl_free(*getargs); /* handles NULL gracefully */
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

	char *getargs __attribute__((cleanup(curl_free_getargs))) = NULL;

	CURLUcode uc = curl_url_get(url, CURLUPART_QUERY, &getargs, 0);
	error_if_uc_msg(uc, "Cannot get CURLUPART_QUERY");
	assert(getargs);

	const size_t getargs_sz = strlen(getargs);
	assert(*(getargs + getargs_sz) == '\0');
	const char *ciphertext_within_getargs = NULL;
	size_t ciphertext_sz = 0;

	/* Note use of non-capturing group: (?:...) */
	if (!re_capture("(?:&|^)n=([^&]+)(?:&|$)",
	                getargs,
	                getargs_sz,
	                &ciphertext_within_getargs,
	                &ciphertext_sz)) {
		warn_then_return("No n-parameter in query: %s", getargs);
	}

	*result = malloc((ciphertext_sz + 1) * sizeof(*result));
	error_if(*result == NULL, "Cannot allocate ciphertext buffer");

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
	 *
	 * Note: it is safe (I think ...) to cast away const below because we
	 * know that <ciphertext_within_getargs> ultimately points at a
	 * subsection of <getargs>, and the latter is non-const.
	 *
	 * Casting away const is required here because the re.h functions
	 * accept and return (const char *) instead of (char *), and I don't
	 * currently know a way to handle this kind of const/non-const
	 * variation cleanly in C (without ugly macro usage, code duplication,
	 * etc); if this were C++, we'd probably use a template with an auto
	 * return type to have a single function definition body expand to both
	 * const and non-const variants.
	 */
	assert(ciphertext_within_getargs[-2] == 'n' &&
	       ciphertext_within_getargs[-1] == '=');
	char *dst = (char *)ciphertext_within_getargs - strlen("n=");
	if (dst > getargs) {
		assert(dst[-1] == '&');
		--dst;
	} /* else: dst == getargs, and n-parameter is the first GET argument */
	char *after_ciphertext =
		(char *)ciphertext_within_getargs + ciphertext_sz;
	const size_t remaining = (getargs + getargs_sz) - after_ciphertext;
	memmove(dst, after_ciphertext, remaining);
	dst[remaining] = '\0';

	debug("After n-param ciphertext removal:  %s", getargs);

	uc = curl_url_set(url, CURLUPART_QUERY, getargs, 0);
	error_if_uc_msg(uc, "Cannot clear ciphertext n-parameter");
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
	error_if(kv == NULL, "Cannot allocate kv-pair buffer");

	kv[0] = 'n';
	kv[1] = '=';
	memcpy(kv + 2, plaintext, sz);
	kv[kv_sz - 1] = '\0';

	CURLU *u = p->url[p->pos++];
	CURLUcode uc = curl_url_set(u, CURLUPART_QUERY, kv, CURLU_APPENDQUERY);
	error_if_uc_msg(uc, "Cannot append plaintext n-parameter");

	free(kv);
}

static bool
download_and_mmap_tmpfd(const char *url,
                        const char *host,
                        const char *path,
                        const char *post_body,
                        int fd,
                        void **addr,
                        unsigned int *sz)
{
	assert(fd >= 0);

	const bool downloaded_and_mapped =
		url_download(url, host, path, post_body, fd) &&
		tmpmap(fd, addr, sz);
	if (downloaded_and_mapped) {
		debug("Downloaded %s to fd=%d", url ? url : path, fd);
	}
	return downloaded_and_mapped;
}

static const char INNERTUBE_URI[] =
	"https://www.youtube.com/youtubei/v1/player";

static const char INNERTUBE_POST_FORMAT[] =
	"{\n"
	"  \"context\": {\n"
	"    \"client\": {\n"
	"      \"clientName\": \"WEB_CREATOR\",\n"
	"      \"clientVersion\": \"1.20240723.03.00\",\n"
	"      \"hl\": \"en\",\n"
	"      \"timeZone\": \"UTC\",\n"
	"      \"utcOffsetMinutes\": 0\n"
	"    }\n"
	"  },\n"
	"  \"videoId\": \"%.*s\",\n"
	"  \"playbackContext\": {\n"
	"    \"contentPlaybackContext\": {\n"
	"      \"html5Preference\": \"HTML5_PREF_WANTS\",\n"
	"    }\n"
	"  },\n"
	"  \"contentCheckOk\": true,\n"
	"  \"racyCheckOk\": true\n"
	"}";

static bool
format_innertube_post(const char *target, char *body, int capacity)
{
	const char *id = NULL;
	size_t sz = 0;

	/* Note use of non-capturing group: (?:...) */
	if (!re_capture("(?:&|\\?)v=([^&]+)(?:&|$)",
	                target,
	                strlen(target),
	                &id,
	                &sz)) {
		warn_then_return_false("Cannot find ID in URL: %s", target);
	}
	debug("Parsed ID: %.*s", (int)sz, id);

	const int printed =
		snprintf(body, capacity, INNERTUBE_POST_FORMAT, (int)sz, id);
	if (printed >= capacity || body[printed] != '\0') {
		warn_then_return_false("%d bytes is too small for snprintf()",
		                       capacity);
	}
	debug("Formatted InnerTube POST body:\n%s", body);

	return true;
}

struct downloaded {
	const char *description; /* does not own */
	int fd;
	unsigned int sz;
	void *buf;
};

static void
downloaded_init(struct downloaded *d, const char *description)
{
	d->description = description;
	d->fd = -1; /* guarantee fd is invalid by default */
	d->sz = 0;
	d->buf = NULL;
}

static void
downloaded_cleanup(struct downloaded *d)
{
	tmpunmap(d->buf, d->sz);
	info_if(d->fd > 0 && close(d->fd) < 0,
	        "Ignoring error close()-ing %s",
	        d->description);
}

static void
ciphertexts_cleanup(char *ciphertexts[][2])
{
	for (size_t i = 0; i < ARRAY_SIZE(*ciphertexts); ++i) {
		free((*ciphertexts)[i]);
		(*ciphertexts)[i] = NULL;
	}
	debug("free()-d %zd n-param ciphertext bufs", ARRAY_SIZE(*ciphertexts));
}

bool
youtube_stream_setup(struct youtube_stream *p,
                     struct youtube_setup_ops *ops,
                     const char *target)
{
	struct downloaded json __attribute__((cleanup(downloaded_cleanup)));
	struct downloaded html __attribute__((cleanup(downloaded_cleanup)));
	struct downloaded js __attribute__((cleanup(downloaded_cleanup)));

	downloaded_init(&json, "JSON tmpfile");
	downloaded_init(&html, "HTML tmpfile");
	downloaded_init(&js, "JavaScript tmpfile");

	if (ops && ops->before) {
		ops->before(p);
	}

	json.fd = tmpfd();
	error_if(json.fd < 0, "Cannot get JSON tmpfile");

	html.fd = tmpfd();
	error_if(html.fd < 0, "Cannot get HTML tmpfile");

	js.fd = tmpfd();
	error_if(js.fd < 0, "Cannot get JavaScript tmpfile");

	if (ops && ops->before_inet) {
		ops->before_inet(p);
	}

	char innertube_post_body[4096];
	const int innertube_post_capacity = sizeof(innertube_post_body);
	if (!format_innertube_post(target,
	                           innertube_post_body,
	                           innertube_post_capacity) ||
	    !download_and_mmap_tmpfd(INNERTUBE_URI,
	                             NULL,
	                             NULL,
	                             innertube_post_body,
	                             json.fd,
	                             &json.buf,
	                             &json.sz)) {
		return false;
	}

	if (!download_and_mmap_tmpfd(target,
	                             NULL,
	                             NULL,
	                             NULL,
	                             html.fd,
	                             &html.buf,
	                             &html.sz)) {
		return false;
	}

	const char *basejs = NULL;
	size_t basejs_sz = 0;
	find_base_js_url(html.buf, html.sz, &basejs, &basejs_sz);
	if (basejs == NULL || basejs_sz == 0) {
		return false;
	}

	debug("Setting base.js URL: %.*s", (int)basejs_sz, basejs);
	p->basejs = strndup(basejs, basejs_sz);
	error_if(p->basejs == NULL, "Cannot strndup() base.js URL");

	if (!download_and_mmap_tmpfd(NULL,
	                             "www.youtube.com",
	                             p->basejs,
	                             NULL,
	                             js.fd,
	                             &js.buf,
	                             &js.sz)) {
		return false;
	}

	if (ops && ops->after_inet) {
		ops->after_inet(p);
	}

	if (ops && ops->before_parse) {
		ops->before_parse(p);
	}

	struct parse_ops pops = {
		.got_video = youtube_stream_set_video,
		.got_audio = youtube_stream_set_audio,
	};
	parse_json(json.buf, json.sz, &pops, p);

	if (ops && ops->after_parse) {
		ops->after_parse(p);
	}

	if (ops && ops->before_eval) {
		ops->before_eval(p);
	}

	const char *deobfuscator = NULL;
	size_t deobfuscator_sz = 0;
	find_js_deobfuscator(js.buf, js.sz, &deobfuscator, &deobfuscator_sz);
	if (deobfuscator == NULL || deobfuscator_sz == 0) {
		return false;
	}

	char *ciphertexts[ARRAY_SIZE(p->url)]
		__attribute__((cleanup(ciphertexts_cleanup))) = {NULL};
	pop_n_param_all(p, ciphertexts, ARRAY_SIZE(ciphertexts));
	for (size_t i = 0; i < ARRAY_SIZE(ciphertexts); ++i) {
		if (ciphertexts[i] == NULL) {
			return false;
		}
	}

	struct call_ops cops = {
		.got_result = append_n_param,
	};
	call_js_foreach(deobfuscator,
	                deobfuscator_sz,
	                ciphertexts,
	                ARRAY_SIZE(ciphertexts),
	                &cops,
	                p);

	if (ops && ops->after_eval) {
		ops->after_eval(p);
	}

	if (ops && ops->after) {
		ops->after(p);
	}

	return true;
}

#undef error_if_uc_msg
