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

result_t
youtube_global_init(void)
{
	return url_global_init();
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
	if (p == NULL) {
		goto oom;
	}

	p->basejs = NULL;
	p->pos = 0;
	memset(p->url, 0, sizeof(p->url)); /* zero early, just in case */

	for (size_t i = 0; i < ARRAY_SIZE(p->url); ++i) {
		p->url[i] = curl_url(); /* may return NULL! */
		if (p->url[i] == NULL) {
			goto oom;
		}
	}

	return p;

oom:
	if (p) {
		youtube_stream_cleanup(p);
	}
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

static void
youtube_stream_valid(struct youtube_stream *p)
{
	assert(p->pos <= ARRAY_SIZE(p->url));
	for (size_t i = 0; i < ARRAY_SIZE(p->url); ++i) {
		assert(p->url[i] != NULL);
	}
}

result_t
youtube_stream_visitor(struct youtube_stream *p, void (*visit)(const char *))
{
	youtube_stream_valid(p);
	for (size_t i = 0; i < ARRAY_SIZE(p->url); ++i) {
		char *s = NULL;
		CURLUcode uc = curl_url_get(p->url[i], CURLUPART_URL, &s, 0);
		check_if_num(uc, ERR_YOUTUBE_STREAM_VISITOR_GET_URL);
		assert(s);
		visit(s);
		curl_free(s);
	}
	return RESULT_OK;
}

static WARN_UNUSED result_t
youtube_stream_set_one(struct youtube_stream *p,
                       int idx,
                       const char *val,
                       size_t sz __attribute__((unused)))
{
	CURLUcode uc = curl_url_set(p->url[idx], CURLUPART_URL, val, 0);
	check_if_num(uc, ERR_JS_PARSE_JSON_CALLBACK_GOT_PLAINTEXT_URL);
	return RESULT_OK;
}

static WARN_UNUSED result_t
youtube_stream_set_video(const char *val, size_t sz, void *userdata)
{
	struct youtube_stream *p = (struct youtube_stream *)userdata;
	debug("Setting video stream: %.*s", (int)sz, val);
	return youtube_stream_set_one(p, 1, val, sz);
}

static WARN_UNUSED result_t
youtube_stream_set_audio(const char *val, size_t sz, void *userdata)
{
	struct youtube_stream *p = (struct youtube_stream *)userdata;
	debug("Setting audio stream: %.*s", (int)sz, val);
	return youtube_stream_set_one(p, 0, val, sz);
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
static WARN_UNUSED result_t
pop_n_param_one(CURLU *url, char **result)
{
	*result = NULL; /* NULL out early, just in case */

	char *getargs __attribute__((cleanup(curl_free_getargs))) = NULL;

	CURLUcode uc = curl_url_get(url, CURLUPART_QUERY, &getargs, 0);
	check_if_num(uc, ERR_YOUTUBE_N_PARAM_QUERY_GET);
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
		return (result_t){
			.err = ERR_YOUTUBE_N_PARAM_FIND_IN_QUERY,
			.msg = result_strdup_span(getargs, getargs_sz),
		};
	}

	*result = malloc((ciphertext_sz + 1) * sizeof(*result));
	check_if(*result == NULL, ERR_YOUTUBE_N_PARAM_QUERY_ALLOC);

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
	char *after_ciphertext =
		(char *)ciphertext_within_getargs + ciphertext_sz;
	if (*after_ciphertext == '&') {
		++after_ciphertext; /* omit duplicate '&' */
	}
	const size_t remaining = (getargs + getargs_sz) - after_ciphertext;
	memmove(dst, after_ciphertext, remaining);
	dst[remaining] = '\0';

	debug("After n-param ciphertext removal:  %s", getargs);

	uc = curl_url_set(url, CURLUPART_QUERY, getargs, 0);
	check_if_num(uc, ERR_YOUTUBE_N_PARAM_QUERY_SET);

	return RESULT_OK;
}

/*
 * Copy and clear n-parameters from all query strings in <p>.
 *
 * Caller is responsible for free()-ing the pointers returned in <results>.
 */
static WARN_UNUSED result_t
pop_n_param_all(struct youtube_stream *p, char **results, size_t capacity)
{
	assert(capacity >= ARRAY_SIZE(p->url));
	for (size_t i = 0; i < ARRAY_SIZE(p->url); ++i) {
		check(pop_n_param_one(p->url[i], results + i));
	}
	return RESULT_OK;
}

static void
kv_free(char **strp)
{
	free(*strp);
}

static WARN_UNUSED result_t
append_n_param(const char *plaintext, size_t sz, void *userdata)
{
	struct youtube_stream *p = (struct youtube_stream *)userdata;

	const size_t kv_sz = sz + 3;
	/* magic number 3: two chars for "n=", one char for NUL terminator */
	char *kv __attribute__((cleanup(kv_free))) =
		malloc(kv_sz * sizeof(*kv));
	check_if(kv == NULL, ERR_YOUTUBE_N_PARAM_KVPAIR_ALLOC);

	kv[0] = 'n';
	kv[1] = '=';
	memcpy(kv + 2, plaintext, sz);
	kv[kv_sz - 1] = '\0';

	CURLU *u = p->url[p->pos++];
	CURLUcode uc = curl_url_set(u, CURLUPART_QUERY, kv, CURLU_APPENDQUERY);
	check_if_num(uc, ERR_YOUTUBE_N_PARAM_QUERY_APPEND_PLAINTEXT);

	return RESULT_OK;
}

static WARN_UNUSED result_t
download_and_mmap_tmpfd(const char *url,
                        const char *host,
                        const char *path,
                        const char *post_body,
                        int fd,
                        void **addr,
                        unsigned int *sz)
{
	assert(fd >= 0);

	check(url_download(url, host, path, post_body, fd));
	check(tmpmap(fd, addr, sz));

	debug("Downloaded %s to fd=%d", url ? url : path, fd);
	return RESULT_OK;
}

static const char INNERTUBE_URI[] =
	"https://www.youtube.com/youtubei/v1/player";

static const char INNERTUBE_POST_FMT[] =
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
	"      \"signatureTimestamp\": %lld,\n"
	"    }\n"
	"  },\n"
	"  \"contentCheckOk\": true,\n"
	"  \"racyCheckOk\": true\n"
	"}";

static WARN_UNUSED result_t
format_innertube_post(const char *target, long long int ts, char **body)
{
	const char *id = NULL;
	size_t sz = 0;

	/* Note use of non-capturing group: (?:...) */
	check_if(!re_capture("(?:&|\\?)v=([^&]+)(?:&|$)",
	                     target,
	                     strlen(target),
	                     &id,
	                     &sz),
	         ERR_YOUTUBE_INNERTUBE_POST_ID);
	debug("Parsed ID: %.*s", (int)sz, id);

	const int rc = asprintf(body, INNERTUBE_POST_FMT, (int)sz, id, ts);
	check_if(rc < 0, ERR_YOUTUBE_INNERTUBE_POST_ALLOC);

	debug("Formatted InnerTube POST body:\n%s", *body);
	return RESULT_OK;
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
	info_m_if(d->fd > 0 && close(d->fd) < 0,
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

static void
asprintf_free(char **strp)
{
	free(*strp);
}

result_t
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
		check(ops->before(p));
	}

	check(tmpfd(&json.fd));
	check(tmpfd(&html.fd));
	check(tmpfd(&js.fd));

	if (ops && ops->before_inet) {
		check(ops->before_inet(p));
	}

	check(download_and_mmap_tmpfd(target,
	                              NULL,
	                              NULL,
	                              NULL,
	                              html.fd,
	                              &html.buf,
	                              &html.sz));

	const char *basejs = NULL;
	size_t basejs_sz = 0;
	check(find_base_js_url(html.buf, html.sz, &basejs, &basejs_sz));

	debug("Setting base.js URL: %.*s", (int)basejs_sz, basejs);
	p->basejs = strndup(basejs, basejs_sz);
	check_if(p->basejs == NULL, ERR_JS_BASEJS_URL_ALLOC);

	check(download_and_mmap_tmpfd(NULL,
	                              "www.youtube.com",
	                              p->basejs,
	                              NULL,
	                              js.fd,
	                              &js.buf,
	                              &js.sz));

	long long int timestamp = 0;
	check(find_js_timestamp(js.buf, js.sz, &timestamp));

	char *innertube_post __attribute__((cleanup(asprintf_free))) = NULL;
	check(format_innertube_post(target, timestamp, &innertube_post));
	check(download_and_mmap_tmpfd(INNERTUBE_URI,
	                              NULL,
	                              NULL,
	                              innertube_post,
	                              json.fd,
	                              &json.buf,
	                              &json.sz));

	if (ops && ops->after_inet) {
		check(ops->after_inet(p));
	}

	if (ops && ops->before_parse) {
		check(ops->before_parse(p));
	}

	struct parse_ops pops = {
		.got_video = youtube_stream_set_video,
		.got_audio = youtube_stream_set_audio,
	};
	check(parse_json(json.buf, json.sz, &pops, p));

	if (ops && ops->after_parse) {
		check(ops->after_parse(p));
	}

	if (ops && ops->before_eval) {
		check(ops->before_eval(p));
	}

	const char *deobfuscator = NULL;
	size_t deob_sz = 0;
	check(find_js_deobfuscator(js.buf, js.sz, &deobfuscator, &deob_sz));

	char *ciphertexts[ARRAY_SIZE(p->url)]
		__attribute__((cleanup(ciphertexts_cleanup))) = {NULL};
	check(pop_n_param_all(p, ciphertexts, ARRAY_SIZE(ciphertexts)));

	struct call_ops cops = {
		.got_result = append_n_param,
	};
	check(call_js_foreach(deobfuscator,
	                      deob_sz,
	                      ciphertexts,
	                      ARRAY_SIZE(ciphertexts),
	                      &cops,
	                      p));

	if (ops && ops->after_eval) {
		check(ops->after_eval(p));
	}

	if (ops && ops->after) {
		check(ops->after(p));
	}

	return RESULT_OK;
}
