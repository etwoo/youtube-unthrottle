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
	CURLU *url[2];
	char *proof_of_origin;
	char *visitor_data;
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

#define check_oom(p)                                                           \
	if ((p) == NULL) {                                                     \
		goto oom;                                                      \
	}

struct youtube_stream *
youtube_stream_init(const char *proof_of_origin, const char *visitor_data)
{
	assert(proof_of_origin && visitor_data);

	struct youtube_stream *p = malloc(sizeof(*p));
	check_oom(p);

	memset(p, 0, sizeof(*p)); /* zero early, just in case */

	for (size_t i = 0; i < ARRAY_SIZE(p->url); ++i) {
		p->url[i] = curl_url(); /* may return NULL! */
		check_oom(p->url[i]);
	}

	p->proof_of_origin = strdup(proof_of_origin);
	check_oom(p->proof_of_origin);

	p->visitor_data = strdup(visitor_data);
	check_oom(p->visitor_data);

	return p;

oom:
	youtube_stream_cleanup(p);
	return NULL;
}

#undef check_oom

void
youtube_stream_cleanup(struct youtube_stream *p)
{
	if (p == NULL) {
		return;
	}
	for (size_t i = 0; i < ARRAY_SIZE(p->url); ++i) {
		curl_url_cleanup(p->url[i]); /* handles NULL gracefully */
		p->url[i] = NULL;
	}
	free(p->proof_of_origin);
	free(p->visitor_data);
	free(p);
}

static void
youtube_stream_valid(struct youtube_stream *p)
{
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

static void
asprintf_free(char **strp)
{
	free(*strp);
}

static WARN_UNUSED result_t
youtube_stream_set_one(struct youtube_stream *p,
                       int idx,
                       const char *val,
                       size_t sz __attribute__((unused)))
{
	CURLUcode uc = CURLUE_OK;
	CURLU *u = p->url[idx];

	uc = curl_url_set(u, CURLUPART_URL, val, 0);
	check_if_num(uc, ERR_JS_PARSE_JSON_CALLBACK_GOT_CIPHERTEXT_URL);

	char *kv __attribute__((cleanup(asprintf_free))) = NULL;
	const int rc = asprintf(&kv, "pot=%s", p->proof_of_origin);
	check_if(rc < 0, ERR_YOUTUBE_POT_PARAM_KVPAIR_ALLOC);

	uc = curl_url_set(u, CURLUPART_QUERY, kv, CURLU_APPENDQUERY);
	check_if_num(uc, ERR_YOUTUBE_POT_PARAM_QUERY_APPEND);

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

static WARN_UNUSED result_t
youtube_stream_choose_quality_any(const char *val,
                                  size_t sz,
                                  void *userdata __attribute__((unused)))
{
	debug("Any quality allowed: %.*s", (int)sz, val);
	return RESULT_OK;
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
		return make_result(ERR_YOUTUBE_N_PARAM_FIND_IN_QUERY,
		                   (const char *)getargs,
		                   getargs_sz);
	}

	/*
	 * Copy n-parameter value out of storage owned by CURLU <url>.
	 *
	 * For now, assume <ciphertext> does not require URI-encoding. If that
	 * ever becomes necessary, use curl_easy_escape().
	 */
	const int rc = asprintf(result,
	                        "%.*s",
	                        (int)ciphertext_sz,
	                        ciphertext_within_getargs);
	check_if(rc < 0, ERR_YOUTUBE_N_PARAM_QUERY_ALLOC);
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

static WARN_UNUSED result_t
append_n_param(const char *plaintext, size_t sz, size_t pos, void *userdata)
{
	struct youtube_stream *p = (struct youtube_stream *)userdata;

	char *kv __attribute__((cleanup(asprintf_free))) = NULL;
	const int rc = asprintf(&kv, "n=%.*s", (int)sz, plaintext);
	check_if(rc < 0, ERR_YOUTUBE_N_PARAM_KVPAIR_ALLOC);

	assert(pos < ARRAY_SIZE(p->url));
	CURLU *u = p->url[pos];
	CURLUcode uc = curl_url_set(u, CURLUPART_QUERY, kv, CURLU_APPENDQUERY);
	check_if_num(uc, ERR_YOUTUBE_N_PARAM_QUERY_APPEND);

	return RESULT_OK;
}

static WARN_UNUSED result_t
download_and_mmap_tmpfd(const char *url,
                        const char *host,
                        const char *path,
                        const char *post_body,
                        const char *post_header,
                        int fd,
                        void **addr,
                        unsigned int *sz)
{
	assert(fd >= 0);

	check(url_download(url, host, path, post_body, post_header, fd));
	check(tmpmap(fd, addr, sz));

	debug("Downloaded %s to fd=%d", url ? url : path, fd);
	return RESULT_OK;
}

static const char INNERTUBE_URI[] =
	"https://www.youtube.com/youtubei/v1/player";

static WARN_UNUSED result_t
make_http_header_visitor_id(const char *visitor_data, char **strp)
{
	const int rc = asprintf(strp, "X-Goog-Visitor-Id: %s", visitor_data);
	check_if(rc < 0, ERR_YOUTUBE_VISITOR_DATA_HEADER_ALLOC);
	debug("Formatted InnerTube header: %s", *strp);
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
strndup_free(char **strp)
{
	free(*strp);
}

static void
json_dump_free(char **strp)
{
	free(*strp);
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

result_t
youtube_stream_setup(struct youtube_stream *p,
                     struct youtube_setup_ops *ops,
                     void *userdata,
                     const char *target)
{
	struct downloaded json __attribute__((cleanup(downloaded_cleanup)));
	struct downloaded html __attribute__((cleanup(downloaded_cleanup)));
	struct downloaded js __attribute__((cleanup(downloaded_cleanup)));

	downloaded_init(&json, "JSON tmpfile");
	downloaded_init(&html, "HTML tmpfile");
	downloaded_init(&js, "JavaScript tmpfile");

	if (ops && ops->before) {
		check(ops->before(userdata));
	}

	check(tmpfd(&json.fd));
	check(tmpfd(&html.fd));
	check(tmpfd(&js.fd));

	if (ops && ops->before_inet) {
		check(ops->before_inet(userdata));
	}

	check(download_and_mmap_tmpfd(target,
	                              NULL,
	                              NULL,
	                              NULL,
	                              NULL,
	                              html.fd,
	                              &html.buf,
	                              &html.sz));

	char *null_terminated_basejs __attribute__((cleanup(strndup_free))) =
		NULL;
	{
		const char *basejs = NULL;
		size_t basejs_sz = 0;
		check(find_base_js_url(html.buf, html.sz, &basejs, &basejs_sz));

		debug("Setting base.js URL: %.*s", (int)basejs_sz, basejs);
		null_terminated_basejs = strndup(basejs, basejs_sz);
	}
	check_if(null_terminated_basejs == NULL, ERR_JS_BASEJS_URL_ALLOC);

	check(download_and_mmap_tmpfd(NULL,
	                              "www.youtube.com",
	                              null_terminated_basejs,
	                              NULL,
	                              NULL,
	                              js.fd,
	                              &js.buf,
	                              &js.sz));

	long long int timestamp = 0;
	check(find_js_timestamp(js.buf, js.sz, &timestamp));

	char *innertube_post __attribute__((cleanup(json_dump_free))) = NULL;
	check(make_innertube_json(target,
	                          p->proof_of_origin,
	                          timestamp,
	                          &innertube_post));

	char *innertube_header __attribute__((cleanup(asprintf_free))) = NULL;
	check(make_http_header_visitor_id(p->visitor_data, &innertube_header));

	check(download_and_mmap_tmpfd(INNERTUBE_URI,
	                              NULL,
	                              NULL,
	                              innertube_post,
	                              innertube_header,
	                              json.fd,
	                              &json.buf,
	                              &json.sz));

	if (ops && ops->after_inet) {
		check(ops->after_inet(userdata));
	}

	if (ops && ops->before_parse) {
		check(ops->before_parse(userdata));
	}

	struct parse_ops pops = {
		.got_video = youtube_stream_set_video,
		.got_video_userdata = p,
		.got_audio = youtube_stream_set_audio,
		.got_audio_userdata = p,
		.choose_quality = ops ? ops->during_parse_choose_quality : NULL,
		.choose_quality_userdata = userdata,
	};
	if (pops.choose_quality == NULL) {
		pops.choose_quality = youtube_stream_choose_quality_any;
	}
	check(parse_json(json.buf, json.sz, &pops));

	if (ops && ops->after_parse) {
		check(ops->after_parse(userdata));
	}

	if (ops && ops->before_eval) {
		check(ops->before_eval(userdata));
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
		check(ops->after_eval(userdata));
	}

	if (ops && ops->after) {
		check(ops->after(userdata));
	}

	return RESULT_OK;
}
