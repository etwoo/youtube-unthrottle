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

/*
 * Extend `struct result_base` to create a module-specific result_t.
 */
struct result_youtube {
	struct result_base base;
	enum {
		OK = 0,
		ERR_CALLBACK_GOT_CIPHERTEXT_URL,
		ERR_BASEJS_URL_ALLOC,
		ERR_INNERTUBE_POST_ID,
		ERR_INNERTUBE_POST_ALLOC,
		ERR_N_PARAM_QUERY_ALLOC,
		ERR_N_PARAM_QUERY_GET,
		ERR_N_PARAM_QUERY_SET,
		ERR_N_PARAM_FIND_IN_QUERY,
		ERR_N_PARAM_KVPAIR_ALLOC,
		ERR_N_PARAM_QUERY_APPEND_PLAINTEXT,
		ERR_STREAM_VISITOR_GET_URL,
	} err;
	CURLUcode curlu_code;
};

static WARN_UNUSED bool
result_ok(result_t r)
{
	struct result_youtube *p = (struct result_youtube *)r;
	return p->err == OK;
}

static WARN_UNUSED const char *
my_result_to_str(result_t r)
{
	struct result_youtube *p = (struct result_youtube *)r;
	int printed = 0;
	char *dynamic = NULL;
	const char *literal = NULL;

	switch (p->err) {
	case OK:
		literal = "Success in " __FILE_NAME__;
		break;
	case ERR_CALLBACK_GOT_CIPHERTEXT_URL:
		printed = asprintf(&dynamic,
		                   "Cannot set ciphertext URL: %s",
		                   curl_url_strerror(p->curlu_code));
		break;
	case ERR_BASEJS_URL_ALLOC:
		literal = "Cannot strndup() base.js URL";
		break;
	case ERR_INNERTUBE_POST_ID:
		literal = "Cannot find video ID for InnerTube POST";
		break;
	case ERR_INNERTUBE_POST_ALLOC:
		literal = "Cannot allocate buffer for InnerTube POST";
		break;
	case ERR_N_PARAM_QUERY_ALLOC:
		literal = "Cannot allocate ciphertext buffer";
		break;
	case ERR_N_PARAM_QUERY_GET:
		printed = asprintf(&dynamic,
		                   "Cannot get URL query string: %s",
		                   curl_url_strerror(p->curlu_code));
		break;
	case ERR_N_PARAM_QUERY_SET:
		literal = "Cannot clear ciphertext n-parameter";
		break;
	case ERR_N_PARAM_FIND_IN_QUERY:
		literal = "No n-parameter in query string";
		break;
	case ERR_N_PARAM_KVPAIR_ALLOC:
		literal = "Cannot allocate kv-pair buffer";
		break;
	case ERR_N_PARAM_QUERY_APPEND_PLAINTEXT:
		printed = asprintf(&dynamic,
		                   "Cannot append plaintext n-parameter: %s",
		                   curl_url_strerror(p->curlu_code));

		break;
	case ERR_STREAM_VISITOR_GET_URL:
		printed = asprintf(&dynamic,
		                   "Cannot get URL as string: %s",
		                   curl_url_strerror(p->curlu_code));
		break;
	}

	if (printed < 0) {
		return NULL;
		// TODO: use RESULT_CANNOT_ALLOC instead?
	}

	if (dynamic) {
		return dynamic; /* already allocated above */
	}

	assert(literal);
	return strdup(literal);
}

static void
my_result_cleanup(result_t r)
{
	if (r == NULL) {
		return;
	}

	struct result_youtube *p = (struct result_youtube *)r;
	free(p);
}

static struct result_ops RESULT_OPS = {
	.result_ok = result_ok,
	.result_to_str = my_result_to_str,
	.result_cleanup = my_result_cleanup,
};

static result_t WARN_UNUSED
make_result_uc(int err_type, CURLUcode uc)
{
	struct result_youtube *r = malloc(sizeof(*r));
	if (r == NULL) {
		return RESULT_CANNOT_ALLOC;
	}

	r->base.ops = &RESULT_OPS;
	r->err = err_type;
	r->curlu_code = uc;
	return (result_t)r;
}

#define check_if_uc(uc, err_type)                                              \
	do {                                                                   \
		if (uc) {                                                      \
			return make_result_uc(err_type, uc);                   \
		}                                                              \
	} while (0)

static result_t WARN_UNUSED
make_result(int err_type)
{
	return make_result_uc(err_type, CURLUE_OK);
}

struct youtube_stream {
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

	memset(p->url, 0, sizeof(p->url)); /* zero early, just in case */

	for (size_t i = 0; i < ARRAY_SIZE(p->url); ++i) {
		p->url[i] = curl_url(); /* may return NULL! */
		if (p->url[i] == NULL) {
			goto oom;
		}
	}

	return p;

oom:
	youtube_stream_cleanup(p);
	return NULL;
}

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
		check_if_uc(uc, ERR_STREAM_VISITOR_GET_URL);
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
	check_if_uc(uc, ERR_CALLBACK_GOT_CIPHERTEXT_URL);
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
	check_if_uc(uc, ERR_N_PARAM_QUERY_GET);
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
		return make_result(ERR_N_PARAM_FIND_IN_QUERY);
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
	if (rc < 0) {
		return make_result(ERR_N_PARAM_QUERY_ALLOC);
	}
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
	check_if_uc(uc, ERR_N_PARAM_QUERY_SET);

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
asprintf_free(char **strp)
{
	free(*strp);
}

static WARN_UNUSED result_t
append_n_param(const char *plaintext, size_t sz, size_t pos, void *userdata)
{
	struct youtube_stream *p = (struct youtube_stream *)userdata;

	char *kv __attribute__((cleanup(asprintf_free))) = NULL;
	const int rc = asprintf(&kv, "n=%.*s", (int)sz, plaintext);
	if (rc < 0) {
		return make_result(ERR_N_PARAM_KVPAIR_ALLOC);
	}

	assert(pos < ARRAY_SIZE(p->url));
	CURLU *u = p->url[pos];
	CURLUcode uc = curl_url_set(u, CURLUPART_QUERY, kv, CURLU_APPENDQUERY);
	check_if_uc(uc, ERR_N_PARAM_QUERY_APPEND_PLAINTEXT);

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
	if (!re_capture("(?:&|\\?)v=([^&]+)(?:&|$)",
	                target,
	                strlen(target),
	                &id,
	                &sz)) {
		return make_result(ERR_INNERTUBE_POST_ID);
	}
	debug("Parsed ID: %.*s", (int)sz, id);

	const int rc = asprintf(body, INNERTUBE_POST_FMT, (int)sz, id, ts);
	if (rc < 0) {
		return make_result(ERR_INNERTUBE_POST_ALLOC);
	}

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
strndup_free(char **strp)
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

	char *null_terminated_basejs __attribute__((cleanup(strndup_free))) =
		NULL;
	{
		const char *basejs = NULL;
		size_t basejs_sz = 0;
		check(find_base_js_url(html.buf, html.sz, &basejs, &basejs_sz));

		debug("Setting base.js URL: %.*s", (int)basejs_sz, basejs);
		null_terminated_basejs = strndup(basejs, basejs_sz);
	}
	if (null_terminated_basejs == NULL) {
		return make_result(ERR_BASEJS_URL_ALLOC);
	}

	check(download_and_mmap_tmpfd(NULL,
	                              "www.youtube.com",
	                              null_terminated_basejs,
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
