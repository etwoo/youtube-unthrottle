#include "youtube.h"

#include "array.h"
#include "debug.h"
#include "js.h"
#include "re.h"
#include "tmpfile.h"
#include "url.h"

#include <ada_c.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h> /* for asprintf() */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char ARG_POT[] = "pot";
static const char ARG_N[] = "n";

struct youtube_stream {
	ada_url url[2];
	const char *proof_of_origin;
	const char *visitor_data;
	struct url_request_context request_context;
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
youtube_stream_init(const char *proof_of_origin,
                    const char *visitor_data,
                    const char *(*io_simulator)(const char *))
{
	assert(proof_of_origin && visitor_data);

	struct youtube_stream *p = malloc(sizeof(*p));
	if (p) {
		memset(p, 0, sizeof(*p)); /* zero early, just in case */
		p->proof_of_origin = proof_of_origin;
		p->visitor_data = visitor_data;
		p->request_context.simulator = io_simulator;
		url_context_init(&p->request_context);
	}
	return p;
}

void
youtube_stream_cleanup(struct youtube_stream *p)
{
	if (p) {
		for (size_t i = 0; i < ARRAY_SIZE(p->url); ++i) {
			ada_free(p->url[i]); /* handles NULL gracefully */
			p->url[i] = NULL;
		}
		url_context_cleanup(&p->request_context);
	}
	free(p);
}

static void
youtube_stream_valid(struct youtube_stream *p)
{
	for (size_t i = 0; i < ARRAY_SIZE(p->url); ++i) {
		assert(ada_is_valid(p->url[i]));
	}
}

result_t
youtube_stream_visitor(struct youtube_stream *p,
                       void (*visit)(const char *, size_t, void *),
                       void *userdata)
{
	youtube_stream_valid(p);
	for (size_t i = 0; i < ARRAY_SIZE(p->url); ++i) {
		ada_string s = ada_get_href(p->url[i]);
		visit(s.data, s.length, userdata);
	}
	return RESULT_OK;
}

static void
free_search_params(ada_url_search_params *params)
{
	ada_free_search_params(*params); /* handles NULL gracefully */
}

static void
free_owned_str(ada_owned_string *str)
{
	ada_free_owned_string(*str); /* handles NULL gracefully */
}

static void
ada_search_params_set_helper(ada_url url, const char *key, const char *val)
{
	ada_string q_str = ada_get_search(url);

	ada_url_search_params q __attribute__((cleanup(free_search_params))) =
		ada_parse_search_params(q_str.data, q_str.length);
	ada_search_params_set(q, key, strlen(key), val, strlen(val));

	ada_owned_string new_q_str __attribute__((cleanup(free_owned_str))) =
		ada_search_params_to_string(q);
	ada_set_search(url, new_q_str.data, new_q_str.length);

	q_str.data = NULL; /* likely invalidated by ada_set_search() above */
	q_str.length = 0;
}

static WARN_UNUSED result_t
youtube_stream_set_one(struct youtube_stream *p, int idx, const char *val)
{
	const size_t val_sz = strlen(val);
	check_if(!ada_can_parse(val, val_sz),
	         ERR_JS_PARSE_JSON_CALLBACK_GOT_CIPHERTEXT_URL,
	         val,
	         val_sz);

	assert(idx >= 0 && (unsigned int)idx < ARRAY_SIZE(p->url));
	p->url[idx] = ada_parse(val, strlen(val));
	ada_search_params_set_helper(p->url[idx], ARG_POT, p->proof_of_origin);
	return RESULT_OK;
}

static WARN_UNUSED result_t
youtube_stream_set_video(const char *val, void *userdata)
{
	struct youtube_stream *p = (struct youtube_stream *)userdata;
	debug("Setting video stream: %s", val);
	return youtube_stream_set_one(p, 1, val);
}

static WARN_UNUSED result_t
youtube_stream_set_audio(const char *val, void *userdata)
{
	struct youtube_stream *p = (struct youtube_stream *)userdata;
	debug("Setting audio stream: %s", val);
	return youtube_stream_set_one(p, 0, val);
}

static WARN_UNUSED result_t
youtube_stream_choose_quality_any(const char *val,
                                  void *userdata __attribute__((unused)))
{
	debug("Any quality allowed: %s", val);
	return RESULT_OK;
}

/*
 * Copy n-parameter value from query string in <url>.
 *
 * Caller has responsibility to free() the pointer returned in <result>.
 */
static WARN_UNUSED result_t
copy_n_param_one(ada_url url, char **result)
{
	*result = NULL; /* NULL out early, just in case */

	ada_string q_str = ada_get_search(url);
	ada_url_search_params q __attribute__((cleanup(free_search_params))) =
		ada_parse_search_params(q_str.data, q_str.length);
	check_if(!ada_search_params_has(q, ARG_N, strlen(ARG_N)),
	         ERR_YOUTUBE_N_PARAM_FIND_IN_QUERY);

	ada_string n_param = ada_search_params_get(q, ARG_N, strlen(ARG_N));
	*result = strndup(n_param.data, n_param.length);
	check_if(*result == NULL, ERR_YOUTUBE_N_PARAM_QUERY_ALLOC);

	debug("Got n-param ciphertext: %s", *result);
	return RESULT_OK;
}

/*
 * Copy n-parameter values from all query strings in <p>.
 *
 * Caller has responsibility to free() the pointers returned in <results>.
 */
static WARN_UNUSED result_t
copy_n_param_all(struct youtube_stream *p, char **results)
{
	for (size_t i = 0; i < ARRAY_SIZE(p->url); ++i) {
		check(copy_n_param_one(p->url[i], results + i));
	}
	return RESULT_OK;
}

static WARN_UNUSED result_t
youtube_stream_update_n_param(const char *val, size_t pos, void *userdata)
{
	struct youtube_stream *p = (struct youtube_stream *)userdata;
	assert(pos < ARRAY_SIZE(p->url));
	ada_search_params_set_helper(p->url[pos], ARG_N, val);
	return RESULT_OK;
}

static WARN_UNUSED result_t
download_and_mmap_tmpfd(const char *url,
                        const char *host,
                        const char *path,
                        const char *post_body,
                        const char *post_header,
                        int fd,
                        struct string_view *data,
                        struct url_request_context *ctx)
{
	assert(fd >= 0);

	check(url_download(url, host, path, post_body, post_header, fd, ctx));
	check(tmpmap(fd, data));

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
	struct string_view data;
};

static void
downloaded_init(struct downloaded *d, const char *description)
{
	d->description = description;
	d->fd = -1; /* guarantee invalid <fd> by default */
	memset(&d->data, 0, sizeof(d->data));
}

static void
downloaded_cleanup(struct downloaded *d)
{
	tmpunmap(&d->data);
	info_m_if(d->fd > 0 && close(d->fd) < 0,
	          "Ignoring error close()-ing %s",
	          d->description);
}

static void
str_free(char **strp)
{
	free(*strp);
}

static void
ciphertexts_cleanup(char *ciphertexts[][3])
{
	size_t free_count = 0;
	for (size_t i = 0; i < ARRAY_SIZE(*ciphertexts); ++i) {
		if ((*ciphertexts)[i]) {
			free((*ciphertexts)[i]);
			(*ciphertexts)[i] = NULL;
			++free_count;
		}
	}
	debug("free()-d %zd n-param ciphertext bufs", free_count);
}

result_t
youtube_stream_setup(struct youtube_stream *p,
                     const struct youtube_setup_ops *ops,
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
	                              &html.data,
	                              &p->request_context));

	char *null_terminated_basejs __attribute__((cleanup(str_free))) = NULL;
	{
		struct string_view basejs = {0};
		check(find_base_js_url(&html.data, &basejs));

		debug("Setting base.js URL: %.*s", (int)basejs.sz, basejs.data);
		null_terminated_basejs = strndup(basejs.data, basejs.sz);
	}
	check_if(null_terminated_basejs == NULL, ERR_JS_BASEJS_URL_ALLOC);

	check(download_and_mmap_tmpfd(NULL,
	                              "www.youtube.com",
	                              null_terminated_basejs,
	                              NULL,
	                              NULL,
	                              js.fd,
	                              &js.data,
	                              &p->request_context));

	long long int timestamp = 0;
	check(find_js_timestamp(&js.data, &timestamp));

	char *innertube_post __attribute__((cleanup(str_free))) = NULL;
	check(make_innertube_json(target,
	                          p->proof_of_origin,
	                          timestamp,
	                          &innertube_post));

	char *innertube_header __attribute__((cleanup(str_free))) = NULL;
	check(make_http_header_visitor_id(p->visitor_data, &innertube_header));

	check(download_and_mmap_tmpfd(INNERTUBE_URI,
	                              NULL,
	                              NULL,
	                              innertube_post,
	                              innertube_header,
	                              json.fd,
	                              &json.data,
	                              &p->request_context));

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
	check(parse_json(&json.data, &pops));

	for (size_t i = 0; i < ARRAY_SIZE(p->url); ++i) {
		if (p->url[i] == NULL) {
			return make_result(ERR_YOUTUBE_STREAM_URL_MISSING);
		}
	}

	if (ops && ops->after_parse) {
		check(ops->after_parse(userdata));
	}

	if (ops && ops->before_eval) {
		check(ops->before_eval(userdata));
	}

	struct string_view magic = {0};
	check(find_js_deobfuscator_magic_global(&js.data, &magic));

	struct string_view deobfuscator = {0};
	check(find_js_deobfuscator(&js.data, &deobfuscator));

	char *ciphertexts[ARRAY_SIZE(p->url) + 1]
		__attribute__((cleanup(ciphertexts_cleanup))) = {NULL};
	check(copy_n_param_all(p, ciphertexts));

	struct call_ops cops = {
		.got_result = youtube_stream_update_n_param,
	};
	check(call_js_foreach(&magic, &deobfuscator, ciphertexts, &cops, p));

	if (ops && ops->after_eval) {
		check(ops->after_eval(userdata));
	}

	if (ops && ops->after) {
		check(ops->after(userdata));
	}

	return RESULT_OK;
}
