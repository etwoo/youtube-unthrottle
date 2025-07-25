#include "youtube.h"

#include "lib/js.h"
#include "lib/re.h"
#include "lib/url.h"
#include "protocol/stream.h"
#include "sys/array.h"
#include "sys/debug.h"
#include "sys/tmpfile.h"

#include <ada_c.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h> /* for asprintf() */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char ARG_N[] = "n";
static const char INNERTUBE[] = "https://www.youtube.com/youtubei/v1/player";

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
	d->fd = -1;
}

struct youtube_stream {
	struct protocol_state *stream;
	ada_url url;
	const char *proof_of_origin;
	const char *visitor_data;
	struct url_request_context context;
	struct parse_ops pops;
	struct downloaded html;
	struct downloaded js;
	struct downloaded json;
	struct downloaded ump;
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
                    const struct youtube_stream_ops *ops)
{
	assert(proof_of_origin && visitor_data);

	struct youtube_stream *p = malloc(sizeof(*p));
	if (p) {
		memset(p, 0, sizeof(*p)); /* zero early, just in case */
		p->proof_of_origin = proof_of_origin;
		p->visitor_data = visitor_data;
		p->context.simulator = ops->io_simulator;
		url_context_init(&p->context);
		p->pops.choose_quality = ops->choose_quality;
		p->pops.userdata = ops->choose_quality_userdata;
	}
	return p;
}

void
youtube_stream_cleanup(struct youtube_stream *p)
{
	if (p) {
		protocol_cleanup(p->stream);
		ada_free(p->url); /* handles NULL gracefully */
		p->url = NULL;
		url_context_cleanup(&p->context);
		downloaded_cleanup(&p->html);
		downloaded_cleanup(&p->js);
		downloaded_cleanup(&p->json);
		downloaded_cleanup(&p->ump);
	}
	free(p);
}

result_t
youtube_stream_visitor(struct youtube_stream *p,
                       void (*visit)(const char *, size_t, void *),
                       void *userdata)
{
	assert(ada_is_valid(p->url));
	ada_string s = ada_get_href(p->url);
	visit(s.data, s.length, userdata);
	return RESULT_OK;
}

result_t
youtube_stream_prepare_tmpfiles(struct youtube_stream *p)
{
	downloaded_init(&p->html, "HTML tmpfile");
	downloaded_init(&p->js, "JavaScript tmpfile");
	downloaded_init(&p->json, "JSON tmpfile");
	downloaded_init(&p->ump, "UMP response tmpfile");

	check(tmpfd(&p->html.fd));
	check(tmpfd(&p->js.fd));
	check(tmpfd(&p->json.fd));
	check(tmpfd(&p->ump.fd));

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
youtube_stream_set_url(struct youtube_stream *p, char *url_as_cstr)
{
	const size_t sz = strlen(url_as_cstr);
	if (!ada_can_parse(url_as_cstr, sz)) {
		return make_result(ERR_YOUTUBE_STREAM_URL_INVALID,
		                   url_as_cstr,
		                   sz);
	}

	ada_free(p->url); /* handles NULL gracefully */
	p->url = ada_parse(url_as_cstr, sz);
	return RESULT_OK;
}

/*
 * Copy n-parameter value from query string in <url>.
 *
 * Caller has responsibility to free() the pointer returned in <result>.
 */
static WARN_UNUSED result_t
youtube_stream_copy_n_param(struct youtube_stream *p, char **result)
{
	*result = NULL; /* NULL out early, just in case */

	ada_string q_str = ada_get_search(p->url);
	ada_url_search_params q __attribute__((cleanup(free_search_params))) =
		ada_parse_search_params(q_str.data, q_str.length);
	if (!ada_search_params_has(q, ARG_N, strlen(ARG_N))) {
		ada_string url_str = ada_get_href(p->url);
		return make_result(ERR_YOUTUBE_N_PARAM_MISSING,
		                   url_str.data,
		                   url_str.length);
	}

	ada_string n_param = ada_search_params_get(q, ARG_N, strlen(ARG_N));
	*result = strndup(n_param.data, n_param.length);
	check_if(*result == NULL, ERR_YOUTUBE_N_PARAM_QUERY_ALLOC);

	debug("Got n-param ciphertext: %s", *result);
	return RESULT_OK;
}

static WARN_UNUSED result_t
youtube_stream_update_n_param(const char *val, size_t pos, void *userdata)
{
	struct youtube_stream *p = (struct youtube_stream *)userdata;
	assert(pos == 0);
	ada_search_params_set_helper(p->url, ARG_N, val);
	return RESULT_OK;
}

static WARN_UNUSED result_t
make_http_header_visitor_id(const char *visitor_data, char **strp)
{
	const int rc = asprintf(strp, "X-Goog-Visitor-Id: %s", visitor_data);
	check_if(rc < 0, ERR_YOUTUBE_VISITOR_DATA_HEADER_ALLOC);
	debug("Formatted InnerTube header: %s", *strp);
	return RESULT_OK;
}

static WARN_UNUSED result_t
http_post(struct youtube_stream *p,
          struct downloaded *d,
          const char *url,
          const struct string_view *post_body,
          url_request_content_type post_content_type,
          const char *post_header)
{
	assert(d->fd >= 0);

	check(url_download(url,
	                   post_body,
	                   post_content_type,
	                   post_header,
	                   &p->context,
	                   d->fd));
	check(tmpmap(d->fd, &d->data));

	debug("Downloaded %s to fd=%d", url, d->fd);
	return RESULT_OK;
}

static WARN_UNUSED result_t
http_get(struct youtube_stream *p, struct downloaded *d, const char *url)
{
	return http_post(p, d, url, NULL, CONTENT_TYPE_UNSET, NULL);
}

static void
str_free(char **strp)
{
	free(*strp);
}

static void
ciphertexts_cleanup(char *ciphertexts[][2])
{
	free((*ciphertexts)[0]);
	(*ciphertexts)[0] = NULL;
	assert((*ciphertexts)[1] == NULL);
	debug("free()-d n-param ciphertext bufs");
}

result_t
youtube_stream_open(struct youtube_stream *p,
                    const char *start_url,
                    const int output_fd[2])
{
	check(http_get(p, &p->html, start_url));

	struct string_view basejs_path = {0};
	check(find_base_js_url(&p->html.data, &basejs_path));

	char *target_js __attribute__((cleanup(str_free))) = NULL;
	const int rc = asprintf(&target_js,
	                        "https://www.youtube.com%.*s",
	                        (int)basejs_path.sz,
	                        basejs_path.data);
	check_if(rc < 0, ERR_JS_BASEJS_URL_ALLOC);
	debug("Got base.js URL: %s", target_js);

	check(http_get(p, &p->js, target_js));

	long long int timestamp = 0;
	check(find_js_timestamp(&p->js.data, &timestamp));

	char *innertube_post __attribute__((cleanup(str_free))) = NULL;
	check(make_innertube_json(start_url,
	                          p->proof_of_origin,
	                          timestamp,
	                          &innertube_post));

	char *hdr __attribute__((cleanup(str_free))) = NULL;
	check(make_http_header_visitor_id(p->visitor_data, &hdr));

	const struct string_view body = {
		.data = innertube_post,
		.sz = strlen(innertube_post),
	};
	check(http_post(p, &p->json, INNERTUBE, &body, CONTENT_TYPE_JSON, hdr));

	struct parse_values parsed
		__attribute__((cleanup(parse_values_cleanup))) = {0};
	check(parse_json(&p->json.data, &p->pops, &parsed));
	check(youtube_stream_set_url(p, parsed.sabr_url));

	struct string_view poo = {
		.data = p->proof_of_origin,
		.sz = strlen(p->proof_of_origin),
	};
	struct string_view pbc = {
		.data = parsed.playback_config,
		.sz = strlen(parsed.playback_config),
	};
	check(protocol_init(&poo, &pbc, parsed.itag, output_fd, &p->stream));

	char *ciphertexts[2] __attribute__((cleanup(ciphertexts_cleanup))) = {
		NULL,
		NULL,
	};
	check(youtube_stream_copy_n_param(p, &ciphertexts[0]));

	struct deobfuscator deobfuscator = {0};
	check(find_js_deobfuscator_magic_global(&p->js.data, &deobfuscator));
	check(find_js_deobfuscator(&p->js.data, &deobfuscator));

	struct call_ops cops = {
		.got_result = youtube_stream_update_n_param,
	};
	check(call_js_foreach(&deobfuscator, ciphertexts, &cops, p));

	return RESULT_OK;
}

result_t
youtube_stream_next(struct youtube_stream *p, int *retry_after)
{
	*retry_after = -1;

	char *sabr_post __attribute__((cleanup(str_free))) = NULL;
	size_t sabr_post_sz = 0;
	check(protocol_next_request(p->stream, &sabr_post, &sabr_post_sz));

	char *url __attribute__((cleanup(str_free))) = NULL;
	{
		ada_string tmp = ada_get_href(p->url);
		url = tmp.data ? strndup(tmp.data, tmp.length) : NULL;
	}
	check_if(url == NULL, ERR_JS_SABR_URL_ALLOC);

	const struct string_view v = {
		.data = sabr_post,
		.sz = sabr_post_sz,
	};

	check(http_post(p, &p->ump, url, &v, CONTENT_TYPE_PROTOBUF, NULL));
	check(protocol_parse_response(p->stream,
	                              &p->ump.data,
	                              &url,
	                              retry_after));
	check(tmptruncate(p->ump.fd, &p->ump.data));
	check(youtube_stream_set_url(p, url));

	return *retry_after > 0 || protocol_knows_end(p->stream)
	               ? RESULT_OK
	               : make_result(ERR_YOUTUBE_EARLY_END_STREAM);
}

bool
youtube_stream_done(struct youtube_stream *p)
{
	struct protocol_state *s = p->stream;
	return s == NULL || !protocol_knows_end(s) || protocol_done(s);
}
