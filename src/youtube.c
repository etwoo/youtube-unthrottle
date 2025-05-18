#include "youtube.h"

#include "lib/js.h"
#include "lib/re.h"
#include "lib/url.h"
#include "protocol/stream.h"
#include "sys/array.h"
#include "sys/debug.h"
#include "sys/tmpfile.h"
#include "sys/write.h"

#include <ada_c.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h> /* for asprintf() */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char ARG_N[] = "n";

struct youtube_stream {
	ada_url url;
	const char *proof_of_origin;
	const char *visitor_data; // TODO: remove unused visitor data
	struct url_request_context request_context;
	int fd[2];
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
                    const char *(*io_simulator)(const char *),
                    int fd[2])
{
	assert(proof_of_origin && visitor_data);

	struct youtube_stream *p = malloc(sizeof(*p));
	if (p) {
		memset(p, 0, sizeof(*p)); /* zero early, just in case */
		p->proof_of_origin = proof_of_origin;
		p->visitor_data = visitor_data;
		p->request_context.simulator = io_simulator;
		url_context_init(&p->request_context);
		p->fd[0] = fd[0];
		p->fd[1] = fd[1];
	}
	return p;
}

void
youtube_stream_cleanup(struct youtube_stream *p)
{
	if (p) {
		ada_free(p->url); /* handles NULL gracefully */
		p->url = NULL;
		url_context_cleanup(&p->request_context);
		for (size_t i = 0; i < ARRAY_SIZE(p->fd); ++i) {
			close(p->fd[i]);
			p->fd[i] = -1;
		}
	}
	free(p);
}

static void
youtube_stream_valid(struct youtube_stream *p)
{
	assert(ada_is_valid(p->url));
	for (size_t i = 0; i < ARRAY_SIZE(p->fd); ++i) {
		assert(p->fd[i] > 0);
	}
}

result_t
youtube_stream_visitor(struct youtube_stream *p,
                       void (*visit)(const char *, size_t, void *),
                       void *userdata)
{
	youtube_stream_valid(p);
	ada_string s = ada_get_href(p->url);
	visit(s.data, s.length, userdata);
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
youtube_stream_set_url(struct youtube_stream *p, const char *val)
{
	const size_t val_sz = strlen(val);
	if (!ada_can_parse(val, val_sz)) {
		return make_result(ERR_YOUTUBE_STREAM_URL_INVALID, val, val_sz);
	}

	p->url = ada_parse(val, strlen(val));
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
		return make_result(ERR_YOUTUBE_N_PARAM_FIND_IN_QUERY);
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
download_and_mmap_tmpfd(const char *url,
                        const char *host,
                        const char *path,
                        const char *post_body,
                        size_t post_body_size,
                        const char *post_header,
                        int fd,
                        struct string_view *data,
                        struct url_request_context *ctx)
{
	assert(fd >= 0);

	check(url_download(url,
	                   host,
	                   path,
	                   post_body,
	                   post_body_size,
	                   post_header,
	                   fd,
	                   ctx));
	check(tmpmap(fd, data));

	debug("Downloaded %s to fd=%d", url ? url : path, fd);
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
ciphertexts_cleanup(char *ciphertexts[][2])
{
	free((*ciphertexts)[0]);
	(*ciphertexts)[0] = NULL;
	assert((*ciphertexts)[1] == NULL);
	debug("free()-d n-param ciphertext bufs");
}

static void
protocol_cleanup_p(protocol *pp)
{
	protocol_cleanup(*pp);
}

static const char AMPERSAND[] = "\\u0026"; // URI-encoded ampersand character
static const size_t AMPERSAND_SZ = strlen(AMPERSAND);

static void
decode_ampersands(struct string_view in /* note: pass by value */, char **out)
{
	char *buffer = malloc((in.sz + 1) * sizeof(*buffer));
	*out = buffer;
	while (buffer) {
		const char *src_end = strnstr(in.data, AMPERSAND, in.sz);
		if (src_end == NULL) {
			memcpy(buffer, in.data, in.sz);
			buffer[in.sz] = '\0';
			break;
		}

		size_t n = src_end - in.data;
		memcpy(buffer, in.data, n);

		buffer += n;
		*buffer = '&';
		buffer += 1;

		n += AMPERSAND_SZ; /* skip URI-encoded ampersand in <in.data> */
		in.data += n;
		in.sz -= n;
	}
}

result_t
youtube_stream_setup(struct youtube_stream *p,
                     const struct youtube_setup_ops *ops,
                     void *userdata,
                     const char *target)
{
	if (ops && ops->before) {
		check(ops->before(userdata));
	}

	struct downloaded html __attribute__((cleanup(downloaded_cleanup)));
	struct downloaded js __attribute__((cleanup(downloaded_cleanup)));

	downloaded_init(&html, "HTML tmpfile");
	downloaded_init(&js, "JavaScript tmpfile");

	check(tmpfd(&html.fd));
	check(tmpfd(&js.fd));

	if (ops && ops->before_inet) {
		check(ops->before_inet(userdata));
	}

	check(download_and_mmap_tmpfd(target,
	                              NULL,
	                              NULL,
	                              NULL,
	                              0,
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
	                              0,
	                              NULL,
	                              js.fd,
	                              &js.data,
	                              &p->request_context));

	if (ops && ops->after_inet) {
		check(ops->after_inet(userdata));
	}

	if (ops && ops->before_eval) {
		check(ops->before_eval(userdata));
	}

	{
		struct string_view sabr = {0};
		check(find_sabr_url(&html.data, &sabr));

		char *null_terminated_sabr __attribute__((cleanup(str_free))) =
			NULL;
		decode_ampersands(sabr, &null_terminated_sabr);
		check_if(null_terminated_sabr == NULL, ERR_JS_SABR_URL_ALLOC);
		debug("Decoded SABR URL: %s", null_terminated_sabr);

		check(youtube_stream_set_url(p, null_terminated_sabr));
	}
	if (p->url == NULL) {
		return make_result(ERR_YOUTUBE_STREAM_URL_MISSING);
	}

	struct deobfuscator d = {0};
	check(find_js_deobfuscator_magic_global(&js.data, &d));
	check(find_js_deobfuscator(&js.data, &d));

	char *ciphertexts[2]
		__attribute__((cleanup(ciphertexts_cleanup))) = {NULL};
	check(youtube_stream_copy_n_param(p, &ciphertexts[0]));

	struct call_ops cops = {
		.got_result = youtube_stream_update_n_param,
	};
	check(call_js_foreach(&d, ciphertexts, &cops, p));

	if (ops && ops->after_eval) {
		check(ops->after_eval(userdata));
	}

	if (ops && ops->after) {
		check(ops->after(userdata));
	}

	char *sabr_url_or_redirect __attribute__((cleanup(str_free))) = NULL;
	{
		ada_string tmp = ada_get_href(p->url);
		sabr_url_or_redirect = strndup(tmp.data, tmp.length);
	}
	check_if(sabr_url_or_redirect == NULL, ERR_JS_SABR_URL_ALLOC);

	struct string_view playback_config = {0};
	check(find_playback_config(&html.data, &playback_config));

	protocol stream __attribute__((cleanup(protocol_cleanup_p))) =
		protocol_init(p->proof_of_origin, &playback_config, p->fd);
	check_if(stream == NULL, ERR_PROTOCOL_STATE_ALLOC);

	// TODO: debug cutoff at 60s, then remove hardcoded 5 request limit
	for (size_t requests = 0; requests < 5; ++requests) {
		char *sabr_post __attribute__((cleanup(str_free))) = NULL;
		size_t sabr_post_sz = 0;
		check(protocol_next_request(stream, &sabr_post, &sabr_post_sz));

		struct downloaded ump
			__attribute__((cleanup(downloaded_cleanup)));
		downloaded_init(&ump, "UMP response tmpfile");
		check(tmpfd(&ump.fd));

		check(download_and_mmap_tmpfd(sabr_url_or_redirect,
		                              NULL,
		                              NULL,
		                              sabr_post,
		                              sabr_post_sz,
		                              NULL,
		                              ump.fd,
		                              &ump.data,
		                              &p->request_context));

		check(protocol_parse_response(stream,
		                              &ump.data,
		                              &sabr_url_or_redirect));
	}

	return RESULT_OK;
}
