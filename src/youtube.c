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
static const char INNERTUBE_URI[] =
	"https://www.youtube.com/youtubei/v1/player";

struct youtube_stream {
	ada_url url;
	const char *proof_of_origin;
	const char *visitor_data;
	struct url_request_context context;
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
		p->context.simulator = io_simulator;
		url_context_init(&p->context);
	}
	return p;
}

void
youtube_stream_cleanup(struct youtube_stream *p)
{
	if (p) {
		ada_free(p->url); /* handles NULL gracefully */
		p->url = NULL;
		url_context_cleanup(&p->context);
	}
	free(p);
}

static void
youtube_stream_valid(struct youtube_stream *p)
{
	assert(ada_is_valid(p->url));
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
youtube_stream_set_url_with_n_param(struct youtube_stream *p, const char *val)
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
	d->fd = -1;
}

static WARN_UNUSED result_t
download_and_mmap_tmpfd(struct youtube_stream *p,
                        struct downloaded *d,
                        const char *url,
                        const struct string_view *post_body,
                        const char *post_header)
{
	assert(d->fd >= 0);

	check(url_download(url, post_body, post_header, &p->context, d->fd));
	check(tmpmap(d->fd, &d->data));

	debug("Downloaded %s to fd=%d", url, d->fd);
	return RESULT_OK;
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

static const char AMPERSAND[] = "\\u0026"; /* URI-encoded ampersand character */
static const size_t AMPERSAND_SZ = sizeof(AMPERSAND) - 1;

static void
decode_ampersands(struct string_view in /* note: pass by value */, char **out)
{
	char *buffer = malloc((in.sz + 1) * sizeof(*buffer));
	*out = buffer;
	while (buffer) {
		const char *src_end =
			memmem(in.data, in.sz, AMPERSAND, AMPERSAND_SZ);
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

static WARN_UNUSED result_t
youtube_stream_setup_sabr(struct youtube_stream *p,
                          const char *start_url,
                          int fd_output[2],
                          int tmpfd_early[3],
                          protocol *stream)
{
	struct downloaded json __attribute__((cleanup(downloaded_cleanup)));
	struct downloaded html __attribute__((cleanup(downloaded_cleanup)));
	struct downloaded js __attribute__((cleanup(downloaded_cleanup)));

	downloaded_init(&json, "JSON tmpfile");
	downloaded_init(&html, "HTML tmpfile");
	downloaded_init(&js, "JavaScript tmpfile");

	json.fd = tmpfd_early[0]; /* takes ownership */
	html.fd = tmpfd_early[1]; /* takes ownership */
	js.fd = tmpfd_early[2];   /* takes ownership */

	check(download_and_mmap_tmpfd(p, &html, start_url, NULL, NULL));

	struct string_view basejs_path = {0};
	check(find_base_js_url(&html.data, &basejs_path));

	char *target_js __attribute__((cleanup(str_free))) = NULL;
	const int rc = asprintf(&target_js,
	                        "https://www.youtube.com%.*s",
	                        (int)basejs_path.sz,
	                        basejs_path.data);
	check_if(rc < 0, ERR_JS_BASEJS_URL_ALLOC);
	debug("Got base.js URL: %s", target_js);

	check(download_and_mmap_tmpfd(p, &js, target_js, NULL, NULL));

	long long int timestamp = 0;
	check(find_js_timestamp(&js.data, &timestamp));

	char *innertube_post __attribute__((cleanup(str_free))) = NULL;
	check(make_innertube_json(start_url,
	                          p->proof_of_origin,
	                          timestamp,
	                          &innertube_post));

	char *header __attribute__((cleanup(str_free))) = NULL;
	check(make_http_header_visitor_id(p->visitor_data, &header));

	const struct string_view ipost = {
		.data = innertube_post,
		.sz = strlen(innertube_post),
	};
	check(download_and_mmap_tmpfd(p, &json, INNERTUBE_URI, &ipost, header));

	struct string_view playback_config = {0};
	check(find_playback_config(&json.data, &playback_config));

	struct string_view poo = {
		.data = p->proof_of_origin,
		.sz = strlen(p->proof_of_origin),
	};
	check(protocol_init(&poo, &playback_config, fd_output, stream));

	struct deobfuscator deobfuscator = {0};
	check(find_js_deobfuscator_magic_global(&js.data, &deobfuscator));
	check(find_js_deobfuscator(&js.data, &deobfuscator));

	struct string_view sabr_raw = {0};
	check(find_sabr_url(&json.data, &sabr_raw));
	{
		char *scratch_buffer __attribute__((cleanup(str_free))) = NULL;
		decode_ampersands(sabr_raw, &scratch_buffer);
		check_if(scratch_buffer == NULL, ERR_JS_SABR_URL_ALLOC);
		debug("Decoded SABR URL: %s", scratch_buffer);
		check(youtube_stream_set_url_with_n_param(p, scratch_buffer));
	}

	char *ciphertexts[2] __attribute__((cleanup(ciphertexts_cleanup))) = {
		NULL,
		NULL,
	};
	check(youtube_stream_copy_n_param(p, &ciphertexts[0]));

	struct call_ops cops = {
		.got_result = youtube_stream_update_n_param,
	};
	check(call_js_foreach(&deobfuscator, ciphertexts, &cops, p));
	return RESULT_OK;
}

result_t
youtube_stream_setup(struct youtube_stream *p,
                     const struct youtube_setup_ops *ops,
                     const char *start_url,
                     int fd_output[2])
{
	if (ops && ops->before_tmpfile) {
		check(ops->before_tmpfile());
	}

	struct downloaded ump __attribute__((cleanup(downloaded_cleanup)));
	downloaded_init(&ump, "UMP response tmpfile");
	check(tmpfd(&ump.fd));

	int tmpfd_early[3] = {
		-1,
		-1,
		-1,
	};
	check(tmpfd(tmpfd_early));
	check(tmpfd(tmpfd_early + 1));
	check(tmpfd(tmpfd_early + 2));

	if (ops && ops->after_tmpfile) {
		check(ops->after_tmpfile());
	}

	if (ops && ops->before_inet) {
		check(ops->before_inet());
	}

	protocol stream __attribute__((cleanup(protocol_cleanup_p))) = NULL;
	check(youtube_stream_setup_sabr(p,
	                                start_url,
	                                fd_output,
	                                tmpfd_early,
	                                &stream));

	char *to_poll __attribute__((cleanup(str_free))) = NULL;
	{
		ada_string tmp = ada_get_href(p->url);
		to_poll = strndup(tmp.data, tmp.length);
	}
	check_if(to_poll == NULL, ERR_JS_SABR_URL_ALLOC);

	do {
		char *sabr_post __attribute__((cleanup(str_free))) = NULL;
		size_t sabr_post_sz = 0;
		check(protocol_next_request(stream, &sabr_post, &sabr_post_sz));

		const struct string_view v = {
			.data = sabr_post,
			.sz = sabr_post_sz,
		};
		check(download_and_mmap_tmpfd(p, &ump, to_poll, &v, NULL));
		check(protocol_parse_response(stream, &ump.data, &to_poll));

		check(tmptruncate(ump.fd, &ump.data));
	} while (protocol_at(stream) < protocol_ends_at(stream));

	if (ops && ops->after_inet) {
		check(ops->after_inet());
	}

	return RESULT_OK;
}
