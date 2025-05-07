#include "youtube.h"

#include "lib/base64.h"
#include "lib/js.h"
#include "lib/re.h"
#include "lib/url.h"
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

#include "video_streaming/video_playback_request_proto.pb-c.h"

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
	if (!ada_can_parse(val, val_sz)) {
		return make_result(ERR_JS_PARSE_JSON_CALLBACK_INVALID_URL,
		                   val,
		                   val_sz);
	}

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
	if (!ada_search_params_has(q, ARG_N, strlen(ARG_N))) {
		return make_result(ERR_YOUTUBE_N_PARAM_FIND_IN_QUERY);
	}

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
	debug("free()-d %zu n-param ciphertext bufs", free_count);
}

/*
 * Convert base64url-encoded content to standard base64 format.
 *
 * https://datatracker.ietf.org/doc/html/rfc4648#section-5
 */
static void
base64url_to_standard_base64(char *buf)
{
	for (char *c = buf; *c; ++c) {
		switch (*c) {
		case '-':
			*c = '+';
			break;
		case '_':
			*c = '/';
			break;
		}
	}
}

result_t
youtube_stream_setup(struct youtube_stream *p,
                     const struct youtube_setup_ops *ops,
                     void *userdata,
                     const char *target)
{
	struct downloaded protobuf __attribute__((cleanup(downloaded_cleanup)));
	struct downloaded html __attribute__((cleanup(downloaded_cleanup)));
	struct downloaded js __attribute__((cleanup(downloaded_cleanup)));

	downloaded_init(&protobuf, "ProtoBuf tmpfile");
	downloaded_init(&html, "HTML tmpfile");
	downloaded_init(&js, "JavaScript tmpfile");

	if (ops && ops->before) {
		check(ops->before(userdata));
	}

	check(tmpfd(&protobuf.fd));
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

	char *null_terminated_sabr __attribute__((cleanup(str_free))) = NULL;
	{
		struct string_view sabr = {0};
		check(find_sabr_url(&html.data, &sabr));
		decode_ampersands(sabr, &null_terminated_sabr);
	}
	check_if(null_terminated_sabr == NULL, ERR_JS_SABR_URL_ALLOC);
	debug("Decoded SABR URL: %s", null_terminated_sabr);

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

#if 0
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
#endif

	if (ops && ops->after_inet) {
		check(ops->after_inet(userdata));
	}

	if (ops && ops->before_parse) {
		check(ops->before_parse(userdata));
	}

	check(youtube_stream_set_video(null_terminated_sabr, p));
	check(youtube_stream_set_audio(null_terminated_sabr, p));

#if 0 // TODO: restore parse_json()
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
#endif

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

	struct deobfuscator d = {0};
	check(find_js_deobfuscator_magic_global(&js.data, &d));
	check(find_js_deobfuscator(&js.data, &d));

	char *ciphertexts[ARRAY_SIZE(p->url) + 1]
		__attribute__((cleanup(ciphertexts_cleanup))) = {NULL};
	check(copy_n_param_all(p, ciphertexts));

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

	VideoStreaming__MediaCapabilities__VideoFormatCapability__Profile vfcp[] = {
		VIDEO_STREAMING__MEDIA_CAPABILITIES__VIDEO_FORMAT_CAPABILITY__PROFILE__MPEG4_SIMPLE,
		VIDEO_STREAMING__MEDIA_CAPABILITIES__VIDEO_FORMAT_CAPABILITY__PROFILE__MPEG4_SIMPLE_0,
		VIDEO_STREAMING__MEDIA_CAPABILITIES__VIDEO_FORMAT_CAPABILITY__PROFILE__INTERMEDIATE,
		VIDEO_STREAMING__MEDIA_CAPABILITIES__VIDEO_FORMAT_CAPABILITY__PROFILE__AVC_BASELINE,
		VIDEO_STREAMING__MEDIA_CAPABILITIES__VIDEO_FORMAT_CAPABILITY__PROFILE__AVC_BASELINE_30,
		VIDEO_STREAMING__MEDIA_CAPABILITIES__VIDEO_FORMAT_CAPABILITY__PROFILE__AVC_BASELINE_31,
		VIDEO_STREAMING__MEDIA_CAPABILITIES__VIDEO_FORMAT_CAPABILITY__PROFILE__AVC_MAIN,
		VIDEO_STREAMING__MEDIA_CAPABILITIES__VIDEO_FORMAT_CAPABILITY__PROFILE__AVC_MAIN_31,
		VIDEO_STREAMING__MEDIA_CAPABILITIES__VIDEO_FORMAT_CAPABILITY__PROFILE__AVC_HIGH,
		VIDEO_STREAMING__MEDIA_CAPABILITIES__VIDEO_FORMAT_CAPABILITY__PROFILE__AVC_HIGH_30,
		VIDEO_STREAMING__MEDIA_CAPABILITIES__VIDEO_FORMAT_CAPABILITY__PROFILE__AVC_HIGH_31,
		VIDEO_STREAMING__MEDIA_CAPABILITIES__VIDEO_FORMAT_CAPABILITY__PROFILE__AVC_HIGH_32,
		VIDEO_STREAMING__MEDIA_CAPABILITIES__VIDEO_FORMAT_CAPABILITY__PROFILE__AVC_HIGH_41,
	};

	VideoStreaming__MediaCapabilities__VideoFormatCapability v_capability;
	video_streaming__media_capabilities__video_format_capability__init(&v_capability);
	v_capability.has_video_codec = true;
	v_capability.video_codec = VIDEO__STORAGE__FORMAT_DESCRIPTION__VIDEO__CODEC__AV1;
	v_capability.profiles_supported = vfcp;
	v_capability.n_profiles_supported = 13;

	VideoStreaming__MediaCapabilities__VideoFormatCapability *vp = &v_capability;
	VideoStreaming__MediaCapabilities__VideoFormatCapability **vpp = { &vp };

	VideoStreaming__MediaCapabilities__AudioFormatCapability a_capability;
	video_streaming__media_capabilities__audio_format_capability__init(&a_capability);
	a_capability.has_audio_codec = true;
	a_capability.audio_codec = VIDEO__STORAGE__FORMAT_DESCRIPTION__AUDIO__CODEC__OPUS;

	VideoStreaming__MediaCapabilities__AudioFormatCapability *ap = &a_capability;
	VideoStreaming__MediaCapabilities__AudioFormatCapability **app = { &ap };

	VideoStreaming__MediaCapabilities media_capabilities;
	video_streaming__media_capabilities__init(&media_capabilities);
	media_capabilities.video_format_capabilities = vpp;
	media_capabilities.n_video_format_capabilities = 1;
	media_capabilities.audio_format_capabilities = app;
	media_capabilities.n_audio_format_capabilities = 1;

	VideoStreaming__ClientAbrState abr_state;
	video_streaming__client_abr_state__init(&abr_state);
	abr_state.has_detailed_network_type = true;
	abr_state.detailed_network_type = YOUTUBE__API__INNERTUBE__DETAILED_NETWORK_TYPE__DETAILED_NETWORK_TYPE_ETHERNET;
	abr_state.has_client_viewport_width = true;
	abr_state.client_viewport_width = 1920;
	abr_state.has_client_viewport_height = true;
	abr_state.client_viewport_height = 1080;
	abr_state.has_bandwidth_estimate_bytes_per_sec = true;
	abr_state.bandwidth_estimate_bytes_per_sec = 7340032; // 7MBps
	abr_state.has_min_audio_quality = true;
	abr_state.min_audio_quality = YOUTUBE__API__INNERTUBE__AUDIO_QUALITY__AUDIO_QUALITY_LOW;
	abr_state.has_max_audio_quality = true;
	abr_state.max_audio_quality = YOUTUBE__API__INNERTUBE__AUDIO_QUALITY__AUDIO_QUALITY_HIGH;
	abr_state.has_video_quality_setting = true;
	abr_state.video_quality_setting = YOUTUBE__API__INNERTUBE__VIDEO_QUALITY_SETTING__VIDEO_QUALITY_SETTING_HIGHER_QUALITY;
	abr_state.has_player_time_ms = true;
	abr_state.player_time_ms = 0;
	abr_state.has_network_metered_state = true;
	abr_state.network_metered_state = YOUTUBE__API__INNERTUBE__NETWORK_METERED_STATE__NETWORK_METERED_STATE_METERED;
	abr_state.has_playback_rate = true;
	abr_state.playback_rate = 1.0;
	abr_state.has_elapsed_wall_time_ms = true;
	abr_state.elapsed_wall_time_ms = 0;
	abr_state.media_capabilities = &media_capabilities;

	Youtube__Api__Innertube__ClientInfo client;
	youtube__api__innertube__client_info__init(&client);
	client.hl = "en";
	client.gl = "US";
	client.visitor_data = strdup(p->visitor_data); // TODO: free when done?
	client.user_agent =
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
		"(KHTML, like Gecko) Chrome/87.0.4280.101 Safari/537.36";
	client.has_client_name = true;
	client.client_name =
		YOUTUBE__API__INNERTUBE__CLIENT_INFO__CLIENT_NAME__WEB;
	client.client_version = "2.20240726.00.00";
	client.time_zone = "UTC";

	VideoStreaming__StreamerContext context;
	video_streaming__streamer_context__init(&context);
	context.client = &client;
	context.has_unnamed_field_2 = true;
	char *decoded_pot __attribute__((cleanup(str_free))) = NULL;
	{
		int decoded_sz = 0;

		char *tmp __attribute__((cleanup(str_free))) =
			strdup(p->proof_of_origin);
		check_if(tmp == NULL, ERR_JS_PROOF_OF_ORIGIN_ALLOC);
		base64url_to_standard_base64(tmp);
		decoded_sz = base64_decode(tmp, NULL, 0);
		check_if(decoded_sz < 0, ERR_JS_PROOF_OF_ORIGIN_BASE64_DECODE);
		decoded_pot = malloc(decoded_sz);
		check_if(decoded_pot == NULL, ERR_JS_PROOF_OF_ORIGIN_ALLOC);

		const int rc = base64_decode(tmp, decoded_pot, decoded_sz);
		check_if(rc < 0, ERR_JS_PROOF_OF_ORIGIN_BASE64_DECODE);

		context.unnamed_field_2.len = decoded_sz;
	}
	context.unnamed_field_2.data = decoded_pot;

	VideoStreaming__VideoPlaybackRequestProto req;
	video_streaming__video_playback_request_proto__init(&req);
	req.abr_state = &abr_state;
	req.has_video_playback_ustreamer_config = true;
	char *decoded_config __attribute__((cleanup(str_free))) = NULL;
	{
		int decoded_sz = 0;

		struct string_view config = {0};
		check(find_playback_config(&html.data, &config));

		char *tmp __attribute__((cleanup(str_free))) =
			strndup(config.data, config.sz);
		check_if(tmp == NULL, ERR_JS_PLAYBACK_CONFIG_ALLOC);
		base64url_to_standard_base64(tmp);
		decoded_sz = base64_decode(tmp, NULL, 0);
		check_if(decoded_sz < 0, ERR_JS_PLAYBACK_CONFIG_BASE64_DECODE);
		decoded_config = malloc(decoded_sz);
		check_if(decoded_config == NULL, ERR_JS_PLAYBACK_CONFIG_ALLOC);

		const int rc = base64_decode(tmp, decoded_config, decoded_sz);
		check_if(rc < 0, ERR_JS_PLAYBACK_CONFIG_BASE64_DECODE);

		req.video_playback_ustreamer_config.len = decoded_sz;
	}
	req.video_playback_ustreamer_config.data = decoded_config;
	req.has_player_time_ms = true;
	req.player_time_ms = 0;
	req.streamer_context = &context;

	const size_t sabr_packed_sz =
		video_streaming__video_playback_request_proto__get_packed_size(
			&req
		);

	char *sabr_post __attribute__((cleanup(str_free))) =
		malloc(sabr_packed_sz * sizeof(*sabr_post));
	// TODO: handle malloc failure
	// TODO: cleanup with video_streaming__video_playback_request_proto__free_unpacked instead of str_free
	video_streaming__video_playback_request_proto__pack(&req, sabr_post);

	debug("Sending protobuf blob"); // TODO remove debug msg
	for (size_t i = 0; i < sabr_packed_sz; ++i) {
		debug("%02X", (unsigned char)sabr_post[i]);
	}

	char *null_terminated_sabr_url __attribute__((cleanup(str_free))) =
		NULL;
	{
		ada_string tmp = ada_get_href(p->url[0]);
		null_terminated_sabr_url = strndup(tmp.data, tmp.length);
		// TODO: handle malloc failure
	}
	check(download_and_mmap_tmpfd(null_terminated_sabr_url,
	                              NULL,
	                              NULL,
	                              sabr_post,
	                              NULL,
	                              protobuf.fd,
	                              &protobuf.data,
	                              &p->request_context));
	debug("Got protobuf blob: %.*s",
	      (int)protobuf.data.sz,
	      protobuf.data.data); // TODO: decode protobuf response?

	return RESULT_OK;
}
