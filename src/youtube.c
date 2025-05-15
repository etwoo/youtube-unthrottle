#include "youtube.h"

#include "lib/base64.h"
#include "lib/js.h"
#include "lib/re.h"
#include "lib/url.h"
#include "sys/array.h"
#include "sys/debug.h"
#include "sys/tmpfile.h"
#include "sys/write.h"
#include "video_streaming/format_initialization_metadata.pb-c.h"
#include "video_streaming/media_header.pb-c.h"
#include "video_streaming/next_request_policy.pb-c.h"
#include "video_streaming/sabr_redirect.pb-c.h"
#include "video_streaming/video_playback_abr_request.pb-c.h"

#include <ada_c.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h> /* for asprintf() */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define min(x, y) (x < y ? x : y) // TODO: reuse some systemwide define?
#define max(x, y) (x > y ? x : y) // TODO: reuse some systemwide define?

static const char ARG_N[] = "n";

struct youtube_stream {
	ada_url url[2];
	const char *proof_of_origin;
	const char *visitor_data;
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
		for (size_t i = 0; i < ARRAY_SIZE(p->url); ++i) {
			ada_free(p->url[i]); /* handles NULL gracefully */
			p->url[i] = NULL;
		}
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
	for (size_t i = 0; i < ARRAY_SIZE(p->url); ++i) {
		assert(ada_is_valid(p->url[i]));
	}
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
ustr_free(unsigned char **strp)
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

static void
ump_request_policy_free(VideoStreaming__NextRequestPolicy **policy)
{
	video_streaming__next_request_policy__free_unpacked(*policy, NULL);
}

static void
ump_header_free(VideoStreaming__MediaHeader **header)
{
	video_streaming__media_header__free_unpacked(*header, NULL);
}

static void
ump_formats_free(VideoStreaming__FormatInitializationMetadata **format_init)
{
	video_streaming__format_initialization_metadata__free_unpacked(
		*format_init,
		NULL);
}

static void
sabr_redirect_free(VideoStreaming__SabrRedirect **redirect)
{
	video_streaming__sabr_redirect__free_unpacked(*redirect, NULL);
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

static const unsigned char CHAR_BIT_0 = 0x80; // bit pattern: 10000000
static const unsigned char CHAR_BIT_1 = 0x40; // bit pattern: 01000000
static const unsigned char CHAR_BIT_2 = 0x20; // bit pattern: 00100000
static const unsigned char CHAR_BIT_3 = 0x10; // bit pattern: 00010000
static const unsigned char CHAR_BIT_4 = 0x08; // bit pattern: 00001000

static void
ump_read_vle(const unsigned char first_byte,
             size_t *bytes_to_read,
             unsigned char *first_byte_mask)
{
	*bytes_to_read = 1;
	*first_byte_mask = 0xFF; // bit pattern: 11111111
	if (0 == (first_byte & CHAR_BIT_0)) {
		return;
	}

	++*bytes_to_read;
	*first_byte_mask ^= CHAR_BIT_0;
	*first_byte_mask ^= CHAR_BIT_1;

	if (0 == (first_byte & CHAR_BIT_1)) {
		return;
	}

	++*bytes_to_read;
	*first_byte_mask ^= CHAR_BIT_2;

	if (0 == (first_byte & CHAR_BIT_2)) {
		return;
	}

	++*bytes_to_read;
	*first_byte_mask ^= CHAR_BIT_3;

	if (0 == (first_byte & CHAR_BIT_3)) {
		return;
	}

	++*bytes_to_read;
	*first_byte_mask ^= CHAR_BIT_4;
}

static result_t
ump_varint_read(const struct string_view *ump, size_t *cursor, uint64_t *value)
{
	assert(*cursor < ump->sz);

	size_t bytes_to_read = 0;
	unsigned char first_byte_mask = 0xFF;
	ump_read_vle(ump->data[*cursor], &bytes_to_read, &first_byte_mask);
	debug("Got first_byte=%hhu, bytes_to_read=%zu, first_byte_mask=%02X",
	      ump->data[*cursor],
	      bytes_to_read,
	      first_byte_mask);

	check_if(*cursor <= SIZE_MAX - bytes_to_read &&
	                 *cursor + bytes_to_read >= ump->sz,
	         1); // TOOD: ERR_YOUTUBE_CURSOR_EXCEEDS_UMP_DATA

	uint64_t parsed[5] = {0};
	switch (bytes_to_read) {
	case 5: // TODO: bytes_to_read=5 is probably broken
		parsed[4] = ump->data[*cursor + 4] << 24;
		__attribute__((fallthrough));
	case 4: // TODO: bytes_to_read=4 is probably broken
		parsed[3] = ump->data[*cursor + 3] << 16;
		__attribute__((fallthrough));
	case 3:
		parsed[2] = ump->data[*cursor + 2] << (8 + (8 - bytes_to_read));
		__attribute__((fallthrough));
	case 2:
		parsed[1] = (unsigned char)ump->data[*cursor + 1]
		            << (8 - bytes_to_read);
		__attribute__((fallthrough));
	case 1:
		parsed[0] = ump->data[*cursor] & first_byte_mask;
		break;
	default:
		assert(false);
		break;
	}
	*cursor += bytes_to_read;

	*value = 0;
	for (size_t i = 0; i < ARRAY_SIZE(parsed); ++i) {
		*value += parsed[i];
	}

	return RESULT_OK;
}

static result_t
ump_part_parse(uint64_t part_type,
               uint64_t part_size,
               const struct string_view *ump,
               size_t *cursor,
               struct youtube_stream *stream,
               VideoStreaming__VideoPlaybackAbrRequest *req,
               VideoStreaming__BufferedRange *buffered_audio_range,
               VideoStreaming__BufferedRange *buffered_video_range,
               bool *skip_media_blobs_until_next_section,
               int *header_chosen_fd,
               int64_t *greatest_seq_audio,
               int64_t *greatest_seq_video)
{
	VideoStreaming__NextRequestPolicy *next_request_policy
		__attribute__((cleanup(ump_request_policy_free))) = NULL;
	VideoStreaming__MediaHeader *header
		__attribute__((cleanup(ump_header_free))) = NULL;
	VideoStreaming__FormatInitializationMetadata *fmt
		__attribute__((cleanup(ump_formats_free))) = NULL;
	VideoStreaming__SabrRedirect *redirect
		__attribute__((cleanup(sabr_redirect_free))) = NULL;
	uint64_t header_id = 0;
	ssize_t written = -1;

	switch (part_type) {
	case 20: /* MEDIA_HEADER */
		*skip_media_blobs_until_next_section = false;
		header = video_streaming__media_header__unpack(NULL,
		                                               part_size,
		                                               ump->data +
		                                                       *cursor);
		assert(header); // TODO: error out on misparse
		debug("Got header header_id=%" PRIu32
		      ", video=%s, itag=%d, xtags=%s"
		      ", start_data_range=%d, is_init_seg=%d"
		      ", seq=%" PRIi64 ", start_ms=%d, duration_ms=%d"
		      ", content_length=%" PRIi64 ", time_range.start=%" PRIi64
		      ", time_range.duration=%" PRIi64
		      ", time_range.timescale=%" PRIi32,
		      header->header_id,
		      header->video_id,
		      header->has_itag ? header->itag : -1,
		      header->xtags,
		      header->has_start_data_range ? header->start_data_range
		                                   : -1,
		      header->has_is_init_seg ? header->is_init_seg : -1,
		      header->has_sequence_number ? header->sequence_number
		                                  : -1,
		      header->has_start_ms ? header->start_ms : -1,
		      header->has_duration_ms ? header->duration_ms : -1,
		      header->has_content_length ? header->content_length : -1,
		      (header->time_range && header->time_range->has_start
		               ? header->time_range->start
		               : -1),
		      (header->time_range && header->time_range->has_duration
		               ? header->time_range->duration
		               : -1),
		      (header->time_range && header->time_range->has_timescale
		               ? header->time_range->timescale
		               : -1));
		switch (header->itag) {
		case 251:
			// TODO: refactor how audio/video is selected
			*header_chosen_fd = stream->fd[0];
			debug("Header switch to audio fd=%d",
			      *header_chosen_fd);
			if (header->has_sequence_number &&
			    header->sequence_number <= *greatest_seq_audio) {
				debug("Skipping repeated seq=%" PRIi64,
				      header->sequence_number);
				*skip_media_blobs_until_next_section = true;
			} else {
				debug("Handling new seq=%" PRIi64
				      ", greatest=%" PRIi64,
				      header->sequence_number,
				      *greatest_seq_audio);
				if (header->has_sequence_number) {
					*greatest_seq_audio =
						header->sequence_number;
					buffered_audio_range
						->end_segment_index =
						header->sequence_number + 1;
				}
				if (header->has_duration_ms) {
					debug("Advancing audio by duration "
					      "%" PRIi64 " + %" PRIi32,
					      buffered_audio_range->duration_ms,
					      header->duration_ms);
					buffered_audio_range->duration_ms +=
						header->duration_ms;
				}
				debug("Setting buffered_audio_range "
				      "duration_ms=%" PRIi64
				      ", start_segment_index=%d, "
				      "end_segment_index=%d",
				      buffered_audio_range->duration_ms,
				      buffered_audio_range->start_segment_index,
				      buffered_audio_range->end_segment_index);
			}
			break;
		case 299:
			// TODO: refactor how audio/video is selected
			*header_chosen_fd = stream->fd[1];
			debug("Header switch to video fd=%d",
			      *header_chosen_fd);
			if (header->has_sequence_number &&
			    header->sequence_number <= *greatest_seq_video) {
				debug("Skipping repeated seq=%" PRIi64,
				      header->sequence_number);
				*skip_media_blobs_until_next_section = true;
			} else {
				debug("Handling new seq=%" PRIi64
				      ", greatest=%" PRIi64,
				      header->sequence_number,
				      *greatest_seq_video);
				if (header->has_sequence_number) {
					*greatest_seq_video =
						header->sequence_number;
					buffered_video_range
						->end_segment_index =
						header->sequence_number + 1;
				}
				if (header->has_duration_ms) {
					debug("Advancing video by duration "
					      "%" PRIi64 " + %" PRIi32,
					      buffered_video_range->duration_ms,
					      header->duration_ms);
					buffered_video_range->duration_ms +=
						header->duration_ms;
				}
				debug("Setting buffered_video_range "
				      "duration_ms=%" PRIi64
				      ", start_segment_index=%d, "
				      "end_segment_index=%d",
				      buffered_video_range->duration_ms,
				      buffered_video_range->start_segment_index,
				      buffered_video_range->end_segment_index);
			}
			break;
		}
		break;
	case 21: /* MEDIA */
		// TODO: raise more specific error for header_id
		if (*skip_media_blobs_until_next_section) {
			debug("Skipping media blob at cursor=%zu", *cursor);
		} else {
			check(ump_varint_read(ump, cursor, &header_id));
			debug("Got media blob header_id=%" PRIu64
			      ", cursor=%zu, part_size=%" PRIu64
			      ", remaining_bytes=%zu",
			      header_id,
			      *cursor,
			      part_size,
			      ump->sz - *cursor);
			// TODO: refactor how audio/video is selected
			written = write_with_retry(*header_chosen_fd,
			                           ump->data + *cursor,
			                           part_size - 1);
			info_m_if(written < 0, "Cannot write media to stdout");
			debug("Wrote media blob bytes=%zd to fd=%d",
			      written,
			      *header_chosen_fd);
			*cursor -= 1; // rewind cursor, let caller update
		}
		break;
	case 35: /* NEXT_REQUEST_POLICY */
		*skip_media_blobs_until_next_section = false;
		next_request_policy =
			video_streaming__next_request_policy__unpack(
				NULL,
				part_size,
				ump->data + *cursor);
		assert(next_request_policy); // error out on misparse
		if (req->streamer_context->has_playback_cookie &&
		    req->streamer_context->playback_cookie.data) {
			free(req->streamer_context->playback_cookie.data);
			req->streamer_context->playback_cookie.data = NULL;
		}
		const size_t cookie_packed_sz =
			video_streaming__playback_cookie__get_packed_size(
				next_request_policy->playback_cookie);
		req->streamer_context->playback_cookie.data = malloc(
			cookie_packed_sz *
			sizeof(*req->streamer_context->playback_cookie.data));
		// TODO: handle malloc error
		req->streamer_context->playback_cookie.len = cookie_packed_sz;
		req->streamer_context->has_playback_cookie = true;
		video_streaming__playback_cookie__pack(
			next_request_policy->playback_cookie,
			req->streamer_context->playback_cookie.data);
		debug("Updating playback cookie of size=%zu", cookie_packed_sz);
		break;
	case 42: /* FORMAT_INITIALIZATION_METADATA */
		*skip_media_blobs_until_next_section = false;
		fmt = video_streaming__format_initialization_metadata__unpack(
			NULL,
			part_size,
			ump->data + *cursor);
		assert(fmt); // TODO: error out on misparse
		debug("Got format video=%s, itag=%d, "
		      "duration=%d"
		      ", init_start=%d, init_end=%d"
		      ", index_start=%d, index_end=%d",
		      fmt->video_id,
		      fmt->format_id->has_itag ? fmt->format_id->itag : -1,
		      (fmt->has_duration_ms ? fmt->duration_ms : -1),
		      (fmt->init_range->has_start ? fmt->init_range->start
		                                  : -1),
		      (fmt->init_range->has_end ? fmt->init_range->end : -1),
		      (fmt->index_range->has_start ? fmt->index_range->start
		                                   : -1),
		      (fmt->index_range->has_end ? fmt->index_range->end : -1));
#if 0
		written = write_with_retry(STDOUT_FILENO,
			                   ump->data + *cursor + fmt->init_range->start,
			                   fmt->init_range->end - fmt->init_range->start);
		info_m_if(written < 0, "Cannot write media header to stdout");
		debug("Wrote media header bytes=%zd to stdout", written);
#endif

		break;
	case 43: /* SABR_REDIRECT */
		*skip_media_blobs_until_next_section = false;
		redirect = video_streaming__sabr_redirect__unpack(
			NULL,
			part_size,
			ump->data + *cursor);
		assert(redirect); // TODO: error out on misparse
		// TODO: handle ada_set_href() returns false
		ada_set_href(stream->url[0],
		             redirect->url,
		             strlen(redirect->url));
		debug("Got redirect to new SABR url: %s", redirect->url);
		break;
	default:
		*skip_media_blobs_until_next_section = false;
		break;
	}

	return RESULT_OK;
}

static result_t
ump_parse(const struct string_view *ump,
          struct youtube_stream *stream,
          VideoStreaming__VideoPlaybackAbrRequest *req,
          VideoStreaming__BufferedRange *buffered_audio_range,
          VideoStreaming__BufferedRange *buffered_video_range,
          int64_t *greatest_seq_audio,
          int64_t *greatest_seq_video)
{
	debug("Got UMP response of sz=%zu", ump->sz);
#if 0
	for (size_t i = 0; i < ump->sz; ++i) {
		debug("%02X", (unsigned char)ump->data[i]); // TODO remove
	}
#endif

	size_t cursor = 0;
	int header_chosen_fd = stream->fd[0];
	bool skip_media_blobs_until_next_section = false;
	while (cursor < ump->sz) {
		uint64_t part_type = 0;
		// TODO: raise more specific error for part_type
		check(ump_varint_read(ump, &cursor, &part_type));

		uint64_t part_size = 0;
		// TODO: raise more specific error for part_size
		check(ump_varint_read(ump, &cursor, &part_size));

		debug("Got part_type=%" PRIu64 ", part_size=%" PRIu64,
		      part_type,
		      part_size);

		check(ump_part_parse(part_type,
		                     part_size,
		                     ump,
		                     &cursor,
		                     stream,
				     req,
		                     buffered_audio_range,
		                     buffered_video_range,
		                     &skip_media_blobs_until_next_section,
		                     &header_chosen_fd,
		                     greatest_seq_audio,
		                     greatest_seq_video));

		cursor += part_size;
	}

	return RESULT_OK;
}

result_t
youtube_stream_setup(struct youtube_stream *p,
                     const struct youtube_setup_ops *ops,
                     void *userdata,
                     const char *target)
{
	struct downloaded html __attribute__((cleanup(downloaded_cleanup)));
	struct downloaded js __attribute__((cleanup(downloaded_cleanup)));

	downloaded_init(&html, "HTML tmpfile");
	downloaded_init(&js, "JavaScript tmpfile");

	if (ops && ops->before) {
		check(ops->before(userdata));
	}

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
	                              0,
	                              NULL,
	                              js.fd,
	                              &js.data,
	                              &p->request_context));

	long long int timestamp = 0;
	check(find_js_timestamp(&js.data, &timestamp));

	if (ops && ops->after_inet) {
		check(ops->after_inet(userdata));
	}

	if (ops && ops->before_parse) {
		check(ops->before_parse(userdata));
	}

	check(youtube_stream_set_video(null_terminated_sabr, p));
	check(youtube_stream_set_audio(null_terminated_sabr, p));

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

	VideoStreaming__ClientAbrState abr_state;
	video_streaming__client_abr_state__init(&abr_state);
	abr_state.has_last_manual_selected_resolution = true;
	abr_state.last_manual_selected_resolution = 1080;
	abr_state.has_sticky_resolution = true;
	abr_state.sticky_resolution = 1080;

	VideoStreaming__StreamerContext__ClientInfo info;
	video_streaming__streamer_context__client_info__init(&info);
	info.has_client_name = true;
	info.client_name = 1;
	info.client_version = "2.20250312.04.00";
	info.os_name = "Windows";
	info.os_version = "10.0";

	VideoStreaming__StreamerContext context;
	video_streaming__streamer_context__init(&context);
	context.client_info = &info;
	context.has_po_token = true;
	unsigned char *decoded_pot __attribute__((cleanup(ustr_free))) = NULL;
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

		context.po_token.len = decoded_sz;
	}
	context.po_token.data = decoded_pot;

	Misc__FormatId selected_audio_format;
	misc__format_id__init(&selected_audio_format);
	selected_audio_format.has_itag = true;
	selected_audio_format.itag = 251;

	Misc__FormatId selected_video_format;
	misc__format_id__init(&selected_video_format);
	selected_video_format.has_itag = true;
	selected_video_format.itag = 299;

	VideoStreaming__BufferedRange buffered_audio_range;
	video_streaming__buffered_range__init(&buffered_audio_range);
	buffered_audio_range.format_id = &selected_audio_format;
	buffered_audio_range.duration_ms = 0;
	buffered_audio_range.start_segment_index = 1;
	buffered_audio_range.end_segment_index = 0;

	VideoStreaming__BufferedRange buffered_video_range;
	video_streaming__buffered_range__init(&buffered_video_range);
	buffered_video_range.format_id = &selected_video_format;
	buffered_video_range.duration_ms = 0;
	buffered_video_range.start_segment_index = 1;
	buffered_video_range.end_segment_index = 0;

	VideoStreaming__VideoPlaybackAbrRequest req;
	video_streaming__video_playback_abr_request__init(&req);
	req.client_abr_state = &abr_state;
	req.has_video_playback_ustreamer_config = true;
	unsigned char *decoded_config __attribute__((cleanup(ustr_free))) =
		NULL;
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
	req.n_selected_audio_format_ids = 1;
	req.selected_audio_format_ids =
		(Misc__FormatId *[]){&selected_audio_format};
	req.n_selected_video_format_ids = 1;
	req.selected_video_format_ids =
		(Misc__FormatId *[]){&selected_video_format};
	req.streamer_context = &context;

	int64_t greatest_seq_audio = -1;
	int64_t greatest_seq_video = -1;

	for (size_t requests = 0; requests < 5; ++requests) {
		const size_t sabr_packed_sz =
			video_streaming__video_playback_abr_request__get_packed_size(
				&req);

		char *sabr_post __attribute__((cleanup(str_free))) =
			malloc(sabr_packed_sz * sizeof(*sabr_post));
		check_if(sabr_post == NULL, ERR_JS_SABR_POST_BODY_ALLOC);
		video_streaming__video_playback_abr_request__pack(
			&req,
			(unsigned char *)sabr_post);

		debug("Sending protobuf blob of sz=%zu", sabr_packed_sz);
		for (size_t i = 0; i < sabr_packed_sz; ++i) {
			debug("%02X",
			      (unsigned char)sabr_post[i]); // TODO remove
		}

		char *null_terminated_sabr_deobuscated_n_param
			__attribute__((cleanup(str_free))) = NULL;
		{
			ada_string tmp = ada_get_href(p->url[0]);
			null_terminated_sabr_deobuscated_n_param =
				strndup(tmp.data, tmp.length);
			check_if(null_terminated_sabr_deobuscated_n_param ==
			                 NULL,
			         ERR_JS_SABR_URL_ALLOC);
		}

		struct downloaded ump
			__attribute__((cleanup(downloaded_cleanup)));
		downloaded_init(&ump, "UMP response tmpfile");
		check(tmpfd(&ump.fd));
		check(download_and_mmap_tmpfd(
			null_terminated_sabr_deobuscated_n_param,
			NULL,
			NULL,
			sabr_post,
			sabr_packed_sz,
			NULL,
			ump.fd,
			&ump.data,
			&p->request_context));
		check(ump_parse(&ump.data,
		                p,
				&req,
		                &buffered_audio_range,
		                &buffered_video_range,
		                &greatest_seq_audio,
		                &greatest_seq_video));

		req.n_selected_format_ids = 2;
		req.selected_format_ids = (Misc__FormatId *[]){
			&selected_audio_format,
			&selected_video_format,
		};
		req.n_buffered_ranges = 2;
		req.buffered_ranges = (VideoStreaming__BufferedRange *[]){
			&buffered_audio_range,
			&buffered_video_range,
		};

		abr_state.has_player_time_ms = true;
		abr_state.player_time_ms =
			min(buffered_audio_range.duration_ms,
		            buffered_video_range.duration_ms);
	}

	return RESULT_OK;
}
