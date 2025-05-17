#include "stream.h"

#include "sys/array.h"
#include "sys/debug.h"
#include "sys/write.h"

#include <inttypes.h>
#include <resolv.h> /* for b64_pton() */
#include <stdbool.h>
#include <stdlib.h>

/*
 * Some helpful references on YouTube's UMP format and SABR protobufs:
 *
 *   https://github.com/gsuberland/UMP_Format/blob/main/UMP_Format.md
 *   https://github.com/LuanRT/googlevideo/blob/HEAD/src/core/UMP.ts
 *   https://github.com/LuanRT/googlevideo/blob/HEAD/src/utils/helpers.ts
 *   https://github.com/LuanRT/googlevideo/blob/main/src/core/ServerAbrStream.ts
 *
 *   https://github.com/LuanRT/googlevideo/tree/main/protos/video_streaming
 *   https://github.com/LuanRT/googlevideo/blob/main/protos/misc/common.proto
 *
 *   https://github.com/LuanRT/googlevideo/blob/main/examples/downloader/main.ts
 *   https://github.com/LuanRT/googlevideo/blob/main/examples/README.md
 */
#include "video_streaming/format_initialization_metadata.pb-c.h"
#include "video_streaming/media_header.pb-c.h"
#include "video_streaming/next_request_policy.pb-c.h"
#include "video_streaming/sabr_redirect.pb-c.h"
#include "video_streaming/video_playback_abr_request.pb-c.h"

#define min(x, y) (x < y ? x : y) // TODO: reuse some systemwide define?
#define max(x, y) (x > y ? x : y) // TODO: reuse some systemwide define?

#define ITAG_AUDIO 251
#define ITAG_VIDEO 299

static void
str_free(char **strp)
{
	free(*strp);
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

static void
debug_protobuf_media_header(const VideoStreaming__MediaHeader *header)
{
	debug("Got header header_id=%" PRIu32 ", video=%s"
	      ", itag=%d"
	      ", xtags=%s"
	      ", start_data_range=%d"
	      ", is_init_seg=%d"
	      ", seq=%" PRIi64 ", start_ms=%d"
	      ", duration_ms=%d"
	      ", content_length=%" PRIi64 ", time_range.start=%" PRIi64
	      ", time_range.duration=%" PRIi64
	      ", time_range.timescale=%" PRIi32,
	      header->header_id,
	      header->video_id,
	      header->has_itag ? header->itag : -1,
	      header->xtags,
	      header->has_start_data_range ? header->start_data_range : -1,
	      header->has_is_init_seg ? header->is_init_seg : -1,
	      header->has_sequence_number ? header->sequence_number : -1,
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
}

static void
debug_protobuf_fmt_init(const VideoStreaming__FormatInitializationMetadata *fmt)
{
	debug("Got format video=%s"
	      ", itag=%d"
	      ", duration=%d"
	      ", init_start=%d"
	      ", init_end=%d"
	      ", index_start=%d"
	      ", index_end=%d",
	      fmt->video_id,
	      fmt->format_id->has_itag ? fmt->format_id->itag : -1,
	      (fmt->has_duration_ms ? fmt->duration_ms : -1),
	      (fmt->init_range->has_start ? fmt->init_range->start : -1),
	      (fmt->init_range->has_end ? fmt->init_range->end : -1),
	      (fmt->index_range->has_start ? fmt->index_range->start : -1),
	      (fmt->index_range->has_end ? fmt->index_range->end : -1));
}

struct protocol_state {
	int outputs[2];
	int64_t sequence_number_cursor[2];
	int header_map[UCHAR_MAX + 1]; // maps header_id number to itag
	VideoStreaming__ClientAbrState abr_state;
	VideoStreaming__StreamerContext__ClientInfo info;
	VideoStreaming__StreamerContext context;
	Misc__FormatId selected_audio_format;
	Misc__FormatId selected_video_format;
	Misc__FormatId *selected_format_ids[2];
	VideoStreaming__BufferedRange buffered_audio_range;
	VideoStreaming__BufferedRange buffered_video_range;
	VideoStreaming__VideoPlaybackAbrRequest req;
	VideoStreaming__BufferedRange *buffered_ranges[2];
};

static void
protocol_init_members(struct protocol_state *p)
{
	video_streaming__client_abr_state__init(&p->abr_state);
	p->abr_state.has_last_manual_selected_resolution = true;
	p->abr_state.last_manual_selected_resolution = 1080;
	p->abr_state.has_sticky_resolution = true;
	p->abr_state.sticky_resolution = 1080;

	video_streaming__streamer_context__client_info__init(&p->info);
	p->info.has_client_name = true;
	p->info.client_name = 1;
	p->info.client_version = "2.20250312.04.00";
	p->info.os_name = "Windows";
	p->info.os_version = "10.0";

	video_streaming__streamer_context__init(&p->context);
	p->context.client_info = &p->info;

	misc__format_id__init(&p->selected_audio_format);
	p->selected_audio_format.has_itag = true;
	p->selected_audio_format.itag = ITAG_AUDIO;

	misc__format_id__init(&p->selected_video_format);
	p->selected_video_format.has_itag = true;
	p->selected_video_format.itag = ITAG_VIDEO;

	p->selected_format_ids[0] = &p->selected_audio_format;
	p->selected_format_ids[1] = &p->selected_video_format;

	video_streaming__buffered_range__init(&p->buffered_audio_range);
	p->buffered_audio_range.format_id = &p->selected_audio_format;
	p->buffered_audio_range.duration_ms = 0;
	p->buffered_audio_range.start_segment_index = 1;
	p->buffered_audio_range.end_segment_index = 0;

	video_streaming__buffered_range__init(&p->buffered_video_range);
	p->buffered_video_range.format_id = &p->selected_video_format;
	p->buffered_video_range.duration_ms = 0;
	p->buffered_video_range.start_segment_index = 1;
	p->buffered_video_range.end_segment_index = 0;

	p->buffered_ranges[0] = &p->buffered_audio_range;
	p->buffered_ranges[1] = &p->buffered_video_range;

	video_streaming__video_playback_abr_request__init(&p->req);
	p->req.client_abr_state = &p->abr_state;

	p->req.n_selected_audio_format_ids = 1;
	p->req.selected_audio_format_ids = p->selected_format_ids;
	p->req.n_selected_video_format_ids = 1;
	p->req.selected_video_format_ids = p->selected_format_ids + 1;
	p->req.streamer_context = &p->context;
}

static void
protocol_update_members(struct protocol_state *p)
{
	p->req.n_selected_format_ids = ARRAY_SIZE(p->selected_format_ids);
	p->req.selected_format_ids = p->selected_format_ids;
	p->req.n_buffered_ranges = ARRAY_SIZE(p->buffered_ranges);
	p->req.buffered_ranges = p->buffered_ranges;

	p->abr_state.has_player_time_ms = true;
	p->abr_state.player_time_ms = min(p->buffered_audio_range.duration_ms,
	                                  p->buffered_video_range.duration_ms);
}

static size_t
get_index_of(const struct protocol_state *p, unsigned char header_id)
{
	return p->header_map[header_id] == ITAG_AUDIO ? 0 : 1;
}

static int
get_fd_for_header(const struct protocol_state *p, unsigned char header_id)
{
	return p->outputs[get_index_of(p, header_id)];
}

static int64_t
get_sequence_number_cursor(const struct protocol_state *p,
                           unsigned char header_id)
{
	return p->sequence_number_cursor[get_index_of(p, header_id)];
}

static void
set_header_media_type(struct protocol_state *p,
                      unsigned char header_id,
                      int itag)
{
	p->header_map[header_id] = itag;
	const int fd = get_fd_for_header(p, header_id);
	debug("Map header_id=%u to fd=%d", header_id, fd);
}

static void
set_header_sequence_number(struct protocol_state *p,
                           unsigned char header_id,
                           int64_t n)
{
	const size_t idx = get_index_of(p, header_id);
	p->sequence_number_cursor[idx] = n;
	VideoStreaming__BufferedRange *br = p->buffered_ranges[idx];
	br->end_segment_index = n + 1;
	debug("Map header_id=%u to seq=%" PRIi64, header_id, n);
}

static void
increment_header_duration(struct protocol_state *p,
                          unsigned char header_id,
                          int64_t duration)
{
	p->buffered_ranges[get_index_of(p, header_id)]->duration_ms += duration;
	debug("Map header_id=%u to duration=%" PRIi64, header_id, duration);
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

static bool
protocol_base64_decode(const struct string_view *in,
                       struct ProtobufCBinaryData *out)
{
	char *scratch_buffer __attribute__((cleanup(str_free))) =
		strndup(in->data, in->sz);
	if (scratch_buffer == NULL) {
		return false;
	}

	base64url_to_standard_base64(scratch_buffer);
	out->len = b64_pton(scratch_buffer, NULL, 0);
	if (out->len <= 0) {
		return false;
	}

	out->data = malloc(out->len);
	if (out->data == NULL) {
		return false;
	}

	const int rc = b64_pton(scratch_buffer, out->data, out->len);
	return (rc > 0);
}

struct protocol_state *
protocol_init(const char *proof_of_origin,
              const struct string_view *playback_config,
              int outputs[2])
{
	struct protocol_state *p = malloc(sizeof(*p));
	if (p == NULL) {
		goto cleanup;
	}

	memset(p, 0, sizeof(*p)); /* zero early, just in case */

	p->outputs[0] = outputs[0];
	p->outputs[1] = outputs[1];

	p->sequence_number_cursor[0] = -1;
	p->sequence_number_cursor[1] = -1;

	protocol_init_members(p);

	const struct string_view po_token_view = {
		.data = proof_of_origin,
		.sz = strlen(proof_of_origin),
	};
	if (!protocol_base64_decode(&po_token_view, &p->context.po_token)) {
		goto cleanup;
	}
	p->context.has_po_token = true;

	if (!protocol_base64_decode(playback_config,
	                            &p->req.video_playback_ustreamer_config)) {
		goto cleanup;
	}
	p->req.has_video_playback_ustreamer_config = true;

	return p;

cleanup:
	protocol_cleanup(p);
	free(p);
	return NULL;
}

void
protocol_cleanup(struct protocol_state *p)
{
	if (p) {
		free(p->context.po_token.data);
		free(p->req.video_playback_ustreamer_config.data);
	}
}

#define request__get_packed_size                                               \
	video_streaming__video_playback_abr_request__get_packed_size
#define request__pack video_streaming__video_playback_abr_request__pack

result_t
protocol_next_request(struct protocol_state *p, char **request, size_t *sz)
{
	*sz = request__get_packed_size(&p->req);
	*request = malloc(*sz * sizeof(**request));
	check_if(*request == NULL, ERR_PROTOCOL_SABR_POST_BODY_ALLOC);
	request__pack(&p->req, (uint8_t *)*request);
	return RESULT_OK;
}

#undef request__get_packed_size
#undef request__pack

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
	         ERR_PROTOCOL_VARINT_READ_OUT_OF_BOUNDS);

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
		return make_result(ERR_PROTOCOL_VARINT_READ_INVALID_SIZE,
		                   (int)bytes_to_read);
	}
	*cursor += bytes_to_read;

	*value = 0;
	for (size_t i = 0; i < ARRAY_SIZE(parsed); ++i) {
		*value += parsed[i];
	}

	return RESULT_OK;
}

static void
ump_parse_media_header(struct protocol_state *p,
                       const VideoStreaming__MediaHeader *header,
                       bool *skip_media_blobs_until_next)
{
	set_header_media_type(p, header->header_id, header->itag);
	if (header->has_sequence_number &&
	    header->sequence_number <=
	            get_sequence_number_cursor(p, header->header_id)) {
		debug("Skipping repeated seq=%" PRIi64,
		      header->sequence_number);
		*skip_media_blobs_until_next = true;
		return;
	}

	debug("Handling new seq=%" PRIi64 ", greatest=%" PRIi64,
	      header->sequence_number,
	      get_sequence_number_cursor(p, header->header_id));
	if (header->has_sequence_number) {
		set_header_sequence_number(p,
		                           header->header_id,
		                           header->sequence_number);
	}
	if (header->has_duration_ms) {
		increment_header_duration(p,
		                          header->header_id,
		                          header->duration_ms);
	}
}

static WARN_UNUSED result_t
ump_parse_media_blob(struct protocol_state *p,
                     unsigned char header_id,
                     const struct string_view *blob)
{
	int fd = get_fd_for_header(p, header_id);
	const ssize_t written = write_with_retry(fd, blob->data, blob->sz);
	check_if(written < 0, ERR_PROTOCOL_MEDIA_BLOB_WRITE, errno);
	debug("Wrote media blob bytes=%zd to fd=%d", written, fd);
}

static void
ump_parse_cookie(const VideoStreaming__NextRequestPolicy *next_request_policy,
                 VideoStreaming__StreamerContext *context)
{
	if (context->has_playback_cookie && context->playback_cookie.data) {
		free(context->playback_cookie.data);
		context->playback_cookie.data = NULL;
	}

	const size_t cookie_packed_sz =
		video_streaming__playback_cookie__get_packed_size(
			next_request_policy->playback_cookie);
	context->playback_cookie.data = malloc(
		cookie_packed_sz * sizeof(*context->playback_cookie.data));
	// TODO: handle malloc error

	context->playback_cookie.len = cookie_packed_sz;
	context->has_playback_cookie = true;
	video_streaming__playback_cookie__pack(
		next_request_policy->playback_cookie,
		context->playback_cookie.data);
	debug("Updated playback cookie of size=%zu", cookie_packed_sz);
}

static result_t
ump_parse_part(struct protocol_state *p,
               struct string_view ump, /* note: pass by value */
               char **target_url,
               uint64_t part_type,
               bool *skip_media_blobs_until_next)
{
	VideoStreaming__NextRequestPolicy *next_request_policy
		__attribute__((cleanup(ump_request_policy_free))) = NULL;
	VideoStreaming__MediaHeader *header
		__attribute__((cleanup(ump_header_free))) = NULL;
	VideoStreaming__FormatInitializationMetadata *fmt
		__attribute__((cleanup(ump_formats_free))) = NULL;
	VideoStreaming__SabrRedirect *redirect
		__attribute__((cleanup(sabr_redirect_free))) = NULL;
	uint64_t parsed_header_id = 0;

	switch (part_type) {
	case 20: /* MEDIA_HEADER */
		*skip_media_blobs_until_next = false;
		assert(sizeof(uint8_t) == sizeof(ump.data[0]));
		header = video_streaming__media_header__unpack(
			NULL,
			ump.sz,
			(const uint8_t *)ump.data);
		assert(header); // TODO: error out on misparse
		debug_protobuf_media_header(header);
		assert(header->header_id <=
		       UCHAR_MAX); // TODO: convert to check_if() error
		ump_parse_media_header(p, header, skip_media_blobs_until_next);
		break;
	case 21: /* MEDIA */
		if (*skip_media_blobs_until_next) {
			debug("Skipping media blob until next section");
		} else {
			// TODO: raise more specific error for header_id
			size_t cursor = 0;
			check(ump_varint_read(&ump,
			                      &cursor,
			                      &parsed_header_id));
			debug("Got media blob header_id=%" PRIu64 ", cursor=%zu"
			      ", part_size=%zu, remaining_bytes=%zu",
			      parsed_header_id,
			      cursor,
			      ump.sz,
			      ump.sz - cursor);
			assert(parsed_header_id <= UCHAR_MAX);
			const struct string_view blob = {
				.data = ump.data + cursor,
				.sz = ump.sz - cursor,
			};
			check(ump_parse_media_blob(p, parsed_header_id, &blob));
		}
		break;
	case 35: /* NEXT_REQUEST_POLICY */
		*skip_media_blobs_until_next = false;
		assert(sizeof(uint8_t) == sizeof(ump.data[0]));
		next_request_policy =
			video_streaming__next_request_policy__unpack(
				NULL,
				ump.sz,
				(const uint8_t *)ump.data);
		assert(next_request_policy); // TODO: error out on misparse
		ump_parse_cookie(next_request_policy, &p->context);
		break;
	case 42: /* FORMAT_INITIALIZATION_METADATA */
		*skip_media_blobs_until_next = false;
		assert(sizeof(uint8_t) == sizeof(ump.data[0]));
		fmt = video_streaming__format_initialization_metadata__unpack(
			NULL,
			ump.sz,
			(const uint8_t *)ump.data);
		assert(fmt); // TODO: error out on misparse
		debug_protobuf_fmt_init(fmt);
		break;
	case 43: /* SABR_REDIRECT */
		*skip_media_blobs_until_next = false;
		assert(sizeof(uint8_t) == sizeof(ump.data[0]));
		redirect = video_streaming__sabr_redirect__unpack(
			NULL,
			ump.sz,
			(const uint8_t *)ump.data);
		assert(redirect); // TODO: error on !redirect || !redirect->url
		debug("Got redirect to new SABR url: %s", redirect->url);
		free(*target_url);
		*target_url = strdup(redirect->url);
		break;
	default:
		*skip_media_blobs_until_next = false;
		break;
	}

	return RESULT_OK;
}

static result_t
ump_parse(struct protocol_state *p,
          const struct string_view *ump,
          char **target_url)
{
	debug("Got UMP response of sz=%zu", ump->sz);

	// TODO: mutate ump->{data,sz} directly, drop separate cursor value
	// for above TODO, make a deep-copy of ump struct here or in caller
	size_t cursor = 0;
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

		const struct string_view part = {
			.data = ump->data + cursor,
			.sz = part_size,
		};
		check(ump_parse_part(p,
		                     part,
		                     target_url,
		                     part_type,
		                     &skip_media_blobs_until_next_section));

		cursor += part_size;
	}

	return RESULT_OK;
}

result_t
protocol_parse_response(struct protocol_state *p,
                        const struct string_view *response,
                        char **target_url)
{
	check(ump_parse(p, response, target_url));
	protocol_update_members(p);
	return RESULT_OK;
}

#undef ITAG_AUDIO
#undef ITAG_VIDEO
