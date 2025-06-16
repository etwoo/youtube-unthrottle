#include "protocol/stream.h"

#include "sys/array.h"
#include "sys/debug.h"
#include "sys/write.h"

#if defined(__OpenBSD__)
#include <netinet/in.h> /* for resolv.h dependencies under OpenBSD */
#endif
#include <resolv.h> /* for b64_pton() */
#include <stdbool.h>
#include <stdlib.h>
#include <sys/param.h> /* for MIN() and MAX() */

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
#include "video_streaming/sabr_context_update.pb-c.h"
#include "video_streaming/sabr_redirect.pb-c.h"
#include "video_streaming/video_playback_abr_request.pb-c.h"

#define ITAG_AUDIO 251

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
sabr_context_update_free(VideoStreaming__SabrContextUpdate **update)
{
	video_streaming__sabr_context_update__free_unpacked(*update, NULL);
}

static void
protocol_cleanup_p(protocol *pp)
{
	protocol_cleanup(*pp);
}

static WARN_UNUSED unsigned char
get_byte(const char *buffer, size_t sz, size_t pos)
{
	return pos < sz ? buffer[pos] : 0;
}

static void
debug_hexdump_buffer(const char *buf, size_t sz)
{
	debug("Sending protobuf blob of sz=%zu", sz);
	for (size_t i = 0; i < sz; i += 16) {
		debug("%02X %02X %02X %02X %02X %02X %02X %02X "
		      "%02X %02X %02X %02X %02X %02X %02X %02X",
		      get_byte(buf, sz, i),
		      get_byte(buf, sz, i + 1),
		      get_byte(buf, sz, i + 2),
		      get_byte(buf, sz, i + 3),
		      get_byte(buf, sz, i + 4),
		      get_byte(buf, sz, i + 5),
		      get_byte(buf, sz, i + 6),
		      get_byte(buf, sz, i + 7),
		      get_byte(buf, sz, i + 8),
		      get_byte(buf, sz, i + 9),
		      get_byte(buf, sz, i + 10),
		      get_byte(buf, sz, i + 11),
		      get_byte(buf, sz, i + 12),
		      get_byte(buf, sz, i + 13),
		      get_byte(buf, sz, i + 14),
		      get_byte(buf, sz, i + 15));
	}
}

static void
debug_protobuf_media_header(const VideoStreaming__MediaHeader *header)
{
	debug("Got header header_id=%" PRIu32 ", video=%s, itag=%d, xtags=%s"
	      ", start_range=%" PRIi64 ", is_init_seg=%d"
	      ", seq=%" PRIi64 ", start_ms=%" PRIi64 ", duration_ms=%" PRIi64
	      ", content_length=%" PRIi64 ", time_range.start=%" PRIi64
	      ", time_range.duration=%" PRIi64
	      ", time_range.timescale=%" PRIi32,
	      header->header_id,
	      header->video_id,
	      header->has_itag ? header->itag : -1,
	      header->xtags,
	      header->has_start_range ? header->start_range : -1,
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
	      ", duration_ms=%d"
	      ", end_time_ms=%d"
	      ", end_segment_number=%" PRIi64 ", init_start=%d"
	      ", init_end=%d"
	      ", index_start=%d"
	      ", index_end=%d",
	      fmt->video_id ? fmt->video_id : "none",
	      (fmt->format_id && fmt->format_id->has_itag)
	              ? fmt->format_id->itag
	              : -1,
	      (fmt->has_duration_ms ? fmt->duration_ms : -1),
	      (fmt->has_end_time_ms ? fmt->end_time_ms : -1),
	      (fmt->has_end_segment_number ? fmt->end_segment_number : -1),
	      (fmt->init_range && fmt->init_range->has_start
	               ? fmt->init_range->start
	               : -1),
	      (fmt->init_range && fmt->init_range->has_end
	               ? fmt->init_range->end
	               : -1),
	      (fmt->index_range && fmt->index_range->has_start
	               ? fmt->index_range->start
	               : -1),
	      (fmt->index_range && fmt->index_range->has_end
	               ? fmt->index_range->end
	               : -1));
}

static void
debug_protobuf_sabr_context_update(const VideoStreaming__SabrContextUpdate *u)
{
	debug("Got SABR context update type=%" PRIi32
	      ", scope=%u, value_sz=%zu, write_policy=%u",
	      u->has_type ? u->type : -1,
	      u->has_scope ? u->scope : UINT_MAX,
	      u->has_value ? u->value.len : 0,
	      u->has_write_policy ? u->write_policy : UINT_MAX);
}

struct protocol_state {
	struct {
		int itag;
		bool got_repeated;
	} header_map[UCHAR_MAX + 1]; /* map header_id number to itag, etc.  */
	int64_t ends_at[2];          /* audio/video ending sequence numbers */
	bool header_written[2];      /* audio/video file headers written?   */
	int outputs[2];              /* audio/video output file descriptors */
	VideoStreaming__ClientAbrState abr_state;
	VideoStreaming__StreamerContext__ClientInfo info;
	VideoStreaming__StreamerContext__Fqa sabr_context;
	VideoStreaming__StreamerContext__Fqa *all_sabr_contexts[1];
	VideoStreaming__StreamerContext context;
	Misc__FormatId selected_audio_format;
	Misc__FormatId selected_video_format;
	Misc__FormatId *selected_format_ids[2];
	VideoStreaming__BufferedRange buffered_audio_range;
	VideoStreaming__BufferedRange buffered_video_range;
	VideoStreaming__BufferedRange *buffered_ranges[2];
	VideoStreaming__VideoPlaybackAbrRequest req;
};

static void
protocol_init_members(struct protocol_state *p, long long int itag_video)
{
	video_streaming__client_abr_state__init(&p->abr_state);
	p->abr_state.has_last_manual_selected_resolution = true;
	p->abr_state.last_manual_selected_resolution = 1080;
	p->abr_state.has_sticky_resolution = true;
	p->abr_state.sticky_resolution = 1080;

	video_streaming__streamer_context__client_info__init(&p->info);
	p->info.has_client_name = true;
	p->info.client_name = 1;
	p->info.client_version = "2.20240726.00.00";
	p->info.os_name = "Windows";
	p->info.os_version = "10.0";

	video_streaming__streamer_context__fqa__init(&p->sabr_context);
	p->all_sabr_contexts[0] = &p->sabr_context;

	video_streaming__streamer_context__init(&p->context);
	p->context.client_info = &p->info;

	misc__format_id__init(&p->selected_audio_format);
	p->selected_audio_format.has_itag = true;
	p->selected_audio_format.itag = ITAG_AUDIO;

	misc__format_id__init(&p->selected_video_format);
	p->selected_video_format.has_itag = true;
	assert(itag_video < INT32_MAX);
	p->selected_video_format.itag = (int32_t)itag_video;

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
	p->abr_state.player_time_ms = MIN(p->buffered_audio_range.duration_ms,
	                                  p->buffered_video_range.duration_ms);
}

static WARN_UNUSED size_t
get_index_of(const struct protocol_state *p, unsigned char header_id)
{
	return p->header_map[header_id].itag == ITAG_AUDIO ? 0 : 1;
}

static WARN_UNUSED int64_t
get_sequence_number_cursor(const struct protocol_state *p,
                           unsigned char header_id)
{
	VideoStreaming__BufferedRange *br =
		p->buffered_ranges[get_index_of(p, header_id)];
	return br->end_segment_index - 1;
}

static void
set_header_sequence_number(struct protocol_state *p,
                           unsigned char header_id,
                           int64_t n)
{
	VideoStreaming__BufferedRange *br =
		p->buffered_ranges[get_index_of(p, header_id)];
	assert(sizeof(int32_t) == sizeof(br->end_segment_index));
	br->end_segment_index = MIN(INT32_MAX, n + 1); /* truncate to int32_t */
	debug("Map header_id=%u to seq=%" PRIi64, header_id, n);
}

static void
increment_header_duration(struct protocol_state *p,
                          unsigned char header_id,
                          int64_t duration)
{
	VideoStreaming__BufferedRange *br =
		p->buffered_ranges[get_index_of(p, header_id)];
	br->duration_ms += duration;
	debug("Increase header_id=%u duration by %" PRIi64 " to %" PRIi64,
	      header_id,
	      duration,
	      br->duration_ms);
}

static void
set_header_media_type(struct protocol_state *p,
                      unsigned char header_id,
                      int itag)
{
	p->header_map[header_id].itag = itag;
	debug("Map header_id=%u to itag=%d", header_id, itag);
}

static WARN_UNUSED bool
is_sequence_number_repeated(const struct protocol_state *p,
                            unsigned char header_id)
{
	return p->header_map[header_id].got_repeated;
}

static void
update_sequence_number_repeated_check(struct protocol_state *p,
                                      unsigned char header_id,
                                      int64_t candidate)
{
	const int64_t cur = get_sequence_number_cursor(p, header_id);
	p->header_map[header_id].got_repeated = (candidate <= cur);
}

static WARN_UNUSED bool
is_header_written(const struct protocol_state *p, unsigned char header_id)
{
	return p->header_written[get_index_of(p, header_id)];
}

static void
set_header_written(struct protocol_state *p, unsigned char header_id)
{
	p->header_written[get_index_of(p, header_id)] = true;
}

static WARN_UNUSED int
get_fd_for_header(const struct protocol_state *p, unsigned char header_id)
{
	return p->outputs[get_index_of(p, header_id)];
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
		default:
			break;
		}
	}
}

static WARN_UNUSED result_t
base64_decode(const struct string_view *in, struct ProtobufCBinaryData *out)
{
	/*
	 * clang-tidy does not seem to understand __attribute__((cleanup))
	 * on <scratch_buffer>. As a workaround, suppress false positives of
	 * clang-analyzer-unix.Malloc with NOLINTBEGIN/NOLINTEND.
	 */

	// NOLINTBEGIN(clang-analyzer-unix.Malloc)

	char *scratch_buffer __attribute__((cleanup(str_free))) =
		strndup(in->data, in->sz);
	check_if(scratch_buffer == NULL, ERR_PROTOCOL_STATE_ALLOC);

	base64url_to_standard_base64(scratch_buffer);
	int rc = b64_pton(scratch_buffer, NULL, 0);
	if (rc < 0) {
		return make_result(ERR_PROTOCOL_STATE_BASE64_DECODE);
	}
	out->len = rc;

	// NOLINTEND(clang-analyzer-unix.Malloc)

	out->data = malloc(out->len);
	check_if(out->data == NULL, ERR_PROTOCOL_STATE_ALLOC);

	const size_t decode_len = out->len + 1; /* extra +1 needed on Linux */
	rc = b64_pton(scratch_buffer, out->data, decode_len);
	check_if(rc < 0, ERR_PROTOCOL_STATE_BASE64_DECODE);

	return RESULT_OK;
}

result_t
protocol_init(const struct string_view *proof_of_origin,
              const struct string_view *playback_config,
              long long int itag_video,
              int outputs[2],
              struct protocol_state **out)
{
	struct protocol_state *p __attribute__((cleanup(protocol_cleanup_p))) =
		malloc(sizeof(*p));
	check_if(p == NULL, ERR_PROTOCOL_STATE_ALLOC);

	memset(p, 0, sizeof(*p)); /* zero early, just in case */

	p->outputs[0] = outputs[0];
	p->outputs[1] = outputs[1];

	protocol_init_members(p, itag_video);

	check(base64_decode(proof_of_origin, &p->context.po_token));
	p->context.has_po_token = true;

	check(base64_decode(playback_config,
	                    &p->req.video_playback_ustreamer_config));
	p->req.has_video_playback_ustreamer_config = true;

	*out = p;
	p = NULL; /* skip automatic cleanup */
	return RESULT_OK;
}

void
protocol_cleanup(struct protocol_state *p)
{
	if (p) {
		free(p->context.po_token.data);
		free(p->context.playback_cookie.data);
		free(p->sabr_context.value.data);
		free(p->req.video_playback_ustreamer_config.data);
		free(p);
	}
}

bool
protocol_knows_end(struct protocol_state *p)
{
	debug("knows_end() if %" PRIi64 " > 0 && %" PRIi64 " > 0",
	      p->ends_at[0],
	      p->ends_at[1]);
	return p->ends_at[0] > 0 && p->ends_at[1] > 0;
}

bool
protocol_done(struct protocol_state *p)
{
	debug("done() if %" PRIi32 " > %" PRIi64 " && %" PRIi32 " > %" PRIi64,
	      p->buffered_ranges[0]->end_segment_index,
	      p->ends_at[0],
	      p->buffered_ranges[1]->end_segment_index,
	      p->ends_at[1]);
	return p->buffered_ranges[0]->end_segment_index > p->ends_at[0] &&
	       p->buffered_ranges[1]->end_segment_index > p->ends_at[1];
}

static void
set_ends_at(struct protocol_state *p, int itag, int64_t value)
{
	p->ends_at[itag == ITAG_AUDIO ? 0 : 1] = value;
	debug("Updated ends_at=%" PRIi64 " for itag=%d", value, itag);
}

result_t
protocol_next_request(struct protocol_state *p, char **buf, size_t *sz)
{
	VideoStreaming__VideoPlaybackAbrRequest *r = &p->req;
	*sz = video_streaming__video_playback_abr_request__get_packed_size(r);
	*buf = malloc(*sz * sizeof(**buf));
	check_if(*buf == NULL, ERR_PROTOCOL_SABR_POST_BODY_ALLOC);
	video_streaming__video_playback_abr_request__pack(r, (uint8_t *)*buf);
	debug_hexdump_buffer(*buf, *sz);
	return RESULT_OK;
}

static const unsigned char CHAR_BIT_0 = 0x80; /* bit pattern: 10000000 */
static const unsigned char CHAR_BIT_1 = 0x40; /* bit pattern: 01000000 */
static const unsigned char CHAR_BIT_2 = 0x20; /* bit pattern: 00100000 */
static const unsigned char CHAR_BIT_3 = 0x10; /* bit pattern: 00010000 */
static const unsigned char CHAR_BIT_4 = 0x08; /* bit pattern: 00001000 */

typedef enum {
	VARINT_BYTES_ONE = 1,
	VARINT_BYTES_TWO,
	VARINT_BYTES_THREE,
	VARINT_BYTES_FOUR,
	VARINT_BYTES_FIVE,
} ump_varint_bytes;

static void
ump_read_vle(unsigned char first_byte,
             ump_varint_bytes *bytes_to_read,
             unsigned char *first_byte_mask)
{
	*bytes_to_read = VARINT_BYTES_ONE;
	*first_byte_mask = 0xFF; /* bit pattern: 11111111 */
	if (0 == (first_byte & CHAR_BIT_0)) {
		return;
	}

	*bytes_to_read = VARINT_BYTES_TWO;
	*first_byte_mask ^= CHAR_BIT_0;
	*first_byte_mask ^= CHAR_BIT_1;

	if (0 == (first_byte & CHAR_BIT_1)) {
		return;
	}

	*bytes_to_read = VARINT_BYTES_THREE;
	*first_byte_mask ^= CHAR_BIT_2;

	if (0 == (first_byte & CHAR_BIT_2)) {
		return;
	}

	*bytes_to_read = VARINT_BYTES_FOUR;
	*first_byte_mask ^= CHAR_BIT_3;

	if (0 == (first_byte & CHAR_BIT_3)) {
		return;
	}

	*bytes_to_read = VARINT_BYTES_FIVE;
	*first_byte_mask ^= CHAR_BIT_4;
}

result_t
ump_varint_read(const struct string_view *ump, size_t *pos, uint64_t *value)
{
	if (*pos >= ump->sz) {
		return make_result(ERR_PROTOCOL_VARINT_READ_PRE, (int)*pos);
	}

	ump_varint_bytes bytes_to_read = VARINT_BYTES_ONE;
	unsigned char first_byte_mask = 0xFF;
	ump_read_vle(ump->data[*pos], &bytes_to_read, &first_byte_mask);

	debug("Got first_byte=%hhu, bytes_to_read=%u, first_byte_mask=%02X",
	      ump->data[*pos],
	      bytes_to_read,
	      first_byte_mask);

	if (*pos > SIZE_MAX - bytes_to_read || /* 1) avoid overflow         */
	    bytes_to_read > ump->sz ||         /* 2) avoid underflow in (3) */
	    *pos > ump->sz - bytes_to_read) {  /* 3) avoid OOB read         */
		return make_result(ERR_PROTOCOL_VARINT_READ_OUT_OF_BOUNDS,
		                   (int)bytes_to_read);
	}

	uint64_t parsed[5] = {0};
	switch (bytes_to_read) {
	case VARINT_BYTES_FIVE:
		parsed[4] = ((uint32_t)ump->data[*pos + 4] << 24) +
		            ((unsigned char)ump->data[*pos + 3] << 16) +
		            ((unsigned char)ump->data[*pos + 2] << 8) +
		            (unsigned char)ump->data[*pos + 1];
		break;
	case VARINT_BYTES_FOUR:
		parsed[3] = (unsigned char)ump->data[*pos + 3]
		            << (16 + (8 - bytes_to_read));
		__attribute__((fallthrough));
	case VARINT_BYTES_THREE:
		parsed[2] = (unsigned char)ump->data[*pos + 2]
		            << (8 + (8 - bytes_to_read));
		__attribute__((fallthrough));
	case VARINT_BYTES_TWO:
		parsed[1] = (unsigned char)ump->data[*pos + 1]
		            << (8 - bytes_to_read);
		__attribute__((fallthrough));
	case VARINT_BYTES_ONE:
		parsed[0] = ump->data[*pos] & first_byte_mask;
		break;
	}
	*pos += bytes_to_read;

	/*
	 * Note: this postcondition assumes a buffer never ends with a dangling
	 * (so to speak) varint, i.e. that a varint always describes the type
	 * or size of an upcoming payload.
	 */
	if (*pos >= ump->sz) {
		return make_result(ERR_PROTOCOL_VARINT_READ_POST, (int)*pos);
	}

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

	if (header->has_is_init_seg && header->is_init_seg) {
		if (is_header_written(p, header->header_id)) {
			debug("Skipping repeated init seg for itag=%d",
			      header->itag);
			*skip_media_blobs_until_next = true;
			return;
		} else {
			set_header_written(p, header->header_id);
		}
	}

	if (header->has_sequence_number) {
		update_sequence_number_repeated_check(p,
		                                      header->header_id,
		                                      header->sequence_number);
		if (is_sequence_number_repeated(p, header->header_id)) {
			debug("Skipping repeated seq=%" PRIi64
			      " for itag=%d, header_id=%" PRIu32,
			      header->sequence_number,
			      header->itag,
			      header->header_id);
			return;
		}
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
                     const struct string_view *blob,
                     unsigned char header_id)
{
	int fd = get_fd_for_header(p, header_id);
	const ssize_t written = write_with_retry(fd, blob->data, blob->sz);
	check_if(written < 0, ERR_PROTOCOL_MEDIA_BLOB_WRITE, errno);
	debug("Wrote media blob bytes=%zd to fd=%d", written, fd);
	return RESULT_OK;
}

static WARN_UNUSED result_t
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
	check_if(context->playback_cookie.data == NULL,
	         ERR_PROTOCOL_PLAYBACK_COOKIE_ALLOC);

	context->playback_cookie.len = cookie_packed_sz;
	context->has_playback_cookie = true;
	video_streaming__playback_cookie__pack(
		next_request_policy->playback_cookie,
		context->playback_cookie.data);

	debug("Updated playback cookie of size=%zu", cookie_packed_sz);
	return RESULT_OK;
}

static WARN_UNUSED result_t
ump_parse_fmt_init(struct protocol_state *p,
                   const VideoStreaming__FormatInitializationMetadata *fmt)
{
	if (fmt->format_id && fmt->format_id->has_itag &&
	    fmt->has_end_segment_number) {
		set_ends_at(p, fmt->format_id->itag, fmt->end_segment_number);
	}
	return RESULT_OK;
}

static WARN_UNUSED result_t
copy_sabr_context_update(const struct ProtobufCBinaryData *src,
                         struct ProtobufCBinaryData *dst)
{
	dst->len = src->len;
	dst->data = malloc(dst->len);
	check_if(dst->data == NULL, ERR_PROTOCOL_SABR_UPDATE_ALLOC);

	memcpy(dst->data, src->data, dst->len);
	return RESULT_OK;
}

static WARN_UNUSED result_t
ump_parse_sabr_context_update(struct protocol_state *p,
                              const VideoStreaming__SabrContextUpdate *update)
{
	if (update->has_type && update->has_value && update->has_write_policy) {
		p->sabr_context.has_type = true;
		p->sabr_context.type = update->type;
		// TODO: switch (update->write_policy)
		p->sabr_context.has_value = true;
		check(copy_sabr_context_update(&update->value,
		                               &p->sabr_context.value));
		p->context.n_field5 = 1;
		p->context.field5 = p->all_sabr_contexts;
	}
	return RESULT_OK;
}

static WARN_UNUSED result_t
ump_parse_part(struct protocol_state *p,
               struct string_view ump, /* note: pass by value */
               char **target_url,
               int *retry_after,
               uint64_t part_type,
               bool *skip_media_blobs_until_next)
{
	VideoStreaming__NextRequestPolicy *pol
		__attribute__((cleanup(ump_request_policy_free))) = NULL;
	VideoStreaming__MediaHeader *header
		__attribute__((cleanup(ump_header_free))) = NULL;
	VideoStreaming__FormatInitializationMetadata *fmt
		__attribute__((cleanup(ump_formats_free))) = NULL;
	VideoStreaming__SabrRedirect *redir
		__attribute__((cleanup(sabr_redirect_free))) = NULL;
	VideoStreaming__SabrContextUpdate *update
		__attribute__((cleanup(sabr_context_update_free))) = NULL;

	switch (part_type) {
	case 20: /* MEDIA_HEADER */
		*skip_media_blobs_until_next = false;
		assert(sizeof(uint8_t) == sizeof(ump.data[0]));
		header = video_streaming__media_header__unpack(
			NULL,
			ump.sz,
			(const uint8_t *)ump.data);
		check_if(header == NULL, ERR_PROTOCOL_UNPACK_MEDIA_HEADER);
		debug_protobuf_media_header(header);
		check_if(header->header_id > UCHAR_MAX,
		         ERR_PROTOCOL_HEADER_ID_OVERFLOW,
		         (int)header->header_id);
		ump_parse_media_header(p, header, skip_media_blobs_until_next);
		break;
	case 21: /* MEDIA */ {
		size_t cursor = 0;
		uint64_t parsed_header_id = 0;
		check(ump_varint_read(&ump, &cursor, &parsed_header_id));
		check_if(parsed_header_id > UCHAR_MAX,
		         ERR_PROTOCOL_HEADER_ID_OVERFLOW,
		         (int)parsed_header_id);
		if (*skip_media_blobs_until_next ||
		    is_sequence_number_repeated(p, parsed_header_id)) {
			debug("Skipping media blob with header_id=%" PRIu64,
			      parsed_header_id);
		} else {
			debug("Got media blob header_id=%" PRIu64 ", cursor=%zu"
			      ", part_size=%zu, remaining_bytes=%zu",
			      parsed_header_id,
			      cursor,
			      ump.sz,
			      ump.sz - cursor);
			const struct string_view blob = {
				.data = ump.data + cursor,
				.sz = ump.sz - cursor,
			};
			check(ump_parse_media_blob(p, &blob, parsed_header_id));
		}
		break;
	};
	case 35: /* NEXT_REQUEST_POLICY */
		*skip_media_blobs_until_next = false;
		assert(sizeof(uint8_t) == sizeof(ump.data[0]));
		pol = video_streaming__next_request_policy__unpack(
			NULL,
			ump.sz,
			(const uint8_t *)ump.data);
		check_if(pol == NULL, ERR_PROTOCOL_UNPACK_NEXT_REQUEST_POLICY);
		check(ump_parse_cookie(pol, &p->context));
		if (pol->has_backoff_time_ms) {
			debug("Got backoff_time_ms=%" PRIi32,
			      pol->backoff_time_ms);
			*retry_after = MAX(pol->backoff_time_ms / 1000, 1);
		}
		break;
	case 42: /* FORMAT_INITIALIZATION_METADATA */
		*skip_media_blobs_until_next = false;
		assert(sizeof(uint8_t) == sizeof(ump.data[0]));
		fmt = video_streaming__format_initialization_metadata__unpack(
			NULL,
			ump.sz,
			(const uint8_t *)ump.data);
		check_if(fmt == NULL, ERR_PROTOCOL_UNPACK_FORMAT_INIT);
		debug_protobuf_fmt_init(fmt);
		check(ump_parse_fmt_init(p, fmt));
		break;
	case 43: /* SABR_REDIRECT */
		*skip_media_blobs_until_next = false;
		assert(sizeof(uint8_t) == sizeof(ump.data[0]));
		redir = video_streaming__sabr_redirect__unpack(
			NULL,
			ump.sz,
			(const uint8_t *)ump.data);
		check_if(redir == NULL, ERR_PROTOCOL_UNPACK_SABR_REDIRECT);
		check_if(redir->url == NULL, ERR_PROTOCOL_UNPACK_SABR_REDIRECT);
		debug("Got redirect to new SABR url: %s", redir->url);
		free(*target_url);
		*target_url = strdup(redir->url);
		break;
	case 57: /* SABR_CONTEXT_UPDATE */
		*skip_media_blobs_until_next = false;
		assert(sizeof(uint8_t) == sizeof(ump.data[0]));
		update = video_streaming__sabr_context_update__unpack(
			NULL,
			ump.sz,
			(const uint8_t *)ump.data);
		check_if(update == NULL, ERR_PROTOCOL_UNPACK_SABR_UPDATE);
		debug_protobuf_sabr_context_update(update);
		check(ump_parse_sabr_context_update(p, update));
		break;
	default:
		*skip_media_blobs_until_next = false;
		break;
	}

	return RESULT_OK;
}

static WARN_UNUSED result_t
ump_parse(struct protocol_state *p,
          const struct string_view *ump,
          char **target_url,
          int *retry_after)
{
	debug("Got UMP response of sz=%zu", ump->sz);

	size_t cursor = 0; /* position within UMP payload */
	bool skip = false; /* whether to skip certain UMP sections */

	while (cursor < ump->sz) {
		uint64_t part_type = 0;
		check(ump_varint_read(ump, &cursor, &part_type));

		uint64_t part_size = 0;
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
		                     retry_after,
		                     part_type,
		                     &skip));

		cursor += part_size;
	}

	return RESULT_OK;
}

result_t
protocol_parse_response(struct protocol_state *p,
                        const struct string_view *response,
                        char **target_url,
                        int *retry_after)
{
	check(ump_parse(p, response, target_url, retry_after));
	protocol_update_members(p);
	return RESULT_OK;
}

#undef ITAG_AUDIO
