#include "protocol/state.h"

#include "protocol/stream.h"
#include "sys/array.h"
#include "sys/debug.h"
#include "video_streaming/video_playback_abr_request.pb-c.h"

#if defined(__OpenBSD__)
#include <netinet/in.h> /* for resolv.h dependencies under OpenBSD */
#endif
#include <protobuf-c/protobuf-c.h>
#include <resolv.h> /* for b64_pton() */
#include <stdlib.h>
#include <sys/param.h> /* for MIN() */

#define ITAG_AUDIO 251

static void
str_free(char **strp)
{
	free(*strp);
}

static void
protocol_cleanup_p(struct protocol_state **pp)
{
	protocol_cleanup(*pp);
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

struct VideoStreaming__VideoPlaybackAbrRequest *
protocol_get_request(struct protocol_state *p)
{
	return &p->req;
}

void
protocol_update_state(struct protocol_state *p)
{
	p->req.n_selected_format_ids = ARRAY_SIZE(p->selected_format_ids);
	p->req.selected_format_ids = p->selected_format_ids;
	p->req.n_buffered_ranges = ARRAY_SIZE(p->buffered_ranges);
	p->req.buffered_ranges = p->buffered_ranges;

	p->abr_state.has_player_time_ms = true;
	p->abr_state.player_time_ms = MIN(p->buffered_audio_range.duration_ms,
	                                  p->buffered_video_range.duration_ms);
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

static WARN_UNUSED size_t
get_index_of(const struct protocol_state *p, unsigned char header_id)
{
	return p->header_map[header_id].itag == ITAG_AUDIO ? 0 : 1;
}

void
set_header_media_type(struct protocol_state *p,
                      unsigned char header_id,
                      int itag)
{
	p->header_map[header_id].itag = itag;
	debug("Map header_id=%u to itag=%d", header_id, itag);
}

int64_t
get_sequence_number_cursor(const struct protocol_state *p,
                           unsigned char header_id)
{
	VideoStreaming__BufferedRange *br =
		p->buffered_ranges[get_index_of(p, header_id)];
	return br->end_segment_index - 1;
}

void
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

bool
is_sequence_number_repeated(const struct protocol_state *p,
                            unsigned char header_id)
{
	return p->header_map[header_id].got_repeated;
}

void
update_sequence_number_repeated_check(struct protocol_state *p,
                                      unsigned char header_id,
                                      int64_t candidate)
{
	const int64_t cur = get_sequence_number_cursor(p, header_id);
	p->header_map[header_id].got_repeated = (candidate <= cur);
}

void
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

void
set_ends_at(struct protocol_state *p, int itag, int64_t value)
{
	p->ends_at[itag == ITAG_AUDIO ? 0 : 1] = value;
	debug("Updated ends_at=%" PRIi64 " for itag=%d", value, itag);
}

bool
is_header_written(const struct protocol_state *p, unsigned char header_id)
{
	return p->header_written[get_index_of(p, header_id)];
}

void
set_header_written(struct protocol_state *p, unsigned char header_id)
{
	p->header_written[get_index_of(p, header_id)] = true;
}

int
get_fd_for_header(const struct protocol_state *p, unsigned char header_id)
{
	return p->outputs[get_index_of(p, header_id)];
}

void
claim_playback_cookie(struct protocol_state *p,
                      uint8_t *data, /* claim ownership */
                      size_t sz)
{
	assert(data != NULL);

	if (p->context.has_playback_cookie && p->context.playback_cookie.data) {
		free(p->context.playback_cookie.data);
		p->context.playback_cookie.len = 0;
		p->context.playback_cookie.data = NULL;
	}

	p->context.has_playback_cookie = true;
	p->context.playback_cookie.len = sz;
	p->context.playback_cookie.data = data;

	debug("Updated playback cookie of size=%zu", sz);
}

/*
 * Note, this implementation of SABR_CONTEXT_UPDATE lacks support for:
 *
 * - multiple SabrContextUpdate values of different types
 * - write_policy == KEEP_EXISTING
 * - unsent SABR context updates, i.e. p->context.field6
 */
void
claim_sabr_context(struct protocol_state *p,
                   int32_t sabr_context_update_type,
                   uint8_t *data, /* claim ownership */
                   size_t sz)
{
	p->sabr_context.has_type = true;
	p->sabr_context.type = sabr_context_update_type;
	p->sabr_context.has_value = true;
	p->sabr_context.value.data = data;
	p->sabr_context.value.len = sz;
	p->context.n_field5 = 1;
	p->context.field5 = p->all_sabr_contexts;
}

#undef ITAG_AUDIO
