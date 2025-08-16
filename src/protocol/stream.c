#include "protocol/stream.h"

#include "protocol/debug.h"
#include "protocol/state.h"
#include "protocol/varint.h"
#include "sys/debug.h"
#include "sys/write.h"

#include <stdlib.h>
#include <sys/param.h> /* for MAX() */

/*
 * Some helpful references on YouTube's UMP format and SABR protobufs:
 *
 * https://github.com/gsuberland/UMP_Format/blob/main/UMP_Format.md
 * https://github.com/LuanRT/googlevideo/blob/HEAD/src/core/UmpReader.ts
 * https://github.com/LuanRT/googlevideo/blob/main/src/core/SabrUmpProcessor.ts
 *
 * https://github.com/LuanRT/googlevideo/tree/main/protos/video_streaming
 * https://github.com/LuanRT/googlevideo/blob/main/protos/misc/common.proto
 *
 * https://github.com/LuanRT/googlevideo/blob/main/examples/downloader/main.ts
 * https://github.com/LuanRT/googlevideo/blob/main/examples/README.md
 */
#include "video_streaming/format_initialization_metadata.pb-c.h"
#include "video_streaming/media_header.pb-c.h"
#include "video_streaming/next_request_policy.pb-c.h"
#include "video_streaming/sabr_context_update.pb-c.h"
#include "video_streaming/sabr_redirect.pb-c.h"

result_t
protocol_next_request(struct protocol_state *p, char **buf, size_t *sz)
{
	*sz = protocol_request_packed_size(p);
	*buf = malloc(*sz * sizeof(**buf));
	check_if(*buf == NULL, ERR_PROTOCOL_SABR_POST_BODY_ALLOC);
	protocol_request_pack(p, (uint8_t *)*buf);
	debug_hexdump_buffer(*buf, *sz);
	return RESULT_OK;
}

static void
ump_parse_media_header(struct protocol_state *p,
                       const VideoStreaming__MediaHeader *header,
                       bool *skip_media_blobs_until_next)
{
	protocol_update_header_map(p, header->header_id, header->itag);

	if (header->has_is_init_seg && header->is_init_seg) {
		if (protocol_is_header_written(p, header->header_id)) {
			debug("Skipping repeated init seg for itag=%d",
			      header->itag);
			*skip_media_blobs_until_next = true;
			return;
		} else {
			protocol_set_header_written(p, header->header_id);
		}
	}

	if (header->has_sequence_number) {
		protocol_update_repeated_check(p,
		                               header->header_id,
		                               header->sequence_number);
		if (protocol_is_sequence_number_repeated(p,
		                                         header->header_id)) {
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
	      protocol_get_cursor(p, header->header_id));
	if (header->has_sequence_number) {
		protocol_set_cursor(p,
		                    header->header_id,
		                    header->sequence_number);
	}
	if (header->has_duration_ms) {
		protocol_increment_duration(p,
		                            header->header_id,
		                            header->duration_ms);
	}
}

static WARN_UNUSED result_t
ump_parse_media_blob(struct protocol_state *p,
                     const struct string_view *blob,
                     unsigned char header_id)
{
	int fd = protocol_get_fd(p, header_id);
	const ssize_t written = write_with_retry(fd, blob->data, blob->sz);
	check_if(written < 0, ERR_PROTOCOL_MEDIA_BLOB_WRITE, errno);
	debug("Wrote media blob bytes=%zd to fd=%d", written, fd);
	return RESULT_OK;
}

static WARN_UNUSED result_t
ump_parse_cookie(struct protocol_state *p,
                 const VideoStreaming__NextRequestPolicy *next_request_policy)
{
	if (next_request_policy->playback_cookie == NULL) {
		return RESULT_OK;
	}

	const size_t sz = video_streaming__playback_cookie__get_packed_size(
		next_request_policy->playback_cookie);
	uint8_t *packed = malloc(sz * sizeof(*packed));
	check_if(packed == NULL, ERR_PROTOCOL_PLAYBACK_COOKIE_ALLOC);

	video_streaming__playback_cookie__pack(
		next_request_policy->playback_cookie,
		packed);
	protocol_claim_playback_cookie(p, packed, sz);

	return RESULT_OK;
}

static WARN_UNUSED result_t
ump_parse_fmt_init(struct protocol_state *p,
                   const VideoStreaming__FormatInitializationMetadata *fmt)
{
	if (fmt->format_id && fmt->format_id->has_itag &&
	    fmt->has_end_segment_number) {
		protocol_set_ends_at(p,
		                     fmt->format_id->itag,
		                     fmt->end_segment_number);
	}
	return RESULT_OK;
}

static WARN_UNUSED result_t
ump_parse_sabr_context_update(struct protocol_state *p,
                              const VideoStreaming__SabrContextUpdate *update)
{
	if (update->has_type && update->has_value) {
		uint8_t *tmp = malloc(update->value.len);
		check_if(tmp == NULL, ERR_PROTOCOL_SABR_UPDATE_ALLOC);
		memcpy(tmp, update->value.data, update->value.len);
		protocol_claim_sabr_context(p,
		                            update->type,
		                            tmp,
		                            update->value.len);
	}
	return RESULT_OK;
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

static WARN_UNUSED result_t
ump_parse_part(struct protocol_state *p,
               struct string_view ump, /* note: pass by value */
               char **target_url,
               int *retry_after,
               uint64_t part_type,
               bool *skip_media_blobs_until_next)
{
	static_assert(sizeof(uint8_t) == sizeof(ump.data[0]),
	              "unpack argument does not safely cast to uint8_t array");

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
		    protocol_is_sequence_number_repeated(p, parsed_header_id)) {
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
		pol = video_streaming__next_request_policy__unpack(
			NULL,
			ump.sz,
			(const uint8_t *)ump.data);
		check_if(pol == NULL, ERR_PROTOCOL_UNPACK_NEXT_REQUEST_POLICY);
		check(ump_parse_cookie(p, pol));
		if (pol->has_backoff_time_ms) {
			debug("Got backoff_time_ms=%" PRIi32,
			      pol->backoff_time_ms);
			*retry_after = MAX(pol->backoff_time_ms / 1000, 1);
		}
		break;
	case 42: /* FORMAT_INITIALIZATION_METADATA */
		*skip_media_blobs_until_next = false;
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
	protocol_update_state(p);
	return RESULT_OK;
}
