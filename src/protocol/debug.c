#include "protocol/debug.h"

#include "sys/compiler_features.h"
#include "sys/debug.h"
#include "video_streaming/format_initialization_metadata.pb-c.h"
#include "video_streaming/media_header.pb-c.h"
#include "video_streaming/sabr_context_update.pb-c.h"

#include <inttypes.h>

static const size_t DEBUG_HEXDUMP_BYTES_CHUNK = 16;

static WARN_UNUSED unsigned char
get_byte(const char *buffer, size_t sz, size_t pos)
{
	return pos < sz ? buffer[pos] : 0;
}

void
dbg_hexdump_buffer(const char *buf, size_t sz)
{
	debug("Sending protobuf blob of sz=%zu", sz);
	for (size_t i = 0; i < sz; i += DEBUG_HEXDUMP_BYTES_CHUNK) {
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

void
dbg_proto_media_header(const VideoStreaming__MediaHeader *header)
{
	debug("Got header header_id=%" PRIu32 ", video=%s, itag=%" PRIi32
	      ", xtags=%s, start_range=%" PRIi64 ", is_init_seg=%d"
	      ", seq=%" PRIi64 ", start_ms=%" PRIi64 ", duration_ms=%" PRIi64
	      ", content_length=%" PRIi64 ", time_range.start=%" PRIi64
	      ", time_range.duration=%" PRIi64
	      ", time_range.timescale=%" PRIi32,
	      header->has_header_id ? header->header_id : 0,
	      header->video_id,
	      header->has_itag ? header->itag : -1,
	      header->xtags,
	      header->has_start_range ? header->start_range : -1,
	      header->has_is_init_seg ? header->is_init_seg : -1,
	      header->has_sequence_number ? header->sequence_number : -1,
	      header->has_start_ms ? header->start_ms : -1,
	      header->has_duration_ms ? header->duration_ms : -1,
	      header->has_content_length ? header->content_length : -1,
	      (header->time_range && header->time_range->has_start_ticks
	               ? header->time_range->start_ticks
	               : -1),
	      (header->time_range && header->time_range->has_duration_ticks
	               ? header->time_range->duration_ticks
	               : -1),
	      (header->time_range && header->time_range->has_timescale
	               ? header->time_range->timescale
	               : -1));
}

void
dbg_proto_fmt_init(const VideoStreaming__FormatInitializationMetadata *f)
{
	debug("Got format video=%s"
	      ", itag=%d"
	      ", duration_ms=%" PRIi64 ", end_time_ms=%" PRIi64
	      ", end_segment_number=%" PRIi64 ", init_start=%d"
	      ", init_end=%d"
	      ", index_start=%d"
	      ", index_end=%d",
	      f->video_id ? f->video_id : "none",
	      (f->format_id && f->format_id->has_itag) ? f->format_id->itag
	                                               : -1,
	      (f->has_duration_units ? f->duration_units : -1),
	      (f->has_end_time_ms ? f->end_time_ms : -1),
	      (f->has_end_segment_number ? f->end_segment_number : -1),
	      (f->init_range && f->init_range->has_start ? f->init_range->start
	                                                 : -1),
	      (f->init_range && f->init_range->has_end ? f->init_range->end
	                                               : -1),
	      (f->index_range && f->index_range->has_start
	               ? f->index_range->start
	               : -1),
	      (f->index_range && f->index_range->has_end ? f->index_range->end
	                                                 : -1));
}

void
dbg_proto_sabr_cxt_update(const VideoStreaming__SabrContextUpdate *u)
{
	debug("Got SABR context update type=%" PRIi32
	      ", scope=%u, value_sz=%zu, write_policy=%u",
	      u->has_type ? u->type : -1,
	      u->has_scope ? u->scope : UINT_MAX,
	      u->has_value ? u->value.len : 0,
	      u->has_write_policy ? u->write_policy : UINT_MAX);
}
