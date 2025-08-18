#ifndef PROTOCOL_DEBUG_H
#define PROTOCOL_DEBUG_H

#include "video_streaming/format_initialization_metadata.pb-c.h"
#include "video_streaming/media_header.pb-c.h"
#include "video_streaming/sabr_context_update.pb-c.h"

#include <stddef.h> /* for size_t */

void dbg_hexdump_buffer(const char *buf, size_t sz);

void dbg_proto_media_header(const VideoStreaming__MediaHeader *h);
void dbg_proto_fmt_init(const VideoStreaming__FormatInitializationMetadata *f);
void dbg_proto_sabr_cxt_update(const VideoStreaming__SabrContextUpdate *u);

#endif
