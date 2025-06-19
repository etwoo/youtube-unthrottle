#ifndef PROTOCOL_DEBUG_H
#define PROTOCOL_DEBUG_H

#include <stddef.h> /* for size_t */

void debug_hexdump_buffer(const char *buf, size_t sz);

typedef struct VideoStreaming__MediaHeader VideoStreaming__MediaHeader;
void debug_protobuf_media_header(const VideoStreaming__MediaHeader *header);

typedef struct VideoStreaming__FormatInitializationMetadata
	FormatInitializationMetadata;
void debug_protobuf_fmt_init(const FormatInitializationMetadata *fmt);

typedef struct VideoStreaming__SabrContextUpdate SabrContextUpdate;
void debug_protobuf_sabr_context_update(const SabrContextUpdate *u);

#endif
