#ifndef PROTOCOL_DEBUG_H
#define PROTOCOL_DEBUG_H

#include <stddef.h> /* for size_t */

void debug_hexdump_buffer(const char *buf, size_t sz);

// NOLINTBEGIN(readability-identifier-naming)
typedef struct VideoStreaming__MediaHeader MediaHeader;
typedef struct VideoStreaming__FormatInitializationMetadata
	FormatInitializationMetadata;
typedef struct VideoStreaming__SabrContextUpdate SabrContextUpdate;
// NOLINTEND(readability-identifier-naming)

void debug_protobuf_media_header(const MediaHeader *header);
void debug_protobuf_fmt_init(const FormatInitializationMetadata *fmt);
void debug_protobuf_sabr_context_update(const SabrContextUpdate *u);

#endif
