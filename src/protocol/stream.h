#ifndef PROTOCOL_STREAM_H
#define PROTOCOL_STREAM_H

#include "result.h"
#include "sys/compiler_features.h"
#include "sys/string_view.h"

#include <inttypes.h>

typedef struct protocol_state *protocol;

result_t protocol_init(const struct string_view *proof_of_origin,
                       const struct string_view *playback_config,
                       int outputs[2],
                       protocol *out) WARN_UNUSED;
void protocol_cleanup(protocol stream);

result_t protocol_next_request(protocol stream,
                               char **request,
                               size_t *size) WARN_UNUSED;
result_t protocol_parse_response(protocol stream,
                                 const struct string_view *response,
                                 char **target_url) WARN_UNUSED;
int32_t protocol_ends_at(protocol stream) WARN_UNUSED;

/*
 * Expose a pure functional subset of parsing logic for UMP format.
 */
result_t ump_varint_read(const struct string_view *ump,
                         size_t *pos,
                         uint64_t *value) WARN_UNUSED;

#endif
