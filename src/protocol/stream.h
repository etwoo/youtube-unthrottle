#ifndef PROTOCOL_STREAM_H
#define PROTOCOL_STREAM_H

#include "result.h"
#include "sys/compiler_features.h"
#include "sys/string_view.h"

typedef struct protocol_state *protocol;

protocol protocol_init(const char *proof_of_origin,
                       const struct string_view *playback_config,
                       int outputs[2]) WARN_UNUSED;
void protocol_cleanup(protocol stream);

result_t protocol_next_request(protocol stream,
                               char **request,
                               size_t *size) WARN_UNUSED;
result_t protocol_parse_response(protocol stream,
                                 const struct string_view *response,
                                 char **target_url) WARN_UNUSED;

#endif
