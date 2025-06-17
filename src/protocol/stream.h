#ifndef PROTOCOL_STREAM_H
#define PROTOCOL_STREAM_H

#include "protocol/state.h"
#include "result.h"
#include "sys/compiler_features.h"
#include "sys/string_view.h"

result_t protocol_next_request(struct protocol_state *stream,
                               char **request,
                               size_t *size) WARN_UNUSED;
result_t protocol_parse_response(struct protocol_state *stream,
                                 const struct string_view *response,
                                 char **target_url,
                                 int *retry_after) WARN_UNUSED;

#endif
