#ifndef PROTOCOL_STREAM_H
#define PROTOCOL_STREAM_H

#include "result.h"
#include "sys/compiler_features.h"
#include "sys/string_view.h"

#include <stdbool.h>

struct protocol_state;

result_t protocol_init(const struct string_view *proof_of_origin,
                       const struct string_view *playback_config,
                       long long int itag_video,
                       const int outputs[2],
                       struct protocol_state **out) WARN_UNUSED;
void protocol_cleanup(struct protocol_state *p);

bool protocol_knows_end(struct protocol_state *p) WARN_UNUSED;
bool protocol_done(struct protocol_state *p) WARN_UNUSED;

result_t protocol_next_request(struct protocol_state *p,
                               char **buf,
                               size_t *sz) WARN_UNUSED;
result_t protocol_parse_response(struct protocol_state *p,
                                 const struct string_view *response,
                                 char **target_url,
                                 int *retry_after) WARN_UNUSED;

#endif
