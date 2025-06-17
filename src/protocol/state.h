#ifndef PROTOCOL_STATE_H
#define PROTOCOL_STATE_H

#include "result.h"
#include "sys/compiler_features.h"
#include "sys/string_view.h"

#include <inttypes.h>
#include <stdbool.h>

struct protocol_state;

result_t protocol_init(const struct string_view *proof_of_origin,
                       const struct string_view *playback_config,
                       long long int itag_video,
                       int outputs[2],
                       struct protocol_state **out) WARN_UNUSED;
void protocol_cleanup(struct protocol_state *p);

typedef struct VideoStreaming__VideoPlaybackAbrRequest VideoPlaybackAbrRequest;
VideoPlaybackAbrRequest *protocol_get_request(struct protocol_state *p);

void protocol_update_state(struct protocol_state *p);

bool protocol_knows_end(struct protocol_state *p) WARN_UNUSED;
bool protocol_done(struct protocol_state *p) WARN_UNUSED;

void set_header_media_type(struct protocol_state *p,
                           unsigned char header_id,
                           int itag);

int64_t get_sequence_number_cursor(const struct protocol_state *p,
                                   unsigned char header_id) WARN_UNUSED;
void set_header_sequence_number(struct protocol_state *p,
                                unsigned char header_id,
                                int64_t n);

bool is_sequence_number_repeated(const struct protocol_state *p,
                                 unsigned char header_id) WARN_UNUSED;
void update_sequence_number_repeated_check(struct protocol_state *p,
                                           unsigned char header_id,
                                           int64_t candidate);

void increment_header_duration(struct protocol_state *p,
                               unsigned char header_id,
                               int64_t duration);

void set_ends_at(struct protocol_state *p, int itag, int64_t value);

bool is_header_written(const struct protocol_state *p,
                       unsigned char header_id) WARN_UNUSED;
void set_header_written(struct protocol_state *p, unsigned char header_id);

int get_fd_for_header(const struct protocol_state *p,
                      unsigned char header_id) WARN_UNUSED;

void claim_playback_cookie(struct protocol_state *p,
                           uint8_t *data, /* claim ownership */
                           size_t sz);
void claim_sabr_context(struct protocol_state *p,
                        int32_t sabr_context_update_type,
                        uint8_t *data, /* claim ownership */
                        size_t sz);

#endif
