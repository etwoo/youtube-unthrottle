#ifndef PROTOCOL_STATE_H
#define PROTOCOL_STATE_H

#include "sys/compiler_features.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h> /* for size_t */

struct protocol_state;

void protocol_update_state(struct protocol_state *p);

size_t protocol_request_packed_size(struct protocol_state *p) WARN_UNUSED;
void protocol_request_pack(struct protocol_state *p, uint8_t *buf);

int protocol_get_fd(const struct protocol_state *p,
                    unsigned char header_id) WARN_UNUSED;

void protocol_update_header_map(struct protocol_state *p,
                                unsigned char header_id,
                                int itag);

int64_t protocol_get_cursor(const struct protocol_state *p,
                            unsigned char header_id) WARN_UNUSED;
void protocol_set_cursor(struct protocol_state *p,
                         unsigned char header_id,
                         int64_t n);

bool protocol_is_sequence_number_repeated(const struct protocol_state *p,
                                          unsigned char header_id) WARN_UNUSED;
void protocol_update_repeated_check(struct protocol_state *p,
                                    unsigned char header_id,
                                    int64_t candidate);

void protocol_increment_duration(struct protocol_state *p,
                                 unsigned char header_id,
                                 int64_t duration);

void protocol_set_ends_at(struct protocol_state *p, int itag, int64_t value);

bool protocol_is_header_written(const struct protocol_state *p,
                                unsigned char header_id) WARN_UNUSED;
void protocol_set_header_written(struct protocol_state *p,
                                 unsigned char header_id);

void protocol_claim_playback_cookie(struct protocol_state *p,
                                    uint8_t *data, /* claims ownership */
                                    size_t sz);
void protocol_claim_sabr_context(struct protocol_state *p,
                                 int32_t sabr_context_update_type,
                                 uint8_t *data, /* claims ownership */
                                 size_t sz);

#endif
