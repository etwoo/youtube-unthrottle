#ifndef PROTOCOL_VARINT_H
#define PROTOCOL_VARINT_H

#include "result.h"
#include "sys/compiler_features.h"
#include "sys/string_view.h"

#include <inttypes.h>

result_t ump_varint_read(const struct string_view *ump,
                         size_t *pos,
                         uint64_t *value) WARN_UNUSED;

#endif
