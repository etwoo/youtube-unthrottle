#ifndef SEATBELT_H
#define SEATBELT_H

#include "compiler_features.h"
#include "result.h"

#include <stdint.h>

struct seatbelt_context {
	int64_t extensions[3];
};

result_t seatbelt_init(struct seatbelt_context *context) WARN_UNUSED;

extern const unsigned SEATBELT_INET;
extern const unsigned SEATBELT_TMPFILE;
extern const unsigned SEATBELT_RPATH;

result_t seatbelt_revoke(struct seatbelt_context *context,
                         unsigned flags) WARN_UNUSED;

#endif
