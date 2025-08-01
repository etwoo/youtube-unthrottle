#ifndef SANDBOX_VERIFY_H
#define SANDBOX_VERIFY_H

#include "result.h"
#include "sys/compiler_features.h"

#include <stdbool.h>

result_t sandbox_verify(const char *const *paths,
                        size_t paths_allowed,
                        size_t paths_total,
                        bool network_allowed) WARN_UNUSED;

extern const char SANDBOX_VERIFY_STATIC_IP_ADDRESS[];

#endif
