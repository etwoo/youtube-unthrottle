#ifndef LANDLOCK_H
#define LANDLOCK_H

#include "result.h"
#include "sys/compiler_features.h"

result_t landlock_apply(const char **paths, int sz, int port) WARN_UNUSED;

#endif
