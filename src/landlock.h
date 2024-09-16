#ifndef LANDLOCK_H
#define LANDLOCK_H

#include "compiler_features.h"
#include "result.h"

result_t landlock_apply(const char **paths, int sz, int port) WARN_UNUSED;

#endif
