#ifndef LANDLOCK_H
#define LANDLOCK_H

#include "result.h"

result_t landlock_apply(const char **paths, int sz, int port);

#endif
