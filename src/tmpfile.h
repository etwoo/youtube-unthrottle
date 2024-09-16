#ifndef TMPFILE_H
#define TMPFILE_H

#include "compiler_features.h"
#include "result.h"

result_t tmpfd(int *fd) WARN_UNUSED;
result_t tmpmap(int fd, void **addr, unsigned int *sz) WARN_UNUSED;
void tmpunmap(void *addr, unsigned int sz);

#endif
