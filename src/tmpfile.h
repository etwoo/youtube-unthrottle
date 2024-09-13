#ifndef TMPFILE_H
#define TMPFILE_H

#include "result.h"

result_t tmpfd(int *fd);
result_t tmpmap(int fd, void **addr, unsigned int *sz);
void tmpunmap(void *addr, unsigned int sz);

#endif
