#ifndef TMPFILE_H
#define TMPFILE_H

#include "result.h"
#include "sys/compiler_features.h"
#include "sys/string_view.h"

result_t tmpfd(int *fd) WARN_UNUSED;
result_t tmpmap(int fd, struct string_view *addr) WARN_UNUSED;
void tmpunmap(struct string_view *addr);
result_t tmptruncate(int fd, struct string_view *addr) WARN_UNUSED;

#endif
