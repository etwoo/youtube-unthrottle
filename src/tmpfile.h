#ifndef TMPFILE_H
#define TMPFILE_H

#include <stdbool.h>

int tmpfd(void);
bool tmpmap(int fd, void **addr, unsigned int *sz);
void tmpunmap(void *addr, unsigned int sz);

#endif
