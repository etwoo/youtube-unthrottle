#ifndef WRITE_H
#define WRITE_H

#include "compiler_features.h"

#include <unistd.h> /* for ssize_t */

/*
 * Keep trying to write() until all <nbyte> of <buf> has been consumed or an
 * error is returned, whichever happens first.
 *
 * In other words, keep trying in the face of partial writes.
 */
ssize_t write_with_retry(int fd, const void *buf, size_t nbyte) WARN_UNUSED;

#endif
