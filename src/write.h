#ifndef WRITE_H
#define WRITE_H

#include "compiler_features.h"

#include <unistd.h> /* for ssize_t */

/*
 * Keep trying to write() until we've consumed all <nbyte> of <buf> or an error
 * occurs, whichever happens first.
 *
 * In other words, keep trying in the face of partial writes.
 */
ssize_t write_with_retry(int fd, const char *buf, size_t nbyte) WARN_UNUSED;

#endif
