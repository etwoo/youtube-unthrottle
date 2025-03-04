#ifndef SECCOMP_H
#define SECCOMP_H

#include "result.h"
#include "sys/compiler_features.h"

extern const unsigned SECCOMP_STDIO;
extern const unsigned SECCOMP_INET;
extern const unsigned SECCOMP_SANDBOX; /* power to alter sandbox itself */
extern const unsigned SECCOMP_TMPFILE; /* power to open* with O_TMPFILE */
extern const unsigned SECCOMP_RPATH;   /* power to open* with O_RDONLY */

result_t seccomp_apply(unsigned flags) WARN_UNUSED;

#endif
