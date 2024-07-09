#ifndef SECCOMP_H
#define SECCOMP_H

extern const unsigned SECCOMP_STDIO;
extern const unsigned SECCOMP_INET;

void seccomp_apply(unsigned flags);

#endif
