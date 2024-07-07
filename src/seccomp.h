#ifndef SECCOMP_H
#define SECCOMP_H

extern const unsigned SECCOMP_IO_OPEN;
extern const unsigned SECCOMP_IO_RW;
extern const unsigned SECCOMP_IO_INET;

void seccomp_apply(unsigned flags);

#endif
