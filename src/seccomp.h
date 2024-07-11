#ifndef SECCOMP_H
#define SECCOMP_H

extern const unsigned SECCOMP_STDIO;
extern const unsigned SECCOMP_INET;
extern const unsigned SECCOMP_SANDBOX; /* power to modify sandbox itself */
extern const unsigned SECCOMP_TMPFILE; /* power to open* with O_TMPFILE */
extern const unsigned SECCOMP_RPATH;   /* power to open* with O_RDONLY */

void seccomp_apply(unsigned flags);

#endif
