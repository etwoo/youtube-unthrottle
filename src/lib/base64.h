#ifndef BASE64_H
#define BASE64_H

#include <stddef.h> /* for size_t */

int base64_decode(char const *src, unsigned char *target, size_t targsize);

#endif
