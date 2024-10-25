#ifndef SANDBOX_H
#define SANDBOX_H

#include "result.h"

result_t sandbox_only_io_inet_tmpfile(void) __attribute__((warn_unused_result));
result_t sandbox_only_io_inet_rpath(void) __attribute__((warn_unused_result));
result_t sandbox_only_io(void) __attribute__((warn_unused_result));

#endif
