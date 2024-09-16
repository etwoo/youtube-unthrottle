#ifndef SANDBOX_H
#define SANDBOX_H

#include "compiler_features.h"
#include "result.h"

result_t sandbox_only_io_inet_tmpfile(void) WARN_UNUSED;
result_t sandbox_only_io_inet_rpath(void) WARN_UNUSED;
result_t sandbox_only_io(void) WARN_UNUSED;

#endif
