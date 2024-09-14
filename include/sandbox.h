#ifndef SANDBOX_H
#define SANDBOX_H

#include "result.h"

result_t sandbox_only_io_inet_tmpfile(void);
result_t sandbox_only_io_inet_rpath(void);
result_t sandbox_only_io(void);

#endif
