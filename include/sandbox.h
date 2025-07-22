#ifndef SANDBOX_H
#define SANDBOX_H

#include "result.h"

typedef struct sandbox_context *sandbox_handle_t;

sandbox_handle_t sandbox_init(void) __attribute__((warn_unused_result));
void sandbox_cleanup(sandbox_handle_t context);

result_t sandbox_only_io_inet_tmpfile(sandbox_handle_t context)
	__attribute__((warn_unused_result));
result_t sandbox_only_io_inet_rpath(sandbox_handle_t context)
	__attribute__((warn_unused_result));
result_t sandbox_only_io(sandbox_handle_t context)
	__attribute__((warn_unused_result));

#endif
