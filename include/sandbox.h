#ifndef SANDBOX_H
#define SANDBOX_H

#include "result.h"

typedef struct sandbox_context *sandbox_handle_t;

sandbox_handle_t sandbox_init(void) __attribute__((warn_unused_result));
void sandbox_free(sandbox_handle_t context);

result_t sandbox_only_io_inet_tmpfile(sandbox_handle_t context)
	__attribute__((warn_unused_result));
result_t sandbox_only_io_inet_rpath(sandbox_handle_t context)
	__attribute__((warn_unused_result));
result_t sandbox_only_io(sandbox_handle_t context)
	__attribute__((warn_unused_result));

/*
 * Convenience helper for use with __attribute__((cleanup)) like:
 *
 *     sandbox_handle_t h __attribute__((sandbox_cleanup)) = sandbox_init();
 *
 * This calls `sandbox_free(h)` when <h> goes out of scope.
 */
void sandbox_cleanup(sandbox_handle_t *pp);

#endif
