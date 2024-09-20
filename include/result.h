#ifndef RESULT_H
#define RESULT_H

#include "compiler_features.h"

#include <stdbool.h>

/*
 * result_t: opaque type representing an arbitrary result
 */
typedef struct result_base *result_t;

/*
 * result_ops, result_base: each subsystem implements result_ops and extends
 * result_base in order to create a customized result type
 */
struct result_ops {
	bool (*result_ok)(result_t);
	const char *(*result_to_str)(result_t);
	void (*result_cleanup)(result_t);
};
struct result_base {
	struct result_ops *ops;
};

/*
 * RESULT_OK: sentinel that represents generic success, not specific to any
 * particular subsystem or function
 */
extern const result_t RESULT_OK;

/*
 * RESULT_CANNOT_ALLOC: sentinel that represents a failure to allocate a more
 * specific result, i.e. allocation failure within the result subsystem itself
 */
extern const result_t RESULT_CANNOT_ALLOC;

/*
 * Return true if <r> represents a successful result. Return false otherwise.
 */
bool is_ok(result_t r) WARN_UNUSED;

/*
 * Return if <expr> yields a non-OK result_t.
 */
#define check(expr)                                                            \
	do {                                                                   \
		result_t x = expr;                                             \
		if (!is_ok(x)) {                                               \
			return x;                                              \
		}                                                              \
	} while (0)

/*
 * Convert a result into a human-readable error message.
 *
 * Note: the caller owns the returned buffer.
 */
const char *result_to_str(result_t r) WARN_UNUSED;

/*
 * Convenience helper for use with __attribute__((cleanup)) like:
 *
 *     result_t err __attribute__((cleanup(result_cleanup))) = [...]
 */
void result_cleanup(result_t *handle);

#endif
