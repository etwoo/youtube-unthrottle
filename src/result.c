#include "result.h"

#include <string.h> /* for strdup() */

const struct result_base RESULT_OK_SENTINEL = {
	.ops = NULL,
};
result_t RESULT_OK = &RESULT_OK_SENTINEL;

const struct result_base RESULT_CANNOT_ALLOC_SENTINEL = {
	.ops = NULL,
};
result_t RESULT_CANNOT_ALLOC = &RESULT_CANNOT_ALLOC_SENTINEL;

bool
is_ok(result_t r)
{
	if (r == RESULT_OK) {
		return true;
	}

	return r->ops->result_ok && r->ops->result_ok(r);
}

char *
result_to_str(result_t r)
{
	if (r == RESULT_OK) {
		return strdup("Success");
	} else if (r == RESULT_CANNOT_ALLOC) {
		return strdup("Cannot allocate result");
	} else if (r && r->ops && r->ops->result_to_str) {
		return r->ops->result_to_str(r);
	}
	return strdup("Cannot stringify result");
}

void
result_cleanup(result_t *handle)
{
	result_t r = *handle;
	if (r && r->ops && r->ops->result_cleanup) {
		r->ops->result_cleanup(r);
	}
}
