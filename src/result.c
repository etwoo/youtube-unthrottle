#include "result.h"

const struct result RESULT_OK_SENTINEL = {
	.ops = NULL,
};
const result_t RESULT_OK = &RESULT_OK_SENTINEL;

const struct result RESULT_CANNOT_ALLOC_SENTINEL = {
	.ops = NULL,
};
const result_t RESULT_CANNOT_ALLOC = &RESULT_CANNOT_ALLOC_SENTINEL;

bool
is_ok(result_t r)
{
	if (r == RESULT_OK) {
		return true;
	}

	return r->result_ok && r->result_ok(r);
}

const char *
result_to_str(result_t r)
{
	if (r == RESULT_OK) {
		return strdup("Success");
	} else if (r == RESULT_CANNOT_ALLOC) {
		return strdup("Cannot allocate result");
	} else if (r && r->ops && r->ops.result_to_str) {
		return r->ops.result_to_str(r);
	}
	return strdup("Cannot stringify result");
}

void
result_cleanup(result_t *handle)
{
	result_t r = *handle;
	if (r && r->ops && r->ops.result_cleanup) {
		r->ops.result_cleanup(r);
	}
}
