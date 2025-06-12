#include "lib/js.h"

int LLVMFuzzerTestOneInput(const char *data, size_t sz);

int
LLVMFuzzerTestOneInput(const char *data, size_t sz)
{
	const struct string_view json = {.data = data, .sz = sz};
	struct parse_ops pops = {
		.choose_quality = NULL,
		.userdata = NULL,
	};
	long long int itag = 0;
	(void)parse_json(&json, &pops, &itag);
	return 0;
}
