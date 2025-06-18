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
	struct parse_values parsed
		__attribute__((cleanup(parse_values_cleanup))) = {0};
	auto_result r = parse_json(&json, &pops, &parsed);
	return 0;
}
