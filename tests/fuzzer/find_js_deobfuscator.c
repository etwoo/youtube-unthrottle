#include "lib/js.h"

int LLVMFuzzerTestOneInput(const char *data, size_t sz);

int
LLVMFuzzerTestOneInput(const char *data, size_t sz)
{
	const struct string_view js = {.data = data, .sz = sz};
	struct deobfuscator d = {0};
	(void)find_js_deobfuscator(&js, &d);
	return 0;
}
