#include "js.h"

int LLVMFuzzerTestOneInput(const char *data, size_t sz);

int
LLVMFuzzerTestOneInput(const char *data, size_t sz)
{
	const char *deobfuscator = NULL;
	size_t deobfuscator_sz = 0;
	(void)find_js_deobfuscator(data, sz, &deobfuscator, &deobfuscator_sz);
	return 0;
}
