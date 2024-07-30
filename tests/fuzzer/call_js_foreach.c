#include "array.h"
#include "js.h"

static void
got_result(const char *val __attribute__((unused)),
           size_t sz __attribute__((unused)),
           void *userdata __attribute__((unused)))
{
}

int LLVMFuzzerTestOneInput(const char *data, size_t sz);

int
LLVMFuzzerTestOneInput(const char *data, size_t sz)
{
	struct call_ops cops = {
		.got_result = got_result,
	};
	char *args[8];
	args[0] = "fPaFSFklkyAP8IeVM1C";
	args[1] = "K-qX7Rx6NF8wh-wN_Ni";
	args[2] = "5KezMq2QMtITgto5cb3";
	args[3] = "NazoWsDZJa71h_heyXB";
	args[4] = "Zx9BTcsQimFxwVqtVfF";
	args[5] = "Kbpbx5yukKR-Px0dhLj";
	args[6] = "t2yEuJMA6mZh68xBzwE";
	args[7] = "6a4RySpPL8dKGrGFAqo";
	call_js_foreach(data, sz, args, ARRAY_SIZE(args), &cops, NULL);
	return 0;
}
