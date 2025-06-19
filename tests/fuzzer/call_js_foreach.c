#include "lib/js.h"
#include "sys/array.h"
#include "test_macros.h"

static WARN_UNUSED result_t
got_result(const char *val __attribute__((unused)),
           size_t pos __attribute__((unused)),
           void *userdata __attribute__((unused)))
{
	return RESULT_OK;
}

int LLVMFuzzerTestOneInput(const char *data, size_t sz);

int
LLVMFuzzerTestOneInput(const char *data, size_t sz)
{
	struct call_ops cops = {
		.got_result = got_result,
	};

	struct deobfuscator d = {
		.magic =
			{
				MAKE_TEST_STRING("var m1=123"),
				MAKE_TEST_STRING("var m2='mmm'"),
			},
		.code =
			{
				.data = data,
				.sz = sz,
			},
	};

	char *args[8];
	args[0] = "fPaFSFklkyAP8IeVM1C";
	args[1] = "K-qX7Rx6NF8wh-wN_Ni";
	args[2] = "5KezMq2QMtITgto5cb3";
	args[3] = "NazoWsDZJa71h_heyXB";
	args[4] = "Zx9BTcsQimFxwVqtVfF";
	args[5] = "Kbpbx5yukKR-Px0dhLj";
	args[6] = "t2yEuJMA6mZh68xBzwE";
	args[7] = NULL;

	auto_result r = call_js_foreach(&d, args, &cops, NULL);
	return 0;
}
