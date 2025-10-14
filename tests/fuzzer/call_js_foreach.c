#include "lib/js.h"
#include "sys/array.h"
#include "test_macros.h"

static WARN_UNUSED result_t
got_result(const char *val MAYBE_UNUSED,
           size_t pos MAYBE_UNUSED,
           void *userdata MAYBE_UNUSED)
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
		.funcname =
			{
				.data = data,
				.sz = sz,
			},
	};

	const char *args[] = {
		"fPaFSFklkyAP8IeVM1C",
		"K-qX7Rx6NF8wh-wN_Ni",
		"5KezMq2QMtITgto5cb3",
		"NazoWsDZJa71h_heyXB",
		"Zx9BTcsQimFxwVqtVfF",
		"Kbpbx5yukKR-Px0dhLj",
		"t2yEuJMA6mZh68xBzwE",
		NULL,
	};

	auto_result r = call_js_foreach(&d, args, &cops, NULL);
	return 0;
}
