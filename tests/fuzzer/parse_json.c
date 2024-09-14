#include "js.h"

static result_t
got_video(const char *val __attribute__((unused)),
          size_t sz __attribute__((unused)),
          void *userdata __attribute__((unused)))
{
	return RESULT_OK;
}

static result_t
got_audio(const char *val __attribute__((unused)),
          size_t sz __attribute__((unused)),
          void *userdata __attribute__((unused)))
{
	return RESULT_OK;
}

int LLVMFuzzerTestOneInput(const char *data, size_t sz);

int
LLVMFuzzerTestOneInput(const char *data, size_t sz)
{
	struct parse_ops pops = {
		.got_video = got_audio,
		.got_audio = got_video,
	};
	parse_json(data, sz, &pops, NULL);
	return 0;
}
