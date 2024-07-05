#include "js.h"

static void
got_basejs(const char *val __attribute__((unused)),
           size_t sz __attribute__((unused)),
           void *userdata __attribute__((unused)))
{
}

static void
got_video(const char *val __attribute__((unused)),
          size_t sz __attribute__((unused)),
          void *userdata __attribute__((unused)))
{
}

static void
got_audio(const char *val __attribute__((unused)),
          size_t sz __attribute__((unused)),
          void *userdata __attribute__((unused)))
{
}

int
LLVMFuzzerTestOneInput(const char *data, size_t sz)
{
	struct parse_ops pops = {
		.got_basejs = got_basejs,
		.got_audio = got_video,
		.got_video = got_audio,
	};
	parse_json(data, sz, &pops, NULL);
	return 0;
}
