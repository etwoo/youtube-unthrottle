#include "js.h"

static WARN_UNUSED result_t
got_video(const char *val __attribute__((unused)),
          void *userdata __attribute__((unused)))
{
	return RESULT_OK;
}

static WARN_UNUSED result_t
got_audio(const char *val __attribute__((unused)),
          void *userdata __attribute__((unused)))
{
	return RESULT_OK;
}

static WARN_UNUSED result_t
choose_quality(const char *val __attribute__((unused)),
               void *userdata __attribute__((unused)))
{
	return RESULT_OK;
}

int LLVMFuzzerTestOneInput(const char *data, size_t sz);

int
LLVMFuzzerTestOneInput(const char *data, size_t sz)
{
	const struct string_view json = {.data = data, .sz = sz};
	struct parse_ops pops = {
		.got_video = got_audio,
		.got_video_userdata = NULL,
		.got_audio = got_video,
		.got_audio_userdata = NULL,
		.choose_quality = choose_quality,
		.choose_quality_userdata = NULL,
	};
	(void)parse_json(&json, &pops);
	return 0;
}
