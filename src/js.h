#ifndef JAVASCRIPT_H
#define JAVASCRIPT_H

#include "compiler_features.h"
#include "result.h"

#include <stddef.h> /* for size_t */

struct parse_ops {
	result_t (*got_video)(const char *, size_t, void *);
	void *got_video_userdata;
	result_t (*got_audio)(const char *, size_t, void *);
	void *got_audio_userdata;
	result_t (*choose_quality)(const char *, size_t, void *);
	void *choose_quality_userdata;
};

result_t parse_json(const char *json_text,
                    size_t json_text_sz,
                    struct parse_ops *ops) WARN_UNUSED;

result_t make_innertube_json(const char *target_url,
                             long long int timestamp,
                             char **body);

result_t find_base_js_url(const char *html,
                          size_t sz,
                          const char **basejs,
                          size_t *basejs_sz) WARN_UNUSED;
result_t find_js_timestamp(const char *js,
                           size_t js_sz,
                           long long int *value) WARN_UNUSED;
result_t find_js_deobfuscator(const char *js,
                              size_t sz,
                              const char **deobfuscator,
                              size_t *deobfuscator_sz) WARN_UNUSED;

struct call_ops {
	result_t (*got_result)(const char *, size_t, size_t, void *);
};

result_t call_js_foreach(const char *code,
                         size_t sz,
                         char **args,
                         const size_t argc,
                         struct call_ops *ops,
                         void *userdata) WARN_UNUSED;

#endif
