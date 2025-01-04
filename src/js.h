#ifndef JAVASCRIPT_H
#define JAVASCRIPT_H

#include "compiler_features.h"
#include "result.h"
#include "string_view.h"

struct parse_ops {
	result_t (*got_video)(const char *, void *);
	void *got_video_userdata;
	result_t (*got_audio)(const char *, void *);
	void *got_audio_userdata;
	result_t (*choose_quality)(const char *, void *);
	void *choose_quality_userdata;
};

result_t parse_json(const struct string_view *json,
                    const struct parse_ops *ops) WARN_UNUSED;

result_t make_innertube_json(const char *target_url,
                             const char *proof_of_origin,
                             long long int timestamp,
                             char **body);

result_t find_base_js_url(const struct string_view *html,
                          struct string_view *basejs) WARN_UNUSED;
result_t find_js_timestamp(const struct string_view *js,
                           long long int *value) WARN_UNUSED;
result_t find_js_deobfuscator_magic_global(const struct string_view *js,
                                           struct string_view *m) WARN_UNUSED;
result_t find_js_deobfuscator(const struct string_view *js,
                              struct string_view *deobfuscator) WARN_UNUSED;

struct call_ops {
	result_t (*got_result)(const char *, size_t, void *);
};

result_t call_js_foreach(const struct string_view *magic,
                         const struct string_view *code,
                         char **args,
                         struct call_ops *ops,
                         void *userdata) WARN_UNUSED;

#endif
