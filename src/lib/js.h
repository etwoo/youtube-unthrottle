#ifndef JAVASCRIPT_H
#define JAVASCRIPT_H

#include "result.h"
#include "sys/compiler_features.h"
#include "sys/string_view.h"

struct parse_ops {
	result_t (*choose_quality)(const char *, void *);
	void *choose_quality_userdata;
};

result_t parse_json(const struct string_view *json,
                    const struct parse_ops *ops,
                    long long int *itag) WARN_UNUSED;

result_t make_innertube_json(const char *target_url,
                             const char *proof_of_origin,
                             long long int timestamp,
                             char **body);

result_t find_base_js_url(const struct string_view *html,
                          struct string_view *basejs) WARN_UNUSED;
result_t find_js_timestamp(const struct string_view *js,
                           long long int *value) WARN_UNUSED;
result_t find_sabr_url(const struct string_view *json,
                       struct string_view *sabr) WARN_UNUSED;
result_t find_playback_config(const struct string_view *json,
                              struct string_view *config) WARN_UNUSED;

struct deobfuscator {
	struct string_view magic[2];
	struct string_view code;
};

result_t find_js_deobfuscator_magic_global(const struct string_view *js,
                                           struct deobfuscator *d) WARN_UNUSED;
result_t find_js_deobfuscator(const struct string_view *js,
                              struct deobfuscator *d) WARN_UNUSED;

struct call_ops {
	result_t (*got_result)(const char *, size_t, void *);
};

result_t call_js_foreach(const struct deobfuscator *d,
                         char **args,
                         const struct call_ops *ops,
                         void *userdata) WARN_UNUSED;

#endif
