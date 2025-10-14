#ifndef JAVASCRIPT_H
#define JAVASCRIPT_H

#include "result.h"
#include "sys/compiler_features.h"
#include "sys/string_view.h"

struct parse_ops {
	result_t (*choose_quality)(const char *, void *);
	void *userdata;
};

struct parse_values {
	long long int itag;
	char *sabr_url;
	char *playback_config;
};

result_t parse_json(const struct string_view *json,
                    const struct parse_ops *ops,
                    struct parse_values *values) WARN_UNUSED;
void parse_values_cleanup(struct parse_values *p);

result_t make_innertube_json(const char *target_url,
                             const char *proof_of_origin,
                             long long int timestamp,
                             char **body);

result_t find_base_js_url(const struct string_view *html,
                          struct string_view *basejs) WARN_UNUSED;
result_t find_js_timestamp(const struct string_view *js,
                           long long int *value) WARN_UNUSED;

struct deobfuscator {
	struct string_view magic[2];
	struct string_view funcname;
};

result_t find_js_deobfuscator_magic_global(const struct string_view *js,
                                           struct deobfuscator *d) WARN_UNUSED;
result_t find_js_deobfuscator(const struct string_view *js,
                              struct deobfuscator *d) WARN_UNUSED;

struct call_ops {
	result_t (*got_result)(const char *, size_t, void *);
};

result_t call_js_foreach(const struct deobfuscator *d,
                         const char *const *args,
                         const struct call_ops *ops,
                         void *userdata) WARN_UNUSED;

#endif
