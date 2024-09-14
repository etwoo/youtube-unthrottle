#ifndef JAVASCRIPT_H
#define JAVASCRIPT_H

#include "result.h"

#include <stddef.h> /* for size_t */

struct parse_ops {
	result_t (*got_video)(const char *, size_t, void *);
	result_t (*got_audio)(const char *, size_t, void *);
};

result_t parse_json(const char *json, size_t sz, struct parse_ops *o, void *ud);

result_t find_base_js_url(const char *html,
                          size_t sz,
                          const char **basejs,
                          size_t *basejs_sz);
result_t find_js_timestamp(const char *js, size_t sz, long long int *ts);
result_t find_js_deobfuscator(const char *js,
                              size_t sz,
                              const char **deobfuscator,
                              size_t *deobfuscator_sz);

struct call_ops {
	result_t (*got_result)(const char *, size_t, void *);
};

result_t call_js_foreach(const char *code,
                         size_t sz,
                         char **args,
                         const size_t argc,
                         struct call_ops *ops,
                         void *userdata);

#endif
