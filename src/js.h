#ifndef JAVASCRIPT_H
#define JAVASCRIPT_H

#include <stddef.h> /* for size_t */

struct parse_ops {
	void (*got_video)(const char *, size_t, void *);
	void (*got_audio)(const char *, size_t, void *);
};

void parse_json(const char *json, size_t sz, struct parse_ops *ops, void *ud);

void find_base_js_url(const char *html,
                      size_t sz,
                      const char **basejs,
                      size_t *basejs_sz);
void find_js_deobfuscator(const char *js,
                          size_t sz,
                          const char **deobfuscator,
                          size_t *deobfuscator_sz);

struct call_ops {
	void (*got_result)(const char *, size_t, void *);
};

void call_js_foreach(const char *code,
                     size_t sz,
                     char **args,
                     const size_t argc,
                     struct call_ops *ops,
                     void *userdata);

#endif
