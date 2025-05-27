#ifndef URL_H
#define URL_H

#include "result.h"
#include "sys/compiler_features.h"

result_t url_global_init(void) WARN_UNUSED;
void url_global_cleanup(void);

typedef const char *(*url_simulator)(const char *);
struct url_request_context {
	void *state;
	url_simulator simulator;
};

void url_context_init(struct url_request_context *context);
void url_context_cleanup(struct url_request_context *context);

result_t url_download(const char *url,
                      const char *post_body,
                      size_t post_body_size,
                      const char *post_header,
                      int fd,
                      struct url_request_context *context) WARN_UNUSED;

#endif
