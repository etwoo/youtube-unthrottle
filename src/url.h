#ifndef URL_H
#define URL_H

#include "compiler_features.h"
#include "result.h"

result_t url_global_init(void) WARN_UNUSED;
void url_global_cleanup(void);

typedef unsigned (*url_handler)(const char *, int);
struct url_request_context {
	void *state;
	url_handler handler;
};

void url_context_init(struct url_request_context *context);
void url_context_cleanup(struct url_request_context *context);

result_t url_download(const char *url,
                      const char *host,
                      const char *path,
                      const char *post_body,
                      const char *post_header,
                      int fd,
                      struct url_request_context *context) WARN_UNUSED;

#endif
