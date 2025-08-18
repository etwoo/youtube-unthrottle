#ifndef URL_H
#define URL_H

#include "result.h"
#include "sys/compiler_features.h"
#include "sys/string_view.h"

result_t url_global_init(void) WARN_UNUSED;
void url_global_cleanup(void);

typedef const char *(*url_simulator)(const char *, const void *);
struct url_request_context {
	void *state;
	url_simulator simulator;
	const void *simulator_state;
};

void url_context_init(struct url_request_context *context);
void url_context_cleanup(struct url_request_context *context);

typedef enum {
	CONTENT_TYPE_UNSET = 0,
	CONTENT_TYPE_JSON,
	CONTENT_TYPE_PROTOBUF,
} url_request_content_type;

result_t url_download(const char *url,
                      const struct string_view *post_body, /* maybe NULL */
                      url_request_content_type post_content_type,
                      const char *post_header, /* maybe NULL */
                      struct url_request_context *context,
                      int fd) WARN_UNUSED;

#endif
