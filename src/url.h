#ifndef URL_H
#define URL_H

#include "compiler_features.h"
#include "result.h"

result_t url_global_init(void) WARN_UNUSED;
void url_global_cleanup(void);
void url_global_set_request_handler(int (*handler)(void *, const char *, int));

typedef void *url_handle_t;

result_t url_download(const char *url,
                      const char *host,
                      const char *path,
                      const char *post_body,
                      const char *post_header,
                      int fd,
                      url_handle_t *cache) WARN_UNUSED;
void url_cleanup(url_handle_t *cache);

#endif
