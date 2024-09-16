#ifndef URL_H
#define URL_H

#include "compiler_features.h"
#include "result.h"

result_t url_global_init(void) WARN_UNUSED;
void url_global_cleanup(void);
void url_global_set_request_handler(int (*handler)(void *, const char *, int));

result_t url_download(const char *url,
                      const char *host,
                      const char *path,
                      const char *post_body,
                      int fd) WARN_UNUSED;

#endif
