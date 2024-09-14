#ifndef URL_H
#define URL_H

#include "result.h"

result_t url_global_init(void);
void url_global_cleanup(void);
void url_global_set_request_handler(int (*handler)(void *, const char *, int));

result_t url_download(const char *url,
                      const char *host,
                      const char *path,
                      const char *post_body,
                      int fd);

#endif
