#ifndef URL_H
#define URL_H

#include <stdbool.h>

void url_global_init(void);
void url_global_cleanup(void);

bool url_download_from(const char *host, const char *path, int fd);
bool url_download(const char *url, int fd);

#endif
