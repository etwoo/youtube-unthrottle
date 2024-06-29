#ifndef YOUTUBE_H
#define YOUTUBE_H

#include <stdbool.h>

void youtube_global_init(void);
void youtube_global_cleanup(void);

typedef struct youtube_stream *youtube_handle_t;

youtube_handle_t youtube_stream_init(void);
void youtube_stream_cleanup(youtube_handle_t h);
void youtube_stream_print(youtube_handle_t h);
bool youtube_stream_setup(youtube_handle_t h, const char *target);

#endif
