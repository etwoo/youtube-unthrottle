#ifndef YOUTUBE_H
#define YOUTUBE_H

#include <stdbool.h>

void youtube_global_init(void);
void youtube_global_cleanup(void);

typedef struct youtube_stream *youtube_handle_t;

youtube_handle_t youtube_stream_init(void);
void youtube_stream_cleanup(youtube_handle_t h);
void youtube_stream_visitor(youtube_handle_t h, void (*visit)(const char *));

struct youtube_setup_ops {
	void (*before)(youtube_handle_t);
	void (*before_inet)(youtube_handle_t);
	void (*after_inet)(youtube_handle_t);
	void (*before_parse)(youtube_handle_t);
	void (*after_parse)(youtube_handle_t);
	void (*before_eval)(youtube_handle_t);
	void (*after_eval)(youtube_handle_t);
	void (*after)(youtube_handle_t);
};

bool youtube_stream_setup(youtube_handle_t h,
                          struct youtube_setup_ops *ops,
                          const char *target);

#endif
