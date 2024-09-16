#ifndef YOUTUBE_H
#define YOUTUBE_H

#include "compiler_features.h"
#include "result.h"

result_t youtube_global_init(void) WARN_UNUSED;
void youtube_global_cleanup(void);

typedef struct youtube_stream *youtube_handle_t;

youtube_handle_t youtube_stream_init(void) WARN_UNUSED;
void youtube_stream_cleanup(youtube_handle_t h);

struct youtube_setup_ops {
	result_t (*before)(youtube_handle_t);
	result_t (*before_inet)(youtube_handle_t);
	result_t (*after_inet)(youtube_handle_t);
	result_t (*before_parse)(youtube_handle_t);
	result_t (*after_parse)(youtube_handle_t);
	result_t (*before_eval)(youtube_handle_t);
	result_t (*after_eval)(youtube_handle_t);
	result_t (*after)(youtube_handle_t);
};

result_t youtube_stream_setup(youtube_handle_t h,
                              struct youtube_setup_ops *ops,
                              const char *target) WARN_UNUSED;

result_t youtube_stream_visitor(youtube_handle_t h,
                                void (*visit)(const char *)) WARN_UNUSED;

#endif
