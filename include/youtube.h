#ifndef YOUTUBE_H
#define YOUTUBE_H

#include "result.h"

result_t youtube_global_init(void) __attribute__((warn_unused_result));
void youtube_global_cleanup(void);

typedef struct youtube_stream *youtube_handle_t;

/*
 * Create a <youtube_handle_t> object.
 *
 * Note: caller must ensure that <proof_of_origin> and <visitor_data> remain
 * valid for the lifetime of the returned <youtube_handle_t>. In other words,
 * this function does not deep-copy any of the passed-in strings.
 */
youtube_handle_t youtube_stream_init(const char *proof_of_origin,
                                     const char *visitor_data,
                                     const char *(*io_simulator)(const char *),
                                     int fd[2])
	__attribute__((warn_unused_result));
void youtube_stream_cleanup(youtube_handle_t h);

struct youtube_setup_ops {
	result_t (*before)(void *);
	result_t (*before_inet)(void *);
	result_t (*after_inet)(void *);
	result_t (*before_parse)(void *);
	result_t (*during_parse_choose_quality)(const char *, void *);
	result_t (*after_parse)(void *);
	result_t (*before_eval)(void *);
	result_t (*after_eval)(void *);
	result_t (*after)(void *);
};

result_t youtube_stream_setup(youtube_handle_t h,
                              const struct youtube_setup_ops *ops,
                              void *userdata,
                              const char *target)
	__attribute__((warn_unused_result));

result_t youtube_stream_visitor(youtube_handle_t h,
                                void (*visit)(const char *, size_t, void *),
                                void *userdata)
	__attribute__((warn_unused_result));

#endif
