#ifndef RESULT_TYPE_H
#define RESULT_TYPE_H

#define INTO_ENUM(x, y) x,

#define INTO_SWITCH(x, y)                                                      \
	case x:                                                                \
		y;                                                             \
		break;

#define DEFINE_RESULT(typ, do_cleanup, do_init, ...)                           \
	static WARN_UNUSED bool typ##_ok(result_t r)                           \
	{                                                                      \
		struct typ *p = (struct typ *)r;                               \
		return p->err == OK;                                           \
	}                                                                      \
	static WARN_UNUSED const char *typ##_to_str(result_t r)                \
	{                                                                      \
		struct typ *p = (struct typ *)r;                               \
		int printed = 0;                                               \
		char *s = NULL;                                                \
		switch (p->err) {                                              \
			ERROR_TABLE(INTO_SWITCH)                               \
		}                                                              \
		if (printed < 0) {                                             \
			return NULL;                                           \
		}                                                              \
		return s;                                                      \
	}                                                                      \
	static void typ##_cleanup(result_t r)                                  \
	{                                                                      \
		if (r == NULL) {                                               \
			return;                                                \
		}                                                              \
		struct typ *p = (struct typ *)r;                               \
		do_cleanup;                                                    \
		free(p);                                                       \
	}                                                                      \
	static struct result_ops RESULT_OPS = {                                \
		.result_ok = typ##_ok,                                         \
		.result_to_str = typ##_to_str,                                 \
		.result_cleanup = typ##_cleanup,                               \
	};                                                                     \
	static result_t WARN_UNUSED make_##typ(__VA_ARGS__)                    \
	{                                                                      \
		struct typ *on_heap = malloc(sizeof(*on_heap));                \
		if (on_heap == NULL) {                                         \
			return RESULT_CANNOT_ALLOC;                            \
		}                                                              \
		struct typ on_stack = do_init;                                 \
		memcpy(on_heap, &on_stack, sizeof(on_stack));                  \
		return (result_t)on_heap;                                      \
	}

#endif
