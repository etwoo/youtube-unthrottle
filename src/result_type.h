#ifndef RESULT_TYPE_H
#define RESULT_TYPE_H

/*
 * Codegen macros that help with implementing the `struct result_ops` interface
 */

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
	static WARN_UNUSED char *typ##_to_str(result_t r)                      \
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
		on_stack.base.ops = &RESULT_OPS;                               \
		memcpy(on_heap, &on_stack, sizeof(on_stack));                  \
		return (result_t)on_heap;                                      \
	}

// TODO: create a globally-visible (non-static) function like test_typ##_foreach(...)
// TODO: ... then make test/result/result.c `extern` all of these functions, and call them to get an example of each subsystem's result_t, then stringify, then strstr() like in existing print_to_str_each_enum_value() testcase
// TODO: verify this causes the various ERROR_TABLE() macros to be covered; looks like clang is smart enough to mark those lines as code (not data) and to only mark them covered if the specific INTO_SWITCH()-generated block actually hits in a testcase!!!

#endif
