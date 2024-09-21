#ifndef RESULT_TYPE_H
#define RESULT_TYPE_H

#include "array.h"

#define INTO_ENUM(x, y) x,
#define INTO_ARRAY(x, y) x,
#define INTO_SWITCH(x, y)                                                      \
	case x:                                                                \
		y;                                                             \
		break;

/*
 * Generate glue code for a subsystem implementing the `struct result_ops` API.
 *
 * Prerequisite macros: ERROR_TABLE, ERROR_EXAMPLE_ARGS
 */
#define DEFINE_RESULT(typ, do_cleanup, do_init, ...)                           \
	static WARN_UNUSED bool typ##_ok(result_t r)                           \
	{                                                                      \
		struct typ *p = (struct typ *)r;                               \
		return p->err == OK;                                           \
	}                                                                      \
	static WARN_UNUSED char *typ##_to_str(result_t r)                      \
	{                                                                      \
		struct typ *p = (struct typ *)r;                               \
		switch (p->err) {                                              \
			ERROR_TABLE(INTO_SWITCH)                               \
		}                                                              \
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
	}                                                                      \
	void test_##typ##_foreach(void (*visit)(size_t, result_t));            \
	void test_##typ##_foreach(void (*visit)(size_t, result_t))             \
	{                                                                      \
		int arr[] = {ERROR_TABLE(INTO_ARRAY)};                         \
		for (size_t i = 0; i < ARRAY_SIZE(arr); ++i) {                 \
			result_t r = make_##typ(arr[i], ERROR_EXAMPLE_ARGS);   \
			visit(i, r);                                           \
			typ##_cleanup(r);                                      \
		}                                                              \
	}

/*
 * Optional: use the helper macros below when writing ERROR_TABLE entries.
 */
#define LITERAL(str)                                                           \
	do {                                                                   \
		return strdup(str);                                            \
	} while (0)
#define ASPRINTF(fmt, ...)                                                     \
	do {                                                                   \
		char *tmp = NULL;                                              \
		return asprintf(&tmp, fmt, __VA_ARGS__) < 0 ? NULL : tmp;      \
	} while (0)
#define PERR(fmt) ASPRINTF(fmt ": %s", strerror(p->num))

#endif
