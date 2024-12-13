#ifndef STRING_VIEW_H
#define STRING_VIEW_H

#include <stddef.h> /* for size_t */

/*
 * Represents a non-owning pointer to non-NUL-terminated character data,
 * analogous to C++17's string_view<>.
 */
struct string_view {
	const char *data;
	size_t sz;
};

#endif
