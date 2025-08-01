#ifndef TEST_MACROS_H
#define TEST_MACROS_H

/*
 * Convenience macro for string_view usage in tests
 *
 * Caller must pass a string literal as <lit>, not a variable of type `char *`.
 *
 * Note: lack of type safety makes this macro suitable for test code only.
 */
#define MAKE_TEST_STRING(lit) {.data = (lit), .sz = sizeof(lit) - 1}

/*
 * Convenience wrapper around `GREATEST_ASSERT_GT(0, fd)` that avoids
 * triggering gcc's `-Wanalyzer-fd-leak` warning.
 */
#define ASSERT_INVALID_DESCRIPTOR(fd)                                          \
	do {                                                                   \
		if ((fd) >= 0) {                                               \
			close(fd);                                             \
		}                                                              \
		ASSERT_GT(0, fd);                                              \
	} while (0)

/*
 * Convenience macro for asserting validity of a file/socket descriptor, the
 * opposite of ASSERT_INVALID_DESCRIPTOR().
 */
#define ASSERT_VALID_DESCRIPTOR(fd) ASSERT_LTE(0, fd)

#endif
