#ifndef TEST_MACROS_H
#define TEST_MACROS_H

/*
 * Convenience macro for string_view usage in tests
 *
 * Caller must pass a string literal as <lit>, not a variable of type `char *`.
 *
 * Note: lack of type safety makes this macro suitable for test code only.
 */
#define MAKE_TEST_STRING(lit) {.data = lit, .sz = sizeof(lit) - 1}

#endif
