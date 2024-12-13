#ifndef TEST_MACROS_H
#define TEST_MACROS_H

/*
 * Convenience macro for string_view usage in tests
 *
 * Note: <lit> must be a string literal and _NOT_ a variable of type `char *`.
 * Lack of type safety here is the main reason we use this only for test code.
 */
#define MAKE_TEST_STRING(lit) {.data = lit, .sz = sizeof(lit) - 1}

#endif
