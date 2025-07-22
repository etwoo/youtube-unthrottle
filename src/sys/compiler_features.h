#ifndef COMPILER_FEATURES_H
#define COMPILER_FEATURES_H

/*
 * Shorthand for oft-used compiler attributes
 */

/*
 * This attribute, attached to a function, causes a warning [...] if a caller
 * of the function with this attribute does not use its return value.
 *
 * https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html
 */
#define WARN_UNUSED __attribute__((warn_unused_result))

/*
 * This attribute, attached to a variable or structure field, means that the
 * variable or field [...] possibly unused.
 *
 * https://gcc.gnu.org/onlinedocs/gcc/Common-Variable-Attributes.html
 */
#define MAYBE_UNUSED __attribute__((unused))

#endif
