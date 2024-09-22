#ifndef MACROS_H
#define MACROS_H

/*
 * Macro gymnastics, inspired by https://gitlab.inria.fr/gustedt/p99/
 *
 * Other sources:
 * - https://stackoverflow.com/a/11763277
 */

#define GET_MACRO(A0, A1, A2, A3, A4, A5, A6, NAME, ...) NAME

#define EVENCOMMA2(A0, A1) A0
#define EVENCOMMA4(A0, A1, A2, A3) A0, A2
#define EVENCOMMA6(A0, A1, A2, A3, A4, A5) A0, A2, A4
#define CHOOSE_EVEN_ARGS(...)                                                  \
	GET_MACRO(__VA_ARGS__,                                                 \
	          FOO,                                                         \
	          EVENCOMMA6,                                                  \
	          FOO,                                                         \
	          EVENCOMMA4,                                                  \
	          FOO,                                                         \
	          EVENCOMMA2)                                                  \
	(__VA_ARGS__)

#define EVEN2(SEP, A0, A1) A0
#define EVEN4(SEP, A0, A1, A2, A3) A0 SEP A2
#define EVEN6(SEP, A0, A1, A2, A3, A4, A5) A0 SEP A2 SEP A4
#define JOIN_EVEN_ARGS(SEP, ...)                                               \
	GET_MACRO(__VA_ARGS__, X, EVEN6, X, EVEN4, X, EVEN2)(SEP, __VA_ARGS__)

#define ODD2(SEP, A0, A1) A1
#define ODD4(SEP, A0, A1, A2, A3) A1 SEP A3
#define ODD6(SEP, A0, A1, A2, A3, A4, A5) A1 SEP A3 SEP A5
#define JOIN_ODD_ARGS(SEP, ...)                                                \
	GET_MACRO(__VA_ARGS__, X, ODD6, X, ODD4, X, ODD2)(SEP, __VA_ARGS__)

#endif
