#ifndef MACROS_H
#define MACROS_H

/*
 * Macro gymnastics, inspired by https://gitlab.inria.fr/gustedt/p99/
 *
 * Other sources:
 * - https://stackoverflow.com/a/11763277
 */

#define GET_MACRO(A0, A1, A2, A3, A4, A5, A6, NAME, ...) NAME

#define EVEN2(A0, A1) A0
#define EVEN4(A0, A1, A2, A3) A0, A2
#define EVEN6(A0, A1, A2, A3, A4, A5) A0, A2, A4
#define CHOOSE_EVEN_ARGS(...)                                                  \
	GET_MACRO(__VA_ARGS__, FOO, EVEN6, FOO, EVEN4, FOO, EVEN2)(__VA_ARGS__)

#define ODD2(SEP, A0, A1) A1
#define ODD4(SEP, A0, A1, A2, A3) A1 SEP A3
#define ODD6(SEP, A0, A1, A2, A3, A4, A5) A1 SEP A3 SEP A5
#define JOIN_ODD_ARGS(SEP, ...)                                                \
	GET_MACRO(__VA_ARGS__, X, ODD6, X, ODD4, X, ODD2)(SEP, __VA_ARGS__)

#endif
