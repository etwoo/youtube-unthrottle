#ifndef COVERAGE_H
#define COVERAGE_H

int coverage_open(void);
void coverage_write_and_close(int fd);

/*
 * Convenience helper for use with __attribute__((cleanup)) like:
 *
 *     int fd __attribute__((cleanup(coverage_cleanup))) = coverage_open();
 */
void coverage_cleanup(int *fd);

#endif
