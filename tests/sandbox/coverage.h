#ifndef COVERAGE_H
#define COVERAGE_H

int open_coverage_fd(void);
void write_coverage_and_close_fd(int fd);

#endif
