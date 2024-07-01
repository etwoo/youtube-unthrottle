#ifndef LANDLOCK_H
#define LANDLOCK_H

#include <stdbool.h>
#include <stddef.h> /* for size_t */

void landlock_apply(const char **paths, int sz, const int *port);

void landlock_check(const char **paths,
                    size_t paths_allowed,
                    size_t paths_total,
                    bool connect_allowed);

#endif
