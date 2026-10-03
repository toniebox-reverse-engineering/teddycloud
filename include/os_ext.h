#pragma once

#include <stdio.h>
#include "os_port.h"

FILE *osPopen(const char *command, const char *type);
int osPclose(FILE *stream);
void osStringToUpper(char *str);
void osStringToLower(char *str);

/*
 * Runs `file` with the given argv (NULL-terminated, argv[0] is the program
 * name) and waits for it to exit. No shell is involved, so no argument
 * escaping is needed. `file` is searched for on PATH.
 * Returns the child's exit code (0 = success), or -1 if it could not be
 * spawned or its exit status could not be determined.
 */
int osSpawnvp(const char *file, char *const argv[]);