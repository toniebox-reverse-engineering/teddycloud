#pragma once

#include <stdbool.h>
#include <stdio.h>
#include "os_port.h"

FILE *osPopen(const char *command, const char *type);
int osPclose(FILE *stream);

/*
 * Quotes `src` as one literal argument for the shell osPopen() runs
 * (/bin/sh, or cmd.exe on Windows). Returns false if the result does not
 * fit into dest_size, or on Windows if src contains a '"', which cmd.exe
 * cannot escape (and Windows file names cannot contain).
 */
bool osShellQuote(char *dest, size_t dest_size, const char *src);

/*
 * Makes a file readable and writable by its owner only (0600), for files
 * holding private keys. Call it right after creating the file, before the
 * key is written. No-op on Windows. Returns false if chmod failed.
 */
bool osChmodOwnerOnly(const char *path);
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