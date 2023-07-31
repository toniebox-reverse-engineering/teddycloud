
#include "fs_port.h"

FsFile *fsOpenFileEx(const char_t *path, char *mode)
{
    // Workaround due to missing append in cyclone framwwork.

    // File pointer
    FILE *fp = NULL;

    // Make sure the pathname is valid
    if (path == NULL)
        return NULL;

    // Open the specified file
    fp = fopen(path, mode);

    // Return a handle to the file
    return fp;
}
