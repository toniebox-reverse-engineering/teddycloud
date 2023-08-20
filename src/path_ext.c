
#include "path_ext.h"

void pathSafeCanonicalize(char *path)
{
    if (!path || osStrlen(path) == 0)
    {
        return;
    }

    pathCanonicalize(path);

    const char *pattern = "../";
    const size_t pattern_len = osStrlen(pattern);

    while (osStrncmp(path, pattern, pattern_len) == 0)
    {
        osMemmove(path, path + pattern_len, 1 + osStrlen(path + pattern_len));
    }
}
