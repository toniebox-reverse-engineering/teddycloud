#include "os_ext.h"

FILE *osPopen(const char *command, const char *type)
{
#ifdef _WIN32
    return _popen(command, type);
#else
    return popen(command, type);
#endif
}

int osPclose(FILE *stream)
{
#ifdef _WIN32
    return _pclose(stream);
#else
    return pclose(stream);
#endif
}