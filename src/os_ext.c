#include "os_ext.h"

#ifdef _WIN32
#include <process.h>
#else
#include <sys/wait.h>
#include <unistd.h>
#endif

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

void osStringToUpper(char *str)
{
    while (*str)
    {
        *str = toupper(*str);
        str++;
    }
}

void osStringToLower(char *str)
{
    while (*str)
    {
        *str = tolower(*str);
        str++;
    }
}

int osSpawnvp(const char *file, char *const argv[])
{
#ifdef _WIN32
    intptr_t rc = _spawnvp(_P_WAIT, file, (const char *const *)argv);
    return (rc == -1) ? -1 : (int)rc;
#else
    pid_t pid = fork();
    if (pid < 0)
    {
        return -1;
    }
    if (pid == 0)
    {
        execvp(file, argv);
        _exit(127); // execvp only returns on failure
    }
    int status;
    if (waitpid(pid, &status, 0) < 0)
    {
        return -1;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
#endif
}