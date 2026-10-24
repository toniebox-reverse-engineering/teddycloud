#include "os_ext.h"

#ifdef _WIN32
#include <process.h>
#else
#include <sys/stat.h>
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

bool osChmodOwnerOnly(const char *path)
{
#ifdef _WIN32
    (void)path;
    return true;
#else
    return chmod(path, S_IRUSR | S_IWUSR) == 0;
#endif
}

bool osShellQuote(char *dest, size_t dest_size, const char *src)
{
#ifdef _WIN32
    /* cmd.exe: everything inside double quotes is literal except '"' itself */
    if (strchr(src, '"'))
    {
        return false;
    }
    int len = snprintf(dest, dest_size, "\"%s\"", src);
    return len >= 0 && (size_t)len < dest_size;
#else
    /* sh: everything inside single quotes is literal, a ' becomes '\'' */
    if (dest_size < 3)
    {
        return false;
    }
    size_t j = 0;
    dest[j++] = '\'';
    for (; *src; src++)
    {
        size_t n = (*src == '\'') ? 4 : 1;
        if (j + n + 2 > dest_size) /* keep room for the closing quote and NUL */
        {
            return false;
        }
        if (n == 4)
        {
            memcpy(&dest[j], "'\\''", 4);
        }
        else
        {
            dest[j] = *src;
        }
        j += n;
    }
    dest[j++] = '\'';
    dest[j] = '\0';
    return true;
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