#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "os_port.h"
#include "tests.h"

#define TASKS 64

/* a field of /proc/self/status (VmSize in kB, Threads), -1 if there is none */
static long status_field(const char *name)
{
    FILE *file = fopen("/proc/self/status", "r");
    if (file == NULL)
    {
        return -1;
    }
    char line[256];
    long value = -1;
    size_t length = strlen(name);
    while (fgets(line, sizeof(line), file) != NULL)
    {
        if (strncmp(line, name, length) == 0 && line[length] == ':')
        {
            sscanf(line + length + 1, "%ld", &value);
            break;
        }
    }
    fclose(file);
    return value;
}

static void ending_task(void *arg)
{
    (void)arg;
    osDeleteTask(OS_SELF_TASK_ID);
}

/* Tasks that end themselves (a stream, a TAP being generated) give their stack back: nothing joins a task, and a
   joinable thread nobody joins keeps its stack mapped after it ended. */
void test_os_task_ends_without_its_stack(void)
{
    if (status_field("VmSize") < 0)
    {
        printf("         no /proc/self/status, skipped\n");
        return;
    }
    pthread_attr_t attr;
    size_t stack = 0;
    assert(pthread_attr_init(&attr) == 0);
    assert(pthread_attr_getstacksize(&attr, &stack) == 0);
    pthread_attr_destroy(&attr);

    long threads = status_field("Threads");
    long before = status_field("VmSize");
    for (int i = 0; i < TASKS; i++)
    {
        assert(osCreateTask("ending", ending_task, NULL, &OS_TASK_DEFAULT_PARAMS) != (OsTaskId)OS_INVALID_TASK_ID);
    }
    /* until they have all ended */
    for (int i = 0; i < 500 && status_field("Threads") > threads; i++)
    {
        nanosleep(&(struct timespec){.tv_nsec = 10 * 1000 * 1000}, NULL);
    }
    assert(status_field("Threads") == threads);

    /* a stack each if they keep them; glibc keeps a few given back (up to 40 MB) for the next threads */
    long grown = (status_field("VmSize") - before) * 1024;
    printf("         %d tasks ended, address space grew by %ld MB (a stack is %zu MB)\n", TASKS, grown / (1024 * 1024), stack / (1024 * 1024));
    fflush(stdout);
    assert(grown < (long)(TASKS / 2 * stack));
}
