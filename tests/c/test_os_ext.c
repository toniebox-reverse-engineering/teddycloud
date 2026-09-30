#include <assert.h>

#include "os_ext.h"
#include "tests.h"

void test_os_spawnvp(void)
{
    char *argv_true[] = {"true", NULL};
    assert(osSpawnvp("true", argv_true) == 0);

    char *argv_false[] = {"false", NULL};
    assert(osSpawnvp("false", argv_false) == 1);

    char *argv_exit[] = {"sh", "-c", "exit 42", NULL};
    assert(osSpawnvp("sh", argv_exit) == 42);

    char *argv_missing[] = {"this-binary-does-not-exist-xyz", NULL};
    assert(osSpawnvp("this-binary-does-not-exist-xyz", argv_missing) == 127);
}
