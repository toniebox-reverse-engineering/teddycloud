/*
 * Runs pure C unit tests that don't need a running server (see tests/py/
 * for the HTTP-level integration tests). Each test function uses assert()
 * and aborts on the first failure, which is enough for `make test_c` to
 * fail loudly and point at the exact check that broke.
 */
#include <stdio.h>

#include "tests.h"

typedef struct
{
    const char *name;
    void (*fn)(void);
} test_case_t;

static const test_case_t tests[] = {
    {"os_spawnvp", test_os_spawnvp},
    {"os_shell_quote", test_os_shell_quote},
    {"os_chmod_owner_only", test_os_chmod_owner_only},
    {"fs_remove_filename", test_fs_remove_filename},
    {"hex_encode", test_hex_encode},
    {"escape_string", test_escape_string},
    {"split_url", test_split_url},
};

int main(void)
{
    size_t count = sizeof(tests) / sizeof(tests[0]);

    for (size_t i = 0; i < count; i++)
    {
        printf("[ RUN  ] %s\n", tests[i].name);
        tests[i].fn();
        printf("[  OK  ] %s\n", tests[i].name);
    }

    printf("%zu C test(s) passed\n", count);
    return 0;
}
