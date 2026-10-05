#include <assert.h>
#include <string.h>

#include "os_ext.h"
#include "tests.h"

static void check_quote(const char *src, const char *expected)
{
    char buf[64];
    assert(osShellQuote(buf, sizeof(buf), src));
    assert(strcmp(buf, expected) == 0);
}

/* the shell must hand the quoted argument back unchanged */
static void check_round_trip(const char *src)
{
    char quoted[256];
    char cmd[300];
    char out[256];
    assert(osShellQuote(quoted, sizeof(quoted), src));
    snprintf(cmd, sizeof(cmd), "printf '%%s' %s", quoted);
    FILE *pipe = osPopen(cmd, "r");
    assert(pipe != NULL);
    size_t n = fread(out, 1, sizeof(out) - 1, pipe);
    osPclose(pipe);
    out[n] = '\0';
    assert(strcmp(out, src) == 0);
}

void test_os_shell_quote(void)
{
    check_quote("", "''");
    check_quote("a b.mp3", "'a b.mp3'");
    check_quote("it's", "'it'\\''s'");

    check_round_trip("/content/a b/it's.mp3");
    check_round_trip("'\"$HOME ; & | \\ '");

    char buf[6];
    assert(osShellQuote(buf, sizeof(buf), "abc"));   /* 'abc' + NUL fits exactly */
    assert(!osShellQuote(buf, sizeof(buf), "abcd")); /* one byte short */
    assert(!osShellQuote(buf, sizeof(buf), "a'b"));  /* 'a'\''b' needs 9 */
    assert(!osShellQuote(buf, 2, ""));
}

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
