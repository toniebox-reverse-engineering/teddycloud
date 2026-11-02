#include <assert.h>
#include <string.h>

#include "error.h"
#include "fs_ext.h"
#include "tests.h"

void test_fs_remove_filename(void)
{
    char path[] = "dir/file.bin";
    assert(fsRemoveFilename(path) == NO_ERROR);
    assert(strcmp(path, "dir") == 0);

    char dir[] = "dir/";
    assert(fsRemoveFilename(dir) == NO_ERROR);
    assert(strcmp(dir, "dir/") == 0);

    char bare[] = "file.bin";
    assert(fsRemoveFilename(bare) != NO_ERROR);
    assert(fsRemoveFilename(NULL) != NO_ERROR);

    /* An empty string used to be indexed at [-1]. Put a separator in front of it, so the
       old code mistook the empty string for a directory path and returned NO_ERROR. */
    char area[2] = {'/', '\0'};
    assert(fsRemoveFilename(&area[1]) != NO_ERROR);
}
