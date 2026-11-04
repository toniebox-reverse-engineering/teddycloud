#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

void test_fs_flush_file(void)
{
    /* the content download writes a file that boxes read at the same time, each with its own handle */
    char path[] = "/tmp/teddycloud_test_XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0);
    close(fd);

    FILE *writer = fopen(path, "wb");
    FILE *reader = fopen(path, "rb");
    assert(writer != NULL && reader != NULL);

    char data[] = "audio";
    char got[sizeof(data)] = {0};
    assert(fwrite(data, 1, sizeof(data), writer) == sizeof(data));
    assert(fsFlushFile(writer) == NO_ERROR);
    assert(fread(got, 1, sizeof(got), reader) == sizeof(data));
    assert(memcmp(got, data, sizeof(data)) == 0);
    assert(fsFlushFile(NULL) != NO_ERROR);

    fclose(reader);
    fclose(writer);
    unlink(path);
}
