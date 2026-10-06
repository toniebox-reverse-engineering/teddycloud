#pragma once

/* Each test_*.c file defines one of these and registers it in test_runner.c. */
void test_os_spawnvp(void);
void test_os_shell_quote(void);
void test_os_chmod_owner_only(void);
void test_fs_remove_filename(void);
void test_hex_encode(void);
void test_escape_string(void);
void test_split_url(void);
