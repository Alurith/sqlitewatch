#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;
typedef int (*open_fn)(const char *, sqlite3 **);
typedef int (*close_fn)(sqlite3 *);
typedef int (*prepare_fn)(sqlite3 *, const char *, int, sqlite3_stmt **, const char **);
typedef int (*step_fn)(sqlite3_stmt *);
typedef int (*finalize_fn)(sqlite3_stmt *);
typedef int (*bind_int_fn)(sqlite3_stmt *, int, int);
typedef const unsigned char *(*column_text_fn)(sqlite3_stmt *, int);
typedef int (*column_int_fn)(sqlite3_stmt *, int);
typedef int (*exec_fn)(sqlite3 *, const char *, int (*)(void *, int, char **, char **), void *, char **);

int main(void) {
    void *handle;
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    open_fn sqlite3_open_ptr;
    close_fn sqlite3_close_ptr;
    prepare_fn sqlite3_prepare_v2_ptr;
    step_fn sqlite3_step_ptr;
    finalize_fn sqlite3_finalize_ptr;
    bind_int_fn sqlite3_bind_int_ptr;
    column_text_fn sqlite3_column_text_ptr;
    column_int_fn sqlite3_column_int_ptr;
    exec_fn sqlite3_exec_ptr;

    usleep(100000);
    handle = dlopen("libsqlite3.so.0", RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) handle = dlopen("libsqlite3.so", RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) return 2;
#define LOAD(name) do { *(void **)(&name##_ptr) = dlsym(handle, #name); if (name##_ptr == NULL) return 3; } while (0)
    LOAD(sqlite3_open);
    LOAD(sqlite3_close);
    LOAD(sqlite3_prepare_v2);
    LOAD(sqlite3_step);
    LOAD(sqlite3_finalize);
    LOAD(sqlite3_bind_int);
    LOAD(sqlite3_column_text);
    LOAD(sqlite3_column_int);
    LOAD(sqlite3_exec);
#undef LOAD

    if (sqlite3_open_ptr(":memory:", &db) != 0) return 4;
    if (sqlite3_exec_ptr(db, "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)", NULL, NULL, NULL) != 0) return 5;
    if (sqlite3_prepare_v2_ptr(db, "INSERT INTO users VALUES (?, 'Ada')", -1, &stmt, NULL) != 0) return 6;
    sqlite3_bind_int_ptr(stmt, 1, 1);
    if (sqlite3_step_ptr(stmt) != 101) return 7;
    sqlite3_finalize_ptr(stmt);
    stmt = NULL;
    if (sqlite3_prepare_v2_ptr(db, "SELECT name FROM users WHERE id = ?", -1, &stmt, NULL) != 0) return 8;
    sqlite3_bind_int_ptr(stmt, 1, 1);
    if (sqlite3_step_ptr(stmt) != 100 || strcmp((const char *)sqlite3_column_text_ptr(stmt, 0), "Ada") != 0) return 9;
    puts("name=Ada");
    sqlite3_finalize_ptr(stmt);
    stmt = NULL;
    sqlite3_close_ptr(db);
    db = NULL;
    dlclose(handle);

    /* Reloading the same module must reinstall listeners and clear address/name
       deduplication from the first instance. */
    usleep(100000);
    handle = dlopen("libsqlite3.so.0", RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) handle = dlopen("libsqlite3.so", RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) return 10;
#define RELOAD(name) do { *(void **)(&name##_ptr) = dlsym(handle, #name); if (name##_ptr == NULL) return 11; } while (0)
    RELOAD(sqlite3_open);
    RELOAD(sqlite3_close);
    RELOAD(sqlite3_prepare_v2);
    RELOAD(sqlite3_step);
    RELOAD(sqlite3_finalize);
    RELOAD(sqlite3_column_int);
#undef RELOAD
    if (sqlite3_open_ptr(":memory:", &db) != 0) return 12;
    if (sqlite3_prepare_v2_ptr(db, "SELECT 2", -1, &stmt, NULL) != 0) return 13;
    if (sqlite3_step_ptr(stmt) != 100 || sqlite3_column_int_ptr(stmt, 0) != 2) return 14;
    sqlite3_finalize_ptr(stmt);
    sqlite3_close_ptr(db);
    dlclose(handle);
    puts("reload=2");
    usleep(100000);
    return 0;
}
