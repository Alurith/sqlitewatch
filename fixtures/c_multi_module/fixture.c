#define _GNU_SOURCE
#include <dlfcn.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

typedef struct sqlite3_stmt sqlite3_stmt;
typedef int (*prepare_fn)(void *, const char *, int, sqlite3_stmt **, const char **);
typedef int (*step_fn)(sqlite3_stmt *);
typedef int (*finalize_fn)(sqlite3_stmt *);

static void *load_sibling(const char *name) {
    char executable[PATH_MAX];
    ssize_t length = readlink("/proc/self/exe", executable, sizeof(executable) - 1);
    if (length <= 0) return NULL;
    executable[length] = '\0';
    char path[PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/%s", dirname(executable), name) >= (int)sizeof(path)) return NULL;
    return dlopen(path, RTLD_NOW | RTLD_LOCAL);
}

int main(void) {
    void *complete = load_sibling("libsqlite_complete.so");
    void *incomplete = load_sibling("libsqlite_incomplete.so");
    if (complete == NULL || incomplete == NULL) return 2;
    prepare_fn prepare;
    step_fn step;
    finalize_fn finalize;
    *(void **)(&prepare) = dlsym(incomplete, "sqlite3_prepare_v2");
    *(void **)(&step) = dlsym(incomplete, "sqlite3_step");
    *(void **)(&finalize) = dlsym(incomplete, "sqlite3_finalize");
    if (prepare == NULL || step == NULL || finalize == NULL) return 3;
    sqlite3_stmt *statement = NULL;
    const char *tail = NULL;
    const char sql[] = "SELECT partial_module";
    if (prepare((void *)0x1, sql, -1, &statement, &tail) != 0) return 4;
    if (tail == NULL || strcmp(tail, "") != 0) return 5;
    if (step(statement) != 101 || finalize(statement) != 0) return 6;
    puts("partial-module=observed");
    usleep(100000);
    dlclose(incomplete);
    dlclose(complete);
    return 0;
}
