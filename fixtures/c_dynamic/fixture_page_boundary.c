#define _GNU_SOURCE
#include <sqlite3.h>
#include <sys/mman.h>
#include <unistd.h>

#include <stdio.h>
#include <string.h>

int main(void) {
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) return 2;
    unsigned char *mapping = mmap(
        NULL, (size_t)page_size * 2, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0
    );
    if (mapping == MAP_FAILED) return 3;
    if (mprotect(mapping + page_size, (size_t)page_size, PROT_NONE) != 0) return 4;
    const char sql[] = "SELECT 1 AS café";
    char *boundary_sql = (char *)mapping + page_size - sizeof(sql);
    memcpy(boundary_sql, sql, sizeof(sql));

    sqlite3 *db = NULL;
    sqlite3_stmt *statement = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) return 5;
    if (sqlite3_prepare_v2(db, boundary_sql, -1, &statement, NULL) != SQLITE_OK) return 6;
    if (sqlite3_step(statement) != SQLITE_ROW) return 7;
    sqlite3_finalize(statement);
    sqlite3_close(db);
    munmap(mapping, (size_t)page_size * 2);
    puts("page-boundary=ok");
    return 0;
}
