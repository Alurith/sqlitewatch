#define _GNU_SOURCE
#include <sqlite3.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <string.h>

int main(int argc, char **argv) {
    sqlite3 *db = NULL;
    sqlite3_stmt *statement = NULL;
    const char *sql = argc > 1 && strcmp(argv[1], "fast") == 0
        ? "SELECT 987654"
        : "WITH RECURSIVE count_rows(x) AS (VALUES(0) UNION ALL "
          "SELECT x + 1 FROM count_rows WHERE x < 100000) "
          "SELECT sum(x) FROM count_rows";
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) return 2;
    if (sqlite3_prepare_v2(db, sql, -1, &statement, NULL) != SQLITE_OK) return 3;
    if (sqlite3_step(statement) != SQLITE_ROW) return 4;
    /* Bypass libc cleanup and statement finalization immediately after the
       expensive first row. SQLiteWatch must retain a flushed started marker. */
    syscall(SYS_exit_group, 0);
    return 5;
}
