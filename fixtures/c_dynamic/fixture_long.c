#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    const int preparations = 200;
    const size_t length = 60 * 1024;
    char *sql = malloc(length + 1);
    sqlite3 *db = NULL;
    sqlite3_stmt *statement = NULL;
    if (sql == NULL) return 2;
    memcpy(sql, "SELECT 1 -- ", 12);
    memset(sql + 12, 'x', length - 12);
    sql[length] = '\0';
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) return 3;
    for (int index = 0; index < preparations; index++) {
        if (sqlite3_prepare_v2(db, sql, -1, &statement, NULL) != SQLITE_OK) return 4;
        if (sqlite3_finalize(statement) != SQLITE_OK) return 5;
        statement = NULL;
    }
    sqlite3_close(db);
    free(sql);
    printf("long-prepares=%d\n", preparations);
    return 0;
}
