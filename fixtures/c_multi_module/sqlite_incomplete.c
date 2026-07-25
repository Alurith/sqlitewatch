/* Active module with prepare/step/finalize but no reset or metric reader. */
#include <stddef.h>
#include <string.h>

typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt { int marker; } sqlite3_stmt;
static sqlite3_stmt statement = {42};

int sqlite3_prepare_v2(sqlite3 *db, const char *sql, int nbyte, sqlite3_stmt **stmt, const char **tail) {
    (void)db;
    if (sql == NULL || stmt == NULL) return 1;
    *stmt = &statement;
    if (tail != NULL) {
        size_t length = nbyte < 0 ? strlen(sql) : (size_t)nbyte;
        *tail = sql + length;
    }
    return 0;
}
int sqlite3_step(sqlite3_stmt *stmt) { return stmt == &statement ? 101 : 1; }
int sqlite3_finalize(sqlite3_stmt *stmt) { return stmt == &statement ? 0 : 1; }
const char *sqlite3_libversion(void) { return "fixture-incomplete"; }
