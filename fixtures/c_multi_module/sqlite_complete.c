/* Complete but deliberately unused SQLite-shaped capability module. */
typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;

int sqlite3_prepare_v2(sqlite3 *db, const char *sql, int nbyte, sqlite3_stmt **stmt, const char **tail) {
    (void)db; (void)sql; (void)nbyte; (void)stmt; (void)tail;
    return 1;
}
int sqlite3_step(sqlite3_stmt *stmt) { (void)stmt; return 101; }
int sqlite3_reset(sqlite3_stmt *stmt) { (void)stmt; return 0; }
int sqlite3_finalize(sqlite3_stmt *stmt) { (void)stmt; return 0; }
int sqlite3_stmt_status(sqlite3_stmt *stmt, int operation, int reset) {
    (void)stmt; (void)operation; (void)reset; return 0;
}
const char *sqlite3_libversion(void) { return "fixture-complete"; }
