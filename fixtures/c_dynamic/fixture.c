#define _DEFAULT_SOURCE
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int check(int rc, sqlite3 *db, const char *where) {
    if (rc != SQLITE_OK && rc != SQLITE_ROW && rc != SQLITE_DONE) {
        fprintf(stderr, "%s: %s\n", where, sqlite3_errmsg(db));
        return 0;
    }
    return 1;
}

static int run_select_cycle(sqlite3_stmt *stmt, int id) {
    int rc = sqlite3_bind_int(stmt, 1, id);
    if (rc != SQLITE_OK) return 0;
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW || strcmp((const char *)sqlite3_column_text(stmt, 0), "Ada") != 0) {
        return 0;
    }
    return sqlite3_step(stmt) == SQLITE_DONE;
}

static int run_to_done(sqlite3_stmt *stmt) {
    int rc;
    do {
        rc = sqlite3_step(stmt);
    } while (rc == SQLITE_ROW);
    return rc == SQLITE_DONE;
}

int main(int argc, char **argv) {
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int rc;
    int result = 0;
    int fail_after_work = argc > 1 && strcmp(argv[1], "fail-after-work") == 0;

    if (argc > 1 && strcmp(argv[1], "fail") == 0) return 7;
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) return 2;
    rc = sqlite3_exec(db, "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL)", NULL, NULL, NULL);
    if (!check(rc, db, "create")) { result = 3; goto done; }

    rc = sqlite3_prepare_v2(db, "INSERT INTO users (id, name) VALUES (?, ?)", -1, &stmt, NULL);
    if (!check(rc, db, "prepare insert")) { result = 4; goto done; }
    sqlite3_bind_int(stmt, 1, 1);
    sqlite3_bind_text(stmt, 2, "Ada", -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    stmt = NULL;
    if (rc != SQLITE_DONE) { result = 5; goto done; }

    /* Explicit nByte and two complete cycles make reset/reuse observable. */
    const char query[] = "SELECT name FROM users WHERE id = ?";
    rc = sqlite3_prepare_v2(db, query, (int)(sizeof(query) - 1), &stmt, NULL);
    if (!check(rc, db, "prepare reused select")) { result = 6; goto done; }
    if (!run_select_cycle(stmt, 1)) { result = 7; goto done; }
    rc = sqlite3_reset(stmt);
    if (rc != SQLITE_OK) { result = 8; goto done; }
    if (!run_select_cycle(stmt, 1)) { result = 9; goto done; }
    printf("name=Ada\n");
    rc = sqlite3_finalize(stmt);
    stmt = NULL;
    if (rc != SQLITE_OK) { result = 10; goto done; }

    /* prepare_v3 has a distinct ABI and must be observed directly. */
    rc = sqlite3_prepare_v3(db, "SELECT 42", -1, 0, &stmt, NULL);
    if (!check(rc, db, "prepare v3")) { result = 11; goto done; }
    if (sqlite3_step(stmt) != SQLITE_ROW || sqlite3_column_int(stmt, 0) != 42) {
        result = 12; goto done;
    }
    sqlite3_finalize(stmt);
    stmt = NULL;

    /* Controlled metric workloads: properties, not version-specific totals. */
    rc = sqlite3_exec(db,
        "CREATE TABLE scan_rows (id INTEGER PRIMARY KEY, value INTEGER NOT NULL);"
        "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<256) "
        "INSERT INTO scan_rows SELECT x, x % 17 FROM n;"
        "PRAGMA automatic_index = ON;"
        "CREATE TABLE join_left (join_key INTEGER NOT NULL, payload INTEGER NOT NULL);"
        "CREATE TABLE join_right (join_key INTEGER NOT NULL, payload INTEGER NOT NULL);"
        "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<256) "
        "INSERT INTO join_left SELECT x, x % 5 FROM n;"
        "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<256) "
        "INSERT INTO join_right SELECT x, x % 7 FROM n;",
        NULL, NULL, NULL);
    if (!check(rc, db, "create metric data")) { result = 13; goto done; }

    const char scan_sql[] = "SELECT value FROM scan_rows WHERE value = ?";
    rc = sqlite3_prepare_v2(db, scan_sql, -1, &stmt, NULL);
    if (!check(rc, db, "prepare scan")) { result = 14; goto done; }
    sqlite3_bind_int(stmt, 1, 3);
    if (!run_to_done(stmt)) { result = 15; goto done; }
    if (sqlite3_reset(stmt) != SQLITE_OK) { result = 16; goto done; }
    sqlite3_bind_int(stmt, 1, 4);
    if (!run_to_done(stmt)) { result = 17; goto done; }
    sqlite3_finalize(stmt);
    stmt = NULL;

    rc = sqlite3_prepare_v2(db, "SELECT value FROM scan_rows ORDER BY value DESC", -1, &stmt, NULL);
    if (!check(rc, db, "prepare sort")) { result = 18; goto done; }
    if (!run_to_done(stmt)) { result = 19; goto done; }
    sqlite3_finalize(stmt);
    stmt = NULL;

    rc = sqlite3_prepare_v2(db,
        "SELECT count(*) FROM join_left AS l JOIN join_right AS r ON l.join_key = r.join_key WHERE l.payload = ?",
        -1, &stmt, NULL);
    if (!check(rc, db, "prepare autoindex join")) { result = 20; goto done; }
    sqlite3_bind_int(stmt, 1, 3);
    if (!run_to_done(stmt)) { result = 21; goto done; }
    if (sqlite3_stmt_status(stmt, SQLITE_STMTSTATUS_AUTOINDEX, 0) <= 0) {
        fprintf(stderr, "autoindex workload did not select an automatic index\n");
        result = 22;
        goto done;
    }
    sqlite3_finalize(stmt);
    stmt = NULL;

    /* nByte = -1 and a bounded long SQL input exercise capture limits. */
    rc = sqlite3_prepare_v2(db, "SELECT 1 -- utf8: caffè\n", -1, &stmt, NULL);
    if (rc == SQLITE_OK) sqlite3_finalize(stmt);
    stmt = NULL;
    rc = sqlite3_prepare_v2(db, "SELECT 'long-query-marker-0123456789'", -1, &stmt, NULL);
    if (rc == SQLITE_OK) sqlite3_finalize(stmt);
    stmt = NULL;

done:
    if (stmt != NULL) sqlite3_finalize(stmt);
    if (db != NULL) sqlite3_close(db);
    usleep(100000);
    return fail_after_work && result == 0 ? 7 : result;
}
