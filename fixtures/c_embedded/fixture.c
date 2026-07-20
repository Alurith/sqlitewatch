#define _DEFAULT_SOURCE
#include "sqlite3.h"

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

int main(int argc, char **argv) {
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int rc;
    int result = 0;

    if (argc > 1 && strcmp(argv[1], "fail") == 0) return 7;

    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) return 2;
    rc = sqlite3_exec(
        db,
        "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL)",
        NULL,
        NULL,
        NULL
    );
    if (!check(rc, db, "create")) { result = 3; goto done; }

    rc = sqlite3_prepare_v2(
        db, "INSERT INTO users (id, name) VALUES (?, ?)", -1, &stmt, NULL
    );
    if (!check(rc, db, "prepare insert")) { result = 4; goto done; }
    sqlite3_bind_int(stmt, 1, 1);
    sqlite3_bind_text(stmt, 2, "Ada", -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    stmt = NULL;
    if (rc != SQLITE_DONE) { result = 5; goto done; }

    const char query[] = "SELECT name FROM users WHERE id = ?";
    rc = sqlite3_prepare_v2(db, query, (int)(sizeof(query) - 1), &stmt, NULL);
    if (!check(rc, db, "prepare select")) { result = 6; goto done; }
    sqlite3_bind_int(stmt, 1, 1);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW || strcmp((const char *)sqlite3_column_text(stmt, 0), "Ada") != 0) {
        result = 7;
    } else {
        printf("name=Ada\n");
    }
    sqlite3_finalize(stmt);
    stmt = NULL;

    rc = sqlite3_prepare_v2(db, "SELECT 1 -- utf8: caffè\n", -1, &stmt, NULL);
    if (rc == SQLITE_OK) sqlite3_finalize(stmt);
    stmt = NULL;

 done:
    if (stmt != NULL) sqlite3_finalize(stmt);
    if (db != NULL) sqlite3_close(db);
    usleep(100000);
    return result;
}
