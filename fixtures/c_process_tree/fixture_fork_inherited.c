#define _DEFAULT_SOURCE
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    sqlite3 *database = NULL;
    sqlite3_stmt *statement = NULL;
    if (sqlite3_open(":memory:", &database) != SQLITE_OK) return 2;
    if (sqlite3_prepare_v2(
            database,
            "SELECT 424242 AS inherited_before_fork",
            -1,
            &statement,
            NULL
        ) != SQLITE_OK) return 3;

    pid_t child = fork();
    if (child < 0) return 4;
    if (child == 0) {
        int rc = sqlite3_step(statement);
        if (rc != SQLITE_ROW || sqlite3_column_int(statement, 0) != 424242) {
            _exit(5);
        }
        printf("fork-inherited=424242\n");
        fflush(stdout);
        sqlite3_finalize(statement);
        sqlite3_close(database);
        usleep(100000);
        _exit(0);
    }

    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0);
    sqlite3_finalize(statement);
    sqlite3_close(database);
    if (waited != child || !WIFEXITED(status)) return 6;
    return WEXITSTATUS(status);
}
