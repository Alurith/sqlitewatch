"""Small standard-library SQLite fixture, kept outside the first native gate."""

import sqlite3


def main() -> int:
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)")
    connection.executemany("INSERT INTO users VALUES (?, ?)", [(1, "Ada"), (2, "Grace")])
    rows = connection.execute("SELECT name FROM users WHERE id = ?", (1,)).fetchall()
    print("names=" + ",".join(row[0] for row in rows))
    connection.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
