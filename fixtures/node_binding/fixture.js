"use strict";

// Deliberately load the native binding after process startup. SQLiteWatch must
// observe this with the Frida module observer while the target is spawned.
setTimeout(() => {
  try {
    const Database = require("better-sqlite3");
    const database = new Database(":memory:");
    database.exec(
      "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL);" +
      "PRAGMA automatic_index = ON;" +
      "CREATE TABLE join_left (join_key INTEGER NOT NULL, payload INTEGER NOT NULL);" +
      "CREATE TABLE join_right (join_key INTEGER NOT NULL, payload INTEGER NOT NULL);" +
      "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<256) " +
      "INSERT INTO join_left SELECT x, x % 5 FROM n;" +
      "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<256) " +
      "INSERT INTO join_right SELECT x, x % 7 FROM n;"
    );

    const insert = database.prepare("INSERT INTO users (id, name) VALUES (?, ?)");
    const insertMany = database.transaction((rows) => {
      for (const row of rows) insert.run(row.id, row.name);
    });
    insertMany([
      { id: 1, name: "Ada" },
      { id: 2, name: "Grace" },
    ]);

    // Database#prepare uses sqlite3_prepare_v3. Reusing this statement proves
    // two lifecycle executions without legacy exec() coverage queries.
    const selectedStatement = database.prepare("SELECT name FROM users WHERE id = ?");
    const selected = selectedStatement.all(1);
    const selectedAgain = selectedStatement.all(1);
    const sorted = database.prepare("SELECT name FROM users ORDER BY name").all();
    const automaticIndex = database.prepare(
      "SELECT count(*) AS count FROM join_left AS l JOIN join_right AS r ON l.join_key = r.join_key WHERE l.payload = ?"
    ).get(3);
    if (selected.length !== 1 || selected[0].name !== "Ada") process.exitCode = 2;
    if (selectedAgain.length !== 1 || selectedAgain[0].name !== "Ada") process.exitCode = 3;
    if (sorted.map((row) => row.name).join(",") !== "Ada,Grace") process.exitCode = 4;
    if (automaticIndex.count !== 51) process.exitCode = 5;
    console.log("names=" + sorted.map((row) => row.name).join(","));
    database.close();
  } catch (error) {
    console.error(error && error.stack ? error.stack : String(error));
    process.exitCode = 1;
  }
}, 50);
