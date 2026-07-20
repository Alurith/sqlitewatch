"use strict";

// Deliberately load the native binding after process startup. SQLiteWatch must
// observe this with the Frida module observer while the target is spawned.
setTimeout(() => {
  try {
    const Database = require("better-sqlite3");
    const database = new Database(":memory:");
    database.exec("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL)");

    const insert = database.prepare("INSERT INTO users (id, name) VALUES (?, ?)");
    const insertMany = database.transaction((rows) => {
      for (const row of rows) insert.run(row.id, row.name);
    });
    insertMany([
      { id: 1, name: "Ada" },
      { id: 2, name: "Grace" },
    ]);

    const selected = database
      .prepare("SELECT name FROM users WHERE id = ?")
      .all(1);
    const sorted = database
      .prepare("SELECT name FROM users ORDER BY name")
      .all();
    // better-sqlite3 uses prepare_v3 for Database#prepare. Keep equivalent
    // prepare_v2 paths as well because this phase intentionally hooks only
    // sqlite3_prepare_v2. sqlite3_exec prepares the marker query with an
    // unbound value; the real bound query above remains the functional gate.
    database.exec("SELECT name FROM users WHERE id = ?");
    database.exec("SELECT name FROM users ORDER BY name");
    if (selected.length !== 1 || selected[0].name !== "Ada") process.exitCode = 2;
    if (sorted.map((row) => row.name).join(",") !== "Ada,Grace") process.exitCode = 3;
    console.log("names=" + sorted.map((row) => row.name).join(","));
    database.close();
  } catch (error) {
    console.error(error && error.stack ? error.stack : String(error));
    process.exitCode = 1;
  }
}, 50);
