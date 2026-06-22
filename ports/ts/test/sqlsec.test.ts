import { strict as assert } from "node:assert";
import test from "node:test";
import { scanText, Finding } from "../src/sqlsec";

const has = (fs: Finding[], id: string) => fs.some((f) => f.ruleId === id);

test("concatenation flagged as SQL001", () => {
  const fs = scanText('const q = "SELECT * FROM users WHERE id = " + userId;');
  assert.ok(has(fs, "SQL001"));
});

test("template literal interpolation flagged as SQL002", () => {
  const fs = scanText("const q = `SELECT * FROM t WHERE name = '${name}'`;");
  assert.ok(has(fs, "SQL002"));
});

test("printf-style formatting flagged as SQL003", () => {
  const fs = scanText('q = "SELECT * FROM t WHERE id = %s" % value');
  assert.ok(has(fs, "SQL003"));
});

test("non-SQL concatenation ignored", () => {
  const fs = scanText('const greeting = "hello " + name;');
  assert.equal(fs.length, 0);
});

test("parameterized query is clean", () => {
  const fs = scanText('db.query("SELECT * FROM users WHERE id = $1", [userId]);');
  assert.equal(fs.length, 0);
});

test("line numbers reported", () => {
  const fs = scanText('const x = 1;\n\nconst q = "SELECT a FROM t WHERE b=" + v;');
  assert.equal(fs[0].line, 3);
});

test("empty input yields no findings", () => {
  assert.equal(scanText("").length, 0);
});
