import { test } from "node:test";
import assert from "node:assert/strict";
import { argumentsComplete, filetimeToUnix, parseKB, parseTags, reportQuery, slugify, tagPattern, versionCompare } from "./parse.ts";
import type { ScriptVersion } from "./types";

test("slugify produces unique, valid IDs", () => {
  assert.equal(slugify("Front Desk PCs", []), "front-desk-pcs");
  assert.equal(slugify("Café Ünits", []), "cafe-units");
  assert.equal(slugify("2nd floor", []), "x-2nd-floor");
  assert.equal(slugify("!!!", []), "x");
  assert.equal(slugify("Lab", ["lab", "lab-2"]), "lab-3");
  assert.ok(slugify("a".repeat(60), []).length <= 28);
});

test("parseTags dedupes, lowercases and sorts", () => {
  assert.deepEqual(parseTags(" Kiosk, lab,LAB,, servers "), ["kiosk", "lab", "servers"]);
  assert.deepEqual(parseTags(""), []);
  assert.ok(tagPattern.test("win-11.x_ok"));
  assert.ok(!tagPattern.test("-bad"));
  assert.ok(!tagPattern.test("a".repeat(33)));
});

test("parseKB accepts mixed separators and prefixes", () => {
  assert.deepEqual(parseKB("KB5034441, 5034122;kb5034441\n 5030000"), ["5034441", "5034122", "5030000"]);
  assert.deepEqual(parseKB("  "), []);
});

test("versionCompare is numeric", () => {
  assert.ok(versionCompare("1.10.0", "1.9.9") > 0);
  assert.ok(versionCompare("1.2", "1.2.1") < 0);
  assert.equal(versionCompare("2.0.0", "2.0"), 0);
});

test("filetimeToUnix", () => {
  assert.equal(filetimeToUnix("133000000000000000"), 1_655_526_400);
  assert.equal(filetimeToUnix("0"), null);
  assert.equal(filetimeToUnix("not a number"), null);
});

test("argumentsComplete requires every required parameter", () => {
  const v = { definition: { parameters: [{ name: "path", required: true }, { name: "note", required: false }] } } as unknown as ScriptVersion;
  assert.equal(argumentsComplete(undefined, {}), false);
  assert.equal(argumentsComplete(v, {}), false);
  assert.equal(argumentsComplete(v, { path: "" }), false);
  assert.equal(argumentsComplete(v, { path: "C:\\x" }), true);
});

test("reportQuery drops empty values", () => {
  assert.equal(reportQuery({ q: "chrome", group: "", os: "windows" }), "q=chrome&os=windows");
  assert.equal(reportQuery({}), "");
});
