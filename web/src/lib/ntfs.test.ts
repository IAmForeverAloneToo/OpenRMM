import { test } from "node:test";
import assert from "node:assert/strict";
import { ntfsVolumes } from "./ntfs.ts";

test("ntfsVolumes reads drive letters", () => {
  assert.deepEqual(ntfsVolumes(""), []);
  assert.deepEqual(ntfsVolumes(" all "), ["all"]);
  assert.deepEqual(ntfsVolumes("c d:, E:"), ["C:", "D:", "E:"]);
  assert.equal(ntfsVolumes("C: c"), null);
  assert.equal(ntfsVolumes("C:\Windows"), null);
  assert.equal(ntfsVolumes("all D:"), null);
});
