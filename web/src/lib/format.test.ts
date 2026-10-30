// Run with Node's built-in test runner (npm test); no test library is used.
import { test } from "node:test";
import assert from "node:assert/strict";
import { alertTitle, bytes, clock, describeInterval, duration, observedText, operationKind, osLabel, percent, plural, relativeTime, short, triggerText, utcTime, windowLabel } from "./format.ts";

test("relativeTime buckets and edges", () => {
  const now = 1_800_000_000_000;
  const at = (secondsAgo: number) => now / 1000 - secondsAgo;
  assert.equal(relativeTime(null, now), "Never");
  assert.equal(relativeTime(0, now), "Never");
  assert.equal(relativeTime(at(-60), now), "in the future");
  assert.equal(relativeTime(at(-3), now), "just now");
  assert.equal(relativeTime(at(4), now), "just now");
  assert.equal(relativeTime(at(59), now), "59s ago");
  assert.equal(relativeTime(at(60), now), "1m ago");
  assert.equal(relativeTime(at(3599), now), "59m ago");
  assert.equal(relativeTime(at(3600), now), "1h ago");
  assert.equal(relativeTime(at(86400 * 29), now), "29d ago");
  assert.doesNotMatch(relativeTime(at(86400 * 31), now), /ago$/);
});

test("utcTime is ISO-like UTC", () => {
  assert.equal(utcTime(null), "Never");
  assert.equal(utcTime(1_700_000_000), "2023-11-14 22:13:20 UTC");
});

test("bytes", () => {
  assert.equal(bytes(null), "—");
  assert.equal(bytes(0), "0 B");
  assert.equal(bytes(1023), "1023 B");
  assert.equal(bytes(1536), "1.5 KB");
  assert.equal(bytes(200 * 1024 * 1024), "200 MB");
  assert.equal(bytes(1024 ** 6), "1024 PB");
});

test("percent and duration", () => {
  assert.equal(percent(undefined), "—");
  assert.equal(percent(Number.NaN), "—");
  assert.equal(percent(12.345, 1), "12.3%");
  assert.equal(duration(null), "—");
  assert.equal(duration(59), "0m");
  assert.equal(duration(3 * 3600 + 120), "3h 2m");
  assert.equal(duration(2 * 86400 + 5 * 3600), "2d 5h");
});

test("labels", () => {
  assert.equal(osLabel("windows"), "Windows");
  assert.equal(osLabel("windows", "10.0", 19045), "Windows 10.0 (build 19045)");
  assert.equal(osLabel("linux", "6.1"), "linux 6.1");
  assert.equal(operationKind("agent-upgrades"), "Agent update");
  assert.equal(operationKind("other"), "other");
  assert.equal(alertTitle("cpu"), "High CPU");
  assert.equal(alertTitle("health", "Spooler"), "Spooler");
  assert.equal(alertTitle("cpu", "ignored"), "High CPU");
  assert.equal(alertTitle("agent_update"), "Agent update failed");
  assert.equal(plural(1, "device"), "1 device");
  assert.equal(plural(2, "device"), "2 devices");
  assert.equal(plural(0, "policy", "policies"), "0 policies");
});

test("maintenance windows wrap at midnight", () => {
  assert.equal(clock(0), "00:00");
  assert.equal(clock(605), "10:05");
  assert.equal(windowLabel(1, 22 * 60, 180), "Monday 22:00–01:00 UTC");
});

test("short hashes", () => {
  assert.equal(short("abc"), "abc");
  assert.equal(short("0123456789abcdef"), "0123456789ab…");
  assert.equal(short("0123456789abcdef", 4), "0123…");
});

test("describeInterval", () => {
  assert.equal(describeInterval(0), "Once");
  assert.equal(describeInterval(86400), "Daily");
  assert.equal(describeInterval(3 * 86400), "Every 3 days");
  assert.equal(describeInterval(3600), "Hourly");
  assert.equal(describeInterval(7200), "Every 2 hours");
  assert.equal(describeInterval(900), "Every 15 minutes");
});

test("observedText marks free disk space", () => {
  assert.equal(observedText("disk_space", 8.04), "8% free");
  assert.equal(observedText("memory", 91.26, 1), "91.3%");
});

test("triggerText per family", () => {
  const a = { kind: "memory", threshold: 90, hold_seconds: 600 };
  assert.equal(triggerText(a, "metric"), "Memory use at or above 90% for 10 min.");
  assert.equal(triggerText({ ...a, kind: "cpu" }, "metric"), "CPU use at or above 90% for 10 min.");
  assert.equal(triggerText({ ...a, hold_seconds: 7200 }, "offline"), "No contact for 2 h after the connection timeout.");
  assert.match(triggerText(a, "disk_space"), /below 90%/);
  assert.match(triggerText(a, "agent_update"), /paused until you resume/);
});
