// Frontend unit tests (node --test) for the pure utility layer.
// These run alongside `cargo test` in the local verification pipeline and
// verify the UTC/relative-time and validation helpers the console depends on.
import test from "node:test";
import assert from "node:assert/strict";

// utils.js is a browser-module; import it as text-free ES module — it only
// touches navigator/document inside functions we do not call here.
const utils = await import("../frontend/assets/js/utils.js");

test("fmtUtc formats unix seconds in UTC", () => {
  assert.equal(utils.fmtUtc(0), "1970-01-01 00:00:00Z");
  assert.equal(utils.fmtUtc(1_800_000_000), "2027-01-15 08:00:00Z");
  assert.equal(utils.fmtUtc(null), "—");
});

test("fmtUtc accepts RFC3339 strings (the API wire format)", () => {
  assert.equal(utils.fmtUtc("2027-01-15T08:00:00Z"), "2027-01-15 08:00:00Z");
  assert.equal(utils.fmtUtc("2027-01-15 08:00:00Z"), "2027-01-15 08:00:00Z");
  assert.equal(utils.fmtUtc("garbage"), "—");
});

test("fmtUtcMs formats milliseconds", () => {
  assert.equal(utils.fmtUtcMs(1_234), "1970-01-01 00:00:01.234Z");
  assert.equal(utils.fmtUtcMs(undefined), "—");
});

test("fmtRelative produces sane deltas", () => {
  const now = 1_000_000_000_000;
  assert.equal(utils.fmtRelative(now, now - 10_000), "10s ago");
  assert.equal(utils.fmtRelative(now, now - 5 * 60_000), "5m ago");
  assert.equal(utils.fmtRelative(now, now - 3 * 3_600_000), "3h ago");
  assert.equal(utils.fmtRelative(now, now - 100 * 3_600_000), "4d ago");
  // never negative
  assert.equal(utils.fmtRelative(now, now + 5_000), "0s ago");
});

test("fmtDuration renders human spans", () => {
  assert.equal(utils.fmtDuration(45), "45s");
  assert.equal(utils.fmtDuration(90), "1m 30s");
  assert.equal(utils.fmtDuration(3600), "1h");
  assert.equal(utils.fmtDuration(90000), "1d 1h");
});

test("daysUntil rounds toward days", () => {
  const now = 1_000_000;
  assert.equal(utils.daysUntil(now, now + 86_400 * 10), 10);
  assert.equal(utils.daysUntil(now, now - 86_400), -1);
});

test("looksLikeEmail matches the conservative client-side check", () => {
  assert.equal(utils.looksLikeEmail("alice@example.io"), true);
  assert.equal(utils.looksLikeEmail("bad@@x"), false);
  assert.equal(utils.looksLikeEmail("no-at-sign"), false);
});

test("clamp bounds values", () => {
  assert.equal(utils.clamp(5, 0, 10), 5);
  assert.equal(utils.clamp(-1, 0, 10), 0);
  assert.equal(utils.clamp(99, 0, 10), 10);
});

test("derivedStatus delegates to the API's computed value", () => {
  assert.equal(utils.derivedStatus("active", { derived_status: "expired" }), "expired");
  assert.equal(utils.derivedStatus("active", { status: "active" }), "active");
  assert.equal(utils.derivedStatus("active", null), "none");
});

test("isUnavailable distinguishes unknown from zero", () => {
  assert.equal(utils.isUnavailable(null), true);
  assert.equal(utils.isUnavailable(undefined), true);
  assert.equal(utils.isUnavailable("unavailable"), true);
  assert.equal(utils.isUnavailable(0), false);
  assert.equal(utils.isUnavailable(17), false);
});

test("escapeAttr neutralizes attribute injection", () => {
  assert.equal(utils.escapeAttr('a"><script'), "a&quot;&gt;&lt;script");
  assert.equal(utils.escapeAttr("plain"), "plain");
});
