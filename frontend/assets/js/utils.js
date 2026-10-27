// Pure helpers shared across the console. No DOM access in this file so
// it stays testable under `node --test` (see scripts/test-frontend.mjs).

/**
 * Format a timestamp as "YYYY-MM-DD HH:MM:SSZ" (UTC).
 * Accepts unix SECONDS (number) OR an RFC3339 string — the API returns
 * RFC3339 strings everywhere, while some call sites hold numeric seconds.
 */
export function fmtUtc(v) {
  const d = toDate(v, 1000);
  return d ? d.toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z") : "—";
}

/** Same, for millisecond values or RFC3339 strings with ms precision. */
export function fmtUtcMs(v) {
  const d = toDate(v, 1);
  return d ? d.toISOString().replace("T", " ") : "—";
}

function toDate(v, multiplier) {
  if (v === null || v === undefined || v === "") return null;
  let d;
  if (typeof v === "number") d = new Date(v * multiplier);
  else if (typeof v === "string") {
    // Normal space-separated form ("2027-01-15 08:00:00Z") is not valid
    // input for Date on all engines — convert to ISO "T" form first.
    d = new Date(v.includes(" ") ? v.replace(" ", "T") : v);
  } else return null;
  return isNaN(d.getTime()) ? null : d;
}

/** "3m ago"-style relative time (rounded, never negative). */
export function fmtRelative(nowMs, tsMs) {
  const d = Math.max(0, nowMs - tsMs);
  const s = Math.round(d / 1000);
  if (s < 45) return s + "s ago";
  const m = Math.round(s / 60);
  if (m < 60) return m + "m ago";
  const h = Math.round(m / 60);
  if (h < 48) return h + "h ago";
  return Math.round(h / 24) + "d ago";
}

/** Duration in seconds → "1h 30m" etc. */
export function fmtDuration(s) {
  s = Math.max(0, Math.round(s));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return s % 60 ? `${m}m ${s % 60}s` : `${m}m`;
  const h = Math.floor(m / 60);
  const rem = m % 60;
  if (h < 24) return rem ? `${h}h ${rem}m` : `${h}h`;
  const d = Math.floor(h / 24);
  return `${d}d ${h % 24}h`;
}

/** Days until a unix-seconds timestamp (negative = past). */
export function daysUntil(nowSecs, targetSecs) {
  return Math.round((targetSecs - nowSecs) / 86400);
}

/** Conservative email check (server validates authoritatively). */
export function looksLikeEmail(v) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v.trim());
}

/** Copy text to the clipboard; returns success. */
export function copyText(text) {
  if (navigator?.clipboard?.writeText) {
    return navigator.clipboard.writeText(text).then(() => true, () => fallbackCopy(text));
  }
  return Promise.resolve(fallbackCopy(text));
}

function fallbackCopy(text) {
  try {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
    return true;
  } catch {
    return false;
  }
}

/** Clamp for pagination etc. */
export function clamp(n, lo, hi) {
  return Math.min(hi, Math.max(lo, n));
}

/** Derive a short label for user statuses the API does not compute. */
export function derivedStatus(userStatus, sub) {
  if (!sub) return "none";
  if (sub.derived_status) return sub.derived_status;
  return sub.status || "none";
}

/** Map metric value cells that may be "unavailable" markers. */
export function isUnavailable(v) {
  return v === null || v === undefined || v === "unavailable";
}

/** Escape a string for safe attribute interpolation. */
export function escapeAttr(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}
