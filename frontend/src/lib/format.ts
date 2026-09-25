/** Capitalizes just the first character, leaving the rest untouched so
 * names like "McDonald" or "O'Brien" aren't mangled. */
export function capitalize(value: string): string {
  if (!value) return value;
  return value.charAt(0).toUpperCase() + value.slice(1);
}

/** Short relative time ("2 hours ago"), falling back to an absolute date
 * ("Sep 18") once it's more than a week old - matches how the Dashboard's
 * Latest Scan / Recent Scans need to read at a glance. */
export function timeAgo(iso: string): string {
  const diffMs = Date.now() - new Date(iso).getTime();
  const minute = 60_000;
  const hour = 60 * minute;
  const day = 24 * hour;

  if (diffMs < minute) return "just now";
  if (diffMs < hour) {
    const m = Math.floor(diffMs / minute);
    return `${m} minute${m === 1 ? "" : "s"} ago`;
  }
  if (diffMs < day) {
    const h = Math.floor(diffMs / hour);
    return `${h} hour${h === 1 ? "" : "s"} ago`;
  }
  if (diffMs < 7 * day) {
    const d = Math.floor(diffMs / day);
    return `${d} day${d === 1 ? "" : "s"} ago`;
  }
  return new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

/** Full absolute date + time ("Sep 18, 2026, 3:45 PM"), matching the format
 * already used on the Reports list for an exact, unambiguous timestamp. */
export function formatDateTime(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

/** Rounds a score difference to one decimal place (dropping a trailing
 * ".0"), which also removes float noise like 45.400000000000006 from a
 * subtraction of two stored scores. */
export function roundDelta(delta: number): number {
  const rounded = Math.round(delta * 10) / 10;
  return Object.is(rounded, -0) ? 0 : rounded;
}

/** Target names are compared loosely (case, surrounding and repeated spaces
 * ignored) so "Production API" and " production   api " are one target. The
 * original spelling is always kept for display. Mirrors the backend. */
export function normalizeTargetName(name: string | null | undefined): string {
  return (name ?? "").trim().replace(/\s+/g, " ").toLowerCase();
}
