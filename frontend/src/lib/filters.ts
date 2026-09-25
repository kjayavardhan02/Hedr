export const DATE_PRESETS = [
  { label: "Today", days: 0 },
  { label: "Last 7 days", days: 6 },
  { label: "Last 30 days", days: 29 },
];

/** yyyy-mm-dd of a timestamp in the viewer's local timezone, to match <input type="date">. */
export function localDateKey(iso: string): string {
  const d = new Date(iso);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

/** Inclusive local-date range ending today and starting `days` days earlier. */
export function presetRange(days: number): { from: string; to: string } {
  const end = new Date();
  const start = new Date();
  start.setDate(end.getDate() - days);
  return { from: localDateKey(start.toISOString()), to: localDateKey(end.toISOString()) };
}

/** Whether a timestamp's local day falls inside an inclusive from/to range (either may be empty). */
export function inDateRange(iso: string, from: string, to: string): boolean {
  const day = localDateKey(iso);
  return (!from || day >= from) && (!to || day <= to);
}

function shortDay(key: string): string {
  const [y, m, d] = key.split("-").map(Number);
  return new Date(y, m - 1, d).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
}

/** Human label for a from/to range, e.g. "Sep 20, 2026 – Sep 26, 2026". */
export function describeDateRange(from: string, to: string): string {
  if (from && to) return from === to ? shortDay(from) : `${shortDay(from)} – ${shortDay(to)}`;
  return from ? `From ${shortDay(from)}` : `Until ${shortDay(to)}`;
}
