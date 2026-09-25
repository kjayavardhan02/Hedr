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
