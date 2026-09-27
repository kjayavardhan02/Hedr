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

/** Short absolute date with no year or time ("Sep 18") - for axis labels and
 * other tight spaces where `timeAgo`'s relative form would be ambiguous once
 * more than one is shown side by side. */
export function formatShortDate(iso: string): string {
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

const DEFAULT_PORTS: Record<string, string> = { "http:": "80", "https:": "443" };

/** Canonical form of a URL for target-identity matching: scheme and host
 * lower-cased, a default port dropped, and a bare root path ("" vs "/")
 * treated as the same address. The rest of the path (and query) stays
 * case-sensitive - different resources are different targets. Falls back to
 * lower-cased text for anything that isn't a plain http(s) URL. Mirrors the
 * backend's scan_comparison.normalize_target_url. */
export function normalizeTargetUrl(url: string): string {
  const text = url.trim().replace(/\s+/g, " ");
  let parsed: URL;
  try {
    parsed = new URL(text);
  } catch {
    return text.toLowerCase();
  }
  if (!/^https?:$/.test(parsed.protocol) || !parsed.hostname) return text.toLowerCase();
  const host = parsed.hostname.toLowerCase();
  const hostText = host.includes(":") ? `[${host}]` : host;
  const port = parsed.port && parsed.port !== DEFAULT_PORTS[parsed.protocol] ? `:${parsed.port}` : "";
  const path = parsed.pathname === "/" ? "" : parsed.pathname;
  const query = parsed.search || "";
  return `${parsed.protocol}//${hostText}${port}${path}${query}`;
}

/** This report's comparison identity: a normalized URL when one exists (a
 * fetched URL, or a raw scan's Target URL), else the normalized name. Two
 * reports are the same target exactly when their identities are equal - this
 * is what lets a raw scan tagged with a Target URL compare against a real
 * URL-mode scan of the same address. Mirrors the backend's
 * scan_comparison._target_identity. */
export function targetIdentity(report: {
  source: "url" | "raw";
  target: string | null;
  target_url?: string | null;
}): string {
  if (report.source === "url" && report.target) return `url:${normalizeTargetUrl(report.target)}`;
  if (report.source === "raw" && report.target_url) return `url:${normalizeTargetUrl(report.target_url)}`;
  return `name:${normalizeTargetName(report.target)}`;
}
