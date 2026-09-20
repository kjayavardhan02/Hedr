import type { ScanReport, ScanResult } from "./types";

function slugify(value: string): string {
  return value.replace(/[^a-z0-9]+/gi, "-").toLowerCase().slice(0, 40);
}

/** Downloads the full report/result object as-is - unlike the PDF export,
 * this isn't reshaped for readability, so it's suited to feeding into
 * another tool or a CI pipeline rather than for a human to read. */
export function downloadReportJson(data: ScanReport | ScanResult): void {
  const target = data.target ?? "scan";
  const suffix = "scan_number" in data && data.scan_number ? `scan-${data.scan_number}` : "result";
  const filename = `hedr-${slugify(target)}-${suffix}.json`;

  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
