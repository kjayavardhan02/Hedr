import { downloadBlob, slugify, todayStamp } from "./download";
import type { ScanReport, ScanResult } from "./types";

/** Downloads the full report/result object as-is - unlike the PDF export,
 * this isn't reshaped for readability, so it's suited to feeding into
 * another tool or a CI pipeline rather than for a human to read. */
export function downloadReportJson(data: ScanReport | ScanResult): void {
  const target = data.target ?? "scan";
  const suffix = "scan_number" in data && data.scan_number ? `scan-${data.scan_number}` : "result";
  downloadBlob(
    JSON.stringify(data, null, 2),
    `hedr-${slugify(target)}-${suffix}.json`,
    "application/json"
  );
}

/** Full reports (findings included) as one JSON array. */
export function downloadReportsJson(reports: ScanReport[], filtered: boolean): void {
  downloadBlob(
    JSON.stringify(reports, null, 2),
    `hedr-reports${filtered ? "-filtered" : ""}-${todayStamp()}.json`,
    "application/json"
  );
}
