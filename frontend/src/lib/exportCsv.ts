import { downloadBlob, slugify, todayStamp } from "./download";
import type { CheckResult, ScanReport, ScanReportSummary, ScanResult } from "./types";

// Report data includes attacker-influenced text (header values, target names).
// A cell starting with = + - @ (or tab/CR) is run as a formula by Excel and
// Sheets, so those get a leading apostrophe to force plain text.
function csvCell(value: unknown): string {
  let text = value === null || value === undefined ? "" : String(value);
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function toCsv(rows: unknown[][]): string {
  // BOM so Excel opens UTF-8 correctly.
  return "﻿" + rows.map((row) => row.map(csvCell).join(",")).join("\r\n") + "\r\n";
}

/** One row per report - the list view as a spreadsheet. */
export function downloadReportsCsv(reports: ScanReportSummary[], filtered: boolean): void {
  const rows: unknown[][] = [
    ["scan_number", "target", "source", "policy", "policy_version", "scanned_at", "score", "grade", "headers_evaluated"],
    ...reports.map((r) => [
      r.scan_number,
      r.target,
      r.source,
      r.policy_name,
      r.policy_version,
      r.scanned_at,
      r.score,
      r.grade,
      r.headers_evaluated,
    ]),
  ];
  downloadBlob(
    toCsv(rows),
    `hedr-reports${filtered ? "-filtered" : ""}-${todayStamp()}.csv`,
    "text/csv;charset=utf-8"
  );
}

/** One row per finding of a single report: each header, then each CSP check. */
export function downloadReportCsv(data: ScanReport | ScanResult): void {
  const scanNumber = "scan_number" in data ? data.scan_number : "";
  const context = [scanNumber, data.target, data.policy_name];

  const cspRow = (section: string, c: CheckResult) => [
    ...context,
    section,
    c.id ? `${c.id} ${c.name}` : c.name,
    c.status,
    c.severity,
    c.expected,
    c.actual,
    c.description,
  ];

  const rows: unknown[][] = [
    ["scan_number", "target", "policy", "section", "name", "status", "severity", "expected", "actual", "recommendation"],
    ...data.findings.map((f) => [
      ...context,
      "Header",
      f.header,
      f.status,
      f.severity,
      f.policy_expected,
      f.actual_value,
      f.recommendation,
    ]),
    ...(data.csp_finding?.policy_checks ?? []).map((c) => cspRow("CSP policy check", c)),
    ...(data.csp_finding?.security_checks ?? []).map((c) => cspRow("CSP best practice", c)),
  ];

  const suffix = scanNumber ? `scan-${scanNumber}` : "result";
  downloadBlob(
    toCsv(rows),
    `hedr-${slugify(data.target ?? "scan")}-${suffix}.csv`,
    "text/csv;charset=utf-8"
  );
}
