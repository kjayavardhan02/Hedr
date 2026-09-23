import { jsPDF } from "jspdf";
import autoTable, { type CellHookData } from "jspdf-autotable";
import type { CSPFinding, HeaderFinding } from "./types";

// Accepted by both a live ScanResult and a saved ScanReport - scan_number
// and policy_version only exist on saved reports, so they're optional.
export interface PdfReportData {
  policy_name: string;
  target: string | null;
  fetched_status_code: number | null;
  score: number;
  grade: string;
  findings: HeaderFinding[];
  csp_finding: CSPFinding | null;
  scanned_at: string;
  scan_number?: number;
  policy_version?: string;
}

const MARGIN_X = 40;
const PAGE_BOTTOM = 790;
const ACCENT_RGB: [number, number, number] = [255, 122, 26];
const STATUS_COLOR: Record<string, [number, number, number]> = {
  PASS: [30, 140, 60],
  FAIL: [200, 50, 50],
  WARNING: [180, 130, 20],
  INFO: [90, 90, 90],
};

function finalY(doc: jsPDF): number {
  return (doc as unknown as { lastAutoTable?: { finalY: number } }).lastAutoTable?.finalY ?? 60;
}

function ensureSpace(doc: jsPDF, y: number, needed = 60): number {
  if (y + needed > PAGE_BOTTOM) {
    doc.addPage();
    return 50;
  }
  return y;
}

function statusColorHook(statusColumnIndex: number) {
  return (hook: CellHookData) => {
    if (hook.section === "body" && hook.column.index === statusColumnIndex) {
      const color = STATUS_COLOR[String(hook.cell.raw)];
      if (color) hook.cell.styles.textColor = color;
    }
  };
}

export function downloadReportPdf(data: PdfReportData): void {
  const doc = new jsPDF({ unit: "pt", format: "a4" });
  let y = 50;

  doc.setFontSize(18);
  doc.setFont("helvetica", "bold");
  doc.setTextColor(0);
  doc.text("Hedr Security Scan Report", MARGIN_X, y);
  y += 26;

  doc.setFontSize(10);
  doc.setFont("helvetica", "normal");
  doc.setTextColor(90);
  const metaLines = [
    data.scan_number ? `Scan #${data.scan_number}` : null,
    `Policy: ${data.policy_name}${data.policy_version ? ` (${data.policy_version})` : ""}`,
    `Target: ${data.target ?? "Pasted response"}`,
    data.fetched_status_code != null ? `HTTP status: ${data.fetched_status_code}` : null,
    `Scanned: ${new Date(data.scanned_at).toLocaleString()}`,
  ].filter((line): line is string => Boolean(line));
  for (const line of metaLines) {
    doc.text(line, MARGIN_X, y);
    y += 14;
  }
  y += 10;

  const passCount = data.findings.filter((f) => f.status === "PASS").length;
  const failCount = data.findings.filter((f) => f.status === "FAIL").length;
  const gradeColor = STATUS_COLOR[data.grade === "F" ? "FAIL" : data.grade === "A" || data.grade === "B" ? "PASS" : "WARNING"];

  doc.setFontSize(15);
  doc.setFont("helvetica", "bold");
  doc.setTextColor(...gradeColor);
  doc.text(`Score: ${data.score} (Grade ${data.grade})`, MARGIN_X, y);
  y += 18;

  doc.setFontSize(10);
  doc.setFont("helvetica", "normal");
  doc.setTextColor(90);
  doc.text(`${passCount} passed  ·  ${failCount} failed`, MARGIN_X, y);
  y += 24;

  if (data.findings.length > 0) {
    autoTable(doc, {
      startY: y,
      head: [["Header", "Status", "Severity", "Score", "Policy Expected", "Actual Value"]],
      body: data.findings.map((f) => [
        f.header,
        f.status,
        f.severity,
        `${f.score_earned}/${f.score_possible}`,
        f.policy_expected ?? "-",
        f.actual_value ?? "(missing)",
      ]),
      margin: { left: MARGIN_X, right: MARGIN_X },
      styles: { fontSize: 8, cellPadding: 5, overflow: "linebreak" },
      headStyles: { fillColor: ACCENT_RGB, textColor: 255 },
      columnStyles: { 4: { cellWidth: 110 }, 5: { cellWidth: 110 } },
      didParseCell: statusColorHook(1),
    });
    y = finalY(doc) + 20;
  }

  const nonPassing = data.findings.filter((f) => f.status !== "PASS" && f.recommendation);
  if (nonPassing.length > 0) {
    y = ensureSpace(doc, y, 40);
    doc.setFontSize(12);
    doc.setFont("helvetica", "bold");
    doc.setTextColor(0);
    doc.text("Recommendations", MARGIN_X, y);
    y += 16;

    doc.setFontSize(9);
    doc.setFont("helvetica", "normal");
    doc.setTextColor(60);
    for (const f of nonPassing) {
      const lines = doc.splitTextToSize(`${f.header}: ${f.recommendation}`, 515) as string[];
      for (const line of lines) {
        y = ensureSpace(doc, y, 14);
        doc.text(line, MARGIN_X, y);
        y += 12;
      }
      y += 4;
    }
    y += 10;
  }

  if (data.csp_finding) {
    const cspRows = [
      ...data.csp_finding.policy_checks.map((c) => [
        c.id ?? "-",
        "Policy",
        c.description,
        c.severity ?? "-",
        c.status,
        c.expected ?? "-",
        c.actual ?? "-",
      ]),
      ...data.csp_finding.security_checks.map((c) => [
        c.id ?? "-",
        "Best practice",
        c.description,
        c.severity ?? "-",
        c.status,
        c.expected ?? "-",
        c.actual ?? "-",
      ]),
    ];
    if (cspRows.length > 0) {
      y = ensureSpace(doc, y, 60);
      doc.setFontSize(13);
      doc.setFont("helvetica", "bold");
      doc.setTextColor(0);
      doc.text("Content-Security-Policy Analysis", MARGIN_X, y);
      y += 14;

      doc.setFontSize(9);
      doc.setFont("helvetica", "normal");
      doc.setTextColor(90);
      doc.text(
        `Policy Compliance: ${data.csp_finding.policy_checks_passed}/${data.csp_finding.policy_checks_total}` +
          `  ·  Best-Practice: ${data.csp_finding.best_practice_passed}/${data.csp_finding.best_practice_total}` +
          `  ·  Overall CSP Score: ${data.csp_finding.overall_score}`,
        MARGIN_X,
        y
      );
      y += 14;

      autoTable(doc, {
        startY: y,
        head: [["ID", "Category", "Check", "Severity", "Status", "Expected", "Actual"]],
        body: cspRows,
        margin: { left: MARGIN_X, right: MARGIN_X },
        styles: { fontSize: 8, cellPadding: 5, overflow: "linebreak" },
        headStyles: { fillColor: ACCENT_RGB, textColor: 255 },
        didParseCell: statusColorHook(4),
      });
      y = finalY(doc) + 16;
    }
  }

  const pageCount = doc.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setTextColor(150);
    doc.text(
      `Generated by Hedr on ${new Date().toLocaleString()}  ·  Page ${i} of ${pageCount}`,
      MARGIN_X,
      815
    );
  }

  const slug = (data.target ?? "scan").replace(/[^a-z0-9]+/gi, "-").toLowerCase().slice(0, 40);
  const suffix = data.scan_number ? `scan-${data.scan_number}` : "result";
  doc.save(`hedr-${slug}-${suffix}.pdf`);
}
