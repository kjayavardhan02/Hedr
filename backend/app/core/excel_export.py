"""Generates the Burp History Security Header Analysis workbook.

Consumes the same normalized BurpAnalysisResult the UI reads - this module
performs no analysis of its own (see hedr-burp-history-ui-excel-export.md
section 34: "The Excel generator should not perform security analysis
itself.").
"""
from __future__ import annotations

import io
import re

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.worksheet.table import Table, TableStyleInfo
from openpyxl.worksheet.worksheet import Worksheet

from app import models
from app.schemas import BurpAnalysisResult, EndpointAnalysisOut

_EM_DASH = "—"
_HEADER_FILL = PatternFill(start_color="FFE8630A", end_color="FFE8630A", fill_type="solid")
_HEADER_FONT = Font(color="FFFFFFFF", bold=True)
_WRAP = Alignment(wrap_text=True, vertical="top")


def _display_value(status: str, actual_value: str | None) -> str:
    """Missing and Not Applicable are never confused with a real value - both
    render as an em dash, never the word "Missing" itself, so a reviewer
    filtering this column for real CSP values never has to exclude that
    literal string (spec section 15)."""
    if status in ("missing", "not_applicable"):
        return _EM_DASH
    return actual_value or _EM_DASH


def _status_label(status: str) -> str:
    return {"present": "Present", "missing": "Missing", "invalid": "Invalid", "not_applicable": "Not Applicable"}[
        status
    ]


def _autosize(ws: Worksheet, max_width: int = 60) -> None:
    for column_cells in ws.columns:
        first = next((c for c in column_cells if c.value is not None), None)
        if first is None:
            continue
        col_letter = first.column_letter
        longest = max((len(str(c.value)) for c in column_cells if c.value is not None), default=10)
        ws.column_dimensions[col_letter].width = min(max(longest + 2, 10), max_width)


def _style_header_row(ws: Worksheet, ncols: int) -> None:
    for col in range(1, ncols + 1):
        cell = ws.cell(row=1, column=col)
        cell.fill = _HEADER_FILL
        cell.font = _HEADER_FONT
    ws.freeze_panes = "A2"


def _add_table(ws: Worksheet, name: str, nrows: int, ncols: int) -> None:
    if nrows == 0:
        return
    last_col = ws.cell(row=1, column=ncols).column_letter
    ref = f"A1:{last_col}{nrows + 1}"
    table = Table(displayName=name, ref=ref)
    table.tableStyleInfo = TableStyleInfo(
        name="TableStyleMedium2", showRowStripes=True, showFirstColumn=False, showLastColumn=False
    )
    ws.add_table(table)


def _summary_sheet(wb: Workbook, record: models.BurpImport, analysis: BurpAnalysisResult) -> None:
    ws = wb.create_sheet("Summary")
    ws.append(["Burp History Security Header Analysis"])
    ws["A1"].font = Font(bold=True, size=14)
    ws.append([])
    ws.append(["Report Name", record.name])
    ws.append(["Source File", record.source_filename])
    ws.append(["Policy", record.policy_name or ""])
    ws.append(["Policy Version", record.policy_version or ""])
    ws.append(["Analysis Type", "Burp History"])
    ws.append(["Imported At", record.imported_at.isoformat() if record.imported_at else ""])
    ws.append(["Analyzed At", record.analyzed_at.isoformat() if record.analyzed_at else ""])
    ws.append([])
    ws.append(["Metric", "Value"])
    metric_header_row = ws.max_row
    ws.append(["Total History Entries", record.entries_found])
    ws.append(["Responses Analyzed", analysis.summary.responses_analyzed])
    ws.append(["Responses Skipped", record.responses_skipped])
    ws.append(["Parse Failures", record.parse_failures])
    ws.append(["Unique Domains", analysis.summary.unique_hosts])
    ws.append(["Unique Paths", analysis.summary.unique_paths])
    ws.append(["Overall Policy Score", f"{analysis.summary.overall_score}%"])
    ws.append(["Responses With Findings", analysis.summary.responses_with_findings])
    ws[f"A{metric_header_row}"].font = Font(bold=True)
    ws[f"B{metric_header_row}"].font = Font(bold=True)
    for row in range(3, 9):
        ws[f"A{row}"].font = Font(bold=True)
    ws.column_dimensions["A"].width = 26
    ws.column_dimensions["B"].width = 40


def _endpoint_analysis_sheet(wb: Workbook, record: models.BurpImport, analysis: BurpAnalysisResult) -> None:
    ws = wb.create_sheet("Endpoint Analysis", 0)
    header_names = [row.header for row in analysis.header_coverage]

    columns = ["Domain", "Path", "Method", "Status Code", "Content-Type"]
    for name in header_names:
        columns += [name, f"{name} Status"]
    columns += ["Policy Score", "Findings"]
    ws.append(columns)

    for endpoint in analysis.endpoints:
        by_header = {hr.header: hr for hr in endpoint.header_results}
        row: list[object] = [
            endpoint.domain,
            endpoint.path,
            endpoint.method,
            endpoint.status_code,
            endpoint.content_type or "",
        ]
        failing: list[str] = []
        for name in header_names:
            hr = by_header.get(name)
            if hr is None:
                row += [_EM_DASH, _EM_DASH]
                continue
            row += [_display_value(hr.status, hr.actual_value), _status_label(hr.status)]
            if hr.status in ("missing", "invalid"):
                failing.append(f"{name} {hr.status}")
        row += [f"{endpoint.policy_score}%", "; ".join(failing) if failing else "None"]
        ws.append(row)

    _style_header_row(ws, len(columns))
    _add_table(ws, "EndpointAnalysis", len(analysis.endpoints), len(columns))
    _autosize(ws)
    # Long CSP-style values need to stay readable rather than truncated.
    for name in header_names:
        col_idx = columns.index(name) + 1
        col_letter = ws.cell(row=1, column=col_idx).column_letter
        ws.column_dimensions[col_letter].width = 40
        for row in range(2, len(analysis.endpoints) + 2):
            ws.cell(row=row, column=col_idx).alignment = _WRAP


def _header_coverage_sheet(wb: Workbook, analysis: BurpAnalysisResult) -> None:
    ws = wb.create_sheet("Header Coverage")
    ws.append(["Header", "Present", "Missing", "Invalid", "Not Applicable", "Coverage"])
    for row in analysis.header_coverage:
        ws.append([row.header, row.present, row.missing, row.invalid, row.not_applicable, f"{row.coverage}%"])
    _style_header_row(ws, 6)
    _add_table(ws, "HeaderCoverage", len(analysis.header_coverage), 6)
    _autosize(ws)


def _findings_sheet(wb: Workbook, record: models.BurpImport, analysis: BurpAnalysisResult) -> None:
    ws = wb.create_sheet("Findings")
    columns = [
        "Domain",
        "Path",
        "Method",
        "Status Code",
        "Header",
        "Finding",
        "Severity",
        "Expected Value",
        "Actual Value",
        "Policy",
        "Policy Version",
    ]
    ws.append(columns)

    def _endpoint_findings(endpoint: EndpointAnalysisOut):
        for hr in endpoint.header_results:
            if hr.status not in ("missing", "invalid"):
                continue
            yield hr

    nrows = 0
    for endpoint in analysis.endpoints:
        for hr in _endpoint_findings(endpoint):
            ws.append(
                [
                    endpoint.domain,
                    endpoint.path,
                    endpoint.method,
                    endpoint.status_code,
                    hr.header,
                    _status_label(hr.status),
                    (hr.severity or "").capitalize(),
                    hr.expected_value or _EM_DASH,
                    _display_value(hr.status, hr.actual_value),
                    record.policy_name or "",
                    record.policy_version or "",
                ]
            )
            nrows += 1

    _style_header_row(ws, len(columns))
    _add_table(ws, "Findings", nrows, len(columns))
    _autosize(ws)


def _import_issues_sheet(wb: Workbook, analysis: BurpAnalysisResult) -> None:
    if not analysis.import_issues:
        return
    ws = wb.create_sheet("Import Issues")
    ws.append(["Entry", "URL", "Host", "Path", "Status", "Reason"])
    for issue in analysis.import_issues:
        ws.append([issue.index, issue.url or "", issue.host or "", issue.path or "", issue.status.capitalize(), issue.reason or ""])
    _style_header_row(ws, 6)
    _add_table(ws, "ImportIssues", len(analysis.import_issues), 6)
    _autosize(ws)


def build_workbook(record: models.BurpImport) -> bytes:
    if record.analysis is None:
        raise ValueError("This import hasn't been analyzed yet.")
    analysis = BurpAnalysisResult.model_validate(record.analysis)

    wb = Workbook()
    wb.remove(wb.active)  # the default blank sheet - each sheet below is created explicitly, in order
    _endpoint_analysis_sheet(wb, record, analysis)
    _summary_sheet(wb, record, analysis)
    _header_coverage_sheet(wb, analysis)
    _findings_sheet(wb, record, analysis)
    _import_issues_sheet(wb, analysis)

    buffer = io.BytesIO()
    wb.save(buffer)
    return buffer.getvalue()


def export_filename(record: models.BurpImport) -> str:
    # Strip characters that are unsafe in a filename across platforms/browsers.
    safe_name = re.sub(r'[\\/*?:"<>|]', "", record.name).strip() or "Burp History"
    return f"{safe_name} - Security Header Analysis.xlsx"
