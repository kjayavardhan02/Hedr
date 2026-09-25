"use client";

import { downloadReportPdf } from "@/lib/pdf";
import { downloadReportJson } from "@/lib/exportJson";
import { downloadReportCsv } from "@/lib/exportCsv";
import type { ScanReport, ScanResult } from "@/lib/types";
import { ExportDropdown } from "./ExportDropdown";

/** Export options for a single report or scan result (PDF, JSON, CSV). */
export function ExportMenu({ data }: { data: ScanReport | ScanResult }) {
  return (
    <ExportDropdown
      items={[
        { label: "Download PDF", onSelect: () => downloadReportPdf(data) },
        { label: "Download JSON", onSelect: () => downloadReportJson(data) },
        { label: "Download CSV", onSelect: () => downloadReportCsv(data) },
      ]}
    />
  );
}
