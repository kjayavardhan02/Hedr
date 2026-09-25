"use client";

import { api, ApiError } from "@/lib/api";
import { downloadReportPdf } from "@/lib/pdf";
import { downloadReportJson } from "@/lib/exportJson";
import { downloadReportCsv } from "@/lib/exportCsv";
import type { Policy, ScanReport, ScanResult } from "@/lib/types";
import { ExportDropdown } from "./ExportDropdown";

/** Loads the saved policy for the PDF, but only if it is still the version that was scanned. */
async function policyForPdf(data: ScanReport | ScanResult) {
  const policyId = "policy_id" in data ? data.policy_id : null;
  if (!policyId) return {};
  try {
    const policy: Policy = await api.getPolicy(policyId);
    const scanned = "policy_version" in data ? data.policy_version : null;
    if (scanned && `v${policy.version}` !== scanned) {
      return {
        policyNote: `This policy has since been edited (now v${policy.version}). The rules below are rebuilt from what was evaluated in this scan (${scanned}).`,
      };
    }
    return { policy };
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) {
      return { policyNote: "The saved policy no longer exists. The rules below are rebuilt from what was evaluated in this scan." };
    }
    return {};
  }
}

/** Export options for a single report or scan result (PDF, JSON, CSV). */
export function ExportMenu({ data }: { data: ScanReport | ScanResult }) {
  return (
    <ExportDropdown
      items={[
        {
          label: "Download PDF",
          onSelect: async () => downloadReportPdf(data, await policyForPdf(data)),
        },
        { label: "Download JSON", onSelect: () => downloadReportJson(data) },
        { label: "Download CSV", onSelect: () => downloadReportCsv(data) },
      ]}
    />
  );
}
