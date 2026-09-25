"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { api, ApiError } from "@/lib/api";
import type { Policy, ScanReport } from "@/lib/types";
import { ExportMenu } from "@/components/ExportMenu";
import { ScoreHero } from "@/components/ScoreHero";
import { FindingCard } from "@/components/FindingCard";
import { CSPPanel } from "@/components/CSPPanel";
import { ComparisonPanel } from "@/components/ComparisonPanel";
import { BackLink } from "@/components/BackLink";
import { PolicyFormSkeleton } from "@/components/Skeleton";
import { useToast } from "@/components/Toast";
import { PolicyPreviewModal } from "@/components/PolicyPreviewModal";

export default function ReportDetailPage() {
  const params = useParams<{ id: string }>();
  const id = params.id;
  const toast = useToast();

  const [report, setReport] = useState<ScanReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [previewPolicy, setPreviewPolicy] = useState<Policy | null>(null);

  async function openPolicy(policyId: string) {
    try {
      const policy = await api.getPolicy(policyId);
      setPreviewPolicy(policy);
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) {
        toast.show(
          "This policy no longer exists — it may have been deleted since this scan.",
          "error"
        );
      } else {
        toast.show(e instanceof ApiError ? e.message : "Couldn't open this policy.", "error");
      }
    }
  }

  useEffect(() => {
    api
      .getReport(id)
      .then(setReport)
      .catch((e) => setError(e instanceof ApiError ? e.message : "Failed to load report."))
      .finally(() => setLoading(false));
  }, [id]);

  if (loading) {
    return (
      <div className="container">
        <BackLink href="/reports" label="Back to Reports" />
        <PolicyFormSkeleton />
      </div>
    );
  }

  if (!report) {
    return (
      <div className="container">
        <BackLink href="/reports" label="Back to Reports" />
        <div className="error-box">{error ?? "Report not found."}</div>
      </div>
    );
  }

  const scannedAt = new Date(report.scanned_at);

  return (
    <div className="container">
      <BackLink href="/reports" label="Back to Reports" />
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: 12,
          marginBottom: 12,
        }}
      >
        <div>
          <p className="field-hint" style={{ margin: 0, overflowWrap: "anywhere" }}>
            Scan #{report.scan_number} ·{" "}
            {report.policy_id ? (
              <button
                type="button"
                className="link-button"
                onClick={() => void openPolicy(report.policy_id as string)}
              >
                {report.policy_name}
              </button>
            ) : (
              report.policy_name
            )}{" "}
            ({report.policy_version}) · {report.headers_evaluated} header
            {report.headers_evaluated === 1 ? "" : "s"} evaluated
          </p>
          <p className="field-hint" style={{ margin: "4px 0 0" }}>
            <strong>Date:</strong> {scannedAt.toLocaleDateString(undefined, { dateStyle: "medium" })} ·{" "}
            <strong>Time:</strong> {scannedAt.toLocaleTimeString(undefined, { timeStyle: "medium" })}
          </p>
        </div>
        <ExportMenu data={report} />
      </div>
      <div className="report-top-row">
        <ScoreHero result={report} tinted />
        <ComparisonPanel reportId={id} />
      </div>

      <div className="panel fade-in-up" style={{ marginTop: 16, animationDelay: "40ms" }}>
        <h3 style={{ marginTop: 0, marginBottom: 12, fontSize: 16 }}>Findings</h3>
        {report.findings.length === 0 && (
          <p className="field-hint">No non-CSP headers were evaluated.</p>
        )}
        {report.findings.map((f, i) => (
          <FindingCard key={f.header} finding={f} index={i} />
        ))}
      </div>

      {report.csp_finding && <CSPPanel csp={report.csp_finding} />}

      {previewPolicy && (
        <PolicyPreviewModal policy={previewPolicy} onClose={() => setPreviewPolicy(null)} />
      )}
    </div>
  );
}
