"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { api, ApiError } from "@/lib/api";
import type { ScanReport } from "@/lib/types";
import { ScoreHero } from "@/components/ScoreHero";
import { FindingCard } from "@/components/FindingCard";
import { CSPPanel } from "@/components/CSPPanel";
import { BackLink } from "@/components/BackLink";
import { PolicyFormSkeleton } from "@/components/Skeleton";

export default function ReportDetailPage() {
  const params = useParams<{ id: string }>();
  const id = params.id;

  const [report, setReport] = useState<ScanReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

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

  return (
    <div className="container">
      <BackLink href="/reports" label="Back to Reports" />
      <p className="field-hint" style={{ marginBottom: 12 }}>
        Scan #{report.scan_number} · Policy version {report.policy_version} ·{" "}
        {report.headers_evaluated} header{report.headers_evaluated === 1 ? "" : "s"} evaluated
      </p>
      <ScoreHero result={report} />

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
    </div>
  );
}
