"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { api, ApiError } from "@/lib/api";
import type { Policy, ScanReportSummary } from "@/lib/types";
import { useToast } from "@/components/Toast";
import { PolicyCardSkeleton } from "@/components/Skeleton";
import { PolicyPreviewModal } from "@/components/PolicyPreviewModal";
import { roundDelta } from "@/lib/format";

function gradeBadgeClass(grade: string): string {
  if (grade === "A" || grade === "B") return "badge-PASS";
  if (grade === "C" || grade === "D") return "badge-WARNING";
  return "badge-FAIL";
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

// Mirrors the backend's default label for a raw scan with no target name
// (app.core.scan_comparison.DEFAULT_RAW_TARGET_NAME) - a placeholder, not an
// identity, so those scans are never compared.
const DEFAULT_RAW_TARGET_NAME = "HTTP Response Scan";

/** Client-side score delta per report, against its immediately-earlier
 * report sharing the same target+policy+version - the same comparison
 * identity the backend's /comparison endpoint uses. Ad-hoc reports
 * (policy_id === null) and unnamed raw scans are never compared, matching
 * that endpoint's rules.
 * This is a cheap visual hint only; the authoritative diff lives in
 * ComparisonPanel on the report detail page. */
function computeScoreDeltas(reports: ScanReportSummary[]): Map<string, number> {
  const deltas = new Map<string, number>();
  const groups = new Map<string, ScanReportSummary[]>();

  for (const r of reports) {
    if (!r.policy_id) continue;
    if (r.source === "raw" && r.target === DEFAULT_RAW_TARGET_NAME) continue;
    const key = `${r.target ?? ""}|${r.policy_id}|${r.policy_version}`;
    const group = groups.get(key) ?? [];
    group.push(r);
    groups.set(key, group);
  }

  for (const group of groups.values()) {
    const sorted = [...group].sort(
      (a, b) => new Date(a.scanned_at).getTime() - new Date(b.scanned_at).getTime()
    );
    for (let i = 1; i < sorted.length; i++) {
      deltas.set(sorted[i].id, roundDelta(sorted[i].score - sorted[i - 1].score));
    }
  }

  return deltas;
}

function DeltaIndicator({ delta }: { delta: number | undefined }) {
  if (delta === undefined) return null;
  if (delta === 0) {
    return <span className="field-hint comparison-delta">→ No change</span>;
  }
  const sign = delta > 0 ? "↑" : "↓";
  const className = delta > 0 ? "comparison-added" : "comparison-removed";
  return (
    <span className={`comparison-delta ${className}`}>
      {sign} {delta > 0 ? "+" : ""}
      {delta}
    </span>
  );
}

export default function ReportsPage() {
  const toast = useToast();
  const [reports, setReports] = useState<ScanReportSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [confirmingId, setConfirmingId] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [previewPolicy, setPreviewPolicy] = useState<Policy | null>(null);
  const confirmTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const scoreDeltas = useMemo(() => computeScoreDeltas(reports), [reports]);

  function load() {
    setLoading(true);
    api
      .listReports()
      .then(setReports)
      .catch((e) => setError(e instanceof ApiError ? e.message : "Failed to load reports."))
      .finally(() => setLoading(false));
  }

  useEffect(load, []);

  function requestDelete(id: string) {
    if (confirmingId === id) {
      if (confirmTimer.current) clearTimeout(confirmTimer.current);
      setConfirmingId(null);
      void performDelete(id);
      return;
    }
    setConfirmingId(id);
    if (confirmTimer.current) clearTimeout(confirmTimer.current);
    confirmTimer.current = setTimeout(() => setConfirmingId(null), 3000);
  }

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

  async function performDelete(id: string) {
    setDeletingId(id);
    try {
      await api.deleteReport(id);
      toast.show("Report deleted.", "success");
      load();
    } catch (e) {
      toast.show(e instanceof ApiError ? e.message : "Failed to delete report.", "error");
    } finally {
      setDeletingId(null);
    }
  }

  return (
    <div className="container">
      <h1 style={{ fontSize: 24, marginBottom: 4 }}>Reports</h1>
      <p className="field-hint" style={{ marginBottom: 20 }}>
        A history of your past scans. Only the headers your policy actually checked are
        saved — not the full response.
      </p>

      {error && <div className="error-box">{error}</div>}

      {loading && (
        <div className="panel">
          <PolicyCardSkeleton />
          <PolicyCardSkeleton />
          <PolicyCardSkeleton />
        </div>
      )}

      {!loading && (
        <div className="panel fade-in-up">
          {reports.length === 0 ? (
            <p className="empty-state">
              No scans saved yet. <Link href="/scan">Run a scan</Link> and it will show up
              here.
            </p>
          ) : (
            reports.map((r) => (
              <div className="policy-card" key={r.id}>
                <div className="policy-card-info">
                  <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <span className="report-scan-badge">{r.scan_number}</span>
                    <span style={{ fontWeight: 600 }} className="mono">
                      {r.target ?? "—"}
                    </span>
                  </div>
                  <div className="policy-card-meta">
                    {r.policy_id ? (
                      <button
                        type="button"
                        className="link-button"
                        onClick={() => void openPolicy(r.policy_id as string)}
                      >
                        {r.policy_name}
                      </button>
                    ) : (
                      r.policy_name
                    )}{" "}
                    <span className="report-version-pill">{r.policy_version}</span>
                    {" · "}
                    {formatDate(r.scanned_at)}
                    {" · "}
                    {r.headers_evaluated} header{r.headers_evaluated === 1 ? "" : "s"} evaluated
                  </div>
                </div>
                <div className="policy-card-actions report-actions">
                  <span className={`badge ${gradeBadgeClass(r.grade)}`}>
                    {r.grade} · {r.score}
                  </span>
                  <DeltaIndicator delta={scoreDeltas.get(r.id)} />
                  <div className="report-actions-buttons">
                    <Link className="btn btn-secondary btn-sm" href={`/reports/${r.id}`}>
                      View
                    </Link>
                    <button
                      className={`btn btn-sm ${confirmingId === r.id ? "btn-danger-solid" : "btn-danger"}`}
                      onClick={() => requestDelete(r.id)}
                      disabled={deletingId === r.id}
                    >
                      {deletingId === r.id
                        ? "Deleting…"
                        : confirmingId === r.id
                          ? "Confirm?"
                          : "Delete"}
                    </button>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {previewPolicy && (
        <PolicyPreviewModal policy={previewPolicy} onClose={() => setPreviewPolicy(null)} />
      )}
    </div>
  );
}
