"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { api, ApiError } from "@/lib/api";
import type { ScanReportSummary } from "@/lib/types";
import { useToast } from "@/components/Toast";
import { PolicyCardSkeleton } from "@/components/Skeleton";

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

export default function ReportsPage() {
  const toast = useToast();
  const [reports, setReports] = useState<ScanReportSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [confirmingId, setConfirmingId] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const confirmTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

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
                    {r.policy_name} <span className="report-version-pill">{r.policy_version}</span>
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
    </div>
  );
}
