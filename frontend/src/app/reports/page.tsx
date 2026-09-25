"use client";

import { memo, useCallback, useDeferredValue, useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { api, ApiError } from "@/lib/api";
import type { Policy, ScanReportSummary } from "@/lib/types";
import { useToast } from "@/components/Toast";
import { PolicyCardSkeleton } from "@/components/Skeleton";
import { PolicyPreviewModal } from "@/components/PolicyPreviewModal";
import { normalizeTargetName, roundDelta } from "@/lib/format";

function gradeBadgeClass(grade: string): string {
  if (grade === "A" || grade === "B") return "badge-PASS";
  if (grade === "C" || grade === "D") return "badge-WARNING";
  return "badge-FAIL";
}

// One shared formatter: building an Intl formatter per row on every render is slow.
const DATE_FORMAT = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });

function formatDate(iso: string): string {
  return DATE_FORMAT.format(new Date(iso));
}

// Mirrors the backend's default label for a raw scan with no target name
// (app.core.scan_comparison.DEFAULT_RAW_TARGET_NAME) - a placeholder, not an
// identity, so those scans are never compared.
const DEFAULT_RAW_TARGET_NAME = "HTTP Response Scan";

/** Score change per report, shown only when a valid comparison exists.
 * Mirrors the backend: reports saved with a stored previous scan use exactly
 * that scan (no delta if it has been deleted); older reports fall back to the
 * immediately earlier scan with the same source, target (raw names compared
 * loosely), policy and policy version. Ad-hoc policies and unnamed raw scans
 * are never compared. A cheap visual hint - the authoritative diff lives in
 * ComparisonPanel on the report detail page. */
function computeScoreDeltas(reports: ScanReportSummary[]): Map<string, number> {
  const deltas = new Map<string, number>();
  const byId = new Map(reports.map((r) => [r.id, r]));
  const groups = new Map<string, ScanReportSummary[]>();

  const isAnonymous = (r: ScanReportSummary) =>
    r.source === "raw" && normalizeTargetName(r.target) === normalizeTargetName(DEFAULT_RAW_TARGET_NAME);

  for (const r of reports) {
    if (!r.policy_id || isAnonymous(r)) continue;
    const target = r.source === "raw" ? normalizeTargetName(r.target) : (r.target ?? "");
    const key = `${r.source}|${target}|${r.policy_id}|${r.policy_version}`;
    const group = groups.get(key) ?? [];
    group.push(r);
    groups.set(key, group);
  }

  for (const group of groups.values()) {
    const sorted = [...group].sort(
      (a, b) => new Date(a.scanned_at).getTime() - new Date(b.scanned_at).getTime()
    );
    for (let i = 0; i < sorted.length; i++) {
      const r = sorted[i];
      if (r.previous_report_id) {
        const previous = byId.get(r.previous_report_id);
        if (previous) deltas.set(r.id, roundDelta(r.score - previous.score));
      } else if (i > 0) {
        deltas.set(r.id, roundDelta(r.score - sorted[i - 1].score));
      }
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

type FilterField = "policy" | "target" | "date" | "grade";
const GRADES = ["A", "B", "C", "D", "F"];
const PAGE_SIZE = 30;

/** yyyy-mm-dd of a timestamp in the viewer's local timezone, to match <input type="date">. */
function localDateKey(iso: string): string {
  const d = new Date(iso);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

type ReportRowProps = {
  report: ScanReportSummary;
  delta: number | undefined;
  confirming: boolean;
  deleting: boolean;
  onOpenPolicy: (policyId: string) => void;
  onDelete: (id: string) => void;
};

// Memoised so typing in the filter box only re-renders rows whose props changed.
const ReportRow = memo(function ReportRow({
  report,
  delta,
  confirming,
  deleting,
  onOpenPolicy,
  onDelete,
}: ReportRowProps) {
  return (
    <div className="policy-card">
      <div className="policy-card-info">
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span className="report-scan-badge">{report.scan_number}</span>
          <span style={{ fontWeight: 600 }} className="mono">
            {report.target ?? "—"}
          </span>
        </div>
        <div className="policy-card-meta">
          {report.policy_id ? (
            <button
              type="button"
              className="link-button"
              onClick={() => onOpenPolicy(report.policy_id as string)}
            >
              {report.policy_name}
            </button>
          ) : (
            report.policy_name
          )}{" "}
          <span className="report-version-pill">{report.policy_version}</span>
          {" · "}
          {formatDate(report.scanned_at)}
          {" · "}
          {report.headers_evaluated} header{report.headers_evaluated === 1 ? "" : "s"} evaluated
        </div>
      </div>
      <div className="policy-card-actions report-actions">
        <span className={`badge ${gradeBadgeClass(report.grade)}`}>
          {report.grade} · {report.score}
        </span>
        <DeltaIndicator delta={delta} />
        <div className="report-actions-buttons">
          <Link className="btn btn-secondary btn-sm" href={`/reports/${report.id}`}>
            View
          </Link>
          <button
            className={`btn btn-sm ${confirming ? "btn-danger-solid" : "btn-danger"}`}
            onClick={() => onDelete(report.id)}
            disabled={deleting}
          >
            {deleting
              ? "Deleting…"
              : confirming
                ? "Confirm?"
                : "Delete"}
          </button>
        </div>
      </div>
    </div>
  );
});

export default function ReportsPage() {
  const toast = useToast();
  const [reports, setReports] = useState<ScanReportSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [confirmingId, setConfirmingId] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [previewPolicy, setPreviewPolicy] = useState<Policy | null>(null);
  const confirmTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  // Deltas are computed from the full history so filtering never changes them.
  const scoreDeltas = useMemo(() => computeScoreDeltas(reports), [reports]);
  const [filterField, setFilterField] = useState<FilterField>("target");
  const [filterText, setFilterText] = useState("");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [grades, setGrades] = useState<string[]>([]);
  // The input stays instant; the (larger) list re-filters at lower priority.
  const deferredText = useDeferredValue(filterText);
  const filterActive =
    filterField === "date"
      ? Boolean(dateFrom || dateTo)
      : filterField === "grade"
        ? grades.length > 0
        : filterText.trim() !== "";
  const visibleReports = useMemo(() => {
    if (!filterActive) return reports;
    const needle = deferredText.trim().toLowerCase();
    return reports.filter((r) => {
      if (filterField === "policy") return r.policy_name.toLowerCase().includes(needle);
      if (filterField === "target") return (r.target ?? "").toLowerCase().includes(needle);
      if (filterField === "grade") return grades.includes(r.grade);
      const day = localDateKey(r.scanned_at);
      return (!dateFrom || day >= dateFrom) && (!dateTo || day <= dateTo);
    });
  }, [reports, filterActive, filterField, deferredText, dateFrom, dateTo, grades]);

  const [shownCount, setShownCount] = useState(PAGE_SIZE);
  // Any filter change starts again from the first page.
  useEffect(() => {
    setShownCount(PAGE_SIZE);
  }, [filterField, deferredText, dateFrom, dateTo, grades]);
  const pageReports = useMemo(() => visibleReports.slice(0, shownCount), [visibleReports, shownCount]);

  function clearFilter() {
    setFilterText("");
    setDateFrom("");
    setDateTo("");
    setGrades([]);
  }

  function load() {
    setLoading(true);
    api
      .listReports()
      .then(setReports)
      .catch((e) => setError(e instanceof ApiError ? e.message : "Failed to load reports."))
      .finally(() => setLoading(false));
  }

  useEffect(load, []);

  const confirmingRef = useRef<string | null>(null);
  const performDeleteRef = useRef<(id: string) => Promise<void>>(async () => {});

  // Stable identity (reads state via refs) so memoised rows don't re-render on every keystroke.
  const requestDelete = useCallback((id: string) => {
    if (confirmTimer.current) clearTimeout(confirmTimer.current);
    if (confirmingRef.current === id) {
      confirmingRef.current = null;
      setConfirmingId(null);
      void performDeleteRef.current(id);
      return;
    }
    confirmingRef.current = id;
    setConfirmingId(id);
    confirmTimer.current = setTimeout(() => {
      confirmingRef.current = null;
      setConfirmingId(null);
    }, 3000);
  }, []);

  const openPolicy = useCallback(async (policyId: string) => {
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
  }, [toast]);

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
  performDeleteRef.current = performDelete;

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

      {!loading && reports.length > 0 && (
        <div className="panel report-filter fade-in-up">
          <select
            aria-label="Filter by"
            value={filterField}
            onChange={(e) => {
              setFilterField(e.target.value as FilterField);
              clearFilter();
            }}
          >
            <option value="target">Target name</option>
            <option value="policy">Policy name</option>
            <option value="date">Date</option>
            <option value="grade">Grade</option>
          </select>
          {filterField === "grade" ? (
            <div className="report-filter-grades" role="group" aria-label="Grades">
              {GRADES.map((g) => (
                <button
                  key={g}
                  type="button"
                  className={`btn btn-sm ${grades.includes(g) ? "" : "btn-secondary"}`}
                  aria-pressed={grades.includes(g)}
                  onClick={() => setGrades((cur) => (cur.includes(g) ? cur.filter((x) => x !== g) : [...cur, g]))}
                >
                  {g}
                </button>
              ))}
            </div>
          ) : filterField === "date" ? (
            <>
              <label className="field-hint">
                From <input type="date" value={dateFrom} max={dateTo || undefined} onChange={(e) => setDateFrom(e.target.value)} />
              </label>
              <label className="field-hint">
                To <input type="date" value={dateTo} min={dateFrom || undefined} onChange={(e) => setDateTo(e.target.value)} />
              </label>
            </>
          ) : (
            <input
              type="text"
              aria-label="Filter text"
              placeholder={filterField === "policy" ? "Search policy name…" : "Search target name…"}
              value={filterText}
              onChange={(e) => setFilterText(e.target.value)}
            />
          )}
          {filterActive && (
            <>
              <button type="button" className="btn btn-secondary btn-sm" onClick={clearFilter}>
                Clear
              </button>
              <span className="field-hint">
                Showing {visibleReports.length} of {reports.length}
              </span>
            </>
          )}
        </div>
      )}

      {!loading && (
        <div className="panel fade-in-up">
          {reports.length === 0 ? (
            <p className="empty-state">
              No scans saved yet. <Link href="/scan">Run a scan</Link> and it will show up
              here.
            </p>
          ) : visibleReports.length === 0 ? (
            <p className="empty-state">No reports match this filter.</p>
          ) : (
            pageReports.map((r) => (
              <ReportRow
                key={r.id}
                report={r}
                delta={scoreDeltas.get(r.id)}
                confirming={confirmingId === r.id}
                deleting={deletingId === r.id}
                onOpenPolicy={openPolicy}
                onDelete={requestDelete}
              />
            ))
          )}
          {visibleReports.length > shownCount && (
            <div style={{ textAlign: "center", marginTop: 14 }}>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => setShownCount((n) => n + PAGE_SIZE)}
              >
                Show more ({visibleReports.length - shownCount} remaining)
              </button>
            </div>
          )}
        </div>
      )}

      {previewPolicy && (
        <PolicyPreviewModal policy={previewPolicy} onClose={() => setPreviewPolicy(null)} />
      )}
    </div>
  );
}
