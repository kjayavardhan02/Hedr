"use client";

import { useEffect, useMemo, useRef, useState, type CSSProperties } from "react";
import { useParams, useRouter } from "next/navigation";
import { api, ApiError } from "@/lib/api";
import type { BurpAnalysisResult, BurpEndpointAnalysis, BurpFindingGroup, BurpImportDetail } from "@/lib/types";
import { BackLink } from "@/components/BackLink";
import { PolicyFormSkeleton } from "@/components/Skeleton";
import { useToast } from "@/components/Toast";
import { downloadBinaryBlob } from "@/lib/download";
import { gradeForScore } from "@/lib/format";
import { ScoreRing } from "@/components/ScoreRing";

const PAGE_SIZE = 30;

// Matches the Dashboard's Findings-by-severity card styling (see
// .findings-grid/.findings-stat) - Low and Info are left un-tinted, the same
// treatment .severity-chip gives them, since they aren't urgent enough to
// warrant a color accent of their own.
const SEVERITY_TIERS: { key: string; label: string; accent?: string; tint?: string }[] = [
  { key: "critical", label: "Critical", accent: "var(--fail)", tint: "rgba(239, 68, 68, 0.08)" },
  { key: "high", label: "High", accent: "var(--accent)", tint: "rgba(255, 122, 26, 0.08)" },
  { key: "medium", label: "Medium", accent: "var(--warn)", tint: "rgba(255, 176, 32, 0.08)" },
  { key: "low", label: "Low" },
  { key: "info", label: "Info" },
];

function scoreTone(score: number): "good" | "mid" | "bad" {
  if (score >= 80) return "good";
  if (score >= 60) return "mid";
  return "bad";
}

function takeaway(grade: string, withFindings: number): string {
  if (grade === "A") return "Excellent — the application's header posture meets the policy overall.";
  if (grade === "B") return "Good, with a little room to tighten things up.";
  if (grade === "C") return "Getting there — a few gaps are worth fixing.";
  if (withFindings === 0) return "No responses had findings against this policy.";
  return "Needs attention — many responses have findings against the policy.";
}

function heroTone(grade: string): "up" | "warn" | "down" {
  if (grade === "A" || grade === "B") return "up";
  if (grade === "C" || grade === "D") return "warn";
  return "down";
}

/** Mirrors ScoreHero's `tinted` variant exactly (same cmp-card/cmp-tile
 * classes as a normal scan report's hero) so a Burp analysis reads as the
 * same kind of report - just scored across many responses instead of one. */
function BurpScoreHero({ record, analysis }: { record: BurpImportDetail; analysis: BurpAnalysisResult }) {
  const { summary } = analysis;
  const grade = gradeForScore(summary.overall_score);
  const compliant = summary.responses_analyzed - summary.responses_with_findings;

  return (
    <div className={`panel cmp-card cmp-card-${heroTone(grade)} fade-in-up`}>
      <div className="score-hero">
        <ScoreRing score={summary.overall_score} grade={grade} />
        <div>
          <div style={{ fontWeight: 700, fontSize: 17, marginBottom: 4, overflowWrap: "anywhere" }}>
            {record.policy_name} {record.policy_version && `(${record.policy_version})`}
          </div>
          <p style={{ margin: "0 0 6px", fontSize: 14 }}>{takeaway(grade, summary.responses_with_findings)}</p>
          <div className="field-hint">
            {summary.unique_hosts} host{summary.unique_hosts === 1 ? "" : "s"} ·{" "}
            {summary.unique_paths} unique path{summary.unique_paths === 1 ? "" : "s"} ·{" "}
            {summary.responses_analyzed} response{summary.responses_analyzed === 1 ? "" : "s"} analyzed
          </div>
        </div>
      </div>
      <div className="cmp-tiles">
        <div className={`cmp-tile cmp-tile-good ${compliant === 0 ? "is-zero" : ""}`}>
          <span className="cmp-tile-value">{compliant}</span>
          <span className="cmp-tile-label">Compliant</span>
        </div>
        <div className={`cmp-tile cmp-tile-bad ${summary.responses_with_findings === 0 ? "is-zero" : ""}`}>
          <span className="cmp-tile-value">{summary.responses_with_findings}</span>
          <span className="cmp-tile-label">With Findings</span>
        </div>
      </div>
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const className =
    status === "present" ? "badge-PASS" : status === "not_applicable" ? "badge-neutral" : "badge-FAIL";
  const label = status === "present" ? "Present" : status === "missing" ? "Missing" : status === "invalid" ? "Invalid" : "N/A";
  return <span className={`badge ${className}`}>{label}</span>;
}

/** Mirrors FindingCard's accordion (.finding/.finding-header/.chevron/
 * .collapse) - a Burp finding is a HEADER FAILING ACROSS MANY ENDPOINTS
 * rather than a single check, so the expanded body lists every affected
 * endpoint instead of a per-check breakdown. */
function FindingGroupCard({ finding, index }: { finding: BurpFindingGroup; index: number }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="finding fade-in-up" style={{ animationDelay: `${Math.min(index, 8) * 40}ms` }}>
      <div
        className="finding-header"
        onClick={() => setOpen((v) => !v)}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") setOpen((v) => !v);
        }}
      >
        <div className="finding-title">
          <span className={`chevron ${open ? "open" : ""}`}>▶</span>
          <StatusBadge status={finding.status} />
          <span>{finding.header}</span>
          <span className="severity">{finding.severity}</span>
        </div>
        <span className="finding-score">
          {finding.affected_count} endpoint{finding.affected_count === 1 ? "" : "s"}
        </span>
      </div>

      <div className={`collapse ${open ? "open" : ""}`}>
        <div className="collapse-inner">
          <div style={{ paddingTop: 10 }}>
            <span className="field-hint">Affected endpoints:</span>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 8 }}>
              {finding.affected_endpoints.map((endpoint) => (
                <span key={endpoint} className="endpoint-tag mono">
                  {endpoint}
                </span>
              ))}
            </div>
            {finding.affected_count > finding.affected_endpoints.length && (
              <p className="field-hint" style={{ marginTop: 8, marginBottom: 0 }}>
                + {finding.affected_count - finding.affected_endpoints.length} more not shown here — see the
                Excel export for the full list.
              </p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function EndpointRow({ endpoint }: { endpoint: BurpEndpointAnalysis }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <tr onClick={() => setOpen((v) => !v)} style={{ cursor: "pointer" }}>
        <td className="dashboard-table-wrap-cell" style={{ textAlign: "left" }}>
          <span className="mono">{endpoint.domain}</span>
        </td>
        <td className="dashboard-table-wrap-cell" style={{ textAlign: "left" }}>
          <span className="mono">{endpoint.path}</span>
        </td>
        <td>{endpoint.method}</td>
        <td>{endpoint.status_code ?? "—"}</td>
        <td>
          <span className={`badge ${scoreTone(endpoint.policy_score) === "good" ? "badge-PASS" : scoreTone(endpoint.policy_score) === "mid" ? "badge-WARNING" : "badge-FAIL"}`}>
            {endpoint.policy_score}%
          </span>
        </td>
        <td>{open ? "▾" : "▸"}</td>
      </tr>
      {open && (
        <tr>
          <td colSpan={6} style={{ background: "color-mix(in srgb, var(--text) 2%, transparent)", textAlign: "left" }}>
            <div style={{ display: "flex", flexDirection: "column", gap: 8, padding: "10px 4px" }}>
              {endpoint.header_results.map((hr) => (
                <div key={hr.header} className="value-row" style={{ alignItems: "center" }}>
                  <StatusBadge status={hr.status} />
                  <span style={{ fontWeight: 600 }}>{hr.header}</span>
                  {hr.actual_value && (
                    <span className="field-hint mono" style={{ overflowWrap: "anywhere" }}>
                      {hr.actual_value}
                    </span>
                  )}
                </div>
              ))}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

export default function BurpReportDetailPage() {
  const params = useParams<{ id: string }>();
  const id = params.id;
  const router = useRouter();
  const toast = useToast();

  const [record, setRecord] = useState<BurpImportDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [exporting, setExporting] = useState(false);
  const confirmTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [search, setSearch] = useState("");
  const [shownCount, setShownCount] = useState(PAGE_SIZE);
  const [issuesOpen, setIssuesOpen] = useState(false);

  useEffect(() => {
    api
      .getBurpImport(id)
      .then(setRecord)
      .catch((e) => setError(e instanceof ApiError ? e.message : "Failed to load this analysis."))
      .finally(() => setLoading(false));
  }, [id]);

  const analysis = record?.analysis ?? null;

  const filteredEndpoints = useMemo(() => {
    if (!analysis) return [];
    const q = search.trim().toLowerCase();
    if (!q) return analysis.endpoints;
    return analysis.endpoints.filter(
      (e) => e.domain.toLowerCase().includes(q) || e.path.toLowerCase().includes(q)
    );
  }, [analysis, search]);
  const pageEndpoints = filteredEndpoints.slice(0, shownCount);

  function requestDelete() {
    if (confirmTimer.current) clearTimeout(confirmTimer.current);
    if (confirming) {
      setConfirming(false);
      void performDelete();
      return;
    }
    setConfirming(true);
    confirmTimer.current = setTimeout(() => setConfirming(false), 3000);
  }

  async function performDelete() {
    setDeleting(true);
    try {
      await api.deleteBurpImport(id);
      toast.show("Burp analysis deleted.", "success");
      router.push("/reports");
    } catch (e) {
      toast.show(e instanceof ApiError ? e.message : "Failed to delete.", "error");
      setDeleting(false);
    }
  }

  async function handleExport() {
    setExporting(true);
    try {
      const { blob, filename } = await api.exportBurpXlsx(id);
      downloadBinaryBlob(blob, filename);
    } catch (e) {
      toast.show(e instanceof ApiError ? e.message : "Export failed.", "error");
    } finally {
      setExporting(false);
    }
  }

  if (loading) {
    return (
      <div className="container">
        <BackLink href="/reports" label="Back to Reports" />
        <PolicyFormSkeleton />
      </div>
    );
  }

  if (!record) {
    return (
      <div className="container">
        <BackLink href="/reports" label="Back to Reports" />
        <div className="error-box">{error ?? "This analysis was not found."}</div>
      </div>
    );
  }

  if (!analysis) {
    return (
      <div className="container">
        <BackLink href="/reports" label="Back to Reports" />
        <div className="panel">
          <p className="empty-state">
            This import hasn&apos;t been analyzed yet. Go to <a href="/scan">Scan → Burp History Import</a> to
            pick a policy and run the analysis.
          </p>
        </div>
      </div>
    );
  }

  const analyzedAt = record.analyzed_at ? new Date(record.analyzed_at) : new Date(record.imported_at);

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
            {record.name} · <span className="mono">{record.source_filename}</span>
          </p>
          <p className="field-hint" style={{ margin: "4px 0 0" }}>
            <strong>Date:</strong> {analyzedAt.toLocaleDateString(undefined, { dateStyle: "medium" })} ·{" "}
            <strong>Time:</strong> {analyzedAt.toLocaleTimeString(undefined, { timeStyle: "medium" })}
          </p>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <button className="btn btn-secondary btn-sm" onClick={handleExport} disabled={exporting}>
            {exporting ? "Exporting…" : "Export Excel"}
          </button>
          <button
            className={`btn btn-sm ${confirming ? "btn-danger-solid" : "btn-danger"}`}
            onClick={requestDelete}
            disabled={deleting}
          >
            {deleting ? "Deleting…" : confirming ? "Confirm?" : "Delete"}
          </button>
        </div>
      </div>

      <BurpScoreHero record={record} analysis={analysis} />

      {Object.keys(analysis.summary.severity_counts).length > 0 && (
        <div className="panel fade-in-up" style={{ marginTop: 16 }}>
          <h3 style={{ marginTop: 0, marginBottom: 4, fontSize: 16 }}>Findings by Severity</h3>
          <p className="field-hint" style={{ marginTop: 0, marginBottom: 14 }}>
            Every header that missed or violated the policy, tallied by severity across all analyzed responses.
          </p>
          <div className="findings-grid findings-grid-5">
            {SEVERITY_TIERS.map(({ key, label, accent, tint }) => (
              <div
                key={key}
                className="findings-stat"
                style={accent ? ({ "--stat-accent": accent, "--stat-tint": tint } as CSSProperties) : undefined}
              >
                <div className="findings-stat-value" style={accent ? { color: accent } : undefined}>
                  {analysis.summary.severity_counts[key] ?? 0}
                </div>
                <div className="findings-stat-label">{label}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="panel fade-in-up" style={{ marginTop: 16 }}>
        <h3 style={{ marginTop: 0, marginBottom: 12, fontSize: 16 }}>Host Summary</h3>
        <div className="dashboard-table-wrap">
          <table className="dashboard-table">
            <thead>
              <tr>
                <th style={{ textAlign: "left" }}>Host</th>
                <th>Responses</th>
                <th>Unique Paths</th>
                <th>Score</th>
              </tr>
            </thead>
            <tbody>
              {analysis.host_summary.map((row) => (
                <tr key={row.host}>
                  <td className="dashboard-table-wrap-cell" style={{ textAlign: "left" }}>
                    <span className="mono">{row.host}</span>
                  </td>
                  <td>{row.responses}</td>
                  <td>{row.unique_paths}</td>
                  <td>{row.score}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="panel fade-in-up" style={{ marginTop: 16 }}>
        <h3 style={{ marginTop: 0, marginBottom: 12, fontSize: 16 }}>Security Header Coverage</h3>
        <div className="dashboard-table-wrap">
          <table className="dashboard-table">
            <thead>
              <tr>
                <th style={{ textAlign: "left" }}>Header</th>
                <th>Present</th>
                <th>Missing</th>
                <th>Invalid</th>
                <th>N/A</th>
                <th>Coverage</th>
              </tr>
            </thead>
            <tbody>
              {analysis.header_coverage.map((row) => (
                <tr key={row.header}>
                  <td className="dashboard-table-wrap-cell" style={{ textAlign: "left" }}>
                    {row.header}
                  </td>
                  <td>{row.present}</td>
                  <td>{row.missing}</td>
                  <td>{row.invalid}</td>
                  <td>{row.not_applicable}</td>
                  <td>{row.coverage}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {analysis.findings.length > 0 && (
        <div className="panel fade-in-up" style={{ marginTop: 16 }}>
          <h3 style={{ marginTop: 0, marginBottom: 4, fontSize: 16 }}>Findings</h3>
          <p className="field-hint" style={{ marginTop: 0, marginBottom: 14 }}>
            Every header missing or invalid against the policy, grouped across endpoints. Click one to see exactly
            where it happened.
          </p>
          {analysis.findings.map((f, i) => (
            <FindingGroupCard key={`${f.header}-${f.status}`} finding={f} index={i} />
          ))}
        </div>
      )}

      {analysis.inconsistencies.length > 0 && (
        <div className="panel fade-in-up" style={{ marginTop: 16 }}>
          <h3 style={{ marginTop: 0, marginBottom: 12, fontSize: 16 }}>Header Inconsistencies</h3>
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            {analysis.inconsistencies.map((inc) => (
              <div key={inc.header}>
                <div style={{ fontWeight: 600, marginBottom: 6 }}>
                  {inc.header} — {inc.configurations.length} configurations detected
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                  {inc.configurations.map((cfg) => (
                    <div key={cfg.value} className="field-hint mono" style={{ overflowWrap: "anywhere" }}>
                      {cfg.value} — {cfg.count} response{cfg.count === 1 ? "" : "s"}
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="panel fade-in-up" style={{ marginTop: 16 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
          <h3 style={{ margin: 0, fontSize: 16 }}>Endpoint Details</h3>
          <input
            placeholder="Search host or path…"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setShownCount(PAGE_SIZE);
            }}
            style={{ maxWidth: 260 }}
          />
        </div>
        <div className="dashboard-table-wrap">
          <table className="dashboard-table">
            <thead>
              <tr>
                <th style={{ textAlign: "left" }}>Domain</th>
                <th style={{ textAlign: "left" }}>Path</th>
                <th>Method</th>
                <th>Status</th>
                <th>Score</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {pageEndpoints.map((endpoint, i) => (
                <EndpointRow key={`${endpoint.raw_url}-${i}`} endpoint={endpoint} />
              ))}
            </tbody>
          </table>
        </div>
        {filteredEndpoints.length === 0 && <p className="empty-state">No endpoints match this search.</p>}
        {filteredEndpoints.length > shownCount && (
          <div style={{ textAlign: "center", marginTop: 14 }}>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => setShownCount((n) => n + PAGE_SIZE)}
            >
              Show more ({filteredEndpoints.length - shownCount} remaining)
            </button>
          </div>
        )}
      </div>

      {analysis.import_issues.length > 0 && (
        <div className="panel fade-in-up" style={{ marginTop: 16 }}>
          <button
            type="button"
            className="link-button"
            style={{ fontWeight: 600, fontSize: 16 }}
            onClick={() => setIssuesOpen((v) => !v)}
          >
            {issuesOpen ? "▾" : "▸"} Import Issues ({analysis.import_issues.length})
          </button>
          {issuesOpen && (
            <div style={{ marginTop: 12, display: "flex", flexDirection: "column", gap: 10 }}>
              {analysis.import_issues.map((issue) => (
                <div key={issue.index} className="value-row" style={{ alignItems: "flex-start" }}>
                  <span className={`badge ${issue.status === "failed" ? "badge-FAIL" : "badge-neutral"}`}>
                    {issue.status === "failed" ? "Failed" : "Skipped"}
                  </span>
                  <div style={{ minWidth: 0 }}>
                    <div className="mono" style={{ overflowWrap: "anywhere" }}>
                      Entry #{issue.index} {issue.url ? `— ${issue.url}` : ""}
                    </div>
                    {issue.reason && <div className="field-hint">{issue.reason}</div>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
