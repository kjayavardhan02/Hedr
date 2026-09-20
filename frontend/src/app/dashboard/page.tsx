"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { api, ApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth-context";
import { capitalize, formatDateTime, greeting, timeAgo } from "@/lib/format";
import type { DashboardSummary, Policy } from "@/lib/types";
import { ScoreRing } from "@/components/ScoreRing";
import { DashboardSkeleton } from "@/components/Skeleton";

function IconReports() {
  return (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M6 3.5h9l3.5 3.5V20a.5.5 0 0 1-.5.5H6a.5.5 0 0 1-.5-.5V4a.5.5 0 0 1 .5-.5Z"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinejoin="round"
      />
      <path d="M8.5 12h7M8.5 15.5h7M8.5 8.5h3.5" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
    </svg>
  );
}

function IconShield() {
  return (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M12 3 5 5.8v5.4c0 5 3.2 8.8 7 10.8 3.8-2 7-5.8 7-10.8V5.8L12 3Z"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function IconLayers() {
  return (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M12 4 4 8l8 4 8-4-8-4Z" stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round" />
      <path d="M4 12l8 4 8-4" stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round" />
      <path d="M4 16l8 4 8-4" stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round" />
    </svg>
  );
}

function IconGauge() {
  return (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M4.5 16a7.5 7.5 0 1 1 15 0" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
      <path d="M12 16 15 11.5" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
    </svg>
  );
}

function IconClock() {
  return (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx="12" cy="12" r="8" stroke="currentColor" strokeWidth="1.6" />
      <path d="M12 8v4.5l3 2" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function IconAlert() {
  return (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M12 4 21 19H3L12 4Z" stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round" />
      <path d="M12 10.5v3.5" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
      <circle cx="12" cy="17" r="0.9" fill="currentColor" stroke="none" />
    </svg>
  );
}

function IconScan() {
  return (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx="11" cy="11" r="7" stroke="currentColor" strokeWidth="1.6" />
      <path d="M20.5 20.5 16 16" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
    </svg>
  );
}

function IconArrow() {
  return (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M9 5l7 7-7 7" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function gradeBadgeClass(grade: string): string {
  if (grade === "A" || grade === "B") return "badge-PASS";
  if (grade === "C" || grade === "D") return "badge-WARNING";
  return "badge-FAIL";
}

function gradeAccent(grade: string): string {
  if (grade === "A" || grade === "B") return "var(--pass)";
  if (grade === "C" || grade === "D") return "var(--warn)";
  return "var(--fail)";
}

function gradeGlow(grade: string): string {
  if (grade === "A" || grade === "B") return "rgba(52, 199, 89, 0.22)";
  if (grade === "C" || grade === "D") return "rgba(255, 176, 32, 0.22)";
  return "rgba(239, 68, 68, 0.22)";
}

export default function DashboardPage() {
  const { user } = useAuth();
  const router = useRouter();
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [baselines, setBaselines] = useState<Policy[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([api.getDashboardSummary(), api.listBaselines()])
      .then(([s, b]) => {
        setSummary(s);
        setBaselines(b);
      })
      .catch((e) => setError(e instanceof ApiError ? e.message : "Failed to load dashboard."))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="container">
        <DashboardSkeleton />
      </div>
    );
  }

  if (error || !summary) {
    return (
      <div className="container">
        <div className="error-box">{error ?? "Failed to load dashboard."}</div>
      </div>
    );
  }

  return (
    <div className="container">
      <div className="panel fade-in-up dashboard-header">
        <div>
          <h1 style={{ fontSize: 22, margin: "0 0 4px" }}>
            {greeting()}
            {user?.first_name ? `, ${capitalize(user.first_name)}` : ""} 👋
          </h1>
          <p className="field-hint" style={{ margin: 0 }}>
            Analyze your application&apos;s security configuration.
          </p>
        </div>
        <Link href="/scan" className="btn">
          + New Scan
        </Link>
      </div>

      <div className="row" style={{ marginTop: 16 }}>
        <div
          className="panel metric-card clickable fade-in-up"
          style={{ animationDelay: "40ms" }}
          role="button"
          tabIndex={0}
          onClick={() => router.push("/reports")}
        >
          <div className="metric-card-top">
            <div className="field-hint">Total Reports</div>
            <div className="metric-icon">
              <IconReports />
            </div>
          </div>
          <div className="metric-value">{summary.reports.total}</div>
          {summary.reports.total === 0 && (
            <div className="metric-sub">Run your first scan to create a report.</div>
          )}
        </div>

        <div
          className="panel metric-card clickable fade-in-up"
          style={{ animationDelay: "80ms" }}
          role="button"
          tabIndex={0}
          onClick={() => router.push("/policies")}
        >
          <div className="metric-card-top">
            <div className="field-hint">Your Policies</div>
            <div className="metric-icon">
              <IconShield />
            </div>
          </div>
          <div className="metric-value">{summary.policies.total}</div>
          {summary.policies.total === 0 && (
            <div className="metric-sub">Create your first custom policy.</div>
          )}
        </div>

        <div
          className="panel metric-card clickable fade-in-up"
          style={{ animationDelay: "120ms" }}
          role="button"
          tabIndex={0}
          onClick={() => router.push("/policies")}
        >
          <div className="metric-card-top">
            <div className="field-hint">Security Baselines</div>
            <div className="metric-icon">
              <IconLayers />
            </div>
          </div>
          <div className="metric-value">{summary.baselines.total}</div>
        </div>

        <div className="panel metric-card fade-in-up" style={{ animationDelay: "160ms" }}>
          <div className="metric-card-top">
            <div className="field-hint">Average Score</div>
            <div className="metric-icon">
              <IconGauge />
            </div>
          </div>
          {summary.average_score === null ? (
            <>
              <div className="metric-value">—</div>
              <div className="metric-sub">Run a scan to calculate your average.</div>
            </>
          ) : (
            <>
              <div className="metric-value" style={{ color: gradeAccent(summary.average_grade ?? "F") }}>
                {summary.average_score}
                {summary.average_grade && <span className="grade">{summary.average_grade}</span>}
              </div>
              <div className="metric-sub">Based on saved reports</div>
            </>
          )}
        </div>
      </div>

      <div
        className="panel fade-in-up latest-scan-card"
        style={
          {
            marginTop: 16,
            ...(summary.latest_scan ? { "--scan-glow": gradeGlow(summary.latest_scan.grade) } : {}),
          } as React.CSSProperties
        }
      >
        <h3 className="section-title" style={{ marginTop: 0, marginBottom: 14 }}>
          <span className="section-icon">
            <IconScan />
          </span>
          Latest Scan
        </h3>
        {summary.latest_scan ? (
          <div className="latest-scan-panel">
            <ScoreRing score={summary.latest_scan.score} grade={summary.latest_scan.grade} />
            <div className="latest-scan-info">
              <div className="mono" style={{ fontWeight: 600, fontSize: 15 }}>
                {summary.latest_scan.target ?? "—"}
              </div>
              <div className="field-hint" style={{ marginTop: 2 }}>
                {summary.latest_scan.policy_name} · {summary.latest_scan.policy_version}
              </div>
              <div style={{ marginTop: 8, fontSize: 13 }}>
                <span style={{ color: "var(--pass)" }}>{summary.latest_scan.passed} passed</span>
                {"  ·  "}
                <span style={{ color: "var(--fail)" }}>{summary.latest_scan.failed} failed</span>
              </div>
              <div className="field-hint" style={{ marginTop: 6 }}>
                Scanned {timeAgo(summary.latest_scan.scanned_at)}
              </div>
              <div style={{ marginTop: 14 }}>
                <Link className="btn btn-sm" href={`/reports/${summary.latest_scan.id}`}>
                  View Report
                </Link>
              </div>
            </div>
            <div className="latest-scan-side">
              {(() => {
                const total = summary.latest_scan.passed + summary.latest_scan.failed;
                const passPct = total > 0 ? Math.round((summary.latest_scan.passed / total) * 100) : null;
                return (
                  <>
                    <div className="latest-scan-stat">
                      <div className="field-hint">Pass rate</div>
                      <div className="latest-scan-bar">
                        <div
                          className="latest-scan-bar-fill"
                          style={{ width: `${passPct ?? 0}%` }}
                        />
                      </div>
                      <div className="field-hint" style={{ marginTop: 4 }}>
                        {passPct === null ? "No header checks in this scan" : `${passPct}% of ${total} checks`}
                      </div>
                    </div>
                    <div className="latest-scan-stat">
                      <div className="field-hint">Headers Evaluated</div>
                      <div className="latest-scan-big-stat">{total}</div>
                    </div>
                  </>
                );
              })()}
            </div>
          </div>
        ) : (
          <div className="empty-state">
            No scans yet.
            <div className="empty-state-action">
              <Link className="btn" href="/scan">
                Start Your First Scan
              </Link>
            </div>
          </div>
        )}
      </div>

      <div className="panel fade-in-up" style={{ marginTop: 16 }}>
        <div className="section-header">
          <h3 className="section-title" style={{ margin: 0 }}>
            <span className="section-icon">
              <IconClock />
            </span>
            Recent Scans
          </h3>
          <Link href="/reports" className="field-hint">
            View All →
          </Link>
        </div>
        {summary.recent_scans.length === 0 ? (
          <p className="empty-state">No scans yet.</p>
        ) : (
          summary.recent_scans.map((s) => (
            <div
              className="dashboard-scan-row"
              key={s.id}
              role="button"
              tabIndex={0}
              style={{ "--row-accent": gradeAccent(s.grade) } as React.CSSProperties}
              onClick={() => router.push(`/reports/${s.id}`)}
            >
              <div style={{ minWidth: 0 }}>
                <div className="mono dashboard-scan-target">{s.target ?? "—"}</div>
                <div className="field-hint">
                  {s.policy_name} · {s.policy_version}
                </div>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 12, flexShrink: 0 }}>
                <span className={`badge ${gradeBadgeClass(s.grade)}`}>
                  {s.grade} · {s.score}
                </span>
                <span className="field-hint">{timeAgo(s.scanned_at)}</span>
                <span className="scan-row-arrow">
                  <IconArrow />
                </span>
              </div>
            </div>
          ))
        )}
      </div>

      <div className="panel fade-in-up" style={{ marginTop: 16 }}>
        <h3 className="section-title" style={{ marginTop: 0, marginBottom: 4 }}>
          <span className="section-icon">
            <IconAlert />
          </span>
          Findings Across Saved Reports
        </h3>
        <p className="field-hint" style={{ marginTop: 0, marginBottom: 14 }}>
          Every failing check across all of your saved reports — not just the latest scan.
        </p>
        <div className="findings-grid">
          <div
            className="findings-stat"
            style={{ "--stat-accent": "var(--fail)", "--stat-tint": "rgba(239, 68, 68, 0.08)" } as React.CSSProperties}
          >
            <div className="findings-stat-value" style={{ color: "var(--fail)" }}>
              {summary.findings.critical}
            </div>
            <div className="findings-stat-label">Critical</div>
          </div>
          <div
            className="findings-stat"
            style={{ "--stat-accent": "var(--accent)", "--stat-tint": "rgba(255, 122, 26, 0.08)" } as React.CSSProperties}
          >
            <div className="findings-stat-value" style={{ color: "var(--accent)" }}>
              {summary.findings.high}
            </div>
            <div className="findings-stat-label">High</div>
          </div>
          <div
            className="findings-stat"
            style={{ "--stat-accent": "var(--warn)", "--stat-tint": "rgba(255, 176, 32, 0.08)" } as React.CSSProperties}
          >
            <div className="findings-stat-value" style={{ color: "var(--warn)" }}>
              {summary.findings.medium}
            </div>
            <div className="findings-stat-label">Medium</div>
          </div>
          <div className="findings-stat">
            <div className="findings-stat-value">{summary.findings.low}</div>
            <div className="findings-stat-label">Low</div>
          </div>
        </div>
      </div>

      <div className="panel fade-in-up" style={{ marginTop: 16 }}>
        <div className="section-header">
          <h3 className="section-title" style={{ margin: 0 }}>
            <span className="section-icon">
              <IconShield />
            </span>
            Your Policies
          </h3>
          <Link href="/policies" className="field-hint">
            View All →
          </Link>
        </div>
        {summary.recent_policies.length === 0 ? (
          <div className="empty-state">
            You haven&apos;t created a custom policy yet.
            <div className="empty-state-action">
              <Link className="btn btn-sm" href="/policies/new">
                Create Policy
              </Link>
            </div>
          </div>
        ) : (
          <div className="policies-table-wrap">
            <table className="policies-table">
              <thead>
                <tr>
                  <th>Policy Name</th>
                  <th>Version</th>
                  <th>Rules</th>
                  <th>Created</th>
                  <th>Updated</th>
                </tr>
              </thead>
              <tbody>
                {summary.recent_policies.map((p) => (
                  <tr key={p.id} onClick={() => router.push(`/policies/${p.id}`)}>
                    <td className="policy-name-cell">
                      <span className="policy-name-inline">
                        <span className="policy-name-icon">
                          <IconShield />
                        </span>
                        {p.name}
                      </span>
                    </td>
                    <td>
                      <span className="report-version-pill">v{p.version}</span>
                    </td>
                    <td>
                      <span className="policies-rules-pill">{p.header_count}</span>
                    </td>
                    <td className="field-hint">{formatDateTime(p.created_at)}</td>
                    <td className="field-hint">{timeAgo(p.updated_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="panel fade-in-up" style={{ marginTop: 16 }}>
        <h3 className="section-title" style={{ marginTop: 0, marginBottom: 14 }}>
          <span className="section-icon">
            <IconLayers />
          </span>
          Security Baselines
        </h3>
        <div className="row">
          {baselines.map((b) => (
            <div key={b.id} className="panel baseline-card">
              <div className="baseline-card-icon">
                <IconShield />
              </div>
              <div style={{ fontWeight: 600 }}>{b.name}</div>
              <div className="field-hint" style={{ marginTop: 4 }}>
                {b.headers.length} header rule{b.headers.length === 1 ? "" : "s"}
              </div>
              <div className="row" style={{ marginTop: 12 }}>
                <Link href={`/policies/${b.id}`} className="btn btn-secondary btn-sm">
                  View
                </Link>
                <Link href={`/policies/new?template=${b.id}`} className="btn btn-sm">
                  Clone
                </Link>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div
        className="panel fade-in-up cta-panel"
        style={{
          marginTop: 16,
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: 12,
        }}
      >
        <div className="cta-panel-icon">
          <IconShield />
        </div>
        <div>
          <div style={{ fontWeight: 600 }}>Create a custom security policy</div>
          <div className="field-hint" style={{ marginTop: 4 }}>
            Define the headers and rules your applications should satisfy.
          </div>
        </div>
        <Link href="/policies/new" className="btn">
          + Create Policy
        </Link>
      </div>
    </div>
  );
}
