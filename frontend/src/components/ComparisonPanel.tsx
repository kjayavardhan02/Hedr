"use client";

import { useEffect, useState } from "react";
import { createPortal } from "react-dom";
import { api } from "@/lib/api";
import { roundDelta } from "@/lib/format";
import type { ComparisonChanges, ComparisonResponse } from "@/lib/types";

const REASON_TEXT: Record<string, { title: string; body: string }> = {
  no_previous_scan: {
    title: "No previous scan available.",
    body: "This is the first scan for this target under this policy version.",
  },
  policy_version_changed: {
    title: "No comparable scan available.",
    body: "The previous scan used a different policy version.",
  },
  raw_default_target: {
    title: "Comparison unavailable.",
    body: "Provide a target name for raw HTTP response scans to enable comparison with previous scans.",
  },
  ad_hoc_policy: {
    title: "Comparison unavailable for this scan.",
    body: "This scan used an ad-hoc policy, which has no stable version to compare across scans.",
  },
};

type Trend = "up" | "down" | "flat";

function trendOf(delta: number): Trend {
  if (delta > 0) return "up";
  if (delta < 0) return "down";
  return "flat";
}

const TREND_LABEL: Record<Trend, string> = {
  up: "Improved",
  down: "Regression",
  flat: "Score unchanged",
};

function formatDelta(delta: number): string {
  if (delta > 0) return `+${delta}`;
  if (delta < 0) return `${delta}`;
  return "0";
}

function TrendIcon({ trend }: { trend: Trend }) {
  const common = {
    width: 18,
    height: 18,
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 2.2,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
    "aria-hidden": true as const,
  };
  if (trend === "up") {
    return (
      <svg {...common}>
        <path d="M4 16l6-6 4 4 6-7" />
        <path d="M15 7h5v5" />
      </svg>
    );
  }
  if (trend === "down") {
    return (
      <svg {...common}>
        <path d="M4 8l6 6 4-4 6 7" />
        <path d="M15 17h5v-5" />
      </svg>
    );
  }
  return (
    <svg {...common}>
      <path d="M5 12h14" />
    </svg>
  );
}

function directiveValue(value: string[] | null): string {
  if (!value || value.length === 0) return "—";
  return value.join(" ");
}

function hasHeaderChanges(changes: ComparisonChanges): boolean {
  return (
    changes.headers_added.length > 0 ||
    changes.headers_removed.length > 0 ||
    changes.headers_changed.length > 0
  );
}

function hasFindingChanges(changes: ComparisonChanges): boolean {
  return (
    changes.findings_resolved.length > 0 ||
    changes.findings_new.length > 0 ||
    changes.severity_changes.length > 0
  );
}

function hasCspChanges(changes: ComparisonChanges): boolean {
  const csp = changes.csp_changes;
  if (!csp) return false;
  return (
    csp.resolved.length > 0 ||
    csp.new.length > 0 ||
    csp.severity_changed.length > 0 ||
    csp.directive_changes.length > 0 ||
    csp.previous_overall_score !== csp.latest_overall_score ||
    csp.previous_policy_checks_passed !== csp.latest_policy_checks_passed ||
    csp.previous_best_practice_passed !== csp.latest_best_practice_passed
  );
}

function ComparisonDetails({ changes }: { changes: ComparisonChanges }) {
  return (
    <>
      {hasHeaderChanges(changes) && (
        <>
          <h4 style={{ margin: "0 0 4px", fontSize: 14 }}>Header Changes</h4>
          <div className="comparison-list">
            {changes.headers_added.map((h) => (
              <div className="comparison-row comparison-row-stacked" key={`added-${h.header}`}>
                <div className="comparison-row-main">
                  <span className="comparison-row-icon comparison-added">+</span>
                  <span className="mono">{h.header}</span>
                  <span className="field-hint">Added</span>
                </div>
                <div className="mono comparison-value">{h.latest_value ?? "—"}</div>
              </div>
            ))}
            {changes.headers_removed.map((h) => (
              <div className="comparison-row comparison-row-stacked" key={`removed-${h.header}`}>
                <div className="comparison-row-main">
                  <span className="comparison-row-icon comparison-removed">−</span>
                  <span className="mono">{h.header}</span>
                  <span className="field-hint">Removed</span>
                </div>
                <div className="mono comparison-value">{h.previous_value ?? "—"}</div>
              </div>
            ))}
            {changes.headers_changed.map((h) => (
              <div className="comparison-row comparison-row-stacked" key={`changed-${h.header}`}>
                <div className="comparison-row-main">
                  <span className="comparison-row-icon comparison-changed">~</span>
                  <span className="mono">{h.header}</span>
                  <span className="field-hint">Changed</span>
                </div>
                <div className="mono comparison-value">
                  {h.previous_value ?? "—"} → {h.latest_value ?? "—"}
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      {hasFindingChanges(changes) && (
        <>
          <h4 style={{ margin: "16px 0 4px", fontSize: 14 }}>Finding Changes</h4>
          <div className="comparison-list">
            {changes.findings_resolved.map((f) => (
              <div className="comparison-row" key={`resolved-${f.header}`}>
                <span className="comparison-row-icon comparison-added">✓</span>
                <span className="mono">{f.header}</span>
                <span className="field-hint">Resolved</span>
              </div>
            ))}
            {changes.findings_new.map((f) => (
              <div className="comparison-row" key={`new-${f.header}`}>
                <span className="comparison-row-icon comparison-removed">⚠</span>
                <span className="mono">{f.header}</span>
                <span className="field-hint">New · {f.severity}</span>
              </div>
            ))}
            {changes.severity_changes.map((s) => (
              <div className="comparison-row" key={`sev-${s.header}`}>
                <span className="comparison-row-icon comparison-changed">~</span>
                <span className="mono">{s.header}</span>
                <span className="field-hint">
                  Severity: {s.previous_severity} → {s.latest_severity}
                </span>
              </div>
            ))}
          </div>
        </>
      )}

      {changes.csp_changes && hasCspChanges(changes) && (
        <>
          <h4 style={{ margin: "16px 0 4px", fontSize: 14 }}>CSP Changes</h4>
          <div className="csp-score-breakdown" style={{ marginBottom: 10 }}>
            <div className="csp-score-stat">
              <span className="field-hint">Policy Compliance</span>
              <span className="csp-score-value">
                {changes.csp_changes.previous_policy_checks_passed}/
                {changes.csp_changes.previous_policy_checks_total} →{" "}
                {changes.csp_changes.latest_policy_checks_passed}/
                {changes.csp_changes.latest_policy_checks_total}
              </span>
            </div>
            <div className="csp-score-stat">
              <span className="field-hint">Best-Practice Checks</span>
              <span className="csp-score-value">
                {changes.csp_changes.previous_best_practice_passed}/
                {changes.csp_changes.previous_best_practice_total} →{" "}
                {changes.csp_changes.latest_best_practice_passed}/
                {changes.csp_changes.latest_best_practice_total}
              </span>
            </div>
            <div className="csp-score-stat">
              <span className="field-hint">Overall CSP Score</span>
              <span className="csp-score-value">
                {changes.csp_changes.previous_overall_score} → {changes.csp_changes.latest_overall_score}
              </span>
            </div>
          </div>

          <div className="comparison-list">
            {changes.csp_changes.resolved.map((c, i) => (
              <div className="comparison-row" key={`csp-resolved-${i}`}>
                <span className="comparison-row-icon comparison-added">✓</span>
                <span className="mono">
                  {c.id}
                  {c.directive ? ` (${c.directive})` : ""}
                </span>
                <span className="field-hint">Resolved</span>
              </div>
            ))}
            {changes.csp_changes.new.map((c, i) => (
              <div className="comparison-row" key={`csp-new-${i}`}>
                <span className="comparison-row-icon comparison-removed">⚠</span>
                <span className="mono">
                  {c.id}
                  {c.directive ? ` (${c.directive})` : ""}
                </span>
                <span className="field-hint">New{c.severity ? ` · ${c.severity}` : ""}</span>
              </div>
            ))}
            {changes.csp_changes.severity_changed.map((c, i) => (
              <div className="comparison-row" key={`csp-sev-${i}`}>
                <span className="comparison-row-icon comparison-changed">~</span>
                <span className="mono">
                  {c.id}
                  {c.directive ? ` (${c.directive})` : ""}
                </span>
                <span className="field-hint">Severity changed</span>
              </div>
            ))}
            {changes.csp_changes.directive_changes.map((d) => (
              <div className="comparison-row comparison-row-stacked" key={`csp-directive-${d.directive}`}>
                <div className="comparison-row-main">
                  <span className="comparison-row-icon comparison-changed">~</span>
                  <span className="mono">{d.directive}</span>
                  <span className="field-hint">Changed</span>
                </div>
                <div className="mono comparison-value">
                  {directiveValue(d.previous_value)} → {directiveValue(d.latest_value)}
                </div>
              </div>
            ))}
          </div>
        </>
      )}
    </>
  );
}

function ComparisonDetailsModal({
  previousScan,
  latestScan,
  changes,
  onClose,
}: {
  previousScan: number;
  latestScan: number;
  changes: ComparisonChanges;
  onClose: () => void;
}) {
  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [onClose]);

  // Rendered into <body>: the card that owns this modal animates with a CSS
  // transform, which would otherwise pin this fixed overlay to the card
  // instead of the viewport.
  return createPortal(
    <div className="modal-overlay fade-in" onClick={onClose}>
      <div
        className="modal-panel modal-panel-wide fade-in-up"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label="Changes since previous scan"
      >
        <div className="modal-header">
          <div className="modal-header-text">
            <h3>Changes Since Previous Scan</h3>
            <div className="modal-header-meta">
              <span className="field-hint" style={{ margin: 0 }}>
                Scan #{previousScan} → Scan #{latestScan}
              </span>
            </div>
          </div>
          <button type="button" className="modal-close" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </div>
        <div className="modal-body" style={{ marginTop: 18 }}>
          <ComparisonDetails changes={changes} />
        </div>
      </div>
    </div>,
    document.body
  );
}

export function ComparisonPanel({ reportId }: { reportId: string }) {
  const [comparison, setComparison] = useState<ComparisonResponse | null>(null);
  const [failed, setFailed] = useState(false);
  const [detailsOpen, setDetailsOpen] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setComparison(null);
    setFailed(false);
    setDetailsOpen(false);
    api
      .getReportComparison(reportId)
      .then((data) => {
        if (!cancelled) setComparison(data);
      })
      .catch(() => {
        if (!cancelled) setFailed(true);
      });
    return () => {
      cancelled = true;
    };
  }, [reportId]);

  // A slow/failing comparison call must never block or break the rest of
  // the report page - render nothing while loading rather than a skeleton
  // for what is a secondary panel.
  if (!comparison && !failed) return null;

  if (failed || !comparison || !comparison.has_comparison) {
    const reason = comparison?.reason ?? null;
    const text = (reason && REASON_TEXT[reason]) ?? {
      title: "Comparison unavailable for this report.",
      body: "",
    };
    return (
      <div className="panel cmp-card cmp-card-flat fade-in-up">
        <div className="cmp-head">
          <span className="cmp-icon">
            <TrendIcon trend="flat" />
          </span>
          <div className="cmp-title">Changes Since Previous Scan</div>
        </div>
        <p className="field-hint" style={{ margin: "12px 0 0" }}>
          {text.title} {text.body}
        </p>
      </div>
    );
  }

  const { previous_report, latest_report, summary, changes } = comparison;
  if (!previous_report || !latest_report || !summary || !changes) return null;

  const hasDetails = hasHeaderChanges(changes) || hasFindingChanges(changes) || hasCspChanges(changes);
  const scoreDelta = roundDelta(summary.score_delta);
  const trend = trendOf(scoreDelta);
  const changedCount = summary.headers_changed + summary.severity_changes;

  return (
    <div className={`panel cmp-card cmp-card-${trend} fade-in-up`}>
      <div className="cmp-head">
        <span className="cmp-icon">
          <TrendIcon trend={trend} />
        </span>
        <div className="cmp-title-block">
          <div className="cmp-title">Changes Since Previous Scan</div>
          <div className="cmp-subtitle">
            Scan #{previous_report.scan_number} → Scan #{latest_report.scan_number}
          </div>
        </div>
        {hasDetails && (
          <button type="button" className="btn btn-secondary btn-sm" onClick={() => setDetailsOpen(true)}>
            View details
          </button>
        )}
      </div>

      <div className="cmp-hero">
        <div className="cmp-delta-block">
          <div className="cmp-delta">{formatDelta(scoreDelta)}</div>
          <div className="cmp-delta-label">{TREND_LABEL[trend]}</div>
        </div>
        <div className="cmp-stats">
          <div className="cmp-stat">
            <span className="cmp-stat-label">Score</span>
            <span className="cmp-stat-value">
              {summary.previous_score} <span className="cmp-arrow">→</span> {summary.latest_score}
            </span>
          </div>
          <div className="cmp-stat">
            <span className="cmp-stat-label">Grade</span>
            <span className="cmp-stat-value">
              {summary.previous_grade} <span className="cmp-arrow">→</span> {summary.latest_grade}
            </span>
          </div>
        </div>
        <div className="cmp-tiles">
          <div className={`cmp-tile cmp-tile-good ${summary.findings_resolved === 0 ? "is-zero" : ""}`}>
            <span className="cmp-tile-value">{summary.findings_resolved}</span>
            <span className="cmp-tile-label">Resolved</span>
          </div>
          <div className={`cmp-tile cmp-tile-bad ${summary.findings_new === 0 ? "is-zero" : ""}`}>
            <span className="cmp-tile-value">{summary.findings_new}</span>
            <span className="cmp-tile-label">New</span>
          </div>
          <div className={`cmp-tile cmp-tile-warn ${changedCount === 0 ? "is-zero" : ""}`}>
            <span className="cmp-tile-value">{changedCount}</span>
            <span className="cmp-tile-label">Changed</span>
          </div>
        </div>
      </div>

      {detailsOpen && (
        <ComparisonDetailsModal
          previousScan={previous_report.scan_number}
          latestScan={latest_report.scan_number}
          changes={changes}
          onClose={() => setDetailsOpen(false)}
        />
      )}
    </div>
  );
}
