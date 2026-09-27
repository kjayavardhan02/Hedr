"use client";

import { useEffect, useRef, useState } from "react";
import { api } from "@/lib/api";
import { formatDateTime, formatShortDate } from "@/lib/format";
import type { TargetHistoryPoint, TargetHistoryResponse } from "@/lib/types";
import { gradeColor } from "./ScoreRing";

const REASON_TEXT: Record<string, string> = {
  ad_hoc_policy: "This scan used an ad-hoc policy, which has no stable identity to track history for.",
  anonymous_target: "Give raw-response scans a Target URL to track this target's score over time.",
};

// Chart geometry, in SVG user units (the <svg> scales to its container's
// width, so these are proportions, not pixels).
const VB_W = 640;
const VB_H = 220;
const PAD_LEFT = 34;
const PAD_RIGHT = 14;
const PAD_TOP = 22;
const PAD_BOTTOM = 28;
const PLOT_W = VB_W - PAD_LEFT - PAD_RIGHT;
const PLOT_H = VB_H - PAD_TOP - PAD_BOTTOM;

function xAt(index: number, count: number): number {
  if (count <= 1) return PAD_LEFT;
  return PAD_LEFT + (index / (count - 1)) * PLOT_W;
}

function yAt(score: number): number {
  const clamped = Math.min(Math.max(score, 0), 100);
  return PAD_TOP + (1 - clamped / 100) * PLOT_H;
}

function ScoreHistoryChart({ points, currentReportId }: { points: TargetHistoryPoint[]; currentReportId: string }) {
  const [hoverIndex, setHoverIndex] = useState<number | null>(null);
  const svgRef = useRef<SVGSVGElement>(null);

  function handleMove(e: React.MouseEvent<SVGSVGElement>) {
    const rect = svgRef.current?.getBoundingClientRect();
    if (!rect || rect.width === 0) return;
    const svgX = ((e.clientX - rect.left) / rect.width) * VB_W;
    let nearest = 0;
    let nearestDist = Infinity;
    points.forEach((_, i) => {
      const d = Math.abs(xAt(i, points.length) - svgX);
      if (d < nearestDist) {
        nearestDist = d;
        nearest = i;
      }
    });
    setHoverIndex(nearest);
  }

  const linePath = points.map((p, i) => `${i === 0 ? "M" : "L"}${xAt(i, points.length)},${yAt(p.score)}`).join(" ");
  const gridScores = [0, 25, 50, 75, 100];
  const versionBoundaries = points
    .map((p, i) => ({ i, changed: i > 0 && p.policy_version !== points[i - 1].policy_version }))
    .filter((b) => b.changed);

  const hover = hoverIndex !== null ? points[hoverIndex] : null;
  const hoverX = hoverIndex !== null ? xAt(hoverIndex, points.length) : 0;
  const hoverY = hover ? yAt(hover.score) : 0;

  return (
    <div className="score-history-chart-wrap">
      <svg
        ref={svgRef}
        viewBox={`0 0 ${VB_W} ${VB_H}`}
        className="score-history-svg"
        onMouseMove={handleMove}
        onMouseLeave={() => setHoverIndex(null)}
        role="img"
        aria-label="Score over time for this target"
      >
        {gridScores.map((s) => (
          <g key={s}>
            <line
              x1={PAD_LEFT}
              x2={VB_W - PAD_RIGHT}
              y1={yAt(s)}
              y2={yAt(s)}
              stroke="var(--panel-border)"
              strokeWidth={1}
            />
            {(s === 0 || s === 50 || s === 100) && (
              <text x={PAD_LEFT - 8} y={yAt(s)} dy="0.32em" textAnchor="end" className="score-history-axis-label">
                {s}
              </text>
            )}
          </g>
        ))}

        {versionBoundaries.map(({ i }) => {
          const bx = (xAt(i - 1, points.length) + xAt(i, points.length)) / 2;
          return (
            <g key={`boundary-${i}`}>
              <line
                x1={bx}
                x2={bx}
                y1={PAD_TOP}
                y2={PAD_TOP + PLOT_H}
                stroke="var(--panel-border)"
                strokeWidth={1}
                strokeDasharray="3 3"
              />
              <text x={bx} y={PAD_TOP - 8} textAnchor="middle" className="score-history-axis-label">
                {points[i].policy_version}
              </text>
            </g>
          );
        })}

        {hover && (
          <line
            x1={hoverX}
            x2={hoverX}
            y1={PAD_TOP}
            y2={PAD_TOP + PLOT_H}
            stroke="var(--text-dim)"
            strokeWidth={1}
            strokeDasharray="2 2"
          />
        )}

        <path d={linePath} fill="none" stroke="var(--accent)" strokeOpacity={0.55} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />

        {points.map((p, i) => {
          const isCurrent = p.id === currentReportId;
          const isHovered = i === hoverIndex;
          const r = isCurrent ? 6 : isHovered ? 5.5 : 4.5;
          return (
            <g key={p.id}>
              {isCurrent && (
                <circle cx={xAt(i, points.length)} cy={yAt(p.score)} r={10} fill="none" stroke="var(--accent)" strokeWidth={2} />
              )}
              <circle
                cx={xAt(i, points.length)}
                cy={yAt(p.score)}
                r={r}
                fill={gradeColor(p.grade)}
                stroke="var(--panel)"
                strokeWidth={2}
              />
            </g>
          );
        })}

        <text x={xAt(0, points.length)} y={VB_H - 6} textAnchor="start" className="score-history-axis-label">
          {formatShortDate(points[0].scanned_at)}
        </text>
        {points.length > 1 && (
          <text x={xAt(points.length - 1, points.length)} y={VB_H - 6} textAnchor="end" className="score-history-axis-label">
            {formatShortDate(points[points.length - 1].scanned_at)}
          </text>
        )}
      </svg>

      {hover && (
        <div
          className="score-history-tooltip"
          style={{
            left: `${(hoverX / VB_W) * 100}%`,
            top: `${(hoverY / VB_H) * 100}%`,
          }}
        >
          <div style={{ fontWeight: 600 }}>
            Scan #{hover.scan_number} · {hover.score} <span style={{ color: gradeColor(hover.grade) }}>{hover.grade}</span>
          </div>
          <div className="field-hint" style={{ margin: 0 }}>
            {formatDateTime(hover.scanned_at)} · {hover.policy_name} ({hover.policy_version})
          </div>
        </div>
      )}
    </div>
  );
}

function ScoreHistoryTable({ points }: { points: TargetHistoryPoint[] }) {
  return (
    <div className="dashboard-table-wrap" style={{ marginTop: 10 }}>
      <table className="dashboard-table">
        <thead>
          <tr>
            <th>Scan</th>
            <th>Date</th>
            <th>Score</th>
            <th>Policy</th>
          </tr>
        </thead>
        <tbody>
          {[...points].reverse().map((p) => (
            <tr key={p.id}>
              <td>#{p.scan_number}</td>
              <td>{formatDateTime(p.scanned_at)}</td>
              <td>
                {p.score} <span style={{ color: gradeColor(p.grade) }}>{p.grade}</span>
              </td>
              <td>
                {p.policy_name} ({p.policy_version})
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function ScoreHistoryPanel({ reportId }: { reportId: string }) {
  const [history, setHistory] = useState<TargetHistoryResponse | null>(null);
  const [failed, setFailed] = useState(false);
  const [listOpen, setListOpen] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setHistory(null);
    setFailed(false);
    setListOpen(false);
    api
      .getReportHistory(reportId)
      .then((data) => {
        if (!cancelled) setHistory(data);
      })
      .catch(() => {
        if (!cancelled) setFailed(true);
      });
    return () => {
      cancelled = true;
    };
  }, [reportId]);

  // A slow/failing history call must never block or break the rest of the
  // report page - render nothing while loading rather than a skeleton for
  // what is a secondary panel.
  if (!history && !failed) return null;

  if (failed || !history || !history.has_history) {
    const reason = history?.reason ?? null;
    const single = history?.points[0];
    return (
      <div className="panel fade-in-up" style={{ marginTop: 16 }}>
        <h3 style={{ marginTop: 0, marginBottom: 4, fontSize: 16 }}>Score History</h3>
        <p className="field-hint" style={{ margin: 0 }}>
          {reason === "not_enough_data" && single
            ? `Only one scan of this target so far (${single.score} ${single.grade}). Scan it again later to see a trend.`
            : (reason && REASON_TEXT[reason]) || "Score history isn't available for this scan."}
        </p>
      </div>
    );
  }

  return (
    <div className="panel fade-in-up" style={{ marginTop: 16 }}>
      <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", flexWrap: "wrap", gap: 8 }}>
        <h3 style={{ marginTop: 0, marginBottom: 4, fontSize: 16 }}>Score History</h3>
        <span className="field-hint">{history.points.length} scans of this target</span>
      </div>
      <ScoreHistoryChart points={history.points} currentReportId={reportId} />
      <button
        type="button"
        className="btn btn-secondary btn-sm"
        style={{ marginTop: 8 }}
        onClick={() => setListOpen(!listOpen)}
      >
        <span className={`chevron ${listOpen ? "open" : ""}`}>▶</span> View as list
      </button>
      <div className={`collapse ${listOpen ? "open" : ""}`}>
        <div className="collapse-inner">
          <ScoreHistoryTable points={history.points} />
        </div>
      </div>
    </div>
  );
}
