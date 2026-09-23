"use client";

import { useState } from "react";
import type { CSPFinding } from "@/lib/types";
import { StatusBadge } from "./StatusBadge";
import { CopyButton } from "./CopyButton";
import { CSPDirectives } from "./CSPDirectives";
import { AIExplain } from "./AIExplain";

function ChecksTable({ rows }: { rows: CSPFinding["policy_checks"] }) {
  if (rows.length === 0) {
    return <p className="field-hint">No checks in this category.</p>;
  }
  return (
    <div className="checks-table-wrap">
      <table className="checks-table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Check</th>
            <th>Severity</th>
            <th>Status</th>
            <th>Expected</th>
            <th>Actual</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((c, i) => (
            <tr key={i}>
              <td className="mono">{c.id ?? "—"}</td>
              <td>{c.description}</td>
              <td>
                {c.severity && <span className={`severity-chip severity-chip-${c.severity}`}>{c.severity}</span>}
              </td>
              <td>
                <StatusBadge status={c.status} />
              </td>
              <td className="mono">{c.expected ?? "—"}</td>
              <td className="mono">{c.actual ?? "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function CSPPanel({ csp }: { csp: CSPFinding }) {
  const [open, setOpen] = useState(true);
  const allChecks = [...csp.policy_checks, ...csp.security_checks];
  const failCount = allChecks.filter((c) => c.status === "FAIL").length;
  const warnCount = allChecks.filter((c) => c.status === "WARNING").length;
  const overallStatus = !csp.present
    ? "FAIL"
    : failCount > 0
      ? "FAIL"
      : warnCount > 0
        ? "WARNING"
        : "PASS";

  return (
    <div className="panel fade-in-up">
      <div
        className="finding-header"
        onClick={() => setOpen(!open)}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") setOpen(!open);
        }}
      >
        <div className="finding-title">
          <span className={`chevron ${open ? "open" : ""}`}>▶</span>
          <span className={`badge badge-${overallStatus}`}>
            {!csp.present ? "MISSING" : overallStatus}
          </span>
          <span>Content-Security-Policy — Dedicated Analysis</span>
        </div>
      </div>

      <div className={`collapse ${open ? "open" : ""}`}>
        <div className="collapse-inner">
          <div style={{ paddingTop: 10 }}>
            <div className="csp-score-breakdown">
              <div className="csp-score-stat">
                <span className="field-hint">Policy Compliance</span>
                <span className="csp-score-value">
                  {csp.policy_checks_passed}/{csp.policy_checks_total}
                </span>
              </div>
              <div className="csp-score-stat">
                <span className="field-hint">Best-Practice Checks</span>
                <span className="csp-score-value">
                  {csp.best_practice_passed}/{csp.best_practice_total}
                </span>
              </div>
              <div className="csp-score-stat">
                <span className="field-hint">Overall CSP Score</span>
                <span className="csp-score-value">{csp.overall_score}</span>
              </div>
            </div>

            {csp.actual_value ? (
              <>
                <div className="value-row" style={{ marginBottom: 10 }}>
                  <span className="field-hint">Directives:</span>
                  <CopyButton value={csp.actual_value} />
                  <span className="field-hint" style={{ fontSize: 11 }}>
                    (copies the raw header value)
                  </span>
                </div>
                <CSPDirectives directives={csp.directives} />
              </>
            ) : (
              <div className="value-row">
                <span className="field-hint">Actual value:</span>
                <span className="mono">(header not present)</span>
              </div>
            )}

            {csp.policy_checks.length > 0 && (
              <>
                <h4 style={{ margin: "16px 0 4px", fontSize: 14 }}>Policy compliance</h4>
                <ChecksTable rows={csp.policy_checks} />
              </>
            )}

            <h4 style={{ margin: "16px 0 4px", fontSize: 14 }}>
              Security best-practices (checked regardless of policy)
            </h4>
            <ChecksTable rows={csp.security_checks} />

            {(failCount > 0 || warnCount > 0 || !csp.present) && (
              <AIExplain
                name="Content-Security-Policy"
                policyExpected={null}
                actualValue={csp.actual_value}
                checks={allChecks.filter((c) => c.status !== "PASS")}
              />
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
