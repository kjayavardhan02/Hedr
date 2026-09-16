"use client";

import { useState } from "react";
import type { HeaderFinding } from "@/lib/types";
import { StatusBadge } from "./StatusBadge";
import { CopyButton } from "./CopyButton";
import { AIExplain } from "./AIExplain";

export function FindingCard({
  finding,
  index = 0,
}: {
  finding: HeaderFinding;
  index?: number;
}) {
  const [open, setOpen] = useState(finding.status !== "PASS");

  return (
    <div
      className="finding fade-in-up"
      style={{ animationDelay: `${Math.min(index, 8) * 40}ms` }}
    >
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
          <StatusBadge status={finding.status} />
          <span>{finding.header}</span>
          <span className="severity">{finding.severity}</span>
          {finding.required && finding.status === "FAIL" && !finding.present && (
            <span className="pill">missing</span>
          )}
        </div>
        <span className="finding-score">
          {finding.score_earned}/{finding.score_possible}
        </span>
      </div>

      <div className={`collapse ${open ? "open" : ""}`}>
        <div className="collapse-inner">
          <div style={{ paddingTop: 10 }}>
            {finding.policy_expected && (
              <div className="value-row">
                <span className="field-hint">Policy expects:</span>
                <span className="mono">{finding.policy_expected}</span>
                <CopyButton value={finding.policy_expected} />
              </div>
            )}
            <div className="value-row">
              <span className="field-hint">Actual value:</span>
              <span className="mono">{finding.actual_value ?? "(header not present)"}</span>
              {finding.actual_value && <CopyButton value={finding.actual_value} />}
            </div>

            {finding.checks.length > 0 && (
              <div className="checks-table-wrap">
                <table className="checks-table">
                  <thead>
                    <tr>
                      <th>Check</th>
                      <th>Status</th>
                      <th>Expected</th>
                      <th>Actual</th>
                    </tr>
                  </thead>
                  <tbody>
                    {finding.checks.map((c, i) => (
                      <tr key={i}>
                        <td>{c.name}</td>
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
            )}

            {finding.recommendation && (
              <div className="recommendation">{finding.recommendation}</div>
            )}

            {finding.status !== "PASS" && (
              <AIExplain
                name={finding.header}
                policyExpected={finding.policy_expected}
                actualValue={finding.actual_value}
                checks={finding.checks}
              />
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
