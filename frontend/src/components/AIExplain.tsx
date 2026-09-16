"use client";

import { useState } from "react";
import { api, ApiError } from "@/lib/api";
import type { CheckResult, ExplainResponse } from "@/lib/types";
import { Spinner } from "./Spinner";

interface Props {
  name: string;
  policyExpected: string | null;
  actualValue: string | null;
  checks: CheckResult[];
}

export function AIExplain({ name, policyExpected, actualValue, checks }: Props) {
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ExplainResponse | null>(null);

  async function handleClick(e: React.MouseEvent) {
    e.stopPropagation();
    if (result) {
      setOpen(!open);
      return;
    }
    setOpen(true);
    setLoading(true);
    setError(null);
    try {
      const res = await api.explain({
        name,
        policy_expected: policyExpected,
        actual_value: actualValue,
        checks,
      });
      setResult(res);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not get an AI explanation.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="ai-explain">
      <button type="button" className="ai-explain-btn" onClick={handleClick}>
        <SparkleIcon />
        {loading ? "Asking AI…" : result ? (open ? "Hide explanation" : "Show explanation") : "Explain with AI"}
      </button>

      <div className={`collapse ${open ? "open" : ""}`}>
        <div className="collapse-inner">
          <div className="ai-explain-body">
            {loading && (
              <div className="ai-explain-loading">
                <Spinner />
                <span>Asking AI to explain this finding…</span>
              </div>
            )}
            {error && <div className="error-box" style={{ marginBottom: 0 }}>{error}</div>}
            {result && (
              <div className="ai-explain-sections">
                <div className="ai-explain-section">
                  <div className="ai-explain-label">What it does</div>
                  <p>{result.what_it_does}</p>
                </div>
                <div className="ai-explain-section">
                  <div className="ai-explain-label">Why it matters here</div>
                  <p>{result.why_it_matters}</p>
                </div>
                <div className="ai-explain-section">
                  <div className="ai-explain-label">
                    Recommendation{result.recommendations.length > 1 ? "s" : ""}
                  </div>
                  {result.recommendations.length === 1 ? (
                    <p>{result.recommendations[0].fix}</p>
                  ) : (
                    <ul className="ai-explain-recs">
                      {result.recommendations.map((r, i) => (
                        <li key={i}>
                          <span className="ai-explain-rec-check">{r.check}</span>
                          {r.fix}
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
                <div className="ai-explain-section">
                  <div className="ai-explain-label">Tradeoffs</div>
                  <p>{result.tradeoffs}</p>
                </div>
                <div className="ai-explain-disclaimer">
                  AI-generated explanation — the PASS/FAIL verdict above is decided
                  by the deterministic rule engine, not by this text.
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function SparkleIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <path
        d="M8 1.5l1.2 3.3L12.5 6l-3.3 1.2L8 10.5l-1.2-3.3L3.5 6l3.3-1.2L8 1.5Z"
        fill="currentColor"
      />
      <path
        d="M13 9.5l.6 1.6 1.6.6-1.6.6-.6 1.6-.6-1.6-1.6-.6 1.6-.6.6-1.6Z"
        fill="currentColor"
      />
    </svg>
  );
}
