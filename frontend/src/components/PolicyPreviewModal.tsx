"use client";

import { useEffect } from "react";
import Link from "next/link";
import type { Policy } from "@/lib/types";
import { CSPPolicySummary } from "./CSPPolicySummary";

interface Props {
  policy: Policy;
  onClose: () => void;
}

export function PolicyPreviewModal({ policy, onClose }: Props) {
  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [onClose]);

  const headerCount = policy.headers.length;

  return (
    <div className="modal-overlay fade-in" onClick={onClose}>
      <div
        className="modal-panel fade-in-up"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
      >
        <div className="modal-header">
          <div className="modal-header-icon" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none">
              <path
                d="M12 3 5 5.8v5.4c0 5 3.2 8.8 7 10.8 3.8-2 7-5.8 7-10.8V5.8L12 3Z"
                stroke="currentColor"
                strokeWidth="1.6"
                strokeLinejoin="round"
              />
            </svg>
          </div>
          <div className="modal-header-text">
            <h3>{policy.name}</h3>
            <div className="modal-header-meta">
              <span className="report-version-pill">v{policy.version}</span>
              <span className="field-hint" style={{ margin: 0 }}>
                {headerCount} header rule{headerCount === 1 ? "" : "s"}
                {policy.csp_policy && " · evaluates CSP"}
              </span>
            </div>
          </div>
          <button type="button" className="modal-close" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </div>

        {policy.description && <p className="modal-description">{policy.description}</p>}

        <div className="modal-body">
          {headerCount === 0 ? (
            <p className="field-hint">
              {policy.csp_policy ? "This policy has no generic header rules." : "This policy has no header rules."}
            </p>
          ) : (
            policy.headers.map((h, i) => (
              <div className="policy-preview-row" key={i}>
                <div className="policy-preview-row-main">
                  <span className="policy-preview-dot" aria-hidden="true" />
                  <div>
                    <div className="mono policy-preview-header-name">{h.header_name}</div>
                    {h.expected_value && (
                      <div className="mono policy-preview-value">{h.expected_value}</div>
                    )}
                  </div>
                </div>
                <span className={`badge ${h.required ? "badge-INFO" : "badge-neutral"}`}>
                  {h.required ? "Required" : "Optional"}
                </span>
              </div>
            ))
          )}

          {policy.csp_policy && (
            <>
              <h4 style={{ margin: "16px 0 4px", fontSize: 14 }}>Content-Security-Policy</h4>
              <CSPPolicySummary policy={policy.csp_policy} />
            </>
          )}
        </div>

        <div className="modal-footer">
          <Link href={`/policies/${policy.id}`} className="btn btn-sm">
            Edit policy
          </Link>
        </div>
      </div>
    </div>
  );
}
