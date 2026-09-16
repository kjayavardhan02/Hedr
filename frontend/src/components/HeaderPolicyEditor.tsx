"use client";

import type { PolicyHeader } from "@/lib/types";

const COMMON_HEADERS = [
  "Strict-Transport-Security",
  "Content-Security-Policy",
  "X-Content-Type-Options",
  "X-Frame-Options",
  "Referrer-Policy",
  "Permissions-Policy",
  "Cross-Origin-Opener-Policy",
  "Cross-Origin-Resource-Policy",
  "Cross-Origin-Embedder-Policy",
  "X-XSS-Protection",
];

interface Props {
  headers: PolicyHeader[];
  onChange: (headers: PolicyHeader[]) => void;
}

export function HeaderPolicyEditor({ headers, onChange }: Props) {
  function updateRow(index: number, patch: Partial<PolicyHeader>) {
    const next = headers.map((h, i) => (i === index ? { ...h, ...patch } : h));
    onChange(next);
  }

  function removeRow(index: number) {
    onChange(headers.filter((_, i) => i !== index));
  }

  function addRow() {
    onChange([...headers, { header_name: "", expected_value: "", required: true }]);
  }

  return (
    <div>
      <datalist id="common-headers">
        {COMMON_HEADERS.map((h) => (
          <option key={h} value={h} />
        ))}
      </datalist>

      {headers.length === 0 && (
        <p className="field-hint" style={{ marginBottom: 10 }}>
          No headers yet. Click &quot;Add Header&quot; to define the first rule.
        </p>
      )}

      {headers.map((h, i) => (
        <div className="header-row" key={i}>
          <div className="field">
            <label>Header name</label>
            <input
              list="common-headers"
              placeholder="e.g. Strict-Transport-Security"
              value={h.header_name}
              onChange={(e) => updateRow(i, { header_name: e.target.value })}
            />
          </div>
          <div className="field" style={{ flex: 2 }}>
            <label>Expected value</label>
            <input
              placeholder="e.g. max-age=31536000; includeSubDomains; preload (leave blank to just require presence)"
              value={h.expected_value}
              onChange={(e) => updateRow(i, { expected_value: e.target.value })}
            />
            <span className="field-hint">
              Tip: separate multiple allowed values with &quot;|&quot;, e.g.{" "}
              <code>no-referrer|strict-origin</code>.
            </span>
          </div>
          <div className="field field-fixed">
            <label>Required</label>
            <input
              type="checkbox"
              checked={h.required}
              onChange={(e) => updateRow(i, { required: e.target.checked })}
              style={{ width: 18, height: 18 }}
            />
          </div>
          <button
            type="button"
            className="btn btn-secondary btn-sm remove-btn"
            onClick={() => removeRow(i)}
          >
            Remove
          </button>
        </div>
      ))}

      <button type="button" className="btn btn-secondary btn-sm" onClick={addRow}>
        + Add Header
      </button>
    </div>
  );
}
