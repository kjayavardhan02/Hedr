"use client";

import type { CSPDirectiveRule, CSPPolicy } from "@/lib/types";

const COMMON_DIRECTIVES = [
  "default-src",
  "script-src",
  "style-src",
  "object-src",
  "base-uri",
  "frame-ancestors",
  "form-action",
  "connect-src",
  "img-src",
  "font-src",
  "worker-src",
  "frame-src",
  "manifest-src",
  "media-src",
];

function emptyRule(): CSPDirectiveRule {
  return {
    directive: "",
    must_contain: [],
    must_not_contain: [],
    allowed_sources: null,
    disallow_wildcards: false,
    disallow_external: false,
    disallow_http: false,
    disallow_data: false,
    disallow_blob: false,
  };
}

function defaultPolicy(): CSPPolicy {
  return { required: true, required_directives: [], directive_rules: [] };
}

function splitTokens(value: string): string[] {
  return value
    .split(",")
    .map((t) => t.trim())
    .filter(Boolean);
}

interface Props {
  policy: CSPPolicy | null;
  onChange: (policy: CSPPolicy | null) => void;
}

export function CSPPolicyBuilder({ policy, onChange }: Props) {
  function toggleEnabled(next: boolean) {
    onChange(next ? defaultPolicy() : null);
  }

  function updatePolicy(patch: Partial<CSPPolicy>) {
    if (!policy) return;
    onChange({ ...policy, ...patch });
  }

  function toggleRequiredDirective(directive: string, on: boolean) {
    if (!policy) return;
    const set = new Set(policy.required_directives);
    if (on) set.add(directive);
    else set.delete(directive);
    updatePolicy({ required_directives: Array.from(set) });
  }

  function updateRule(index: number, patch: Partial<CSPDirectiveRule>) {
    if (!policy) return;
    const rules = policy.directive_rules.map((r, i) => (i === index ? { ...r, ...patch } : r));
    updatePolicy({ directive_rules: rules });
  }

  function removeRule(index: number) {
    if (!policy) return;
    updatePolicy({ directive_rules: policy.directive_rules.filter((_, i) => i !== index) });
  }

  function addRule() {
    if (!policy) return;
    updatePolicy({ directive_rules: [...policy.directive_rules, emptyRule()] });
  }

  return (
    <div>
      <datalist id="csp-directives">
        {COMMON_DIRECTIVES.map((d) => (
          <option key={d} value={d} />
        ))}
      </datalist>

      <label className="csp-toggle">
        <input type="checkbox" checked={policy !== null} onChange={(e) => toggleEnabled(e.target.checked)} />
        Evaluate Content-Security-Policy
      </label>

      {policy && (
        <div style={{ marginTop: 14 }}>
          <label className="csp-toggle">
            <input
              type="checkbox"
              checked={policy.required}
              onChange={(e) => updatePolicy({ required: e.target.checked })}
            />
            Header required (fail if the response never sends a CSP header at all)
          </label>

          <div className="field" style={{ marginTop: 14 }}>
            <label>Required directives</label>
            <div className="csp-directive-checks">
              {COMMON_DIRECTIVES.map((d) => (
                <label className="csp-directive-check" key={d}>
                  <input
                    type="checkbox"
                    checked={policy.required_directives.includes(d)}
                    onChange={(e) => toggleRequiredDirective(d, e.target.checked)}
                  />
                  <span className="mono">{d}</span>
                </label>
              ))}
            </div>
          </div>

          <div style={{ marginTop: 18 }}>
            <div className="field-hint" style={{ marginBottom: 10 }}>
              Directive rules — what each directive&apos;s value must or must not contain.
            </div>

            {policy.directive_rules.length === 0 && (
              <p className="field-hint" style={{ marginBottom: 10 }}>
                No per-directive rules yet. Click &quot;Add Directive Rule&quot; to define one.
              </p>
            )}

            {policy.directive_rules.map((rule, i) => (
              <div className="csp-rule-card" key={i}>
                <div className="field">
                  <label>Directive</label>
                  <input
                    list="csp-directives"
                    placeholder="e.g. script-src"
                    value={rule.directive}
                    onChange={(e) => updateRule(i, { directive: e.target.value })}
                  />
                </div>
                <div className="field">
                  <label>Must contain</label>
                  <input
                    placeholder="'self', 'none' (comma-separated)"
                    value={rule.must_contain.join(", ")}
                    onChange={(e) => updateRule(i, { must_contain: splitTokens(e.target.value) })}
                  />
                </div>
                <div className="field">
                  <label>Must NOT contain</label>
                  <input
                    placeholder="'unsafe-inline', 'unsafe-eval' (comma-separated)"
                    value={rule.must_not_contain.join(", ")}
                    onChange={(e) => updateRule(i, { must_not_contain: splitTokens(e.target.value) })}
                  />
                </div>
                <div className="field">
                  <label>Allowed sources (allowlist)</label>
                  <input
                    placeholder="'self', https://cdn.example.com — leave blank for no allowlist"
                    value={rule.allowed_sources?.join(", ") ?? ""}
                    onChange={(e) => {
                      const tokens = splitTokens(e.target.value);
                      updateRule(i, { allowed_sources: tokens.length > 0 ? tokens : null });
                    }}
                  />
                  <span className="field-hint">
                    Any actual source not in this list fails. Leave blank to not enforce an allowlist.
                  </span>
                </div>
                <div className="csp-pattern-checks">
                  <label>
                    <input
                      type="checkbox"
                      checked={rule.disallow_wildcards}
                      onChange={(e) => updateRule(i, { disallow_wildcards: e.target.checked })}
                    />
                    No wildcards (*)
                  </label>
                  <label>
                    <input
                      type="checkbox"
                      checked={rule.disallow_external}
                      onChange={(e) => updateRule(i, { disallow_external: e.target.checked })}
                    />
                    No external sources
                  </label>
                  <label>
                    <input
                      type="checkbox"
                      checked={rule.disallow_http}
                      onChange={(e) => updateRule(i, { disallow_http: e.target.checked })}
                    />
                    No http: sources
                  </label>
                  <label>
                    <input
                      type="checkbox"
                      checked={rule.disallow_data}
                      onChange={(e) => updateRule(i, { disallow_data: e.target.checked })}
                    />
                    No data: sources
                  </label>
                  <label>
                    <input
                      type="checkbox"
                      checked={rule.disallow_blob}
                      onChange={(e) => updateRule(i, { disallow_blob: e.target.checked })}
                    />
                    No blob: sources
                  </label>
                </div>
                <button
                  type="button"
                  className="btn btn-secondary btn-sm remove-btn"
                  onClick={() => removeRule(i)}
                >
                  Remove rule
                </button>
              </div>
            ))}

            <button type="button" className="btn btn-secondary btn-sm" onClick={addRule}>
              + Add Directive Rule
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
