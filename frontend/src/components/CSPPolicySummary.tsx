import type { CSPPolicy } from "@/lib/types";

function restrictionLabels(rule: CSPPolicy["directive_rules"][number]): string[] {
  return [
    rule.disallow_wildcards && "no wildcards",
    rule.disallow_external && "no external sources",
    rule.disallow_http && "no http: sources",
    rule.disallow_data && "no data: sources",
    rule.disallow_blob && "no blob: sources",
  ].filter((label): label is string => Boolean(label));
}

export function CSPPolicySummary({ policy }: { policy: CSPPolicy | null }) {
  if (!policy) {
    return <p className="field-hint">This policy does not evaluate Content-Security-Policy.</p>;
  }

  return (
    <div>
      <div className="field-hint" style={{ marginBottom: 10 }}>
        Header required: {policy.required ? "Yes" : "No"}
        {policy.required_directives.length > 0 && (
          <>
            {" · "}
            Required directives: <span className="mono">{policy.required_directives.join(", ")}</span>
          </>
        )}
      </div>

      {policy.directive_rules.length === 0 ? (
        <p className="field-hint">No per-directive rules configured.</p>
      ) : (
        policy.directive_rules.map((rule, i) => {
          const restrictions = restrictionLabels(rule);
          return (
            <div className="csp-rule-card" key={i}>
              <div className="mono" style={{ fontWeight: 600 }}>
                {rule.directive}
              </div>
              {rule.must_contain.length > 0 && (
                <div className="field-hint">
                  Must contain: <span className="mono">{rule.must_contain.join(", ")}</span>
                </div>
              )}
              {rule.must_not_contain.length > 0 && (
                <div className="field-hint">
                  Must NOT contain: <span className="mono">{rule.must_not_contain.join(", ")}</span>
                </div>
              )}
              {rule.allowed_sources && (
                <div className="field-hint">
                  Allowed sources: <span className="mono">{rule.allowed_sources.join(", ")}</span>
                </div>
              )}
              {restrictions.length > 0 && <div className="field-hint">Restrictions: {restrictions.join(", ")}</div>}
            </div>
          );
        })
      )}
    </div>
  );
}
