"use client";

import { useEffect, useMemo, useState, type CSSProperties } from "react";
import { useToast } from "@/components/Toast";
import { useAuth } from "@/lib/auth-context";
import { ApiError, api } from "@/lib/api";
import type { Policy } from "@/lib/types";
import { IconSliders } from "./icons";

function ruleSummary(policy: Policy): string {
  const n = policy.headers.length;
  return `${n} header rule${n === 1 ? "" : "s"}${policy.csp_policy ? " · CSP" : ""}`;
}

export function PreferencesCard({
  defaultPolicyId,
  style,
}: {
  defaultPolicyId: string | null;
  style?: CSSProperties;
}) {
  const toast = useToast();
  const { refreshUser } = useAuth();
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [value, setValue] = useState(defaultPolicyId ?? "");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    api.listPolicies().catch(() => []).then((data) => setPolicies(data ?? []));
  }, []);

  useEffect(() => {
    setValue(defaultPolicyId ?? "");
  }, [defaultPolicyId]);

  const selectedPolicy = useMemo(() => policies.find((p) => p.id === value), [policies, value]);

  async function handleChange(next: string) {
    setValue(next);
    setSaving(true);
    try {
      await api.updatePreferences({ default_policy_id: next || null });
      await refreshUser();
      toast.show("Preferences saved.", "success");
    } catch (e) {
      setValue(defaultPolicyId ?? "");
      toast.show(e instanceof ApiError ? e.message : "Couldn't save preferences.", "error");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="panel fade-in-up" id="preferences" style={style}>
      <h3 className="section-title" style={{ marginTop: 0, marginBottom: 14 }}>
        <span className="section-icon">
          <IconSliders />
        </span>
        Preferences
      </h3>

      <div className="field">
        <label>Appearance</label>
        <div className="field-hint">
          Dark is currently Hedr&apos;s only theme - Light and System will show up here once one exists.
        </div>
      </div>

      <div className="field" style={{ marginTop: 16 }}>
        <label>Default Policy</label>
        <select value={value} onChange={(e) => handleChange(e.target.value)} disabled={saving}>
          <option value="">None - choose a policy each time</option>
          {policies.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name} {p.is_baseline ? "(baseline)" : `(v${p.version})`}
            </option>
          ))}
        </select>
        <span className="field-hint">Pre-selected when you start a new scan.</span>

        {selectedPolicy && (
          <div className="profile-policy-preview">
            <span className="profile-row-icon">
              <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <path
                  d="M12 3 5 5.8v5.4c0 5 3.2 8.8 7 10.8 3.8-2 7-5.8 7-10.8V5.8L12 3Z"
                  stroke="currentColor"
                  strokeWidth="1.6"
                  strokeLinejoin="round"
                />
              </svg>
            </span>
            <div style={{ minWidth: 0, flex: 1 }}>
              <div style={{ fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {selectedPolicy.name}
              </div>
              <div className="field-hint">
                {selectedPolicy.is_baseline ? "Baseline" : `v${selectedPolicy.version}`} · {ruleSummary(selectedPolicy)}
              </div>
            </div>
            <span className={`ps-badge ${selectedPolicy.is_baseline ? "ps-badge-baseline" : "ps-badge-custom"}`}>
              {selectedPolicy.is_baseline ? "Baseline" : "Custom"}
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
