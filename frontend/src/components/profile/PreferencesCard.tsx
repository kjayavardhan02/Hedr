"use client";

import { useEffect, useState } from "react";
import { useToast } from "@/components/Toast";
import { useAuth } from "@/lib/auth-context";
import { ApiError, api } from "@/lib/api";
import type { Policy } from "@/lib/types";

export function PreferencesCard({ defaultPolicyId }: { defaultPolicyId: string | null }) {
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
    <div className="panel fade-in-up" id="preferences">
      <h3 style={{ marginTop: 0, marginBottom: 12, fontSize: 16 }}>Preferences</h3>

      <div className="field">
        <label>Appearance</label>
        <div className="field-hint">
          Dark is currently Hedr&apos;s only theme - Light and System will show up here once one exists.
        </div>
      </div>

      <div className="field" style={{ marginTop: 14 }}>
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
      </div>
    </div>
  );
}
