"use client";

import { duplicateHeaderMessage, duplicateHeaderNames } from "@/lib/policyValidation";
import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { api, ApiError } from "@/lib/api";
import type { CSPPolicy, Policy, PolicyHeader } from "@/lib/types";
import { HeaderPolicyEditor } from "@/components/HeaderPolicyEditor";
import { CSPPolicyBuilder } from "@/components/CSPPolicyBuilder";
import { CSPPolicySummary } from "@/components/CSPPolicySummary";
import { Spinner } from "@/components/Spinner";
import { useToast } from "@/components/Toast";
import { PolicyFormSkeleton } from "@/components/Skeleton";
import { BackLink } from "@/components/BackLink";

export default function EditPolicyPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const toast = useToast();
  const id = params.id;

  const [policy, setPolicy] = useState<Policy | null>(null);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [headers, setHeaders] = useState<PolicyHeader[]>([]);
  const [cspPolicy, setCspPolicy] = useState<CSPPolicy | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .getPolicy(id)
      .then((p) => {
        setPolicy(p);
        setName(p.name);
        setDescription(p.description);
        setHeaders(p.headers);
        setCspPolicy(p.csp_policy);
      })
      .catch((e) => setError(e instanceof ApiError ? e.message : "Failed to load policy."))
      .finally(() => setLoading(false));
  }, [id]);

  async function handleSave() {
    setError(null);
    const cleaned = headers.filter((h) => h.header_name.trim());
    if (!name.trim()) {
      setError("Give the policy a name.");
      return;
    }
    if (cleaned.length === 0 && !cspPolicy) {
      setError("Add at least one header rule or configure a CSP policy.");
      return;
    }
    const duplicates = duplicateHeaderNames(cleaned);
    if (duplicates.length > 0) {
      setError(duplicateHeaderMessage(duplicates));
      return;
    }
    setSaving(true);
    try {
      const updated = await api.updatePolicy(id, {
        name: name.trim(),
        description: description.trim(),
        headers: cleaned,
        csp_policy: cspPolicy,
      });
      setPolicy(updated);
      toast.show("Changes saved.", "success");
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Failed to save policy.");
    } finally {
      setSaving(false);
    }
  }

  if (loading) {
    return (
      <div className="container">
        <BackLink />
        <PolicyFormSkeleton />
      </div>
    );
  }

  if (!policy) {
    return (
      <div className="container">
        <BackLink />
        <div className="error-box">{error ?? "Policy not found."}</div>
      </div>
    );
  }

  const readOnly = policy.is_baseline;

  return (
    <div className="container">
      <BackLink />
      <h1 style={{ fontSize: 24, marginBottom: 4 }}>
        {readOnly ? "View Baseline" : "Edit Policy"}
        <span className="pill">v{policy.version}</span>
      </h1>
      {readOnly && (
        <p className="field-hint" style={{ marginBottom: 20 }}>
          Baseline policies are read-only.{" "}
          <button
            className="btn btn-secondary btn-sm"
            style={{ marginLeft: 4 }}
            onClick={() => router.push(`/policies/new?template=${policy.id}`)}
          >
            Use as template
          </button>
        </p>
      )}

      {!readOnly && (
        <p className="field-hint" style={{ marginBottom: 20 }}>
          Need a variant of this policy?{" "}
          <button
            className="btn btn-secondary btn-sm"
            style={{ marginLeft: 4 }}
            onClick={() => router.push(`/policies/new?template=${policy.id}`)}
          >
            Clone
          </button>{" "}
          Copies the saved version, not unsaved edits.
        </p>
      )}

      {error && <div className="error-box">{error}</div>}

      <div className="panel fade-in-up">
        <div className="field">
          <label>Policy name</label>
          <input value={name} disabled={readOnly} onChange={(e) => setName(e.target.value)} />
        </div>
        <div className="field">
          <label>Description</label>
          <input
            value={description}
            disabled={readOnly}
            onChange={(e) => setDescription(e.target.value)}
          />
        </div>

        {readOnly ? (
          <div>
            {headers.map((h, i) => (
              <div className="header-row" key={i}>
                <div className="field">
                  <label>Header name</label>
                  <input value={h.header_name} disabled />
                </div>
                <div className="field" style={{ flex: 2 }}>
                  <label>Expected value</label>
                  <input value={h.expected_value} disabled />
                </div>
                <div className="field field-fixed">
                  <label>Required</label>
                  <input type="checkbox" checked={h.required} disabled />
                </div>
              </div>
            ))}
          </div>
        ) : (
          <HeaderPolicyEditor headers={headers} onChange={setHeaders} />
        )}
      </div>

      <div className="panel fade-in-up" style={{ marginTop: 16 }}>
        <h3 style={{ marginTop: 0, fontSize: 16 }}>Content-Security-Policy</h3>
        {readOnly ? (
          <CSPPolicySummary policy={cspPolicy} />
        ) : (
          <CSPPolicyBuilder policy={cspPolicy} onChange={setCspPolicy} />
        )}

        {!readOnly && (
          <div style={{ marginTop: 18 }}>
            <button className="btn" onClick={handleSave} disabled={saving}>
              {saving && <Spinner />}
              {saving ? "Saving..." : "Save Changes"}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
