"use client";

import { Suspense, useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { api, ApiError } from "@/lib/api";
import type { CSPPolicy, PolicyHeader } from "@/lib/types";
import { HeaderPolicyEditor } from "@/components/HeaderPolicyEditor";
import { CSPPolicyBuilder } from "@/components/CSPPolicyBuilder";
import { Spinner } from "@/components/Spinner";
import { useToast } from "@/components/Toast";
import { PolicyFormSkeleton } from "@/components/Skeleton";
import { BackLink } from "@/components/BackLink";

function NewPolicyForm() {
  const router = useRouter();
  const toast = useToast();
  const searchParams = useSearchParams();
  const templateId = searchParams.get("template");

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [headers, setHeaders] = useState<PolicyHeader[]>([
    { header_name: "", expected_value: "", required: true },
  ]);
  const [cspPolicy, setCspPolicy] = useState<CSPPolicy | null>(null);
  const [loadingTemplate, setLoadingTemplate] = useState(!!templateId);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!templateId) return;
    api
      .getPolicy(templateId)
      .then((p) => {
        setName(`${p.name} (copy)`);
        setDescription(p.description);
        setHeaders(p.headers);
        setCspPolicy(p.csp_policy);
      })
      .catch(() => setError("Could not load template policy."))
      .finally(() => setLoadingTemplate(false));
  }, [templateId]);

  async function handleSave() {
    setError(null);
    if (!name.trim()) {
      setError("Give the policy a name.");
      return;
    }
    const cleaned = headers.filter((h) => h.header_name.trim());
    if (cleaned.length === 0 && !cspPolicy) {
      setError("Add at least one header rule or configure a CSP policy.");
      return;
    }
    setSaving(true);
    try {
      const policy = await api.createPolicy({
        name: name.trim(),
        description: description.trim(),
        headers: cleaned,
        csp_policy: cspPolicy,
      });
      toast.show(`Policy "${policy.name}" created.`, "success");
      router.push(`/policies/${policy.id}`);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Failed to save policy.");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="container">
      <BackLink />
      <h1 style={{ fontSize: 24, marginBottom: 4 }}>New Policy</h1>
      <p className="field-hint" style={{ marginBottom: 20 }}>
        Add each header you want to enforce, the value you expect, and whether it&apos;s
        required.
      </p>

      {loadingTemplate && <PolicyFormSkeleton />}
      {error && <div className="error-box">{error}</div>}

      {!loadingTemplate && (
        <div className="panel fade-in-up">
          <div className="field">
            <label>Policy name</label>
            <input value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="field">
            <label>Description</label>
            <input value={description} onChange={(e) => setDescription(e.target.value)} />
          </div>

          <HeaderPolicyEditor headers={headers} onChange={setHeaders} />
        </div>
      )}

      {!loadingTemplate && (
        <div className="panel fade-in-up" style={{ marginTop: 16 }}>
          <h3 style={{ marginTop: 0, fontSize: 16 }}>Content-Security-Policy</h3>
          <CSPPolicyBuilder policy={cspPolicy} onChange={setCspPolicy} />

          <div style={{ marginTop: 18 }}>
            <button className="btn" onClick={handleSave} disabled={saving}>
              {saving && <Spinner />}
              {saving ? "Saving..." : "Save Policy"}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export default function NewPolicyPage() {
  return (
    <Suspense fallback={<div className="container">Loading...</div>}>
      <NewPolicyForm />
    </Suspense>
  );
}
