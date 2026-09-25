"use client";

import { CharCount } from "@/components/CharCount";
import {
  POLICY_NAME_MAX_LENGTH,
  RAW_RESPONSE_MAX_LENGTH,
  SCAN_URL_MAX_LENGTH,
  TARGET_NAME_MAX_LENGTH,
} from "@/lib/limits";
import { duplicateHeaderMessage, duplicateHeaderNames } from "@/lib/policyValidation";
import { useEffect, useState } from "react";
import { api, ApiError } from "@/lib/api";
import type { CSPPolicy, Policy, PolicyHeader, ScanResult } from "@/lib/types";
import { ExportMenu } from "@/components/ExportMenu";
import { HeaderPolicyEditor } from "@/components/HeaderPolicyEditor";
import { CSPPolicyBuilder } from "@/components/CSPPolicyBuilder";
import { ScoreHero } from "@/components/ScoreHero";
import { FindingCard } from "@/components/FindingCard";
import { CSPPanel } from "@/components/CSPPanel";
import { Spinner } from "@/components/Spinner";
import { PolicySelect } from "@/components/PolicySelect";


const EXAMPLE_RAW = `HTTP/1.1 200 OK
Content-Type: text/html
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
X-Frame-Options: SAMEORIGIN`;

export default function ScanPage() {
  const [inputMode, setInputMode] = useState<"url" | "raw">("url");
  const [url, setUrl] = useState("");
  const [rawResponse, setRawResponse] = useState("");
  const [targetName, setTargetName] = useState("");

  const [policies, setPolicies] = useState<Policy[]>([]);
  const [policySource, setPolicySource] = useState<"saved" | "adhoc">("saved");
  const [selectedPolicyId, setSelectedPolicyId] = useState<string>("");

  const [adhocName, setAdhocName] = useState("Ad-hoc Policy");
  const [adhocHeaders, setAdhocHeaders] = useState<PolicyHeader[]>([
    { header_name: "", expected_value: "", required: true },
  ]);
  const [adhocCspPolicy, setAdhocCspPolicy] = useState<CSPPolicy | null>(null);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);

  useEffect(() => {
    api
      .listPolicies()
      .then((data) => {
        setPolicies(data);
        if (data.length > 0) setSelectedPolicyId(data[0].id);
      })
      .catch(() => {
        // Non-fatal: user can still use an ad-hoc policy.
      });
  }, []);

  async function handleScan() {
    setError(null);
    setResult(null);

    if (inputMode === "url" && !url.trim()) {
      setError("Enter a URL to scan.");
      return;
    }
    if (inputMode === "raw" && !rawResponse.trim()) {
      setError("Paste a raw HTTP response or header set.");
      return;
    }
    if (policySource === "saved" && !selectedPolicyId) {
      setError("Select a policy, or switch to 'Build ad-hoc policy'.");
      return;
    }
    if (policySource === "adhoc") {
      const cleaned = adhocHeaders.filter((h) => h.header_name.trim());
      if (cleaned.length === 0 && !adhocCspPolicy) {
        setError("Add at least one header or configure a CSP policy for the ad-hoc policy.");
        return;
      }
      const duplicates = duplicateHeaderNames(cleaned);
      if (duplicates.length > 0) {
        setError(duplicateHeaderMessage(duplicates));
        return;
      }
    }

    setLoading(true);
    try {
      const payload =
        policySource === "saved"
          ? {
              source: inputMode,
              url: inputMode === "url" ? url.trim() : undefined,
              raw_response: inputMode === "raw" ? rawResponse : undefined,
              target_name: inputMode === "raw" ? targetName.trim() || undefined : undefined,
              policy_id: selectedPolicyId,
            }
          : {
              source: inputMode,
              url: inputMode === "url" ? url.trim() : undefined,
              raw_response: inputMode === "raw" ? rawResponse : undefined,
              target_name: inputMode === "raw" ? targetName.trim() || undefined : undefined,
              policy: {
                name: adhocName || "Ad-hoc Policy",
                description: "",
                headers: adhocHeaders.filter((h) => h.header_name.trim()),
                csp_policy: adhocCspPolicy,
              },
            };

      const scanResult = await api.scan(payload);
      setResult(scanResult);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Scan failed unexpectedly.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="container">
      <h1 style={{ fontSize: 24, marginBottom: 4 }}>Scan a target</h1>
      <p className="field-hint" style={{ marginBottom: 20 }}>
        Provide a URL or a pasted HTTP response, pick a policy, and see exactly what
        complies and what doesn&apos;t.
      </p>

      <div className="panel">
        <div className="tabs">
          <button
            className={`tab ${inputMode === "url" ? "active" : ""}`}
            onClick={() => setInputMode("url")}
          >
            URL
          </button>
          <button
            className={`tab ${inputMode === "raw" ? "active" : ""}`}
            onClick={() => setInputMode("raw")}
          >
            Raw HTTP Response
          </button>
        </div>

        {inputMode === "url" ? (
          <div className="field fade-in" key="url-field">
            <label>Target URL</label>
            <input
              placeholder="https://example.com"
              value={url}
              maxLength={SCAN_URL_MAX_LENGTH}
              onChange={(e) => setUrl(e.target.value)}
            />
            <CharCount length={url.length} max={SCAN_URL_MAX_LENGTH} showFrom={0.8} />
            <span className="field-hint">
              Hedr fetches this URL server-side and reads the response headers.
              Requests to private/internal addresses are blocked.
            </span>
          </div>
        ) : (
          <div className="fade-in" key="raw-field">
            <div className="field">
              <label>Target name (optional)</label>
              <input
                placeholder="e.g. My Staging Site"
                value={targetName}
                maxLength={TARGET_NAME_MAX_LENGTH}
                onChange={(e) => setTargetName(e.target.value)}
              />
              <span className="field-hint">
                There&apos;s no URL to label a pasted response with. Give it a name, or
                leave this blank to use &quot;HTTP Response Scan&quot;. Up to {TARGET_NAME_MAX_LENGTH}{" "}
                characters ({targetName.length}/{TARGET_NAME_MAX_LENGTH}).
              </span>
            </div>
            <div className="field">
              <label>Raw response / headers</label>
              <textarea
                rows={10}
                placeholder={EXAMPLE_RAW}
                value={rawResponse}
                maxLength={RAW_RESPONSE_MAX_LENGTH}
                onChange={(e) => setRawResponse(e.target.value)}
                className="mono"
              />
              <CharCount length={rawResponse.length} max={RAW_RESPONSE_MAX_LENGTH} showFrom={0.5} />
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                style={{ alignSelf: "flex-start" }}
                onClick={() => setRawResponse(EXAMPLE_RAW)}
              >
                Fill example
              </button>
            </div>
          </div>
        )}
      </div>

      <div className="panel panel-raised">
        <div className="tabs">
          <button
            className={`tab ${policySource === "saved" ? "active" : ""}`}
            onClick={() => setPolicySource("saved")}
          >
            Use a saved policy
          </button>
          <button
            className={`tab ${policySource === "adhoc" ? "active" : ""}`}
            onClick={() => setPolicySource("adhoc")}
          >
            Build ad-hoc policy
          </button>
        </div>

        {policySource === "saved" ? (
          <div className="field fade-in" key="saved-policy-field">
            <label>Policy</label>
            {policies.length === 0 ? (
              <p className="field-hint">
                No policies yet. <a href="/policies">Create one</a> or build an
                ad-hoc policy for this scan.
              </p>
            ) : (
              <PolicySelect policies={policies} value={selectedPolicyId} onChange={setSelectedPolicyId} />
            )}
          </div>
        ) : (
          <div className="fade-in" key="adhoc-policy-field">
            <div className="adhoc-note" role="note">
              <span className="adhoc-note-icon" aria-hidden="true">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="12" cy="12" r="9" />
                  <path d="M12 11v5M12 8h.01" />
                </svg>
              </span>
              <div>
                <strong>This policy won&apos;t be saved.</strong> It&apos;s used for this scan only and
                won&apos;t appear in your Policies list. The scan report keeps its name, marked
                &quot;ad-hoc&quot;, but the rules can&apos;t be reused or compared later. To keep a policy,{" "}
                <a href="/policies/new" target="_blank" rel="noopener noreferrer">
                  create a saved policy
                </a>.
              </div>
            </div>
            <div className="field">
              <label>Policy name (for this scan only)</label>
              <input
                value={adhocName}
                maxLength={POLICY_NAME_MAX_LENGTH}
                onChange={(e) => setAdhocName(e.target.value)}
              />
              <CharCount length={adhocName.length} max={POLICY_NAME_MAX_LENGTH} showFrom={0.8} />
            </div>
            <HeaderPolicyEditor headers={adhocHeaders} onChange={setAdhocHeaders} />
            <div style={{ marginTop: 18 }}>
              <h3 style={{ marginTop: 0, fontSize: 15 }}>Content-Security-Policy</h3>
              <CSPPolicyBuilder policy={adhocCspPolicy} onChange={setAdhocCspPolicy} />
            </div>
          </div>
        )}
      </div>

      {error && <div className="error-box">{error}</div>}

      <div style={{ marginTop: 16 }}>
        <button className="btn" onClick={handleScan} disabled={loading}>
          {loading && <Spinner />}
          {loading ? "Scanning..." : "Scan"}
        </button>
      </div>

      {result && (
        <div style={{ marginTop: 24 }}>
          <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 8 }}>
            <ExportMenu data={result} />
          </div>
          <ScoreHero result={result} />

          <div className="panel fade-in-up" style={{ animationDelay: "40ms" }}>
            <h3 style={{ marginTop: 0, marginBottom: 12, fontSize: 16 }}>Findings</h3>
            {result.findings.length === 0 && (
              <p className="field-hint">No non-CSP headers were evaluated.</p>
            )}
            {result.findings.map((f, i) => (
              <FindingCard key={f.header} finding={f} index={i} />
            ))}
          </div>

          {result.csp_finding && <CSPPanel csp={result.csp_finding} />}
        </div>
      )}
    </div>
  );
}
