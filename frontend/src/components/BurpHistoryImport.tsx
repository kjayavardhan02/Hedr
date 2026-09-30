"use client";

import { useEffect, useRef, useState, type ReactNode } from "react";
import { useRouter } from "next/navigation";
import { api, ApiError } from "@/lib/api";
import { useToast } from "@/components/Toast";
import { Spinner } from "@/components/Spinner";
import { PolicySelect } from "@/components/PolicySelect";
import type { BurpImportSummary, Policy } from "@/lib/types";

type Stage = "idle" | "uploading" | "parsed" | "analyzing";

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/** Everything checked = "no filter on this dimension" (backend `null`), so an
 * import with more hosts than the user has seen yet never gets silently
 * excluded by a stale filter. */
function toFilterList(selected: Set<string>, allOptions: string[]): string[] | undefined {
  if (selected.size === allOptions.length) return undefined;
  return Array.from(selected);
}

/** A checkbox re-imagined as a toggleable pill, matching the same
 * clickable-chip language the Reports filter bar uses for its Grade filter -
 * a plain native checkbox here would look like an afterthought next to the
 * rest of this panel's styled controls. */
function Chip({
  checked,
  onToggle,
  children,
  mono,
}: {
  checked: boolean;
  onToggle: () => void;
  children: ReactNode;
  mono?: boolean;
}) {
  return (
    <button
      type="button"
      role="checkbox"
      aria-checked={checked}
      className={`burp-chip ${checked ? "burp-chip-on" : ""}`}
      onClick={onToggle}
    >
      <span className="burp-chip-check" aria-hidden="true">
        <svg viewBox="0 0 16 16" fill="none">
          <path d="M3.5 8.5 6.5 11.5 12.5 4.5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </span>
      <span className={mono ? "mono" : undefined}>{children}</span>
    </button>
  );
}

function FacetGroup({
  label,
  options,
  selected,
  onChange,
}: {
  label: string;
  options: string[];
  selected: Set<string>;
  onChange: (next: Set<string>) => void;
}) {
  if (options.length === 0) return null;
  function toggle(option: string) {
    const next = new Set(selected);
    if (next.has(option)) next.delete(option);
    else next.add(option);
    onChange(next);
  }
  return (
    <div className="field">
      <label>{label}</label>
      <div className="burp-facet-list">
        {options.map((option) => (
          <Chip key={option} checked={selected.has(option)} onToggle={() => toggle(option)} mono>
            {option}
          </Chip>
        ))}
      </div>
    </div>
  );
}

export function BurpHistoryImport() {
  const router = useRouter();
  const toast = useToast();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [stage, setStage] = useState<Stage>("idle");
  const [dragOver, setDragOver] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [summary, setSummary] = useState<BurpImportSummary | null>(null);

  const [selectedHosts, setSelectedHosts] = useState<Set<string>>(new Set());
  const [selectedMethods, setSelectedMethods] = useState<Set<string>>(new Set());
  const [selectedStatusBuckets, setSelectedStatusBuckets] = useState<Set<string>>(new Set());
  const [selectedContentTypes, setSelectedContentTypes] = useState<Set<string>>(new Set());
  const [httpsOnly, setHttpsOnly] = useState(false);
  const [excludeStatic, setExcludeStatic] = useState(false);
  const [deduplicate, setDeduplicate] = useState(true);

  const [policies, setPolicies] = useState<Policy[]>([]);
  const [policyId, setPolicyId] = useState("");
  const [reportName, setReportName] = useState("");

  useEffect(() => {
    api.listPolicies().catch(() => []).then((data) => setPolicies(data ?? []));
  }, []);

  function reset() {
    setStage("idle");
    setFile(null);
    setSummary(null);
    setError(null);
    setReportName("");
    if (fileInputRef.current) fileInputRef.current.value = "";
  }

  async function upload(selected: File) {
    setError(null);
    setFile(selected);
    setStage("uploading");
    try {
      const result = await api.importBurpHistory(selected);
      setSummary(result);
      setSelectedHosts(new Set(result.facets.hosts));
      setSelectedMethods(new Set(result.facets.methods));
      setSelectedStatusBuckets(new Set(result.facets.status_buckets));
      setSelectedContentTypes(new Set(result.facets.content_types));
      setStage("parsed");
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Couldn't import this file.");
      setStage("idle");
    }
  }

  async function handleAnalyze() {
    if (!summary) return;
    if (!policyId) {
      setError("Select a policy to analyze against.");
      return;
    }
    setError(null);
    setStage("analyzing");
    try {
      const result = await api.analyzeBurpImport(summary.id, {
        policy_id: policyId,
        name: reportName.trim() || undefined,
        filters: {
          hosts: toFilterList(selectedHosts, summary.facets.hosts),
          methods: toFilterList(selectedMethods, summary.facets.methods),
          status_buckets: toFilterList(selectedStatusBuckets, summary.facets.status_buckets),
          content_types: toFilterList(selectedContentTypes, summary.facets.content_types),
          https_only: httpsOnly,
          exclude_static: excludeStatic,
          deduplicate,
        },
      });
      toast.show("Burp history analyzed.", "success");
      router.push(`/reports/burp/${result.id}`);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Analysis failed unexpectedly.");
      setStage("parsed");
    }
  }

  if (stage === "idle" || stage === "uploading") {
    return (
      <div className="fade-in">
        <div
          className={`burp-dropzone ${dragOver ? "burp-dropzone-active" : ""}`}
          onDragOver={(e) => {
            e.preventDefault();
            setDragOver(true);
          }}
          onDragLeave={() => setDragOver(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDragOver(false);
            const dropped = e.dataTransfer.files?.[0];
            if (dropped) void upload(dropped);
          }}
        >
          {stage === "uploading" ? (
            <>
              <Spinner />
              <p style={{ marginTop: 10 }}>Importing {file?.name}…</p>
            </>
          ) : (
            <>
              <p style={{ fontWeight: 600, marginBottom: 8 }}>Drag &amp; drop a Burp history export</p>
              <p className="field-hint" style={{ marginBottom: 14 }}>
                A Burp Suite &quot;Save items&quot; HTTP history export (.xml). Max 25MB.
              </p>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => fileInputRef.current?.click()}
              >
                Browse File
              </button>
              <input
                ref={fileInputRef}
                type="file"
                accept=".xml"
                style={{ display: "none" }}
                onChange={(e) => {
                  const selected = e.target.files?.[0];
                  if (selected) void upload(selected);
                }}
              />
            </>
          )}
        </div>
        {error && <div className="error-box" style={{ marginTop: 12 }}>{error}</div>}
      </div>
    );
  }

  // stage is "parsed" or "analyzing" - summary is always set by this point.
  if (!summary) return null;
  const totalUnusable = summary.failed_count + summary.skipped_count;

  return (
    <div className="fade-in">
      <div className="value-row" style={{ alignItems: "center", marginBottom: 16 }}>
        <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
          <span style={{ fontWeight: 600 }} className="mono">
            {summary.source_filename}
          </span>
          <span className="field-hint">
            {summary.entries_found} entries found{file ? ` · ${formatBytes(file.size)}` : ""}
          </span>
        </div>
        <button type="button" className="btn btn-secondary btn-sm" style={{ marginLeft: "auto" }} onClick={reset}>
          Start Over
        </button>
      </div>

      <div className="burp-stat-row">
        <div className="profile-stat">
          <div className="profile-stat-value">{summary.parsed_count + summary.partial_count}</div>
          <div className="profile-stat-label">Usable</div>
        </div>
        <div className="profile-stat">
          <div className="profile-stat-value">{summary.skipped_count}</div>
          <div className="profile-stat-label">Skipped</div>
        </div>
        <div className="profile-stat">
          <div className="profile-stat-value">{summary.failed_count}</div>
          <div className="profile-stat-label">Failed</div>
        </div>
      </div>
      {totalUnusable > 0 && (
        <p className="field-hint" style={{ marginTop: 10 }}>
          {totalUnusable} entr{totalUnusable === 1 ? "y" : "ies"} won&apos;t be analyzed (no usable HTTP
          response). The full breakdown will be in the report&apos;s Import Issues section.
        </p>
      )}

      <div style={{ marginTop: 18, display: "flex", flexDirection: "column", gap: 14 }}>
        <FacetGroup label="Hosts" options={summary.facets.hosts} selected={selectedHosts} onChange={setSelectedHosts} />
        <FacetGroup
          label="HTTP Methods"
          options={summary.facets.methods}
          selected={selectedMethods}
          onChange={setSelectedMethods}
        />
        <FacetGroup
          label="Status Codes"
          options={summary.facets.status_buckets}
          selected={selectedStatusBuckets}
          onChange={setSelectedStatusBuckets}
        />
        <FacetGroup
          label="Content Types"
          options={summary.facets.content_types}
          selected={selectedContentTypes}
          onChange={setSelectedContentTypes}
        />

        <div className="field">
          <label>Additional options</label>
          <div className="burp-facet-list">
            <Chip checked={httpsOnly} onToggle={() => setHttpsOnly((v) => !v)}>
              Analyze HTTPS responses only
            </Chip>
            <Chip checked={excludeStatic} onToggle={() => setExcludeStatic((v) => !v)}>
              Exclude static resources (images, fonts, CSS, JS)
            </Chip>
            <Chip checked={deduplicate} onToggle={() => setDeduplicate((v) => !v)}>
              Deduplicate identical responses
            </Chip>
          </div>
        </div>
      </div>

      <div className="field" style={{ marginTop: 18 }}>
        <label>Security Policy</label>
        {policies.length === 0 ? (
          <p className="field-hint">
            No policies yet. <a href="/policies">Create one</a> before analyzing.
          </p>
        ) : (
          <PolicySelect policies={policies} value={policyId} onChange={setPolicyId} />
        )}
      </div>

      <div className="field" style={{ marginTop: 14 }}>
        <label>Report Name (optional)</label>
        <input
          value={reportName}
          onChange={(e) => setReportName(e.target.value)}
          placeholder={`Burp History - ${summary.source_filename.replace(/\.[^.]+$/, "")}`}
        />
      </div>

      {error && <div className="error-box" style={{ marginTop: 12 }}>{error}</div>}

      <div style={{ marginTop: 16 }}>
        <button className="btn" onClick={handleAnalyze} disabled={stage === "analyzing"}>
          {stage === "analyzing" && <Spinner />}
          {stage === "analyzing" ? "Analyzing…" : "Analyze"}
        </button>
      </div>
    </div>
  );
}
